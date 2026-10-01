//! FCM HTTP v1 push transport.
//!
//! Uses a Google service-account JSON key to mint short-lived OAuth2 access
//! tokens (RS256-signed JWTs exchanged for bearer tokens) and dispatches one
//! message per call: a data-only wake or a visible welcome. Error mapping
//! matches the contract laid out in `push::transport::SendOutcome`:
//! - `NOT_FOUND` / `UNREGISTERED`, or `INVALID_ARGUMENT` blaming the token
//!   field → `InvalidToken`
//! - 429 (quota exceeded) → `Backoff(Quota)`
//! - 503 → `Backoff(Unavailable)`, other 5xx → `Backoff(ServerError)`
//! - 401 → cached access token dropped, `TransientError`
//! - other 4xx, network / timeout / unexpected → `TransientError`
//!
//! No retries inside the client — the scheduler owns retry policy via the
//! exponential backoff (`suppressed_until_secs`) in `PushState`.

use std::fs;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode as jwt_encode};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::domain::priority::MessagePriority;
use crate::push::transport::{BackoffReason, PushKind, PushPayload, PushTransport, SendOutcome};

/// Greeting shown when a brand-new user registers their first push token.
const WELCOME_TITLE: &str = "Welcome!";
const WELCOME_BODY: &str = "From doctor with love";

const GOOGLE_TOKEN_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const ACCESS_TOKEN_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
}

/// Concrete FCM v1 transport. Cheap to clone — wraps an `Arc` over the
/// internal state (HTTP client, signing key, cached access token).
#[derive(Clone)]
pub struct FcmHttpV1Client {
    inner: Arc<Inner>,
}

struct Inner {
    project_id: String,
    http: reqwest::Client,
    service_account: ServiceAccount,
    encoding_key: EncodingKey,
    access_token: Mutex<Option<CachedToken>>,
    send_url: String,
}

struct CachedToken {
    bearer: String,
    expires_at: Instant,
}

impl FcmHttpV1Client {
    /// Load a service-account JSON from `service_account_path` and build the
    /// HTTP client. The private key is parsed into an `EncodingKey` once at
    /// startup so subsequent JWT mints are cheap.
    pub fn new(
        project_id: impl Into<String>,
        service_account_path: &str,
        http_timeout: Duration,
    ) -> Result<Self> {
        let project_id = project_id.into();
        if project_id.is_empty() {
            bail!("FCM project_id must not be empty");
        }

        let raw = fs::read_to_string(service_account_path).with_context(|| {
            format!("failed to read FCM service account at {service_account_path}")
        })?;
        let service_account: ServiceAccount =
            serde_json::from_str(&raw).context("FCM service account JSON could not be parsed")?;

        let encoding_key = EncodingKey::from_rsa_pem(service_account.private_key.as_bytes())
            .context("FCM service account private_key is not a valid RSA PEM")?;

        let http = reqwest::Client::builder()
            .timeout(http_timeout)
            .build()
            .context("failed to build FCM HTTP client")?;

        let send_url = format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send");

        Ok(Self {
            inner: Arc::new(Inner {
                project_id,
                http,
                service_account,
                encoding_key,
                access_token: Mutex::new(None),
                send_url,
            }),
        })
    }

    /// Public helper for unit tests of the envelope shape.
    #[cfg(test)]
    pub fn build_envelope(payload: &PushPayload) -> Value {
        build_envelope(payload)
    }

    async fn bearer(&self) -> Result<String> {
        let mut guard = self.inner.access_token.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.expires_at > Instant::now() + ACCESS_TOKEN_SKEW
        {
            return Ok(cached.bearer.clone());
        }

        let fresh = mint_access_token(
            &self.inner.http,
            &self.inner.service_account,
            &self.inner.encoding_key,
        )
        .await?;

        *guard = Some(CachedToken {
            bearer: fresh.bearer.clone(),
            expires_at: fresh.expires_at,
        });
        Ok(fresh.bearer)
    }

    /// Force-invalidate the cached bearer. Called after a `401` so the next
    /// attempt mints a fresh access token.
    async fn invalidate_bearer(&self) {
        *self.inner.access_token.lock().await = None;
    }

    async fn dispatch(&self, payload: PushPayload) -> SendOutcome {
        let envelope = build_envelope(&payload);

        let bearer = match self.bearer().await {
            Ok(token) => token,
            Err(err) => {
                warn!(error = %err, "FCM access token mint failed");
                return SendOutcome::TransientError;
            }
        };

        let response = match self
            .inner
            .http
            .post(&self.inner.send_url)
            .bearer_auth(&bearer)
            .json(&envelope)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                warn!(error = %err, "FCM request failed at transport layer");
                return SendOutcome::TransientError;
            }
        };

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        match status {
            s if s.is_success() => {
                debug!(project = %self.inner.project_id, "FCM send ok");
                SendOutcome::Ok
            }
            StatusCode::UNAUTHORIZED => {
                warn!(body = %body, "FCM returned 401 — bearer invalidated");
                self.invalidate_bearer().await;
                SendOutcome::TransientError
            }
            StatusCode::TOO_MANY_REQUESTS => SendOutcome::Backoff(BackoffReason::Quota),
            StatusCode::SERVICE_UNAVAILABLE => SendOutcome::Backoff(BackoffReason::Unavailable),
            s if s.is_server_error() => SendOutcome::Backoff(BackoffReason::ServerError),
            s if s.is_client_error() => classify_client_error(&body),
            _ => {
                warn!(status = %status, body = %body, "FCM returned unexpected status");
                SendOutcome::TransientError
            }
        }
    }
}

impl PushTransport for FcmHttpV1Client {
    fn send(&self, payload: PushPayload) -> impl Future<Output = SendOutcome> + Send {
        let me = self.clone();
        async move { me.dispatch(payload).await }
    }
}

fn build_envelope(payload: &PushPayload) -> Value {
    match payload.kind {
        PushKind::Wake => build_wake_envelope(payload),
        PushKind::Welcome => build_welcome_envelope(payload),
    }
}

fn build_wake_envelope(payload: &PushPayload) -> Value {
    let max_priority = priority_label(payload.max_priority);
    // A wake push is a silent, data-only message whose entire purpose is to
    // wake a backgrounded / Doze'd app. Android only delivers data-only
    // messages promptly (and at all, under Doze) at "high" priority, so wake
    // pushes always use "high" regardless of the message priority. APNs keeps
    // the priority-routed value ("5" stays background-safe for iOS).
    let (_routed_android_priority, apns_priority) = priority_routing(payload.max_priority);
    let android_priority = "high";

    let device = if payload.device_id == 0 {
        String::new()
    } else {
        payload.device_id.to_string()
    };

    json!({
        "message": {
            "token": payload.token,
            "data": {
                "kind": "wake",
                "pending": payload.pending.to_string(),
                "max_priority": max_priority,
                "user": hex::encode(payload.user_id),
                "device": device,
                "ts": payload.server_ts_secs.to_string(),
            },
            "android": { "priority": android_priority },
            "apns": { "headers": { "apns-priority": apns_priority } }
        }
    })
}

/// Welcome envelope carries a user-visible `notification` block (so the OS
/// renders a banner even if the app isn't running) plus a small data tag the
/// client can use to suppress in-app routing.
fn build_welcome_envelope(payload: &PushPayload) -> Value {
    let device = if payload.device_id == 0 {
        String::new()
    } else {
        payload.device_id.to_string()
    };

    json!({
        "message": {
            "token": payload.token,
            "notification": {
                "title": WELCOME_TITLE,
                "body": WELCOME_BODY,
            },
            "data": {
                "kind": "welcome",
                "user": hex::encode(payload.user_id),
                "device": device,
                "ts": payload.server_ts_secs.to_string(),
            },
            "android": { "priority": "high" },
            "apns": { "headers": { "apns-priority": "10" } }
        }
    })
}

fn priority_label(p: Option<MessagePriority>) -> &'static str {
    match p {
        Some(MessagePriority::High) => "high",
        Some(MessagePriority::Medium) => "medium",
        Some(MessagePriority::Low) => "low",
        None => "none",
    }
}

/// Per-platform priority hints `(android, apns)` for a message priority. Wake
/// pushes use only the APNs value — Android wake is always `"high"` (see
/// `build_wake_envelope`). APNs `"10"` (immediate) is reserved for High;
/// `"5"` lets iOS schedule delivery around the device's power state.
fn priority_routing(p: Option<MessagePriority>) -> (&'static str, &'static str) {
    match p {
        Some(MessagePriority::High) => ("high", "10"),
        Some(MessagePriority::Medium) => ("high", "5"),
        Some(MessagePriority::Low) | None => ("normal", "5"),
    }
}

fn classify_client_error(body: &str) -> SendOutcome {
    // FCM v1 error body shape: { "error": { "status": "...", "details": [...] } }
    let parsed: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return SendOutcome::TransientError,
    };

    let status = parsed
        .get("error")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let message = parsed
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");

    // Token-fatal statuses per
    // https://firebase.google.com/docs/cloud-messaging/send-message#rest
    if status == "NOT_FOUND" || status == "UNREGISTERED" {
        return SendOutcome::InvalidToken;
    }

    if status == "INVALID_ARGUMENT" && invalid_argument_blames_token(&parsed, message) {
        // `INVALID_ARGUMENT` покрывает и битый токен, и битый payload —
        // различаем по тому, на какое поле жалуется FCM.
        return SendOutcome::InvalidToken;
    }

    // Include the full body so the `details[].fieldViolations` are visible —
    // the human-readable `message` for INVALID_ARGUMENT is generic ("Request
    // contains an invalid argument.") and hides which field FCM rejected.
    warn!(
        status = %status,
        message = %message,
        body = %body,
        "FCM client error treated as transient"
    );
    SendOutcome::TransientError
}

/// Виноват ли в `INVALID_ARGUMENT` именно registration token.
///
/// FCM кладёт причину в `details[].fieldViolations[]`, а `error.message` для
/// этого статуса обычно generic — «Request contains an invalid argument.».
/// Проверка одного `message` пропускала бы битые токены: они уходили бы в
/// `TransientError`, ретраились бесконечно и не вычищались из
/// `PushTokenStore`.
///
/// `message` проверяется тоже — на случай, если FCM положит туда
/// человекочитаемую причину.
fn invalid_argument_blames_token(parsed: &serde_json::Value, message: &str) -> bool {
    if message.to_ascii_lowercase().contains("registration") {
        return true;
    }

    let Some(details) = parsed
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.as_array())
    else {
        return false;
    };

    details
        .iter()
        .filter_map(|detail| detail.get("fieldViolations")?.as_array())
        .flatten()
        .any(|violation| {
            let field = violation
                .get("field")
                .and_then(|f| f.as_str())
                .unwrap_or_default();
            let description = violation
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            // `field` — это путь в запросе (`message.token`); description
            // дублирует причину текстом. Совпадения любого достаточно.
            field == "message.token" || description.contains("registration")
        })
}

struct MintedToken {
    bearer: String,
    expires_at: Instant,
}

/// Exchange a self-signed service-account JWT for an OAuth2 access token
/// (JWT bearer grant, RFC 7523). Google caps the assertion lifetime at one
/// hour, hence `exp = iat + 3600`.
async fn mint_access_token(
    http: &reqwest::Client,
    service_account: &ServiceAccount,
    encoding_key: &EncodingKey,
) -> Result<MintedToken> {
    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        scope: &'a str,
        aud: &'a str,
        exp: u64,
        iat: u64,
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs();
    let claims = Claims {
        iss: &service_account.client_email,
        scope: GOOGLE_TOKEN_SCOPE,
        aud: &service_account.token_uri,
        exp: now + 3600,
        iat: now,
    };
    let assertion = jwt_encode(&Header::new(Algorithm::RS256), &claims, encoding_key)
        .context("failed to sign OAuth2 JWT assertion")?;

    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        expires_in: u64,
    }

    let response = http
        .post(&service_account.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .context("OAuth2 token exchange request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("OAuth2 token exchange failed: {status} {body}"));
    }

    let parsed: TokenResp = response
        .json()
        .await
        .context("OAuth2 token response not JSON")?;
    Ok(MintedToken {
        bearer: parsed.access_token,
        expires_at: Instant::now() + Duration::from_secs(parsed.expires_in),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::PushPayload;
    use crate::state::registry::DeviceId;

    fn user(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn payload(priority: Option<MessagePriority>) -> PushPayload {
        PushPayload {
            user_id: user(1),
            device_id: 7 as DeviceId,
            token: "fcm-tok".to_string(),
            pending: 3,
            max_priority: priority,
            server_ts_secs: 1_700_000_000,
            kind: PushKind::Wake,
        }
    }

    fn welcome_payload() -> PushPayload {
        PushPayload {
            user_id: user(9),
            device_id: 2 as DeviceId,
            token: "fcm-tok-welcome".to_string(),
            pending: 0,
            max_priority: None,
            server_ts_secs: 1_700_000_000,
            kind: PushKind::Welcome,
        }
    }

    #[test]
    fn envelope_carries_only_wake_metadata_not_message_body() {
        let env = build_envelope(&payload(Some(MessagePriority::High)));
        let message = env.get("message").unwrap();

        assert_eq!(message["token"], "fcm-tok");
        let data = message.get("data").unwrap();
        assert_eq!(data["kind"], "wake");
        assert_eq!(data["pending"], "3");
        assert_eq!(data["max_priority"], "high");
        assert_eq!(data["user"], hex::encode(user(1)));
        assert_eq!(data["device"], "7");
        assert_eq!(data["ts"], "1700000000");

        // Neither sender id nor message body is leaked into the payload.
        assert!(data.get("body").is_none());
        assert!(data.get("sender").is_none());
    }

    #[test]
    fn wake_android_priority_is_always_high_apns_tracks_message_priority() {
        // A wake push is a silent data-only message: Android only delivers
        // those reliably (and under Doze) at "high", so wake always uses
        // "high" regardless of the message priority. APNs keeps tracking the
        // message priority (10 for High, 5 otherwise — background-safe on iOS).
        let high = build_envelope(&payload(Some(MessagePriority::High)));
        assert_eq!(high["message"]["android"]["priority"], "high");
        assert_eq!(high["message"]["apns"]["headers"]["apns-priority"], "10");

        let medium = build_envelope(&payload(Some(MessagePriority::Medium)));
        assert_eq!(medium["message"]["android"]["priority"], "high");
        assert_eq!(medium["message"]["apns"]["headers"]["apns-priority"], "5");

        let low = build_envelope(&payload(Some(MessagePriority::Low)));
        assert_eq!(low["message"]["android"]["priority"], "high");
        assert_eq!(low["message"]["apns"]["headers"]["apns-priority"], "5");

        let none = build_envelope(&payload(None));
        assert_eq!(none["message"]["android"]["priority"], "high");
        assert_eq!(none["message"]["apns"]["headers"]["apns-priority"], "5");
    }

    #[test]
    fn classify_unregistered_status_as_invalid_token() {
        let body =
            r#"{"error":{"status":"NOT_FOUND","message":"Requested entity was not found."}}"#;
        assert!(matches!(
            classify_client_error(body),
            SendOutcome::InvalidToken
        ));

        let body2 = r#"{"error":{"status":"UNREGISTERED","message":""}}"#;
        assert!(matches!(
            classify_client_error(body2),
            SendOutcome::InvalidToken
        ));
    }

    #[test]
    fn classify_invalid_argument_uses_message_hint() {
        let token_err =
            r#"{"error":{"status":"INVALID_ARGUMENT","message":"Invalid registration token"}}"#;
        assert!(matches!(
            classify_client_error(token_err),
            SendOutcome::InvalidToken
        ));

        let payload_err =
            r#"{"error":{"status":"INVALID_ARGUMENT","message":"Invalid value at message.data"}}"#;
        assert!(matches!(
            classify_client_error(payload_err),
            SendOutcome::TransientError
        ));
    }

    /// Типичный ответ FCM HTTP v1: `message` generic, причина — в
    /// `details[].fieldViolations[]`. Проверка только по `message` на нём
    /// промахивается, и битый токен ушёл бы в бесконечный retry вместо
    /// удаления из стора.
    #[test]
    fn classify_invalid_argument_reads_field_violations() {
        let token_err = r#"{
          "error": {
            "code": 400,
            "message": "Request contains an invalid argument.",
            "status": "INVALID_ARGUMENT",
            "details": [
              {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
               "errorCode": "INVALID_ARGUMENT"},
              {"@type": "type.googleapis.com/google.rpc.BadRequest",
               "fieldViolations": [
                 {"field": "message.token", "description": "Invalid registration token"}
               ]}
            ]
          }
        }"#;
        assert!(matches!(
            classify_client_error(token_err),
            SendOutcome::InvalidToken
        ));

        // Тот же конверт, но претензия к payload — токен ни при чём,
        // удалять его нельзя.
        let payload_err = r#"{
          "error": {
            "code": 400,
            "message": "Request contains an invalid argument.",
            "status": "INVALID_ARGUMENT",
            "details": [
              {"@type": "type.googleapis.com/google.rpc.BadRequest",
               "fieldViolations": [
                 {"field": "message.data[0].value", "description": "Invalid value"}
               ]}
            ]
          }
        }"#;
        assert!(matches!(
            classify_client_error(payload_err),
            SendOutcome::TransientError
        ));
    }

    #[test]
    fn welcome_envelope_carries_notification_block_with_doctor_signoff() {
        let env = build_envelope(&welcome_payload());
        let message = env.get("message").unwrap();

        let notification = message.get("notification").expect("notification block");
        assert_eq!(notification["title"], WELCOME_TITLE);
        assert_eq!(notification["body"], WELCOME_BODY);

        let data = message.get("data").unwrap();
        assert_eq!(data["kind"], "welcome");
        assert_eq!(data["user"], hex::encode(user(9)));
        assert_eq!(data["device"], "2");
        // Welcome must not leak wake-fan-out fields.
        assert!(data.get("pending").is_none());
        assert!(data.get("max_priority").is_none());

        assert_eq!(message["android"]["priority"], "high");
        assert_eq!(message["apns"]["headers"]["apns-priority"], "10");
    }

    #[test]
    fn classify_unparseable_body_falls_back_to_transient() {
        assert!(matches!(
            classify_client_error("not json"),
            SendOutcome::TransientError
        ));
    }
}
