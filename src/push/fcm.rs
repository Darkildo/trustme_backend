//! FCM HTTP v1 push transport.
//!
//! Uses a Google service-account JSON key to mint short-lived OAuth2 access
//! tokens (RS256-signed JWTs exchanged for bearer tokens) and dispatches one
//! message per call: a data-only wake or a visible welcome. Error mapping
//! matches the contract laid out in `push::transport::SendOutcome`:
//! - `details[].errorCode` (`google.firebase.fcm.v1.FcmError`) =
//!   `UNREGISTERED` (404) or `SENDER_ID_MISMATCH` (403), or
//!   `INVALID_ARGUMENT` blaming the token field → `InvalidToken`
//! - any other 404 / 403 (wrong project, disabled API, missing IAM role) →
//!   `TransientError`: the token is not at fault and must not be evicted
//! - 429 (quota exceeded) → `Backoff(Quota)`
//! - 503 → `Backoff(Unavailable)`, other 5xx → `Backoff(ServerError)`;
//!   a `Retry-After` header (delay-seconds) travels along as the minimum pause
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
use crate::domain::wake::WakeHint;
use crate::push::transport::{
    BackoffReason, PushKind, PushPayload, PushTransport, SendOutcome, loggable,
};

/// Greeting shown when a brand-new user registers their first push token.
const WELCOME_TITLE: &str = "Welcome!";
const WELCOME_BODY: &str = "From doctor with love";

/// Значение `data.wake_hint` для звонкового wake'а. Совпадает со значением
/// `wake` в APNs voip-payload'е (`push::apns`) намеренно: клиент читает один
/// и тот же словарь, каким бы путём его ни разбудили.
const WAKE_HINT_CALL: &str = "call";

const GOOGLE_TOKEN_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const ACCESS_TOKEN_SKEW: Duration = Duration::from_secs(60);

/// `@type` деталей ошибки, в которых FCM HTTP v1 кладёт машинный
/// `errorCode`.
const FCM_ERROR_TYPE: &str = "type.googleapis.com/google.firebase.fcm.v1.FcmError";

#[derive(Clone, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
}

/// Вручную, а не `derive`: `private_key` — ключ подписи всего проекта
/// Firebase, и `{:?}` где-нибудь в логе или в тексте ошибки выложил бы его
/// целиком.
impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .finish()
    }
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
                warn!(error = %loggable(err), "FCM request failed at transport layer");
                return SendOutcome::TransientError;
            }
        };

        let status = response.status();
        let retry_after = retry_after(response.headers());
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
            StatusCode::TOO_MANY_REQUESTS => SendOutcome::Backoff {
                reason: BackoffReason::Quota,
                retry_after,
            },
            StatusCode::SERVICE_UNAVAILABLE => SendOutcome::Backoff {
                reason: BackoffReason::Unavailable,
                retry_after,
            },
            s if s.is_server_error() => SendOutcome::Backoff {
                reason: BackoffReason::ServerError,
                retry_after,
            },
            s if s.is_client_error() => classify_client_error(status, &body),
            _ => {
                warn!(status = %status, body = %body, "FCM returned unexpected status");
                SendOutcome::TransientError
            }
        }
    }
}

/// `Retry-After` в форме delay-seconds — так его отдаёт FCM на 429 и 503.
/// Форма HTTP-date не разбирается: FCM её не использует, а без подсказки
/// планировщик всё равно отступит по собственной экспоненте.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
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

/// Wake-конверт: data-only, без единого байта переписки. Контракт `data`
/// (все значения — строки, как того требует FCM):
///
/// | ключ | значение |
/// |---|---|
/// | `kind` | `"wake"` |
/// | `pending` | сколько недоставленных накопилось с прошлого пуша |
/// | `max_priority` | `"high"` / `"medium"` / `"low"` / `"none"` |
/// | `user` | hex получателя (64 символа) |
/// | `device` | `device_id` строкой (пустая строка, если 0) |
/// | `ts` | серверное unix-время принятия решения |
/// | `wake_hint` | `"call"` — **только** у звонкового wake'а |
///
/// `wake_hint` именно отсутствует, а не равен какому-нибудь `"none"`:
/// контракт клиента — «ключ есть ⇒ это звонок», и нейтральное значение
/// пришлось бы отличать от звонка на каждой стороне.
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

    let mut data = json!({
        "kind": "wake",
        "pending": payload.pending.to_string(),
        "max_priority": max_priority,
        "user": hex::encode(payload.user_id),
        "device": device,
        "ts": payload.server_ts_secs.to_string(),
    });

    // Звонок доезжает до Android'а только этим ключом: voip-путь у него
    // отсутствует, а обычный wake неотличим от «пришли сообщения» — и
    // получатель увидит баннер вместо входящего звонка.
    if let (Some(WakeHint::IncomingCall), Some(fields)) = (payload.wake_hint, data.as_object_mut())
    {
        fields.insert("wake_hint".to_string(), Value::from(WAKE_HINT_CALL));
    }

    json!({
        "message": {
            "token": payload.token,
            "data": data,
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

/// Классификация 4xx-ответа (кроме 401 и 429, разобранных выше).
///
/// Решение о смерти токена принимается только по машинному `errorCode` из
/// `details[]` (`google.firebase.fcm.v1.FcmError`), а не по HTTP-статусу или
/// `error.status`: тот же 404 `NOT_FOUND` FCM отдаёт и на неверный project
/// id, и тогда эвикция по статусу стёрла бы токены всех устройств ноды за
/// один проход. Ошибиться в сторону ретрая дешевле: лишний запрос против
/// устройства, молчащего до следующей регистрации.
///
/// Справочник кодов:
/// https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
fn classify_client_error(http_status: StatusCode, body: &str) -> SendOutcome {
    // FCM v1 error body shape: { "error": { "status": "...", "details": [...] } }
    let parsed: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => {
            warn!(status = %http_status, body = %body, "FCM client error with a non-JSON body");
            return SendOutcome::TransientError;
        }
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

    match fcm_error_code(&parsed) {
        // Токен отозван: приложение удалено, токен протух или перевыпущен.
        Some("UNREGISTERED") => return SendOutcome::InvalidToken,
        // Токен выписан другому Firebase-проекту. Ретрай его не оживит —
        // он не наш, и держать его значит вечно ретраить в пустоту.
        Some("SENDER_ID_MISMATCH") => return SendOutcome::InvalidToken,
        _ => {}
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
        http_status = %http_status,
        status = %status,
        message = %message,
        body = %body,
        "FCM client error treated as transient"
    );
    SendOutcome::TransientError
}

/// `errorCode` из деталей типа `google.firebase.fcm.v1.FcmError`, если FCM
/// его прислал. Детали других типов (`google.rpc.BadRequest` и т. п.) не
/// смотрятся: поле с тем же именем в них значило бы другое.
fn fcm_error_code(parsed: &Value) -> Option<&str> {
    parsed
        .get("error")?
        .get("details")?
        .as_array()?
        .iter()
        .filter(|detail| detail.get("@type").and_then(Value::as_str) == Some(FCM_ERROR_TYPE))
        .find_map(|detail| detail.get("errorCode")?.as_str())
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
            wake_hint: None,
        }
    }

    fn call_payload() -> PushPayload {
        PushPayload {
            wake_hint: Some(WakeHint::IncomingCall),
            ..payload(Some(MessagePriority::High))
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
            wake_hint: None,
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
        // Не звонок — ключа нет вовсе (а не «есть со значением none»):
        // клиент читает его как «ключ есть ⇒ показать ринг».
        assert!(data.get("wake_hint").is_none());
    }

    /// Звонковый wake несёт маркер, по которому Android-клиент показывает
    /// ринг вместо баннера «новые сообщения». Остальной конверт — тот же.
    #[test]
    fn wake_envelope_marks_incoming_call() {
        let env = build_envelope(&call_payload());
        let data = env["message"].get("data").unwrap();

        assert_eq!(data["wake_hint"], "call");
        assert_eq!(data["kind"], "wake");
        assert_eq!(data["max_priority"], "high");
        // Маркер не заменяет собой содержимое: его по-прежнему нет.
        assert!(data.get("body").is_none());
        assert_eq!(env["message"]["android"]["priority"], "high");
    }

    /// Welcome-конверт звонковым не бывает: у него собственный `kind` и
    /// свой набор ключей, и `wake_hint` туда не протекает.
    #[test]
    fn welcome_envelope_never_carries_wake_hint() {
        let env = build_envelope(&welcome_payload());
        let data = env["message"].get("data").unwrap();

        assert_eq!(data["kind"], "welcome");
        assert!(data.get("wake_hint").is_none());
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

    /// Ответ FCM на отозванный токен: 404 `NOT_FOUND` с `errorCode =
    /// UNREGISTERED` в деталях `FcmError`.
    #[test]
    fn classify_unregistered_error_code_as_invalid_token() {
        let body = r#"{
          "error": {
            "code": 404,
            "message": "Requested entity was not found.",
            "status": "NOT_FOUND",
            "details": [
              {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
               "errorCode": "UNREGISTERED"}
            ]
          }
        }"#;
        assert_eq!(
            classify_client_error(StatusCode::NOT_FOUND, body),
            SendOutcome::InvalidToken
        );
    }

    /// 404 без `errorCode = UNREGISTERED` — это не про токен: так FCM
    /// отвечает, например, на неверный project id. Стирать по нему токен
    /// значило бы за один проход вычистить все устройства ноды.
    #[test]
    fn other_not_found_never_evicts_the_token() {
        let wrong_project = r#"{"error":{"code":404,"status":"NOT_FOUND","message":"Requested entity was not found."}}"#;
        assert_eq!(
            classify_client_error(StatusCode::NOT_FOUND, wrong_project),
            SendOutcome::TransientError
        );

        let html = "<html><body>404 Not Found</body></html>";
        assert_eq!(
            classify_client_error(StatusCode::NOT_FOUND, html),
            SendOutcome::TransientError
        );

        // `errorCode` с тем же значением, но в деталях чужого типа, — не
        // сигнал FCM о токене.
        let foreign_detail = r#"{
          "error": {
            "status": "NOT_FOUND",
            "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                         "errorCode": "UNREGISTERED"}]
          }
        }"#;
        assert_eq!(
            classify_client_error(StatusCode::NOT_FOUND, foreign_detail),
            SendOutcome::TransientError
        );
    }

    /// Токен чужого Firebase-проекта не оживёт никаким ретраем.
    #[test]
    fn sender_id_mismatch_evicts_the_token() {
        let body = r#"{
          "error": {
            "code": 403,
            "message": "SenderId mismatch",
            "status": "PERMISSION_DENIED",
            "details": [
              {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
               "errorCode": "SENDER_ID_MISMATCH"}
            ]
          }
        }"#;
        assert_eq!(
            classify_client_error(StatusCode::FORBIDDEN, body),
            SendOutcome::InvalidToken
        );
    }

    /// Прочие 403 — вопрос прав сервисного аккаунта или выключенного API,
    /// а не токена.
    #[test]
    fn permission_denied_without_error_code_keeps_the_token() {
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Firebase Cloud Messaging API has not been used in project"}}"#;
        assert_eq!(
            classify_client_error(StatusCode::FORBIDDEN, body),
            SendOutcome::TransientError
        );
    }

    #[test]
    fn classify_invalid_argument_uses_message_hint() {
        let token_err =
            r#"{"error":{"status":"INVALID_ARGUMENT","message":"Invalid registration token"}}"#;
        assert!(matches!(
            classify_client_error(StatusCode::BAD_REQUEST, token_err),
            SendOutcome::InvalidToken
        ));

        let payload_err =
            r#"{"error":{"status":"INVALID_ARGUMENT","message":"Invalid value at message.data"}}"#;
        assert!(matches!(
            classify_client_error(StatusCode::BAD_REQUEST, payload_err),
            SendOutcome::TransientError
        ));
    }

    #[test]
    fn retry_after_reads_delay_seconds_only() {
        use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};

        let mut headers = HeaderMap::new();
        assert_eq!(retry_after(&headers), None);

        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(120)));

        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(retry_after(&headers), None);
    }

    /// `private_key` — ключ подписи всего проекта: `{:?}` не должен его
    /// показывать ни целиком, ни частично.
    #[test]
    fn service_account_debug_redacts_the_private_key() {
        // PEM-обёртка собирается из частей: целиком она выглядела бы для
        // сканеров секретов как настоящий ключ в репозитории.
        let pem_label = ["PRIVATE", "KEY"].join(" ");
        let account = ServiceAccount {
            client_email: "push@project.iam.gserviceaccount.com".into(),
            private_key: format!(
                "-----BEGIN {pem_label}-----\nMIIEsecretmaterial\n-----END {pem_label}-----\n"
            ),
            token_uri: "https://oauth2.googleapis.com/token".into(),
        };
        let shown = format!("{account:?}");
        assert!(!shown.contains("secretmaterial"), "key leaked: {shown}");
        assert!(!shown.contains("BEGIN PRIVATE KEY"), "key leaked: {shown}");
        assert!(shown.contains("push@project.iam.gserviceaccount.com"));
        assert!(shown.contains("<redacted>"));
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
            classify_client_error(StatusCode::BAD_REQUEST, token_err),
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
            classify_client_error(StatusCode::BAD_REQUEST, payload_err),
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
            classify_client_error(StatusCode::BAD_REQUEST, "not json"),
            SendOutcome::TransientError
        ));
    }

    /// Обмен на OAuth-токен: RS256-assertion, подписанный ключом service
    /// account, уходит формой на `token_uri`. Ловит и jsonwebtoken без
    /// бэкенда подписи (собирается, но паникует на первой подписи), и
    /// reqwest без фичи `form`.
    #[tokio::test]
    async fn token_exchange_posts_rs256_assertion_signed_by_service_account() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;
        use jsonwebtoken::{DecodingKey, Validation, decode};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8: Pkcs8V1Der = pair.as_der().unwrap();
        let private_key = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref()));

        // Token endpoint: принять один запрос, вернуть токен, отдать тело
        // формы тесту.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_uri = format!("http://{}/token", listener.local_addr().unwrap());
        let endpoint = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            let form = loop {
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0, "connection closed before the request body");
                request.extend_from_slice(&buf[..n]);
                let Some(head_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&request[..head_end]).to_lowercase();
                let body_len: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |len| len.trim().parse().unwrap());
                let body = &request[head_end + 4..];
                if body.len() >= body_len {
                    break String::from_utf8(body[..body_len].to_vec()).unwrap();
                }
            };
            let reply = r#"{"access_token":"ya29.test","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            form
        });

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("trust_message_tcp_fcm_sa_{nanos}.json"));
        let account = json!({
            "client_email": "push@project.iam.gserviceaccount.com",
            "private_key": private_key,
            "token_uri": token_uri,
        });
        fs::write(&path, account.to_string()).unwrap();
        let client =
            FcmHttpV1Client::new("project", path.to_str().unwrap(), Duration::from_secs(5));
        fs::remove_file(&path).unwrap();
        let client = client.unwrap();

        assert_eq!(client.bearer().await.unwrap(), "ya29.test");

        let form = endpoint.await.unwrap();
        let mut grant_type = None;
        let mut assertion = None;
        for pair in form.split('&') {
            match pair.split_once('=') {
                Some(("grant_type", value)) => grant_type = Some(value),
                Some(("assertion", value)) => assertion = Some(value),
                _ => {}
            }
        }
        assert_eq!(
            grant_type,
            Some("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
        );

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["push@project.iam.gserviceaccount.com"]);
        validation.set_audience(&[token_uri.as_str()]);
        let claims = decode::<Value>(
            assertion.expect("assertion in the form"),
            &DecodingKey::from_rsa_der(pair.public_key().as_ref()),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims["scope"], GOOGLE_TOKEN_SCOPE);
    }
}
