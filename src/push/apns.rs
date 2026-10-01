//! APNs VoIP push transport (PushKit).
//!
//! FCM не умеет доставлять PushKit-пуши (`apns-push-type: voip`), поэтому
//! ring-и уходят напрямую в APNs по HTTP/2 с token-based авторизацией:
//! ES256-JWT из .p8-ключа (`kid` — в заголовке, `iss` = Team ID — в claims),
//! кэшируется ~50 минут (APNs принимает токены до часа, повторный минт чаще
//! раза в 20 минут карается `TooManyProviderTokenUpdates`).
//!
//! Контракт использования (iOS 13+): получатель voip-пуша обязан синхронно
//! отрепортить входящий звонок в CallKit, поэтому сюда попадают только
//! конверты с `wakeHint = incomingCall` (клиент-отправитель ставит его только
//! на WebRTC OFFER). Payload content-free — E2E-инвариант.
//!
//! Маппинг ошибок — тот же контракт `SendOutcome`, что и у FCM:
//! - 410 (`Unregistered`, `ExpiredToken`) / 400 `BadDeviceToken` /
//!   `DeviceTokenNotForTopic` → `InvalidToken` (scheduler эвиктит voip-слот)
//! - 429 `TooManyRequests` → `Backoff(Quota)`
//! - 503 → `Backoff(Unavailable)`, прочие 5xx → `Backoff(ServerError)`
//! - 403 (протух/битый provider token) → инвалидация JWT-кэша + `TransientError`
//! - сеть / таймаут / неожиданный статус → `TransientError`
//!
//! Ретраев внутри клиента нет: неудавшийся ring scheduler отправляет обычным
//! FCM-wake путём.

use std::fs;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode as jwt_encode};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::push::transport::{BackoffReason, RingPayload, SendOutcome, VoipRingTransport};

/// APNs принимает provider-токены возрастом до часа; обновляем заранее.
const PROVIDER_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);

/// Звонок протухает быстро: если устройство недоступно дольше ring-окна,
/// доставлять voip-пуш уже вредно (phantom-ring на давно отменённый звонок).
const RING_EXPIRATION_SECS: u64 = 30;

/// APNs environment. Sandbox — для dev-билдов (Xcode-подпись), production —
/// для TestFlight/App Store. Токен устройства из sandbox-билда не работает
/// на production-хосте и наоборот (`BadDeviceToken`), поэтому неверное
/// окружение эвиктит voip-слот каждого устройства на первом же ring'е.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApnsEnvironment {
    Sandbox,
    Production,
}

impl ApnsEnvironment {
    fn host(self) -> &'static str {
        match self {
            Self::Sandbox => "https://api.sandbox.push.apple.com",
            Self::Production => "https://api.push.apple.com",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sandbox" | "dev" | "development" => Ok(Self::Sandbox),
            "production" | "prod" => Ok(Self::Production),
            other => bail!("unknown APNs environment: {other} (expected sandbox|production)"),
        }
    }
}

/// Concrete APNs voip transport. Cheap to clone — wraps an `Arc` over the
/// internal state (HTTP/2 client, signing key, cached provider token).
#[derive(Clone)]
pub struct ApnsVoipClient {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    encoding_key: EncodingKey,
    key_id: String,
    team_id: String,
    /// `apns-topic` для voip-пушей: `<bundle-id>.voip`.
    voip_topic: String,
    host: String,
    provider_token: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    jwt: String,
    minted_at: Instant,
}

#[derive(Serialize)]
struct ProviderClaims<'a> {
    iss: &'a str,
    iat: u64,
}

impl ApnsVoipClient {
    /// Load the .p8 signing key from `key_path` and build the HTTP/2 client.
    /// `bundle_id` is the app bundle identifier; the `.voip` topic suffix is
    /// appended here. The key is parsed into an `EncodingKey` once at startup
    /// so subsequent JWT mints are cheap.
    pub fn new(
        key_path: &str,
        key_id: impl Into<String>,
        team_id: impl Into<String>,
        bundle_id: &str,
        environment: ApnsEnvironment,
        http_timeout: Duration,
    ) -> Result<Self> {
        let key_id = key_id.into();
        let team_id = team_id.into();
        if key_id.is_empty() {
            bail!("APNs key_id must not be empty");
        }
        if team_id.is_empty() {
            bail!("APNs team_id must not be empty");
        }
        if bundle_id.is_empty() {
            bail!("APNs bundle_id must not be empty");
        }

        let raw = fs::read_to_string(key_path)
            .with_context(|| format!("failed to read APNs .p8 key at {key_path}"))?;
        let encoding_key = EncodingKey::from_ec_pem(raw.as_bytes())
            .context("APNs key is not a valid EC (.p8) PEM")?;

        let http = reqwest::Client::builder()
            .timeout(http_timeout)
            // APNs принимает только HTTP/2: prior knowledge исключает откат
            // на HTTP/1.1, если ALPN не договорится.
            .http2_prior_knowledge()
            .build()
            .context("failed to build APNs HTTP client")?;

        Ok(Self {
            inner: Arc::new(Inner {
                http,
                encoding_key,
                key_id,
                team_id,
                voip_topic: format!("{bundle_id}.voip"),
                host: environment.host().to_string(),
                provider_token: Mutex::new(None),
            }),
        })
    }

    /// Public helper for unit tests of the payload shape.
    #[cfg(test)]
    pub fn build_ring_payload(payload: &RingPayload) -> Value {
        build_ring_payload(payload)
    }

    async fn provider_token(&self) -> Result<String> {
        let mut guard = self.inner.provider_token.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.minted_at.elapsed() < PROVIDER_TOKEN_TTL
        {
            return Ok(cached.jwt.clone());
        }

        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before unix epoch")?
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.inner.key_id.clone());
        let claims = ProviderClaims {
            iss: &self.inner.team_id,
            iat,
        };
        let jwt = jwt_encode(&header, &claims, &self.inner.encoding_key)
            .context("failed to sign APNs provider token")?;

        *guard = Some(CachedToken {
            jwt: jwt.clone(),
            minted_at: Instant::now(),
        });
        Ok(jwt)
    }

    /// Force-invalidate the cached provider token. Called after a `403` so the
    /// next attempt mints a fresh one.
    async fn invalidate_provider_token(&self) {
        *self.inner.provider_token.lock().await = None;
    }

    async fn dispatch(&self, payload: RingPayload) -> SendOutcome {
        let body = build_ring_payload(&payload);

        let jwt = match self.provider_token().await {
            Ok(token) => token,
            Err(err) => {
                warn!(error = %err, "APNs provider token mint failed");
                return SendOutcome::TransientError;
            }
        };

        let url = format!("{}/3/device/{}", self.inner.host, payload.token);
        let expiration = payload.server_ts_secs + RING_EXPIRATION_SECS;
        let response = match self
            .inner
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            .header("apns-topic", &self.inner.voip_topic)
            .header("apns-expiration", expiration.to_string())
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                warn!(error = %err, "APNs request failed at transport layer");
                return SendOutcome::TransientError;
            }
        };

        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();

        match status {
            s if s.is_success() => {
                debug!(topic = %self.inner.voip_topic, "APNs voip ring ok");
                SendOutcome::Ok
            }
            StatusCode::GONE => SendOutcome::InvalidToken, // 410 Unregistered
            StatusCode::FORBIDDEN => {
                warn!(body = %response_body, "APNs returned 403 — provider token invalidated");
                self.invalidate_provider_token().await;
                SendOutcome::TransientError
            }
            StatusCode::TOO_MANY_REQUESTS => SendOutcome::Backoff(BackoffReason::Quota),
            StatusCode::SERVICE_UNAVAILABLE => SendOutcome::Backoff(BackoffReason::Unavailable),
            s if s.is_server_error() => SendOutcome::Backoff(BackoffReason::ServerError),
            s if s.is_client_error() => classify_client_error(&response_body),
            _ => {
                warn!(status = %status, body = %response_body, "APNs returned unexpected status");
                SendOutcome::TransientError
            }
        }
    }
}

impl VoipRingTransport for ApnsVoipClient {
    fn send_ring(&self, payload: RingPayload) -> impl Future<Output = SendOutcome> + Send {
        let me = self.clone();
        async move { me.dispatch(payload).await }
    }
}

/// Content-free ring payload. `aps` пустой (voip-пуши не показывают алертов —
/// весь UI строит CallKit на устройстве), `wake`/`server_ts` — сигнал клиенту
/// «это звонок» + свежесть.
fn build_ring_payload(payload: &RingPayload) -> Value {
    json!({
        "aps": {},
        "wake": "call",
        "server_ts": payload.server_ts_secs,
    })
}

/// APNs кладёт машинную причину в JSON-поле `reason` тела ответа.
fn classify_client_error(body: &str) -> SendOutcome {
    let reason = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        .unwrap_or_default();

    match reason.as_str() {
        "BadDeviceToken" | "Unregistered" | "DeviceTokenNotForTopic" => SendOutcome::InvalidToken,
        "ExpiredProviderToken" | "InvalidProviderToken" | "MissingProviderToken" => {
            // APNs отдаёт эти причины с 403 — та ветка сбрасывает кэш JWT.
            // Здесь (не-403 статус) кэш не сбрасывается: токен перевыпустится
            // только по истечении `PROVIDER_TOKEN_TTL`.
            SendOutcome::TransientError
        }
        "TooManyProviderTokenUpdates" => SendOutcome::Backoff(BackoffReason::Quota),
        other => {
            warn!(reason = %other, body = %body, "APNs client error");
            SendOutcome::TransientError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> RingPayload {
        RingPayload {
            user_id: [7; 32],
            device_id: 3,
            token: "voip-token".to_string(),
            server_ts_secs: 1_700_000_000,
        }
    }

    #[test]
    fn ring_payload_is_content_free() {
        let value = build_ring_payload(&ring());
        assert_eq!(value["wake"], "call");
        assert_eq!(value["server_ts"], 1_700_000_000u64);
        // Ни имени звонящего, ни room id, ни каких-либо контентных полей.
        assert_eq!(value["aps"], json!({}));
        assert_eq!(value.as_object().unwrap().len(), 3);
    }

    #[test]
    fn environment_parse_accepts_common_spellings() {
        for raw in ["sandbox", "dev", "development"] {
            assert_eq!(
                ApnsEnvironment::parse(raw).unwrap(),
                ApnsEnvironment::Sandbox
            );
        }
        for raw in ["production", "prod", "PROD"] {
            assert_eq!(
                ApnsEnvironment::parse(raw).unwrap(),
                ApnsEnvironment::Production
            );
        }
        assert!(ApnsEnvironment::parse("staging").is_err());
    }

    #[test]
    fn client_error_classification_maps_apns_reasons() {
        assert_eq!(
            classify_client_error(r#"{"reason":"BadDeviceToken"}"#),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            classify_client_error(r#"{"reason":"Unregistered"}"#),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            classify_client_error(r#"{"reason":"DeviceTokenNotForTopic"}"#),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            classify_client_error(r#"{"reason":"TooManyProviderTokenUpdates"}"#),
            SendOutcome::Backoff(BackoffReason::Quota)
        );
        assert_eq!(
            classify_client_error(r#"{"reason":"PayloadTooLarge"}"#),
            SendOutcome::TransientError
        );
        assert_eq!(
            classify_client_error("not json"),
            SendOutcome::TransientError
        );
    }
}
