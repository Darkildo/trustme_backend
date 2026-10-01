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
//! - 403 `ExpiredProviderToken` / `InvalidProviderToken` → `TransientError` и
//!   сброс JWT-кэша, но не чаще раза в 20 минут; прочие 403 (сертификат,
//!   окружение, `Forbidden`) → `TransientError` без сброса: новый токен их не
//!   лечит, а частый перевыпуск APNs карает `TooManyProviderTokenUpdates`
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

use crate::push::transport::{
    BackoffReason, RingPayload, SendOutcome, VoipRingTransport, loggable,
};

/// APNs принимает provider-токены возрастом до часа; обновляем заранее.
const PROVIDER_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);

/// Перевыпуск provider-токена чаще раза в 20 минут APNs отвергает
/// (`TooManyProviderTokenUpdates`).
const MIN_PROVIDER_TOKEN_REFRESH: Duration = Duration::from_secs(20 * 60);

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
    provider_token: Mutex<ProviderTokenCache>,
}

struct CachedToken {
    jwt: String,
    minted_at: Instant,
}

/// Кэш provider-токена. Вынесен в отдельный тип, чтобы правила перевыпуска
/// проверялись без ключа и сети.
#[derive(Default)]
struct ProviderTokenCache {
    cached: Option<CachedToken>,
}

impl ProviderTokenCache {
    /// Закэшированный токен, если он ещё не подошёл к пределу жизни.
    fn fresh(&self, now: Instant) -> Option<&str> {
        self.cached
            .as_ref()
            .filter(|cached| now.saturating_duration_since(cached.minted_at) < PROVIDER_TOKEN_TTL)
            .map(|cached| cached.jwt.as_str())
    }

    fn store(&mut self, jwt: String, now: Instant) {
        self.cached = Some(CachedToken {
            jwt,
            minted_at: now,
        });
    }

    /// APNs отверг закэшированный токен (`ExpiredProviderToken` /
    /// `InvalidProviderToken`). Сбрасывает его, только если перевыпуск уже
    /// разрешён: токен моложе 20 минут по возрасту протухнуть не мог, значит,
    /// дело в ключе или часах, и свежий APNs отверг бы так же — да ещё с
    /// `TooManyProviderTokenUpdates`. При устойчиво битом ключе это даёт не
    /// больше одного перевыпуска за 20 минут вместо перевыпуска на каждый
    /// ring. Возвращает `true`, если токен сброшен.
    fn on_rejected(&mut self, now: Instant) -> bool {
        let refresh_allowed = self.cached.as_ref().is_some_and(|cached| {
            now.saturating_duration_since(cached.minted_at) >= MIN_PROVIDER_TOKEN_REFRESH
        });
        if refresh_allowed {
            self.cached = None;
        }
        refresh_allowed
    }
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
                provider_token: Mutex::new(ProviderTokenCache::default()),
            }),
        })
    }

    /// Public helper for unit tests of the payload shape.
    #[cfg(test)]
    pub fn build_ring_payload(payload: &RingPayload) -> Value {
        build_ring_payload(payload)
    }

    async fn provider_token(&self) -> Result<String> {
        let mut cache = self.inner.provider_token.lock().await;
        let now = Instant::now();
        if let Some(jwt) = cache.fresh(now) {
            return Ok(jwt.to_owned());
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

        cache.store(jwt.clone(), now);
        Ok(jwt)
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
                // Токен устройства — часть URL, а reqwest печатает URL в
                // тексте ошибки.
                warn!(error = %loggable(err), "APNs request failed at transport layer");
                return SendOutcome::TransientError;
            }
        };

        let status = response.status();
        if status.is_success() {
            debug!(topic = %self.inner.voip_topic, "APNs voip ring ok");
            return SendOutcome::Ok;
        }

        let response_body = response.text().await.unwrap_or_default();
        let rejection = classify_rejection(status, &response_body);
        if rejection.provider_token_rejected
            && self
                .inner
                .provider_token
                .lock()
                .await
                .on_rejected(Instant::now())
        {
            debug!("APNs provider token dropped; the next ring mints a new one");
        }
        rejection.outcome
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

/// Как поступить с неуспешным ответом APNs.
#[derive(Debug, PartialEq, Eq)]
struct Rejection {
    outcome: SendOutcome,
    /// APNs отверг сам provider-токен: кэш стоит сбросить (с оглядкой на
    /// `ProviderTokenCache::on_rejected`).
    provider_token_rejected: bool,
}

/// Классификация неуспешного ответа. Машинную причину APNs кладёт в
/// JSON-поле `reason` тела; токена устройства в теле нет.
fn classify_rejection(status: StatusCode, body: &str) -> Rejection {
    let reason = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        .unwrap_or_default();
    let provider_token_rejected = matches!(
        reason.as_str(),
        "ExpiredProviderToken" | "InvalidProviderToken"
    );

    let outcome = match status {
        // 410: `Unregistered` / `ExpiredToken` — токен устройства мёртв.
        StatusCode::GONE => SendOutcome::InvalidToken,
        StatusCode::TOO_MANY_REQUESTS => SendOutcome::backoff(BackoffReason::Quota),
        StatusCode::SERVICE_UNAVAILABLE => SendOutcome::backoff(BackoffReason::Unavailable),
        s if s.is_server_error() => SendOutcome::backoff(BackoffReason::ServerError),
        _ => match reason.as_str() {
            "BadDeviceToken" | "Unregistered" | "DeviceTokenNotForTopic" => {
                SendOutcome::InvalidToken
            }
            "TooManyProviderTokenUpdates" => SendOutcome::backoff(BackoffReason::Quota),
            // Сюда же причины 403 про сертификат, окружение и `Forbidden`:
            // ни ретрай, ни новый provider-токен их не лечат, нужен оператор.
            other => {
                warn!(
                    status = %status,
                    reason = %other,
                    body = %body,
                    "APNs rejected the voip push"
                );
                SendOutcome::TransientError
            }
        },
    };

    Rejection {
        outcome,
        provider_token_rejected,
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

    fn outcome(status: StatusCode, body: &str) -> SendOutcome {
        classify_rejection(status, body).outcome
    }

    #[test]
    fn client_error_classification_maps_apns_reasons() {
        let bad_request = StatusCode::BAD_REQUEST;
        assert_eq!(
            outcome(bad_request, r#"{"reason":"BadDeviceToken"}"#),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            outcome(StatusCode::GONE, r#"{"reason":"Unregistered"}"#),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            outcome(bad_request, r#"{"reason":"DeviceTokenNotForTopic"}"#),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            outcome(
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"reason":"TooManyProviderTokenUpdates"}"#
            ),
            SendOutcome::backoff(BackoffReason::Quota)
        );
        assert_eq!(
            outcome(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"reason":"PayloadTooLarge"}"#
            ),
            SendOutcome::TransientError
        );
        assert_eq!(
            outcome(bad_request, "not json"),
            SendOutcome::TransientError
        );
        assert_eq!(
            outcome(StatusCode::SERVICE_UNAVAILABLE, ""),
            SendOutcome::backoff(BackoffReason::Unavailable)
        );
        assert_eq!(
            outcome(StatusCode::INTERNAL_SERVER_ERROR, ""),
            SendOutcome::backoff(BackoffReason::ServerError)
        );
    }

    /// Кэш сбрасывают только причины про сам provider-токен. Прочие 403
    /// (сертификат, окружение, `Forbidden`) раньше тоже сбрасывали его, и
    /// при устойчивой ошибке каждый ring минтил новый токен — прямой путь к
    /// `TooManyProviderTokenUpdates`.
    #[test]
    fn only_provider_token_reasons_reject_the_cached_token() {
        let forbidden = StatusCode::FORBIDDEN;
        for reason in ["ExpiredProviderToken", "InvalidProviderToken"] {
            let rejection = classify_rejection(forbidden, &format!(r#"{{"reason":"{reason}"}}"#));
            assert!(rejection.provider_token_rejected, "{reason}");
            assert_eq!(rejection.outcome, SendOutcome::TransientError);
        }

        for body in [
            r#"{"reason":"BadCertificateEnvironment"}"#,
            r#"{"reason":"BadCertificate"}"#,
            r#"{"reason":"Forbidden"}"#,
            r#"{"reason":"MissingProviderToken"}"#,
            "",
        ] {
            let rejection = classify_rejection(forbidden, body);
            assert!(!rejection.provider_token_rejected, "{body}");
            assert_eq!(rejection.outcome, SendOutcome::TransientError);
        }
    }

    #[test]
    fn rejected_token_is_dropped_at_most_once_per_refresh_window() {
        let minted = Instant::now();
        let mut cache = ProviderTokenCache::default();
        assert!(!cache.on_rejected(minted), "пустой кэш сбрасывать нечего");

        cache.store("jwt-1".into(), minted);
        assert_eq!(cache.fresh(minted), Some("jwt-1"));

        // Свежий токен APNs отверг — дело не в возрасте, перевыпуск не
        // поможет и только сожжёт лимит.
        assert!(!cache.on_rejected(minted + Duration::from_secs(60)));
        assert_eq!(cache.fresh(minted + Duration::from_secs(60)), Some("jwt-1"));

        // Через 20 минут перевыпуск уже разрешён.
        assert!(cache.on_rejected(minted + MIN_PROVIDER_TOKEN_REFRESH));
        assert_eq!(cache.fresh(minted + MIN_PROVIDER_TOKEN_REFRESH), None);
    }

    #[test]
    fn cached_token_expires_before_apns_would_reject_it() {
        let minted = Instant::now();
        let mut cache = ProviderTokenCache::default();
        cache.store("jwt".into(), minted);

        assert_eq!(
            cache.fresh(minted + PROVIDER_TOKEN_TTL - Duration::from_secs(1)),
            Some("jwt")
        );
        assert_eq!(cache.fresh(minted + PROVIDER_TOKEN_TTL), None);
    }

    /// Provider token — ES256 JWT, подписанный ключом `.p8`, с `kid` ключа
    /// и `iss` команды. Ловит и jsonwebtoken без бэкенда подписи: он
    /// собирается, но паникует на первой подписи.
    #[tokio::test]
    async fn provider_token_is_es256_jwt_signed_by_the_p8_key() {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let pkcs8 = pair.to_pkcs8v1().unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("trust_message_tcp_apns_{nanos}.p8"));
        fs::write(
            &path,
            pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref())),
        )
        .unwrap();
        let client = ApnsVoipClient::new(
            path.to_str().unwrap(),
            "KEYID12345",
            "TEAMID1234",
            "com.example.app",
            ApnsEnvironment::Sandbox,
            Duration::from_secs(5),
        );
        fs::remove_file(&path).unwrap();
        let client = client.unwrap();

        let jwt = client.provider_token().await.unwrap();

        let header = decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEYID12345"));

        // У provider token нет `exp`: срок жизни задаёт APNs по `iat`.
        let mut validation = Validation::new(Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let claims = decode::<Value>(
            &jwt,
            &DecodingKey::from_ec_der(pair.public_key().as_ref()),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims["iss"], "TEAMID1234");
    }
}
