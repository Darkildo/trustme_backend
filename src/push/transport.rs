use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use crate::domain::priority::MessagePriority;
use crate::domain::wake::WakeHint;
use crate::state::registry::{DeviceId, UserId};

/// Outcome of a single push send (FCM, APNs or the push gateway), used by the
/// scheduler to update state and possibly evict the recipient's token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Push accepted by the provider.
    Ok,
    /// The provider reported the token as dead (FCM `NOT_FOUND` /
    /// `INVALID_ARGUMENT` on the token field, APNs `Unregistered` /
    /// `BadDeviceToken`, etc). The scheduler drops it from `TokenStore`.
    InvalidToken,
    /// Provider overload: 5xx, quota exceeded, unavailable. For wakes the
    /// scheduler applies exponential backoff (`suppress_initial` →
    /// `suppress_max`); a failed ring falls back to an FCM wake instead.
    Backoff {
        reason: BackoffReason,
        /// Пауза, которую провайдер назвал сам (`Retry-After`). Планировщик
        /// не повторит раньше неё, даже если собственный шаг backoff'а
        /// короче. `None` — провайдер ничего не назвал.
        retry_after: Option<Duration>,
    },
    /// Network / unexpected error. Treated like `Backoff` but counted
    /// separately in metrics.
    TransientError,
}

impl SendOutcome {
    /// `Backoff` без подсказки провайдера — так отвечают все транспорты,
    /// кроме FCM с заголовком `Retry-After`.
    pub const fn backoff(reason: BackoffReason) -> Self {
        Self::Backoff {
            reason,
            retry_after: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackoffReason {
    Quota,
    ServerError,
    Unavailable,
}

/// Ошибка reqwest, пригодная для лога.
///
/// `Display` у `reqwest::Error` печатает URL запроса, а у APNs токен
/// устройства — часть пути (`/3/device/<token>`). Токен — это и есть
/// capability на пробуждение устройства, в логах ему не место.
pub(crate) fn loggable(err: reqwest::Error) -> reqwest::Error {
    err.without_url()
}

/// Токен в отладочном выводе: только длина. Сам токен — capability на
/// пробуждение устройства, а `Debug` нагрузки легко оказывается в логе.
struct RedactedToken<'a>(&'a str);

impl std::fmt::Debug for RedactedToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted, {} bytes>", self.0.len())
    }
}

/// Kind of push being dispatched. `Wake` is the default fan-out used by the
/// delivery layer (data-only payload, no user-visible content). `Welcome` is a
/// one-shot greeting fired on a user's very first push-token registration; it
/// carries a user-visible notification block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PushKind {
    #[default]
    Wake,
    Welcome,
}

/// Data passed to the transport when the scheduler decides to send. The
/// transport serializes it into its own wire format (FCM v1 envelope, gateway
/// protobuf).
#[derive(Clone)]
pub struct PushPayload {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub token: String,
    /// How many undelivered messages have accumulated since the last push.
    pub pending: u32,
    /// Highest priority among those messages. `None` means none of them had
    /// a priority set.
    pub max_priority: Option<MessagePriority>,
    /// Server's view of "now" at the moment the decision was made (unix seconds).
    /// Useful for the client to compute push staleness.
    pub server_ts_secs: u64,
    /// Distinguishes the wake fan-out from special one-shots (e.g. welcome).
    pub kind: PushKind,
    /// `Some(IncomingCall)` — этот wake будит получателя под звонок: конверт,
    /// вызвавший отправку, нёс `wakeHint = incomingCall`, а voip-путь был
    /// недоступен (Android, либо iOS без PushKit-слота). Транспорт обязан
    /// донести признак до клиента (FCM: `data.wake_hint = "call"`), иначе
    /// получатель покажет баннер «новые сообщения» вместо ринга. Транспорт
    /// шлюза (`push::gateway`) признак не передаёт: в `push.proto` для него
    /// нет поля.
    ///
    /// Живёт только в конверте пуша: в inbox `WakeHint` не персистится, а
    /// значит и повторно взяться ему неоткуда.
    pub wake_hint: Option<WakeHint>,
}

impl std::fmt::Debug for PushPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushPayload")
            .field("user_id", &hex::encode(self.user_id))
            .field("device_id", &self.device_id)
            .field("token", &RedactedToken(&self.token))
            .field("pending", &self.pending)
            .field("max_priority", &self.max_priority)
            .field("server_ts_secs", &self.server_ts_secs)
            .field("kind", &self.kind)
            .field("wake_hint", &self.wake_hint)
            .finish()
    }
}

/// Pluggable wake transport: FCM HTTP v1, the push gateway, or a mock in
/// tests. The returned future must be `Send` so the worker can run on the
/// multi-threaded runtime.
pub trait PushTransport: Send + Sync + 'static {
    fn send(&self, payload: PushPayload) -> impl Future<Output = SendOutcome> + Send;
}

/// Данные для одного APNs voip-ring'а: получатель офлайн, конверт нёс
/// `wakeHint = incomingCall`, у устройства зарегистрирован PushKit-токен.
/// Payload на проводе content-free (E2E-инвариант) — вся идентификация
/// звонящего происходит на клиенте после дренажа mailbox'а.
#[derive(Clone)]
pub struct RingPayload {
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// PushKit VoIP-токен (hex-строка от `PKPushRegistry`).
    pub token: String,
    /// Server "now" (unix seconds) — клиент оценивает свежесть ring'а.
    pub server_ts_secs: u64,
}

impl std::fmt::Debug for RingPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingPayload")
            .field("user_id", &hex::encode(self.user_id))
            .field("device_id", &self.device_id)
            .field("token", &RedactedToken(&self.token))
            .field("server_ts_secs", &self.server_ts_secs)
            .finish()
    }
}

/// Транспорт APNs voip-пушей (`apns-push-type: voip`). Отдельный от
/// [`PushTransport`]: ring минует decision-машину коалесинга, а его outcome
/// эвиктит voip-слот (не alert-слот) при `InvalidToken`.
pub trait VoipRingTransport: Send + Sync + 'static {
    fn send_ring(&self, payload: RingPayload) -> impl Future<Output = SendOutcome> + Send;
}

/// Заглушка для конфигураций без APNs (voip выключен). Никогда не вызывается:
/// scheduler без voip-транспорта уводит ring-триггеры в обычный FCM-wake.
pub struct NoVoipRingTransport;

impl VoipRingTransport for NoVoipRingTransport {
    async fn send_ring(&self, _payload: RingPayload) -> SendOutcome {
        unreachable!("NoVoipRingTransport must never be dispatched")
    }
}

/// Test/dev voip-транспорт — записывает ring'и и возвращает scripted outcomes.
pub struct MockRingTransport {
    sent: Mutex<Vec<RingPayload>>,
    outcome: OutcomeStrategy,
}

impl MockRingTransport {
    pub fn always_ok() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::AlwaysOk,
        }
    }

    pub fn always_invalid_token() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::AlwaysInvalidToken,
        }
    }

    pub fn always_backoff(reason: BackoffReason) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::AlwaysBackoff(reason),
        }
    }

    pub fn sent_rings(&self) -> Vec<RingPayload> {
        self.sent.lock().unwrap().clone()
    }
}

impl VoipRingTransport for MockRingTransport {
    fn send_ring(&self, payload: RingPayload) -> impl Future<Output = SendOutcome> + Send {
        let outcome = match &self.outcome {
            OutcomeStrategy::AlwaysOk => SendOutcome::Ok,
            OutcomeStrategy::AlwaysInvalidToken => SendOutcome::InvalidToken,
            OutcomeStrategy::AlwaysBackoff(reason) => SendOutcome::backoff(*reason),
            OutcomeStrategy::Scripted(queue) => {
                queue.lock().unwrap().pop_front().unwrap_or(SendOutcome::Ok)
            }
        };
        self.sent.lock().unwrap().push(payload);
        async move { outcome }
    }
}

/// Lookup / removal of push tokens by `(user, device)`. Production uses the
/// sled-backed `PushTokenStore`; tests use `InMemoryTokenStore`.
///
/// `remove` is called when the transport reports `InvalidToken`. It must be
/// idempotent — concurrent removes for the same key are fine.
///
/// `resolve_voip` / `remove_voip` address the separate PushKit VoIP slot of an
/// iOS device. The default implementations report "no slot", so stores
/// without VoIP support need not implement them.
pub trait TokenStore: Send + Sync + 'static {
    fn resolve(&self, user: &UserId, device: DeviceId) -> Option<String>;
    fn remove(&self, user: &UserId, device: DeviceId);
    fn resolve_voip(&self, _user: &UserId, _device: DeviceId) -> Option<String> {
        None
    }
    fn remove_voip(&self, _user: &UserId, _device: DeviceId) {}
}

/// In-memory token store for tests. A plain `Mutex` is enough at test scale.
pub struct InMemoryTokenStore {
    inner: Mutex<HashMap<(UserId, DeviceId), String>>,
    voip: Mutex<HashMap<(UserId, DeviceId), String>>,
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            voip: Mutex::new(HashMap::new()),
        }
    }
}

impl InMemoryTokenStore {
    pub fn insert(&self, user: UserId, device: DeviceId, token: impl Into<String>) {
        self.inner
            .lock()
            .unwrap()
            .insert((user, device), token.into());
    }

    pub fn insert_voip(&self, user: UserId, device: DeviceId, token: impl Into<String>) {
        self.voip
            .lock()
            .unwrap()
            .insert((user, device), token.into());
    }
}

impl TokenStore for InMemoryTokenStore {
    fn resolve(&self, user: &UserId, device: DeviceId) -> Option<String> {
        self.inner.lock().unwrap().get(&(*user, device)).cloned()
    }

    fn remove(&self, user: &UserId, device: DeviceId) {
        self.inner.lock().unwrap().remove(&(*user, device));
    }

    fn resolve_voip(&self, user: &UserId, device: DeviceId) -> Option<String> {
        self.voip.lock().unwrap().get(&(*user, device)).cloned()
    }

    fn remove_voip(&self, user: &UserId, device: DeviceId) {
        self.voip.lock().unwrap().remove(&(*user, device));
    }
}

/// Test transport that records every send and returns scripted outcomes,
/// simulating provider responses without HTTP. Also serves as the inert
/// transport when push is disabled (`PUSH_ENABLED=false`).
pub struct MockTransport {
    sent: Mutex<Vec<PushPayload>>,
    outcome: OutcomeStrategy,
    latency: Duration,
}

pub enum OutcomeStrategy {
    AlwaysOk,
    AlwaysInvalidToken,
    AlwaysBackoff(BackoffReason),
    /// Pop outcomes from the front; once empty, defaults to `Ok`.
    Scripted(Mutex<std::collections::VecDeque<SendOutcome>>),
}

impl MockTransport {
    pub fn always_ok() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::AlwaysOk,
            latency: Duration::ZERO,
        }
    }

    pub fn always_invalid_token() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::AlwaysInvalidToken,
            latency: Duration::ZERO,
        }
    }

    pub fn always_backoff(reason: BackoffReason) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::AlwaysBackoff(reason),
            latency: Duration::ZERO,
        }
    }

    pub fn scripted<I: IntoIterator<Item = SendOutcome>>(outcomes: I) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            outcome: OutcomeStrategy::Scripted(Mutex::new(outcomes.into_iter().collect())),
            latency: Duration::ZERO,
        }
    }

    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    pub fn sent_payloads(&self) -> Vec<PushPayload> {
        self.sent.lock().unwrap().clone()
    }
}

impl PushTransport for MockTransport {
    fn send(&self, payload: PushPayload) -> impl Future<Output = SendOutcome> + Send {
        let outcome = match &self.outcome {
            OutcomeStrategy::AlwaysOk => SendOutcome::Ok,
            OutcomeStrategy::AlwaysInvalidToken => SendOutcome::InvalidToken,
            OutcomeStrategy::AlwaysBackoff(reason) => SendOutcome::backoff(*reason),
            OutcomeStrategy::Scripted(queue) => {
                queue.lock().unwrap().pop_front().unwrap_or(SendOutcome::Ok)
            }
        };
        self.sent.lock().unwrap().push(payload);
        let latency = self.latency;
        async move {
            if !latency.is_zero() {
                tokio::time::sleep(latency).await;
            }
            outcome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a1b2c3d4e5f6-device-token";

    /// reqwest печатает URL в `Display` ошибки — проверяется и сама утечка
    /// (иначе тест молча устареет вместе с reqwest), и то, что `loggable`
    /// её закрывает.
    #[tokio::test]
    async fn loggable_error_does_not_carry_the_url() {
        // Порт 1 закрыт: запрос падает на соединении, и ошибка несёт URL.
        let err = reqwest::Client::new()
            .post(format!("http://127.0.0.1:1/3/device/{SECRET}"))
            .send()
            .await
            .expect_err("port 1 must refuse the connection");
        assert!(
            err.to_string().contains(SECRET),
            "reqwest больше не печатает URL — проверку можно упростить"
        );

        let shown = loggable(err).to_string();
        assert!(!shown.contains(SECRET), "token leaked: {shown}");
    }

    #[test]
    fn payload_debug_never_prints_the_token() {
        let wake = PushPayload {
            user_id: [3; 32],
            device_id: 4,
            token: SECRET.to_string(),
            pending: 1,
            max_priority: None,
            server_ts_secs: 1,
            kind: PushKind::Wake,
            wake_hint: None,
        };
        let shown = format!("{wake:?}");
        assert!(!shown.contains(SECRET), "token leaked: {shown}");
        assert!(shown.contains(&hex::encode([3u8; 32])));

        let ring = RingPayload {
            user_id: [3; 32],
            device_id: 4,
            token: SECRET.to_string(),
            server_ts_secs: 1,
        };
        let shown = format!("{ring:?}");
        assert!(!shown.contains(SECRET), "token leaked: {shown}");
    }
}
