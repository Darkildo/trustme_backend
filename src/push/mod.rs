//! Push notification subsystem.
//!
//! The scheduler is fed by the delivery layer whenever a message has no live
//! TCP target for the recipient. It coalesces and throttles those triggers per
//! `(user_id, device_id)` and hands the survivors to a pluggable
//! `PushTransport`: FCM HTTP v1 (`fcm`), the external push gateway
//! (`gateway`), or a mock. Incoming-call envelopes may bypass the decision
//! machine through a `VoipRingTransport` (APNs PushKit, `apns`).
//!
//! Design:
//! - Single bounded mpsc trigger channel; `on_undelivered` uses `try_send`, so
//!   the hot delivery path never blocks and a saturated channel drops triggers.
//! - One worker task with per-key coalescing timers and one in-flight send at
//!   a time: a slow transport delays every recipient, not just one.
//! - The decision logic is pure (`state::decide`) and unit-tested.

pub mod apns;
pub mod fcm;
pub mod gateway;
pub mod state;
pub mod transport;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::config::PushConfig;
use crate::domain::priority::MessagePriority;
use crate::domain::wake::WakeHint;
use crate::observability;
use crate::state::registry::{DeviceId, UserId};

pub use apns::{ApnsEnvironment, ApnsVoipClient};
pub use fcm::FcmHttpV1Client;
pub use gateway::PushGatewayClient;
pub use state::{
    Decision, DecisionAction, DecisionConfig, DecisionInput, PushState, decide, on_send_backoff,
    on_send_success,
};
pub use transport::{
    BackoffReason, InMemoryTokenStore, MockRingTransport, MockTransport, NoVoipRingTransport,
    OutcomeStrategy, PushKind, PushPayload, PushTransport, RingPayload, SendOutcome, TokenStore,
    VoipRingTransport,
};

/// Durable mirror for the in-memory `PushState` map. The scheduler calls
/// `save` after every state mutation and `load_all` once at startup so a
/// restart does not zero the throttling counters (which would let a backlog
/// of buffered messages all trigger a fresh push simultaneously).
///
/// Implementations are expected to be best-effort: persistence is for crash
/// resilience, not correctness. Failures must be logged, not propagated.
pub trait PushStatePersistence: Send + Sync + 'static {
    fn load_all(&self) -> Vec<((UserId, DeviceId), PushState)>;
    fn save(&self, user: UserId, device: DeviceId, state: &PushState);
}

/// No-op persistence for tests and other setups that don't need durability.
pub struct NoopStatePersistence;

impl PushStatePersistence for NoopStatePersistence {
    fn load_all(&self) -> Vec<((UserId, DeviceId), PushState)> {
        Vec::new()
    }
    fn save(&self, _user: UserId, _device: DeviceId, _state: &PushState) {}
}

type RecipientKey = (UserId, DeviceId);

/// Handle held by the rest of the server. Cheap to clone (just an `Arc` inside).
#[derive(Clone)]
pub struct PushScheduler {
    inner: Arc<SchedulerInner>,
}

struct SchedulerInner {
    tx: mpsc::Sender<Trigger>,
    enabled: bool,
}

#[derive(Debug)]
enum Trigger {
    NewMessage {
        user: UserId,
        device: DeviceId,
        priority: Option<MessagePriority>,
        /// `Some(IncomingCall)` — конверт начинает звонок: устройству с
        /// PushKit-токеном шлём APNs voip-ring мимо decision-машины.
        wake_hint: Option<WakeHint>,
    },
    TimerTick {
        user: UserId,
        device: DeviceId,
    },
    /// Greeting fired when a user goes from having no push tokens to having
    /// one. Bypasses the decision machine: no coalescing, no throttling.
    Welcome {
        user: UserId,
        device: DeviceId,
    },
}

impl PushScheduler {
    /// Spawn the worker task and return a handle. The transport, token store,
    /// and persistence layer are kept alive for as long as the scheduler is.
    /// Pass `Arc::new(NoopStatePersistence)` when durability is not required.
    pub fn start<T, S>(
        cfg: PushConfig,
        transport: Arc<T>,
        tokens: Arc<S>,
        persistence: Arc<dyn PushStatePersistence>,
    ) -> Self
    where
        T: PushTransport,
        S: TokenStore,
    {
        Self::start_with_voip::<T, S, NoVoipRingTransport>(
            cfg,
            transport,
            tokens,
            persistence,
            None,
        )
    }

    /// Как [`Self::start`], но с APNs voip-транспортом для PushKit ring'ов.
    /// `voip = None` (или отсутствие voip-токена у устройства) уводит
    /// ring-триггеры в обычный FCM-wake путь.
    pub fn start_with_voip<T, S, V>(
        cfg: PushConfig,
        transport: Arc<T>,
        tokens: Arc<S>,
        persistence: Arc<dyn PushStatePersistence>,
        voip: Option<Arc<V>>,
    ) -> Self
    where
        T: PushTransport,
        S: TokenStore,
        V: VoipRingTransport,
    {
        let (tx, rx) = mpsc::channel(cfg.channel_capacity.max(1));
        let worker_tx = tx.clone();
        let decision_cfg = cfg.decision_config();
        let ring_cooldown = cfg.ring_cooldown;
        let enabled = cfg.enabled;

        // Hydrate the in-memory state map from persistence so a restart
        // keeps honouring prior coalescing windows and backoff deadlines.
        // Timers are not re-armed: a recipient with pending counters is
        // re-evaluated only on its next trigger.
        let states = DashMap::new();
        let loaded = persistence.load_all();
        let loaded_count = loaded.len();
        let mut pending_recipients = 0usize;
        for (key, state) in loaded {
            if state.pending_since_last_push > 0 {
                pending_recipients += 1;
            }
            states.insert(key, state);
        }
        // Глубина восстанавливается абсолютным значением ровно здесь: дальше
        // её двигают только дельты переходов, и стартовать с нуля значило бы
        // уйти в минус на первом же гашении переживших рестарт счётчиков.
        observability::set_push_pending_recipients(pending_recipients);
        if loaded_count > 0 {
            tracing::info!(
                loaded = loaded_count,
                "push scheduler hydrated state from persistence"
            );
        }

        let worker = Worker {
            rx,
            tx: worker_tx,
            transport,
            tokens,
            voip,
            persistence,
            decision_cfg,
            ring_cooldown,
            states,
            timers: DashMap::new(),
            last_ring: DashMap::new(),
        };

        tokio::spawn(worker.run());

        Self {
            inner: Arc::new(SchedulerInner { tx, enabled }),
        }
    }

    /// Notify the scheduler that a message could not be handed to a live session.
    /// Non-blocking: if the trigger channel is saturated the trigger is dropped
    /// (counted in `push_dropped_total`). Push is best-effort — the canonical
    /// inbox / JetStream redelivery path remains responsible for actual delivery.
    pub fn on_undelivered(
        &self,
        user: UserId,
        device: DeviceId,
        priority: Option<MessagePriority>,
        wake_hint: Option<WakeHint>,
    ) {
        if !self.inner.enabled {
            return;
        }

        let trigger = Trigger::NewMessage {
            user,
            device,
            priority,
            wake_hint,
        };

        match self.inner.tx.try_send(trigger) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                observability::observe_push_dropped("channel_full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                observability::observe_push_dropped("channel_closed");
            }
        }
    }

    /// Fire a welcome push to `(user, device)`. Called when a user registers
    /// a push token while having none. Non-blocking — if the channel is
    /// saturated the trigger is dropped (counted as `welcome_channel_full` in
    /// `push_dropped_total`). When push is disabled at the config level the
    /// call is silently ignored.
    pub fn send_welcome(&self, user: UserId, device: DeviceId) {
        if !self.inner.enabled {
            return;
        }

        let trigger = Trigger::Welcome { user, device };

        match self.inner.tx.try_send(trigger) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                observability::observe_push_dropped("welcome_channel_full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                observability::observe_push_dropped("welcome_channel_closed");
            }
        }
    }
}

struct Worker<T: PushTransport, S: TokenStore, V: VoipRingTransport> {
    rx: mpsc::Receiver<Trigger>,
    tx: mpsc::Sender<Trigger>,
    transport: Arc<T>,
    tokens: Arc<S>,
    voip: Option<Arc<V>>,
    persistence: Arc<dyn PushStatePersistence>,
    decision_cfg: DecisionConfig,
    /// Окно подавления повторного voip-ring'а той же `(user, device)` —
    /// mesh-леги/ре-офферы одной комнаты не должны дёргать APNs очередью.
    ring_cooldown: Duration,
    states: DashMap<RecipientKey, PushState>,
    timers: DashMap<RecipientKey, JoinHandle<()>>,
    last_ring: DashMap<RecipientKey, u64>,
}

impl<T: PushTransport, S: TokenStore, V: VoipRingTransport> Worker<T, S, V> {
    async fn run(mut self) {
        while let Some(trigger) = self.rx.recv().await {
            self.process(trigger).await;
        }
    }

    async fn process(&self, trigger: Trigger) {
        let (key, input) = match trigger {
            Trigger::NewMessage {
                user,
                device,
                priority,
                wake_hint,
            } => {
                let key = (user, device);
                // Звонковый конверт: устройству с PushKit-токеном — APNs
                // voip-ring, минуя decision-машину (коалесинг звонку вреден).
                // Неудача ring'а (нет voip-слота / invalid token / сеть)
                // проваливается в обычный FCM-wake ниже — Android и
                // legacy-iOS пути не меняются.
                if wake_hint == Some(WakeHint::IncomingCall) && self.try_dispatch_ring(key).await {
                    return;
                }
                (key, DecisionInput::NewMessage(priority))
            }
            Trigger::TimerTick { user, device } => ((user, device), DecisionInput::TimerTick),
            Trigger::Welcome { user, device } => {
                self.dispatch_welcome((user, device)).await;
                return;
            }
        };

        let now = now_secs();
        let prior = self
            .states
            .get(&key)
            .map(|entry| *entry.value())
            .unwrap_or_default();

        let decision = decide(prior, input, now, &self.decision_cfg);
        self.write_state(key, decision.state);

        match decision.action {
            DecisionAction::Idle => {
                // `Idle` в ответ на новое сообщение — это не «делать нечего», а
                // «разбудить по времени не обещаем». Без счётчика такие
                // сообщения копились бы незаметно для мониторинга.
                if let DecisionInput::NewMessage(p) = input {
                    observability::observe_push_deferred(priority_label(p));
                }
                debug!(?key, "push decision: idle");
            }
            DecisionAction::WaitUntil(fire_at) => {
                if let DecisionInput::NewMessage(p) = input {
                    observability::observe_push_coalesced(priority_label(p));
                }
                self.schedule_timer(key, fire_at, now);
            }
            DecisionAction::SendNow {
                pending,
                max_priority,
            } => {
                self.dispatch_send(key, pending, max_priority, now).await;
            }
        }
    }

    async fn dispatch_send(
        &self,
        key: RecipientKey,
        pending: u32,
        max_priority: Option<MessagePriority>,
        now: u64,
    ) {
        let Some(token) = self.tokens.resolve(&key.0, key.1) else {
            // No push token for this device — record and move on. The state
            // has already been advanced by `decide` (counters reset), so an
            // unregistered device is not retried forever.
            observability::observe_push_sent(priority_label(max_priority), "no_token");
            warn!(?key, "push send skipped: no token");
            return;
        };

        let payload = PushPayload {
            user_id: key.0,
            device_id: key.1,
            token,
            pending,
            max_priority,
            server_ts_secs: now,
            kind: PushKind::Wake,
        };

        let started = std::time::Instant::now();
        let outcome = self.transport.send(payload).await;
        observability::observe_push_latency(started.elapsed());

        match outcome {
            SendOutcome::Ok => {
                observability::observe_push_sent(priority_label(max_priority), "ok");
                self.mutate_state(key, on_send_success);
                // After a successful send, fresh NewMessage triggers will handle
                // re-firing — no preemptive tick needed.
            }
            SendOutcome::InvalidToken => {
                observability::observe_push_sent(priority_label(max_priority), "invalid_token");
                observability::observe_push_token_removed("invalid_token");
                self.tokens.remove(&key.0, key.1);
                // Treat as a successful send for backoff purposes — the
                // token is gone, retrying won't help.
                self.mutate_state(key, on_send_success);
            }
            SendOutcome::Backoff(reason) => {
                observability::observe_push_sent(priority_label(max_priority), "backoff");
                self.rollback_and_suppress(key, pending, max_priority, now);
                debug!(?key, ?reason, "push backoff");
            }
            SendOutcome::TransientError => {
                observability::observe_push_sent(priority_label(max_priority), "transient_error");
                self.rollback_and_suppress(key, pending, max_priority, now);
            }
        }
    }

    /// Voip-ring (APNs PushKit напрямую или через шлюз) для звонкового
    /// конверта. Минует decision-машину: звонок нельзя коалесить или
    /// откладывать. Возвращает `true`, если устройство разбужено voip-путём
    /// (включая подавленный cooldown'ом дубль) — тогда обычный FCM-wake не
    /// нужен; `false` — вызывающий обязан провалиться в стандартный путь.
    async fn try_dispatch_ring(&self, key: RecipientKey) -> bool {
        let Some(voip) = self.voip.as_ref() else {
            return false;
        };
        let Some(token) = self.tokens.resolve_voip(&key.0, key.1) else {
            return false;
        };

        let now = now_secs();
        if let Some(last) = self.last_ring.get(&key)
            && now.saturating_sub(*last.value()) < self.ring_cooldown.as_secs()
        {
            // Устройство уже звонит: повторные OFFER'ы той же комнаты
            // (mesh-леги, ре-офферы) не должны слать очередь voip-пушей —
            // каждый из них iOS обязует репортить отдельный CallKit-звонок.
            observability::observe_push_sent("ring", "cooldown");
            debug!(?key, "voip ring suppressed by cooldown");
            return true;
        }

        let payload = RingPayload {
            user_id: key.0,
            device_id: key.1,
            token,
            server_ts_secs: now,
        };

        let started = std::time::Instant::now();
        let outcome = voip.send_ring(payload).await;
        observability::observe_push_latency(started.elapsed());

        match outcome {
            SendOutcome::Ok => {
                observability::observe_push_sent("ring", "ok");
                self.last_ring.insert(key, now);
                true
            }
            SendOutcome::InvalidToken => {
                observability::observe_push_sent("ring", "invalid_token");
                observability::observe_push_token_removed("voip_invalid_token");
                self.tokens.remove_voip(&key.0, key.1);
                // Voip-слот мёртв — пусть хотя бы FCM-wake разбудит.
                false
            }
            SendOutcome::Backoff(reason) => {
                observability::observe_push_sent("ring", "backoff");
                debug!(?key, ?reason, "voip ring backoff; falling back to FCM wake");
                false
            }
            SendOutcome::TransientError => {
                observability::observe_push_sent("ring", "transient_error");
                false
            }
        }
    }

    /// Fire the welcome push. Bypasses the decision/throttling layer and
    /// deliberately leaves the coalescing state untouched, so a welcome never
    /// consumes the budget of the next real-message wake.
    async fn dispatch_welcome(&self, key: RecipientKey) {
        let Some(token) = self.tokens.resolve(&key.0, key.1) else {
            warn!(?key, "welcome push skipped: no token at dispatch time");
            return;
        };

        let payload = PushPayload {
            user_id: key.0,
            device_id: key.1,
            token,
            pending: 0,
            max_priority: None,
            server_ts_secs: now_secs(),
            kind: PushKind::Welcome,
        };

        let started = std::time::Instant::now();
        let outcome = self.transport.send(payload).await;
        observability::observe_push_latency(started.elapsed());

        match outcome {
            SendOutcome::Ok => {
                observability::observe_push_sent("welcome", "ok");
                tracing::info!(?key, "welcome push sent");
            }
            SendOutcome::InvalidToken => {
                observability::observe_push_sent("welcome", "invalid_token");
                observability::observe_push_token_removed("invalid_token");
                self.tokens.remove(&key.0, key.1);
            }
            SendOutcome::Backoff(reason) => {
                observability::observe_push_sent("welcome", "backoff");
                debug!(?key, ?reason, "welcome push backoff; not retrying");
            }
            SendOutcome::TransientError => {
                observability::observe_push_sent("welcome", "transient_error");
                debug!(?key, "welcome push transient error; not retrying");
            }
        }
    }

    /// Restore the pending counters that `decide` eagerly cleared, then apply
    /// exponential backoff and schedule a retry tick at the suppression deadline.
    fn rollback_and_suppress(
        &self,
        key: RecipientKey,
        pending: u32,
        max_priority: Option<MessagePriority>,
        now: u64,
    ) {
        let until = self.mutate_state(key, |state| {
            state.pending_since_last_push = state.pending_since_last_push.saturating_add(pending);
            let restored = MessagePriority::as_storage_byte(max_priority);
            if restored > state.highest_pending_priority {
                state.highest_pending_priority = restored;
            }
            on_send_backoff(state, now, &self.decision_cfg);
            state.suppressed_until_secs
        });
        self.schedule_timer(key, until, now);
    }

    /// Replace the cached state for `key`, mirroring the new value to durable
    /// storage. Use this on every transition that begins as a `Decision`.
    fn write_state(&self, key: RecipientKey, state: PushState) {
        let prior = self.states.insert(key, state);
        Self::track_pending_depth(
            prior.map(|p| p.pending_since_last_push).unwrap_or(0),
            state.pending_since_last_push,
        );
        self.persistence.save(key.0, key.1, &state);
    }

    /// Двигает глубину `push_pending_recipients` на переходах «накопленного
    /// нет» ↔ «накопленное есть». Считается по факту записи состояния, а не
    /// по решению: гасит счётчик и успешная отправка, и подхват накопленного
    /// приоритетным соседом.
    fn track_pending_depth(before: u32, after: u32) {
        match (before == 0, after == 0) {
            (true, false) => observability::observe_push_pending_transition(true),
            (false, true) => observability::observe_push_pending_transition(false),
            _ => {}
        }
    }

    /// Apply `f` to the mutable in-place state and write the result back through
    /// `persistence`. The closure can return a value (e.g. the new
    /// `suppressed_until_secs`) which is forwarded to the caller.
    fn mutate_state<R>(&self, key: RecipientKey, f: impl FnOnce(&mut PushState) -> R) -> R {
        let mut entry = self.states.entry(key).or_default();
        let before = entry.value().pending_since_last_push;
        let result = f(entry.value_mut());
        let snapshot = *entry.value();
        drop(entry);
        Self::track_pending_depth(before, snapshot.pending_since_last_push);
        self.persistence.save(key.0, key.1, &snapshot);
        result
    }

    fn schedule_timer(&self, key: RecipientKey, fire_at_secs: u64, now: u64) {
        if let Some((_, prior)) = self.timers.remove(&key) {
            prior.abort();
        }

        let wait = Duration::from_secs(fire_at_secs.saturating_sub(now));
        let tx = self.tx.clone();
        let handle = tokio::spawn(async move {
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            // Best-effort: if the worker has shut down, drop the tick.
            let _ = tx
                .send(Trigger::TimerTick {
                    user: key.0,
                    device: key.1,
                })
                .await;
        });
        self.timers.insert(key, handle);
    }
}

fn priority_label(p: Option<MessagePriority>) -> &'static str {
    match p {
        Some(MessagePriority::High) => "high",
        Some(MessagePriority::Medium) => "medium",
        Some(MessagePriority::Low) => "low",
        None => "none",
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::PushConfig;

    fn user(seed: u8) -> UserId {
        [seed; 32]
    }

    fn fast_cfg() -> PushConfig {
        PushConfig {
            enabled: true,
            gateway_url: None,
            gateway_timeout: Duration::from_secs(10),
            fcm_project_id: String::new(),
            fcm_service_account_path: String::new(),
            http_timeout: Duration::from_secs(5),
            min_gap_high: Duration::from_secs(0),
            min_gap_medium: Duration::from_millis(0),
            min_gap_low: Duration::from_secs(60),
            min_gap_none: Duration::from_secs(120),
            wake_on_unspecified: true,
            burst_high: 1,
            burst_medium: 3,
            burst_low: 8,
            burst_none: 15,
            suppress_initial: Duration::from_secs(1),
            suppress_max: Duration::from_secs(8),
            channel_capacity: 64,
            apns: None,
            ring_cooldown: Duration::from_secs(3),
        }
    }

    #[tokio::test]
    async fn high_priority_triggers_immediate_send_through_mock() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(1), 7, "test-token");

        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens,
            Arc::new(NoopStatePersistence),
        );
        scheduler.on_undelivered(user(1), 7, Some(MessagePriority::High), None);

        // Give the worker a moment to drain the channel.
        for _ in 0..50 {
            if !transport.sent_payloads().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].user_id, user(1));
        assert_eq!(sent[0].device_id, 7);
        assert_eq!(sent[0].pending, 1);
        assert_eq!(sent[0].max_priority, Some(MessagePriority::High));
        assert_eq!(sent[0].token, "test-token");
    }

    #[tokio::test]
    async fn invalid_token_response_removes_token() {
        let transport = Arc::new(MockTransport::always_invalid_token());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(2), 3, "dead-token");

        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );
        scheduler.on_undelivered(user(2), 3, Some(MessagePriority::High), None);

        for _ in 0..50 {
            if !transport.sent_payloads().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Give a beat for the post-send cleanup to land.
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(tokens.resolve(&user(2), 3).is_none());
    }

    /// Records every `save` call so tests can assert that the worker mirrors
    /// state changes to persistence. Hydrated from a seed map on construction.
    struct RecordingPersistence {
        seed: Vec<((UserId, DeviceId), PushState)>,
        saves: std::sync::Mutex<Vec<(UserId, DeviceId, PushState)>>,
    }

    impl RecordingPersistence {
        fn empty() -> Self {
            Self {
                seed: Vec::new(),
                saves: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn seeded(seed: Vec<((UserId, DeviceId), PushState)>) -> Self {
            Self {
                seed,
                saves: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn save_count(&self) -> usize {
            self.saves.lock().unwrap().len()
        }
    }

    impl PushStatePersistence for RecordingPersistence {
        fn load_all(&self) -> Vec<((UserId, DeviceId), PushState)> {
            self.seed.clone()
        }
        fn save(&self, user: UserId, device: DeviceId, state: &PushState) {
            self.saves.lock().unwrap().push((user, device, *state));
        }
    }

    #[tokio::test]
    async fn worker_mirrors_state_to_persistence_after_send() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(3), 5, "tok");

        let persistence = Arc::new(RecordingPersistence::empty());
        let scheduler =
            PushScheduler::start(fast_cfg(), transport.clone(), tokens, persistence.clone());
        scheduler.on_undelivered(user(3), 5, Some(MessagePriority::High), None);

        for _ in 0..50 {
            if persistence.save_count() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // We expect at least two saves: one for the `decide` transition and one
        // for the post-send `on_send_success` mutation.
        assert!(
            persistence.save_count() >= 2,
            "expected ≥2 persistence saves, got {}",
            persistence.save_count()
        );
    }

    #[tokio::test]
    async fn hydration_restores_prior_state_so_no_immediate_resend() {
        // Hydrated state with a recent `last_push_at_secs` and a 300 s Medium
        // gap must put a new Medium message into `WaitUntil`, not send it.
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(7), 2, "tok");

        let far_future = now_secs() + 600;
        let mut cfg = fast_cfg();
        cfg.min_gap_medium = Duration::from_secs(300);

        let prior_state = PushState {
            last_push_at_secs: far_future,
            ..Default::default()
        };
        let persistence = Arc::new(RecordingPersistence::seeded(vec![(
            (user(7), 2),
            prior_state,
        )]));

        let scheduler = PushScheduler::start(cfg, transport.clone(), tokens, persistence.clone());
        scheduler.on_undelivered(user(7), 2, Some(MessagePriority::Medium), None);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            transport.sent_payloads().is_empty(),
            "hydrated state must defer the send beyond test window"
        );
    }

    #[tokio::test]
    async fn send_welcome_dispatches_with_welcome_kind_and_bypasses_decision() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(11), 1, "welcome-tok");

        // Seed a non-default state so we can later verify the welcome path
        // did not mutate it (the welcome must not consume real-message budget).
        let seeded = PushState {
            last_push_at_secs: 12345,
            ..Default::default()
        };
        let persistence = Arc::new(RecordingPersistence::seeded(vec![((user(11), 1), seeded)]));

        let scheduler =
            PushScheduler::start(fast_cfg(), transport.clone(), tokens, persistence.clone());
        scheduler.send_welcome(user(11), 1);

        for _ in 0..50 {
            if !transport.sent_payloads().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].kind, PushKind::Welcome);
        assert_eq!(sent[0].user_id, user(11));
        assert_eq!(sent[0].device_id, 1);
        assert_eq!(sent[0].token, "welcome-tok");
        assert_eq!(sent[0].pending, 0);
        assert!(sent[0].max_priority.is_none());

        // The decision machine must not be entered: hydration does not call
        // `save`, so any persisted write would come from the welcome path.
        assert_eq!(
            persistence.save_count(),
            0,
            "welcome dispatch must not touch push throttling state"
        );
    }

    #[tokio::test]
    async fn send_welcome_with_no_token_is_noop() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens,
            Arc::new(NoopStatePersistence),
        );
        scheduler.send_welcome(user(99), 1);

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(transport.sent_payloads().is_empty());
    }

    #[tokio::test]
    async fn disabled_scheduler_drops_triggers_silently() {
        let mut cfg = fast_cfg();
        cfg.enabled = false;
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(1), 1, "tok");

        let scheduler = PushScheduler::start(
            cfg,
            transport.clone(),
            tokens,
            Arc::new(NoopStatePersistence),
        );
        scheduler.on_undelivered(user(1), 1, Some(MessagePriority::High), None);

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(transport.sent_payloads().is_empty());
    }

    fn start_with_ring(
        transport: Arc<MockTransport>,
        tokens: Arc<InMemoryTokenStore>,
        ring: Arc<MockRingTransport>,
    ) -> PushScheduler {
        PushScheduler::start_with_voip(
            fast_cfg(),
            transport,
            tokens,
            Arc::new(NoopStatePersistence),
            Some(ring),
        )
    }

    async fn wait_for<F: Fn() -> bool>(cond: F) {
        for _ in 0..50 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Звонковый конверт устройству с voip-токеном уходит APNs-ring'ом,
    /// обычный FCM-wake при этом НЕ шлётся.
    #[tokio::test]
    async fn incoming_call_hint_rings_voip_and_skips_fcm() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(1), 7, "fcm-token");
        tokens.insert_voip(user(1), 7, "voip-token");

        let scheduler = start_with_ring(transport.clone(), tokens, ring.clone());
        scheduler.on_undelivered(
            user(1),
            7,
            Some(MessagePriority::High),
            Some(WakeHint::IncomingCall),
        );

        wait_for(|| !ring.sent_rings().is_empty()).await;
        let rings = ring.sent_rings();
        assert_eq!(rings.len(), 1);
        assert_eq!(rings[0].user_id, user(1));
        assert_eq!(rings[0].device_id, 7);
        assert_eq!(rings[0].token, "voip-token");

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            transport.sent_payloads().is_empty(),
            "voip-ring must suppress the ordinary FCM wake"
        );
    }

    /// Без voip-токена звонковый конверт проваливается в обычный FCM-wake —
    /// Android/legacy-iOS путь не меняется.
    #[tokio::test]
    async fn incoming_call_hint_falls_back_to_fcm_without_voip_token() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(2), 4, "fcm-token");

        let scheduler = start_with_ring(transport.clone(), tokens, ring.clone());
        scheduler.on_undelivered(
            user(2),
            4,
            Some(MessagePriority::High),
            Some(WakeHint::IncomingCall),
        );

        wait_for(|| !transport.sent_payloads().is_empty()).await;
        assert!(ring.sent_rings().is_empty());
        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].token, "fcm-token");
    }

    /// Invalid voip token: слот эвиктится, конверт уходит FCM-wake'ом.
    #[tokio::test]
    async fn invalid_voip_token_evicts_slot_and_falls_back_to_fcm() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_invalid_token());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(3), 9, "fcm-token");
        tokens.insert_voip(user(3), 9, "dead-voip");

        let scheduler = start_with_ring(transport.clone(), tokens.clone(), ring.clone());
        scheduler.on_undelivered(
            user(3),
            9,
            Some(MessagePriority::High),
            Some(WakeHint::IncomingCall),
        );

        wait_for(|| !transport.sent_payloads().is_empty()).await;
        assert_eq!(ring.sent_rings().len(), 1);
        assert!(
            tokens.resolve_voip(&user(3), 9).is_none(),
            "voip slot evicted"
        );
        // Alert-слот жив, FCM-wake ушёл.
        assert_eq!(transport.sent_payloads().len(), 1);
    }

    /// Повторный ring в пределах cooldown-окна подавляется целиком (ни APNs,
    /// ни FCM): устройство уже звонит.
    #[tokio::test]
    async fn repeat_ring_within_cooldown_is_suppressed() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert_voip(user(4), 2, "voip-token");

        let scheduler = start_with_ring(transport.clone(), tokens, ring.clone());
        scheduler.on_undelivered(
            user(4),
            2,
            Some(MessagePriority::High),
            Some(WakeHint::IncomingCall),
        );
        wait_for(|| !ring.sent_rings().is_empty()).await;

        // Второй OFFER той же комнаты (mesh-лег / ре-оффер) сразу следом.
        scheduler.on_undelivered(
            user(4),
            2,
            Some(MessagePriority::High),
            Some(WakeHint::IncomingCall),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            ring.sent_rings().len(),
            1,
            "cooldown must swallow the duplicate"
        );
        assert!(transport.sent_payloads().is_empty());
    }

    /// Обычный High-priority конверт (без wake-hint) НЕ звонит даже при
    /// наличии voip-токена — ring строго по маркеру.
    #[tokio::test]
    async fn high_priority_without_hint_does_not_ring() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(5), 1, "fcm-token");
        tokens.insert_voip(user(5), 1, "voip-token");

        let scheduler = start_with_ring(transport.clone(), tokens, ring.clone());
        scheduler.on_undelivered(user(5), 1, Some(MessagePriority::High), None);

        wait_for(|| !transport.sent_payloads().is_empty()).await;
        assert!(ring.sent_rings().is_empty());
        assert_eq!(transport.sent_payloads().len(), 1);
    }
}
