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
//! - A dispatcher task hands triggers to per-recipient tasks: triggers of one
//!   `(user, device)` run strictly one after another, in arrival order, while
//!   different recipients run concurrently. Provider calls are bounded by a
//!   semaphore (`DEFAULT_SEND_CONCURRENCY`), so a degraded provider slows
//!   sends down but does not stall decisions for everyone else.
//! - State exists only for devices with a push token and only while it can
//!   still affect a decision: idle entries are dropped on write and swept
//!   every `SWEEP_INTERVAL`, together with the auxiliary maps.
//! - Coalescing timers are re-armed after a restart from the persisted state.
//! - The decision logic is pure (`state::decide`) and unit-tested.
//! - The incoming-call marker (`WakeHint::IncomingCall`) survives the decision
//!   machine via `Worker::call_hints` and reaches the transport in
//!   `PushPayload::wake_hint`; see `CALL_HINT_TTL_SECS`.

pub mod apns;
pub mod fcm;
pub mod gateway;
pub mod state;
pub mod transport;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

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
    on_send_success, resume_deadline,
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
    /// Forget the row for `(user, device)`: its state no longer affects any
    /// decision, or the device has no push token left. Removing a missing row
    /// is not an error.
    fn remove(&self, user: UserId, device: DeviceId);
}

/// No-op persistence for tests and other setups that don't need durability.
pub struct NoopStatePersistence;

impl PushStatePersistence for NoopStatePersistence {
    fn load_all(&self) -> Vec<((UserId, DeviceId), PushState)> {
        Vec::new()
    }
    fn save(&self, _user: UserId, _device: DeviceId, _state: &PushState) {}
    fn remove(&self, _user: UserId, _device: DeviceId) {}
}

type RecipientKey = (UserId, DeviceId);

/// Сколько обращений к провайдеру (wake, ring, welcome) идут одновременно.
///
/// Последовательный воркер при деградации провайдера ждал таймаут на каждом
/// запросе, переставал разбирать канал, тот заполнялся — и отбрасывались
/// триггеры всех получателей, а не только тех, чья отправка висела. 32
/// запроса помещаются в одно HTTP/2-соединение и к FCM, и к APNs.
pub const DEFAULT_SEND_CONCURRENCY: usize = 32;

/// Сколько триггеров одного получателя могут ждать, пока обрабатывается
/// предыдущий. Сверх этого триггеры отбрасываются
/// (`push_dropped_total{reason="recipient_backlog"}`): поток сообщений одному
/// устройству, чья отправка повисла, не должен копить память без предела, а
/// пуш на окно коалесинга всё равно один.
const MAX_QUEUED_PER_RECIPIENT: usize = 64;

/// Как часто вычищаются состояния, которые больше ни на что не влияют, и
/// служебные отметки: cooldown ring'ов, протухшие call-hint'ы, отработавшие
/// таймеры. Без вычистки все эти карты росли бы на каждую пару, которой хоть
/// раз слали пуш.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Сколько живёт «ожидающий call-hint» — промежуток между решением разбудить
/// под звонок и фактической отправкой wake-пуша (отправку может отложить
/// активный backoff, вплоть до TimerTick'а).
///
/// Минута: dial-таймаут звонящего — 45 с, так что hint, переживший это окно,
/// относится к уже отменённому звонку. Прилипнув к следующему, ни разу не
/// звонковому wake'у, он заставил бы получателя показать ринг на обычное
/// сообщение — хуже, чем не показать ринг вовсе.
const CALL_HINT_TTL_SECS: u64 = 60;

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

impl Trigger {
    fn key(&self) -> RecipientKey {
        match self {
            Self::NewMessage { user, device, .. }
            | Self::TimerTick { user, device }
            | Self::Welcome { user, device } => (*user, *device),
        }
    }
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
        let send_concurrency = cfg.send_concurrency;
        Self::spawn(cfg, transport, tokens, persistence, voip, send_concurrency)
    }

    fn spawn<T, S, V>(
        cfg: PushConfig,
        transport: Arc<T>,
        tokens: Arc<S>,
        persistence: Arc<dyn PushStatePersistence>,
        voip: Option<Arc<V>>,
        send_concurrency: usize,
    ) -> Self
    where
        T: PushTransport,
        S: TokenStore,
        V: VoipRingTransport,
    {
        let capacity = cfg.channel_capacity.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        let enabled = cfg.enabled;

        let worker = Arc::new(Worker::new(
            &cfg,
            tx.clone(),
            transport,
            tokens,
            voip,
            persistence,
            send_concurrency,
        ));
        // Выключенные пуши не должны «досылать» накопленное моком: оно
        // дождётся включения.
        worker.hydrate(enabled);
        // Занятых получателей не больше, чем вмещает канал: дальше диспетчер
        // перестаёт его разбирать, канал заполняется, и `on_undelivered`
        // отбрасывает триггеры — горячий путь доставки не ждёт никогда.
        tokio::spawn(worker.run(rx, capacity));

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

/// Освобождает получателя в диспетчере, когда его задача завершилась.
/// Через `Drop`, а не явным вызовом: паника внутри обработки иначе навсегда
/// оставила бы получателя «занятым», и его триггеры копились бы в очереди.
struct RecipientRelease {
    key: RecipientKey,
    done: mpsc::UnboundedSender<RecipientKey>,
}

impl Drop for RecipientRelease {
    fn drop(&mut self) {
        let _ = self.done.send(self.key);
    }
}

struct Worker<T: PushTransport, S: TokenStore, V: VoipRingTransport> {
    tx: mpsc::Sender<Trigger>,
    transport: Arc<T>,
    tokens: Arc<S>,
    voip: Option<Arc<V>>,
    persistence: Arc<dyn PushStatePersistence>,
    decision_cfg: DecisionConfig,
    /// [`DecisionConfig::longest_gap_secs`], посчитанный один раз: сколько
    /// после пуша состояние без накопленного ещё влияет на решения.
    longest_gap_secs: u64,
    /// Окно подавления повторного voip-ring'а той же `(user, device)` —
    /// mesh-леги/ре-офферы одной комнаты не должны дёргать APNs очередью.
    ring_cooldown: Duration,
    /// Разрешения на обращение к провайдеру; см. [`DEFAULT_SEND_CONCURRENCY`].
    send_permits: Semaphore,
    states: DashMap<RecipientKey, PushState>,
    timers: DashMap<RecipientKey, JoinHandle<()>>,
    /// Момент последнего успешного ring'а. `Instant`, а не unix-секунды:
    /// cooldown задан в миллисекундах и сравнивается в них же.
    last_ring: DashMap<RecipientKey, Instant>,
    /// Устройства, чей ближайший FCM-wake будит получателя под звонок, и
    /// момент (unix-секунды) выставления признака. Заводится, когда
    /// voip-ring не состоялся и звонковый конверт ушёл в decision-машину:
    /// та оперирует одним приоритетом и «это звонок» до транспорта не несёт.
    /// Снимается первой же отправкой; протухшее по [`CALL_HINT_TTL_SECS`]
    /// отбрасывается.
    call_hints: DashMap<RecipientKey, u64>,
}

impl<T: PushTransport, S: TokenStore, V: VoipRingTransport> Worker<T, S, V> {
    fn new(
        cfg: &PushConfig,
        tx: mpsc::Sender<Trigger>,
        transport: Arc<T>,
        tokens: Arc<S>,
        voip: Option<Arc<V>>,
        persistence: Arc<dyn PushStatePersistence>,
        send_concurrency: usize,
    ) -> Self {
        let decision_cfg = cfg.decision_config();
        Self {
            tx,
            transport,
            tokens,
            voip,
            persistence,
            longest_gap_secs: decision_cfg.longest_gap_secs(),
            decision_cfg,
            ring_cooldown: cfg.ring_cooldown,
            send_permits: Semaphore::new(send_concurrency.max(1)),
            states: DashMap::new(),
            timers: DashMap::new(),
            last_ring: DashMap::new(),
            call_hints: DashMap::new(),
        }
    }

    /// Поднять состояние из персистентности, чтобы рестарт не сбрасывал окна
    /// коалесинга и backoff'а, и перевзвести таймеры накопленного: таймеры
    /// живут только в памяти, и без перевзвода отложенные wake терялись бы
    /// на каждом деплое.
    ///
    /// Записи, которые уже ни на что не влияют, и записи устройств без
    /// токена не грузятся, а удаляются: их наплодили версии, заводившие
    /// состояние под любую пару.
    fn hydrate(&self, resume_timers: bool) {
        let now = now_secs();
        let mut kept = 0usize;
        let mut dropped = 0usize;
        let mut pending_recipients = 0usize;
        for (key, state) in self.persistence.load_all() {
            if state.is_idle(now, self.longest_gap_secs)
                || self.tokens.resolve(&key.0, key.1).is_none()
            {
                self.persistence.remove(key.0, key.1);
                dropped += 1;
                continue;
            }
            if state.pending_since_last_push > 0 {
                pending_recipients += 1;
            }
            if resume_timers && let Some(fire_at) = resume_deadline(&state, &self.decision_cfg) {
                self.schedule_timer(key, fire_at, now);
            }
            self.states.insert(key, state);
            kept += 1;
        }
        // Глубина восстанавливается абсолютным значением ровно здесь: дальше
        // её двигают только дельты переходов, и стартовать с нуля значило бы
        // уйти в минус на первом же гашении переживших рестарт счётчиков.
        observability::set_push_pending_recipients(pending_recipients);
        if kept > 0 || dropped > 0 {
            info!(
                kept,
                dropped, "push scheduler hydrated state from persistence"
            );
        }
    }

    /// Диспетчер: раздаёт триггеры задачам по получателям. Пока задача
    /// получателя работает, его следующие триггеры ждут в его же очереди —
    /// так переходы состояния одной пары остаются строго последовательными,
    /// а медленная отправка одному не задерживает решения для остальных.
    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<Trigger>, max_busy: usize) {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<RecipientKey>();
        let mut busy: HashMap<RecipientKey, VecDeque<Trigger>> = HashMap::new();
        let mut sweep =
            tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Сначала завершения: они освобождают место под новые триггеры.
                biased;
                Some(key) = done_rx.recv() => {
                    match busy.get_mut(&key).and_then(VecDeque::pop_front) {
                        Some(next) => self.spawn_process(key, next, &done_tx),
                        None => {
                            busy.remove(&key);
                        }
                    }
                }
                received = rx.recv(), if busy.len() < max_busy => {
                    // Канал не закрывается, пока жив сам воркер: таймеры
                    // держат его отправителя.
                    let Some(trigger) = received else { break };
                    let key = trigger.key();
                    match busy.get_mut(&key) {
                        None => {
                            busy.insert(key, VecDeque::new());
                            self.spawn_process(key, trigger, &done_tx);
                        }
                        Some(queue) if queue.len() < MAX_QUEUED_PER_RECIPIENT => {
                            queue.push_back(trigger);
                        }
                        Some(_) => observability::observe_push_dropped("recipient_backlog"),
                    }
                }
                _ = sweep.tick() => self.sweep(&busy),
            }
        }
    }

    fn spawn_process(
        self: &Arc<Self>,
        key: RecipientKey,
        trigger: Trigger,
        done: &mpsc::UnboundedSender<RecipientKey>,
    ) {
        let worker = Arc::clone(self);
        let release = RecipientRelease {
            key,
            done: done.clone(),
        };
        tokio::spawn(async move {
            let _release = release;
            worker.process(trigger).await;
        });
    }

    /// Вычистка того, что больше ни на что не влияет. Получатели, чья задача
    /// сейчас работает, пропускаются: их состояние меняется прямо сейчас.
    fn sweep(&self, busy: &HashMap<RecipientKey, VecDeque<Trigger>>) {
        let now = now_secs();
        let idle: Vec<RecipientKey> = self
            .states
            .iter()
            .filter(|entry| {
                !busy.contains_key(entry.key()) && entry.value().is_idle(now, self.longest_gap_secs)
            })
            .map(|entry| *entry.key())
            .collect();
        for key in idle {
            if self
                .states
                .remove_if(&key, |_, state| state.is_idle(now, self.longest_gap_secs))
                .is_some()
            {
                self.persistence.remove(key.0, key.1);
            }
        }

        let ring_cooldown = self.ring_cooldown;
        self.last_ring
            .retain(|_, rang_at| rang_at.elapsed() < ring_cooldown);
        self.call_hints
            .retain(|_, at| now.saturating_sub(*at) <= CALL_HINT_TTL_SECS);
        self.timers.retain(|_, timer| !timer.is_finished());
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
                let incoming_call = wake_hint == Some(WakeHint::IncomingCall);
                // Звонковый конверт: устройству с PushKit-токеном — APNs
                // voip-ring, минуя decision-машину (коалесинг звонку вреден).
                // Неудача ring'а (нет voip-слота / invalid token / сеть)
                // проваливается в обычный FCM-wake ниже — Android и
                // legacy-iOS пути не меняются.
                if incoming_call && self.try_dispatch_ring(key).await {
                    return;
                }
                // Без alert-токена будить нечем, и состояние под такую пару
                // не заводится. `device_id` выбирает отправитель, так что
                // иначе любой клиент раздувал бы карту и дерево
                // `push_state` произвольными парами.
                if self.tokens.resolve(&key.0, key.1).is_none() {
                    observability::observe_push_dropped("no_token");
                    debug!(
                        user = %hex::encode(key.0),
                        device = key.1,
                        "push trigger dropped: no token"
                    );
                    return;
                }
                if incoming_call {
                    // FCM-путь звонок не различает: decision-машина видит
                    // только приоритет. Без маркера на конверте получатель
                    // покажет баннер «новые сообщения» вместо ринга, поэтому
                    // «это звонок» едет рядом с решением — до отправки.
                    self.remember_call_hint(key);
                }
                (key, DecisionInput::NewMessage(priority))
            }
            Trigger::TimerTick { user, device } => {
                let key = (user, device);
                // Таймер, приславший тик, отработал — его handle больше не нужен.
                self.timers.remove_if(&key, |_, timer| timer.is_finished());
                // Тик от уже погашенного окна: заводить под него запись незачем.
                if !self.states.contains_key(&key) {
                    return;
                }
                (key, DecisionInput::TimerTick)
            }
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
        self.write_state(key, decision.state, now);

        match decision.action {
            DecisionAction::Idle => {
                // `Idle` в ответ на новое сообщение — это не «делать нечего», а
                // «разбудить по времени не обещаем». Без счётчика такие
                // сообщения копились бы незаметно для мониторинга.
                if let DecisionInput::NewMessage(p) = input {
                    observability::observe_push_deferred(priority_label(p));
                }
                debug!(
                    user = %hex::encode(key.0),
                    device = key.1,
                    "push decision: idle"
                );
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
        // Снимается до резолва токена: устройство без токена не должно
        // оставлять «звонковый» маркер следующему, уже обычному сообщению.
        let call_hint_at = self.take_call_hint(key, now);

        let Some(token) = self.tokens.resolve(&key.0, key.1) else {
            // Токен исчез, пока копилось окно: будить нечем, и состояние пары
            // больше ни на что не влияет. Без токена новых триггеров под неё
            // не будет, поэтому запись не ретраится, а забывается.
            observability::observe_push_sent(priority_label(max_priority), "no_token");
            debug!(
                user = %hex::encode(key.0),
                device = key.1,
                "push send skipped: no token"
            );
            self.forget(key);
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
            wake_hint: call_hint_at.map(|_| WakeHint::IncomingCall),
        };

        match self.send_wake(payload).await {
            SendOutcome::Ok => {
                observability::observe_push_sent(priority_label(max_priority), "ok");
                self.mutate_state(key, now, on_send_success);
                // After a successful send, fresh NewMessage triggers will handle
                // re-firing — no preemptive tick needed.
            }
            SendOutcome::InvalidToken => {
                observability::observe_push_sent(priority_label(max_priority), "invalid_token");
                observability::observe_push_token_removed("invalid_token");
                self.tokens.remove(&key.0, key.1);
                // Токена больше нет — состояние под пару держать незачем.
                self.forget(key);
            }
            SendOutcome::Backoff {
                reason,
                retry_after,
            } => {
                observability::observe_push_sent(priority_label(max_priority), "backoff");
                self.restore_call_hint(key, call_hint_at);
                self.rollback_and_suppress(key, pending, max_priority, now, retry_after);
                debug!(
                    user = %hex::encode(key.0),
                    device = key.1,
                    ?reason,
                    ?retry_after,
                    "push backoff"
                );
            }
            SendOutcome::TransientError => {
                observability::observe_push_sent(priority_label(max_priority), "transient_error");
                self.restore_call_hint(key, call_hint_at);
                self.rollback_and_suppress(key, pending, max_priority, now, None);
            }
        }
    }

    /// Обращение к wake-транспорту под разрешением семафора: одновременных
    /// запросов к провайдеру не больше `DEFAULT_SEND_CONCURRENCY`. Задержка
    /// меряется без ожидания разрешения — это задержка провайдера.
    async fn send_wake(&self, payload: PushPayload) -> SendOutcome {
        let _permit = self.send_permits.acquire().await.ok();
        let started = Instant::now();
        let outcome = self.transport.send(payload).await;
        observability::observe_push_latency(started.elapsed());
        outcome
    }

    /// Пометить `key`: ближайший wake этому устройству будит его под звонок.
    /// Hint ставится и тогда, когда `decide` решит не будить вовсе (конверт
    /// без приоритета на ноде с `wake_on_unspecified = false`); протухшие
    /// такие записи вычищает [`Self::sweep`].
    fn remember_call_hint(&self, key: RecipientKey) {
        self.call_hints.insert(key, now_secs());
    }

    /// Снять hint устройства. Возвращает момент выставления, если он ещё
    /// свежий; протухший так же снимается, но отбрасывается — «прицепить
    /// позже» для звонка означает «прицепить не к тому».
    fn take_call_hint(&self, key: RecipientKey, now: u64) -> Option<u64> {
        let (_, at) = self.call_hints.remove(&key)?;
        (now.saturating_sub(at) <= CALL_HINT_TTL_SECS).then_some(at)
    }

    /// Вернуть hint на место: wake не доехал (backoff / сетевая ошибка), и
    /// ретрай на TimerTick'е обязан унести звонковый маркер с собой — ровно
    /// как `rollback_and_suppress` возвращает накопленные счётчики.
    ///
    /// Момент выставления сохраняется исходный: TTL отсчитывается от звонка,
    /// а не от неудачной попытки, иначе цепочка ретраев продлевала бы жизнь
    /// маркера бесконечно.
    fn restore_call_hint(&self, key: RecipientKey, at: Option<u64>) {
        let Some(at) = at else {
            return;
        };
        // `or_insert`, а не `insert`: если за время отправки приехал новый
        // звонок, его отметка свежее и затирать её нечем.
        self.call_hints.entry(key).or_insert(at);
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

        // Сравнение в `Duration`, а не в целых секундах: cooldown в конфиге
        // миллисекундный, и `as_secs()` превращал 500 мс в ноль.
        if self
            .last_ring
            .get(&key)
            .is_some_and(|rang_at| rang_at.elapsed() < self.ring_cooldown)
        {
            // Устройство уже звонит: повторные OFFER'ы той же комнаты
            // (mesh-леги, ре-офферы) не должны слать очередь voip-пушей —
            // каждый из них iOS обязует репортить отдельный CallKit-звонок.
            observability::observe_push_sent("ring", "cooldown");
            debug!(
                user = %hex::encode(key.0),
                device = key.1,
                "voip ring suppressed by cooldown"
            );
            return true;
        }

        let payload = RingPayload {
            user_id: key.0,
            device_id: key.1,
            token,
            server_ts_secs: now_secs(),
        };

        let (outcome, started) = {
            let _permit = self.send_permits.acquire().await.ok();
            let started = Instant::now();
            let outcome = voip.send_ring(payload).await;
            observability::observe_push_latency(started.elapsed());
            (outcome, started)
        };

        match outcome {
            SendOutcome::Ok => {
                observability::observe_push_sent("ring", "ok");
                self.last_ring.insert(key, started);
                true
            }
            SendOutcome::InvalidToken => {
                observability::observe_push_sent("ring", "invalid_token");
                observability::observe_push_token_removed("voip_invalid_token");
                self.tokens.remove_voip(&key.0, key.1);
                // Voip-слот мёртв — пусть хотя бы FCM-wake разбудит.
                false
            }
            SendOutcome::Backoff { reason, .. } => {
                observability::observe_push_sent("ring", "backoff");
                debug!(
                    user = %hex::encode(key.0),
                    device = key.1,
                    ?reason,
                    "voip ring backoff; falling back to FCM wake"
                );
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
            warn!(
                user = %hex::encode(key.0),
                device = key.1,
                "welcome push skipped: no token at dispatch time"
            );
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
            // Приветствие звонком не бывает by construction.
            wake_hint: None,
        };

        match self.send_wake(payload).await {
            SendOutcome::Ok => {
                observability::observe_push_sent("welcome", "ok");
                // Идентификаторы получателя — метаданные переписки; в info
                // им не место.
                debug!(
                    user = %hex::encode(key.0),
                    device = key.1,
                    "welcome push sent"
                );
            }
            SendOutcome::InvalidToken => {
                observability::observe_push_sent("welcome", "invalid_token");
                observability::observe_push_token_removed("invalid_token");
                self.tokens.remove(&key.0, key.1);
            }
            SendOutcome::Backoff { reason, .. } => {
                observability::observe_push_sent("welcome", "backoff");
                debug!(
                    user = %hex::encode(key.0),
                    device = key.1,
                    ?reason,
                    "welcome push backoff; not retrying"
                );
            }
            SendOutcome::TransientError => {
                observability::observe_push_sent("welcome", "transient_error");
                debug!(
                    user = %hex::encode(key.0),
                    device = key.1,
                    "welcome push transient error; not retrying"
                );
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
        retry_after: Option<Duration>,
    ) {
        let until = self.mutate_state(key, now, |state| {
            state.pending_since_last_push = state.pending_since_last_push.saturating_add(pending);
            let restored = MessagePriority::as_storage_byte(max_priority);
            if restored > state.highest_pending_priority {
                state.highest_pending_priority = restored;
            }
            on_send_backoff(state, now, &self.decision_cfg, retry_after);
            state.suppressed_until_secs
        });
        self.schedule_timer(key, until, now);
    }

    /// Replace the cached state for `key`, mirroring the new value to durable
    /// storage. Use this on every transition that begins as a `Decision`.
    /// A state that no longer affects decisions is dropped instead of stored.
    fn write_state(&self, key: RecipientKey, state: PushState, now: u64) {
        if state.is_idle(now, self.longest_gap_secs) {
            self.forget_state(key);
            return;
        }
        let prior = self.states.insert(key, state);
        Self::track_pending_depth(
            prior.map(|p| p.pending_since_last_push).unwrap_or(0),
            state.pending_since_last_push,
        );
        self.persistence.save(key.0, key.1, &state);
    }

    /// Убрать состояние пары из памяти и из персистентности.
    fn forget_state(&self, key: RecipientKey) {
        if let Some((_, prior)) = self.states.remove(&key) {
            Self::track_pending_depth(prior.pending_since_last_push, 0);
            self.persistence.remove(key.0, key.1);
        }
    }

    /// Забыть пару целиком: у неё не осталось токена, будить нечем. Таймер
    /// снимается, чтобы тик не пришёл к уже забытой паре.
    fn forget(&self, key: RecipientKey) {
        self.forget_state(key);
        if let Some((_, timer)) = self.timers.remove(&key) {
            timer.abort();
        }
        self.call_hints.remove(&key);
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

    /// Apply `f` to a copy of the current state and write the result back
    /// through [`Self::write_state`] (same depth accounting, same "idle is not
    /// stored" rule). The closure can return a value (e.g. the new
    /// `suppressed_until_secs`) which is forwarded to the caller.
    ///
    /// Read-modify-write без замка безопасен: переходы одной пары
    /// выполняются строго последовательно (см. [`Self::run`]), а вычистка
    /// пропускает занятые пары.
    fn mutate_state<R>(
        &self,
        key: RecipientKey,
        now: u64,
        f: impl FnOnce(&mut PushState) -> R,
    ) -> R {
        let mut next = self
            .states
            .get(&key)
            .map(|entry| *entry.value())
            .unwrap_or_default();
        let result = f(&mut next);
        self.write_state(key, next, now);
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
            send_concurrency: crate::push::DEFAULT_SEND_CONCURRENCY,
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
        assert!(
            sent[0].wake_hint.is_none(),
            "обычное сообщение не должно выглядеть звонком"
        );
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

    /// Records every `save` / `remove` call so tests can assert that the
    /// worker mirrors state changes to persistence. Hydrated from a seed map
    /// on construction.
    struct RecordingPersistence {
        seed: Vec<((UserId, DeviceId), PushState)>,
        saves: std::sync::Mutex<Vec<(UserId, DeviceId, PushState)>>,
        removes: std::sync::Mutex<Vec<RecipientKey>>,
    }

    impl RecordingPersistence {
        fn empty() -> Self {
            Self::seeded(Vec::new())
        }
        fn seeded(seed: Vec<((UserId, DeviceId), PushState)>) -> Self {
            Self {
                seed,
                saves: std::sync::Mutex::new(Vec::new()),
                removes: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn save_count(&self) -> usize {
            self.saves.lock().unwrap().len()
        }
        fn removed(&self) -> Vec<RecipientKey> {
            self.removes.lock().unwrap().clone()
        }
    }

    impl PushStatePersistence for RecordingPersistence {
        fn load_all(&self) -> Vec<((UserId, DeviceId), PushState)> {
            self.seed.clone()
        }
        fn save(&self, user: UserId, device: DeviceId, state: &PushState) {
            self.saves.lock().unwrap().push((user, device, *state));
        }
        fn remove(&self, user: UserId, device: DeviceId) {
            self.removes.lock().unwrap().push((user, device));
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

    /// Android-путь звонка: voip-слота у устройства нет, ring не состоялся,
    /// и разбудить получателя может только FCM-wake — но помеченный. Без
    /// маркера клиент покажет баннер «новые сообщения» вместо ринга.
    #[tokio::test]
    async fn call_wake_without_voip_token_carries_the_hint() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(21), 4, "fcm-token");

        let scheduler = start_with_ring(transport.clone(), tokens, ring.clone());
        scheduler.on_undelivered(
            user(21),
            4,
            Some(MessagePriority::High),
            Some(WakeHint::IncomingCall),
        );

        wait_for(|| !transport.sent_payloads().is_empty()).await;
        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].wake_hint, Some(WakeHint::IncomingCall));
        assert!(ring.sent_rings().is_empty());
    }

    /// Тот же путь, но конверт обычный: маркер не должен появляться сам по
    /// себе — ни от High-приоритета, ни от наличия voip-токена.
    #[tokio::test]
    async fn ordinary_wake_carries_no_hint_even_at_high_priority() {
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(22), 1, "fcm-token");

        let scheduler = start_with_ring(transport.clone(), tokens, ring.clone());
        scheduler.on_undelivered(user(22), 1, Some(MessagePriority::High), None);

        wait_for(|| !transport.sent_payloads().is_empty()).await;
        assert_eq!(transport.sent_payloads()[0].wake_hint, None);
    }

    /// Worker напрямую, без `spawn`: TTL звонкового hint'а меряется
    /// системными часами, подменить которые в этом модуле нечем, — зато
    /// тест может выставить отметку времени задним числом сам.
    fn bare_worker(
        transport: Arc<MockTransport>,
        tokens: Arc<InMemoryTokenStore>,
    ) -> Worker<MockTransport, InMemoryTokenStore, NoVoipRingTransport> {
        bare_worker_with(
            fast_cfg(),
            transport,
            tokens,
            Arc::new(NoopStatePersistence),
        )
    }

    fn bare_worker_with(
        cfg: PushConfig,
        transport: Arc<MockTransport>,
        tokens: Arc<InMemoryTokenStore>,
        persistence: Arc<dyn PushStatePersistence>,
    ) -> Worker<MockTransport, InMemoryTokenStore, NoVoipRingTransport> {
        // Получатель канала не нужен: тики таймеров в этих тестах никто не
        // разбирает, и отправитель просто упрётся в закрытый канал.
        let (tx, _rx) = mpsc::channel(8);
        Worker::new(
            &cfg,
            tx,
            transport,
            tokens,
            None,
            persistence,
            DEFAULT_SEND_CONCURRENCY,
        )
    }

    /// Hint старше TTL относится к звонку, который у звонящего давно
    /// оборвался по dial-таймауту. Прицепить его к подвернувшемуся wake'у —
    /// это ринг на постороннее сообщение, поэтому он снимается и гибнет.
    #[tokio::test]
    async fn stale_call_hint_is_dropped_rather_than_attached() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(23), 3, "tok");
        let worker = bare_worker(transport.clone(), tokens);

        let now = now_secs();
        let key = (user(23), 3);
        worker
            .call_hints
            .insert(key, now.saturating_sub(CALL_HINT_TTL_SECS + 1));

        worker
            .dispatch_send(key, 1, Some(MessagePriority::High), now)
            .await;

        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].wake_hint.is_none());
        assert!(
            worker.call_hints.is_empty(),
            "протухший hint снимается, а не ждёт следующего wake'а"
        );
    }

    /// Свежий hint доезжает с отправкой ровно один раз: следующее сообщение
    /// тому же устройству звонком уже не притворяется.
    #[tokio::test]
    async fn fresh_call_hint_attaches_exactly_once() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(24), 8, "tok");
        let worker = bare_worker(transport.clone(), tokens);

        let now = now_secs();
        let key = (user(24), 8);
        worker
            .call_hints
            .insert(key, now.saturating_sub(CALL_HINT_TTL_SECS - 1));

        worker
            .dispatch_send(key, 1, Some(MessagePriority::High), now)
            .await;
        worker
            .dispatch_send(key, 1, Some(MessagePriority::Medium), now)
            .await;

        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].wake_hint, Some(WakeHint::IncomingCall));
        assert_eq!(sent[1].wake_hint, None, "hint одноразовый");
    }

    /// Неудачная отправка возвращает hint на место — ровно как
    /// `rollback_and_suppress` возвращает накопленные счётчики. Иначе
    /// звонок, попавший в backoff-окно, доезжал бы ретраем уже «обычным».
    #[tokio::test]
    async fn failed_send_keeps_the_call_hint_for_the_retry() {
        let transport = Arc::new(MockTransport::scripted([
            SendOutcome::backoff(BackoffReason::Quota),
            SendOutcome::Ok,
        ]));
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(25), 2, "tok");
        let worker = bare_worker(transport.clone(), tokens);

        let now = now_secs();
        let key = (user(25), 2);
        worker.call_hints.insert(key, now);

        // Первая попытка упирается в квоту FCM.
        worker
            .dispatch_send(key, 1, Some(MessagePriority::High), now)
            .await;
        // Ретрай: в работе его приносит TimerTick по истечении backoff'а.
        worker
            .dispatch_send(key, 1, Some(MessagePriority::High), now)
            .await;

        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].wake_hint, Some(WakeHint::IncomingCall));
        assert_eq!(
            sent[1].wake_hint,
            Some(WakeHint::IncomingCall),
            "ретрай обязан унести звонковый маркер с собой"
        );
    }

    /// Устройство без FCM-токена: пуша нет, но и hint не остаётся висеть —
    /// иначе он прилипнет к первому же сообщению после перерегистрации.
    #[tokio::test]
    async fn dispatch_without_token_still_consumes_the_hint() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        let worker = bare_worker(transport.clone(), tokens);

        let now = now_secs();
        let key = (user(26), 5);
        worker.call_hints.insert(key, now);

        worker
            .dispatch_send(key, 1, Some(MessagePriority::High), now)
            .await;

        assert!(transport.sent_payloads().is_empty());
        assert!(worker.call_hints.is_empty());
    }

    fn new_message(user: UserId, device: DeviceId, priority: MessagePriority) -> Trigger {
        Trigger::NewMessage {
            user,
            device,
            priority: Some(priority),
            wake_hint: None,
        }
    }

    /// `device_id` выбирает отправитель. Триггер для пары без токена не
    /// должен заводить ни состояния в памяти, ни строки в `push_state` —
    /// иначе любой клиент раздувал бы их произвольными парами.
    #[tokio::test]
    async fn trigger_without_token_leaves_no_state() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        let persistence = Arc::new(RecordingPersistence::empty());
        let worker = bare_worker_with(fast_cfg(), transport.clone(), tokens, persistence.clone());

        for device in 0..50u16 {
            worker
                .process(new_message(user(30), device, MessagePriority::Medium))
                .await;
        }
        worker
            .process(Trigger::NewMessage {
                user: user(30),
                device: 7,
                priority: Some(MessagePriority::High),
                wake_hint: Some(WakeHint::IncomingCall),
            })
            .await;

        assert!(worker.states.is_empty());
        assert!(worker.call_hints.is_empty(), "hint без токена не нужен");
        assert_eq!(persistence.save_count(), 0);
        assert!(transport.sent_payloads().is_empty());
    }

    /// Тик от уже погашенного окна не заводит пустую запись.
    #[tokio::test]
    async fn stale_timer_tick_leaves_no_state() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(31), 1, "tok");
        let persistence = Arc::new(RecordingPersistence::empty());
        let worker = bare_worker_with(fast_cfg(), transport, tokens, persistence.clone());

        worker
            .process(Trigger::TimerTick {
                user: user(31),
                device: 1,
            })
            .await;

        assert!(worker.states.is_empty());
        assert_eq!(persistence.save_count(), 0);
    }

    /// Мёртвый токен — состояние пары больше ни на что не влияет и
    /// забывается вместе с ним, а не висит в памяти и в дереве навсегда.
    #[tokio::test]
    async fn invalid_token_forgets_the_state() {
        let transport = Arc::new(MockTransport::always_invalid_token());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(32), 2, "dead");
        let persistence = Arc::new(RecordingPersistence::empty());
        let worker = bare_worker_with(fast_cfg(), transport, tokens, persistence.clone());

        worker
            .process(new_message(user(32), 2, MessagePriority::High))
            .await;

        assert!(worker.states.is_empty());
        assert_eq!(persistence.removed(), vec![(user(32), 2)]);
    }

    /// Если ни один интервал не держит окно, после успешной отправки
    /// помнить нечего — запись не хранится вовсе.
    #[tokio::test]
    async fn nothing_is_retained_when_no_gap_holds_the_window() {
        let mut cfg = fast_cfg();
        cfg.min_gap_low = Duration::ZERO;
        cfg.min_gap_none = Duration::ZERO;
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(33), 4, "tok");
        let persistence = Arc::new(RecordingPersistence::empty());
        let worker = bare_worker_with(cfg, transport.clone(), tokens, persistence.clone());

        worker
            .process(new_message(user(33), 4, MessagePriority::High))
            .await;

        assert_eq!(transport.sent_payloads().len(), 1);
        assert!(worker.states.is_empty());
        assert_eq!(persistence.save_count(), 0);
    }

    /// Вычистка убирает состояния, которые уже ни на что не влияют, из
    /// памяти и из персистентности; живые и занятые прямо сейчас — оставляет.
    #[tokio::test]
    async fn sweep_drops_idle_states_but_keeps_live_and_busy_ones() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        let persistence = Arc::new(RecordingPersistence::empty());
        let worker = bare_worker_with(fast_cfg(), transport, tokens, persistence.clone());

        let now = now_secs();
        let long_ago = PushState {
            last_push_at_secs: now - 10_000,
            ..Default::default()
        };
        let idle = (user(34), 1);
        let busy_idle = (user(34), 2);
        let recent = (user(34), 3);
        let pending = (user(34), 4);
        worker.states.insert(idle, long_ago);
        worker.states.insert(busy_idle, long_ago);
        worker.states.insert(
            recent,
            PushState {
                last_push_at_secs: now,
                ..Default::default()
            },
        );
        worker.states.insert(
            pending,
            PushState {
                pending_since_last_push: 1,
                ..long_ago
            },
        );

        let busy = HashMap::from([(busy_idle, VecDeque::new())]);
        worker.sweep(&busy);

        assert!(!worker.states.contains_key(&idle));
        assert!(worker.states.contains_key(&busy_idle));
        assert!(worker.states.contains_key(&recent));
        assert!(worker.states.contains_key(&pending));
        assert_eq!(persistence.removed(), vec![idle]);
    }

    /// Служебные карты тоже не растут без предела: истёкший cooldown,
    /// протухший call-hint и отработавший таймер вычищаются.
    #[tokio::test]
    async fn sweep_prunes_auxiliary_maps() {
        let mut cfg = fast_cfg();
        cfg.ring_cooldown = Duration::from_millis(30);
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        let worker = bare_worker_with(cfg, transport, tokens, Arc::new(NoopStatePersistence));

        let now = now_secs();
        let old = (user(35), 1);
        let fresh = (user(35), 2);

        worker.last_ring.insert(old, Instant::now());
        worker
            .call_hints
            .insert(old, now.saturating_sub(CALL_HINT_TTL_SECS + 1));
        worker.timers.insert(old, tokio::spawn(async {}));
        tokio::time::sleep(Duration::from_millis(50)).await;

        worker.last_ring.insert(fresh, Instant::now());
        worker.call_hints.insert(fresh, now);
        worker.timers.insert(
            fresh,
            tokio::spawn(tokio::time::sleep(Duration::from_secs(60))),
        );

        worker.sweep(&HashMap::new());

        assert!(!worker.last_ring.contains_key(&old));
        assert!(worker.last_ring.contains_key(&fresh));
        assert!(!worker.call_hints.contains_key(&old));
        assert!(worker.call_hints.contains_key(&fresh));
        assert!(!worker.timers.contains_key(&old));
        assert!(worker.timers.contains_key(&fresh));
    }

    /// Гидрация не грузит мусор: записи, которые уже ни на что не влияют, и
    /// записи устройств без токена удаляются из персистентности.
    #[tokio::test]
    async fn hydration_drops_idle_and_tokenless_rows() {
        let now = now_secs();
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(36), 1, "tok");
        tokens.insert(user(36), 3, "tok");

        let idle = PushState {
            last_push_at_secs: now - 10_000,
            ..Default::default()
        };
        let live = PushState {
            last_push_at_secs: now,
            ..Default::default()
        };
        let persistence = Arc::new(RecordingPersistence::seeded(vec![
            ((user(36), 1), idle),
            ((user(36), 2), live),
            ((user(36), 3), live),
        ]));
        let worker = bare_worker_with(
            fast_cfg(),
            Arc::new(MockTransport::always_ok()),
            tokens,
            persistence.clone(),
        );

        worker.hydrate(false);

        assert_eq!(worker.states.len(), 1);
        assert!(worker.states.contains_key(&(user(36), 3)));
        let mut removed = persistence.removed();
        removed.sort();
        assert_eq!(removed, vec![(user(36), 1), (user(36), 2)]);
    }

    /// Таймеры живут только в памяти. Накопленное до рестарта, срок
    /// которого уже наступил, обязано уйти само, без нового сообщения тому
    /// же устройству, — иначе каждый деплой терял бы отложенные wake.
    #[tokio::test]
    async fn hydration_rearms_timers_for_pending_state() {
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(37), 6, "tok");

        let pending = PushState {
            last_push_at_secs: now_secs() - 1_000,
            pending_since_last_push: 2,
            highest_pending_priority: MessagePriority::as_storage_byte(Some(MessagePriority::Low)),
            ..Default::default()
        };
        let persistence = Arc::new(RecordingPersistence::seeded(vec![((user(37), 6), pending)]));

        let _scheduler = PushScheduler::start(fast_cfg(), transport.clone(), tokens, persistence);

        wait_for(|| !transport.sent_payloads().is_empty()).await;
        let sent = transport.sent_payloads();
        assert_eq!(sent.len(), 1, "накопленное до рестарта должно уйти");
        assert_eq!(sent[0].pending, 2);
        assert_eq!(sent[0].max_priority, Some(MessagePriority::Low));
    }

    /// Выключенные пуши ничего не «досылают» по перевзведённым таймерам.
    #[tokio::test]
    async fn disabled_scheduler_does_not_resume_pending_state() {
        let mut cfg = fast_cfg();
        cfg.enabled = false;
        let transport = Arc::new(MockTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(38), 6, "tok");
        let pending = PushState {
            last_push_at_secs: now_secs() - 1_000,
            pending_since_last_push: 2,
            ..Default::default()
        };
        let persistence = Arc::new(RecordingPersistence::seeded(vec![((user(38), 6), pending)]));

        let _scheduler = PushScheduler::start(cfg, transport.clone(), tokens, persistence);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(transport.sent_payloads().is_empty());
    }

    /// Cooldown меньше секунды раньше округлялся до нуля через `as_secs()`
    /// и не подавлял ничего. Теперь он сравнивается в своих миллисекундах.
    #[tokio::test]
    async fn sub_second_ring_cooldown_still_suppresses_duplicates() {
        let mut cfg = fast_cfg();
        cfg.ring_cooldown = Duration::from_millis(800);
        let transport = Arc::new(MockTransport::always_ok());
        let ring = Arc::new(MockRingTransport::always_ok());
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert_voip(user(39), 2, "voip-token");

        let scheduler = PushScheduler::start_with_voip(
            cfg,
            transport.clone(),
            tokens,
            Arc::new(NoopStatePersistence),
            Some(ring.clone()),
        );
        let call = |scheduler: &PushScheduler| {
            scheduler.on_undelivered(
                user(39),
                2,
                Some(MessagePriority::High),
                Some(WakeHint::IncomingCall),
            )
        };

        call(&scheduler);
        wait_for(|| !ring.sent_rings().is_empty()).await;
        call(&scheduler);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(ring.sent_rings().len(), 1, "дубль внутри окна подавлен");

        tokio::time::sleep(Duration::from_millis(800)).await;
        call(&scheduler);
        wait_for(|| ring.sent_rings().len() == 2).await;
        assert_eq!(ring.sent_rings().len(), 2, "после окна звонок проходит");
        assert!(transport.sent_payloads().is_empty());
    }

    /// Транспорт, который считает одновременные отправки — всего и по
    /// токену. Токен `slow` отвечает долго, остальные — с `latency`.
    struct TrackingTransport {
        latency: Duration,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
        per_token: std::sync::Mutex<HashMap<String, usize>>,
        max_per_token: std::sync::atomic::AtomicUsize,
        sent: std::sync::Mutex<Vec<String>>,
    }

    impl TrackingTransport {
        fn new(latency: Duration) -> Self {
            Self {
                latency,
                in_flight: Default::default(),
                max_in_flight: Default::default(),
                per_token: Default::default(),
                max_per_token: Default::default(),
                sent: Default::default(),
            }
        }

        fn sent(&self) -> Vec<String> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl PushTransport for TrackingTransport {
        async fn send(&self, payload: PushPayload) -> SendOutcome {
            use std::sync::atomic::Ordering::SeqCst;

            let now_in_flight = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.max_in_flight.fetch_max(now_in_flight, SeqCst);
            {
                let mut per_token = self.per_token.lock().unwrap();
                let count = per_token.entry(payload.token.clone()).or_default();
                *count += 1;
                self.max_per_token.fetch_max(*count, SeqCst);
            }

            let latency = if payload.token == "slow" {
                Duration::from_secs(5)
            } else {
                self.latency
            };
            tokio::time::sleep(latency).await;

            *self
                .per_token
                .lock()
                .unwrap()
                .get_mut(&payload.token)
                .unwrap() -= 1;
            self.in_flight.fetch_sub(1, SeqCst);
            self.sent.lock().unwrap().push(payload.token);
            SendOutcome::Ok
        }
    }

    fn start_tracking(
        transport: Arc<TrackingTransport>,
        tokens: Arc<InMemoryTokenStore>,
        send_concurrency: usize,
    ) -> PushScheduler {
        PushScheduler::spawn::<_, _, NoVoipRingTransport>(
            fast_cfg(),
            transport,
            tokens,
            Arc::new(NoopStatePersistence),
            None,
            send_concurrency,
        )
    }

    /// Повисшая отправка одному получателю не задерживает остальных: раньше
    /// единственный воркер ждал её таймаут, и канал вставал для всех.
    #[tokio::test]
    async fn slow_recipient_does_not_block_others() {
        let transport = Arc::new(TrackingTransport::new(Duration::ZERO));
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(40), 1, "slow");
        tokens.insert(user(41), 1, "fast");

        let scheduler = start_tracking(transport.clone(), tokens, 4);
        scheduler.on_undelivered(user(40), 1, Some(MessagePriority::High), None);
        scheduler.on_undelivered(user(41), 1, Some(MessagePriority::High), None);

        wait_for(|| !transport.sent().is_empty()).await;
        assert_eq!(transport.sent(), vec!["fast".to_string()]);
    }

    /// Отправки одному получателю никогда не идут внахлёст — переходы его
    /// состояния последовательны, и ни одно сообщение не теряется.
    #[tokio::test]
    async fn sends_to_one_recipient_never_overlap() {
        use std::sync::atomic::Ordering::SeqCst;

        let transport = Arc::new(TrackingTransport::new(Duration::from_millis(20)));
        let tokens = Arc::new(InMemoryTokenStore::default());
        tokens.insert(user(42), 1, "one");

        let scheduler = start_tracking(transport.clone(), tokens, 8);
        for _ in 0..5 {
            scheduler.on_undelivered(user(42), 1, Some(MessagePriority::High), None);
        }

        for _ in 0..100 {
            if transport.sent().len() == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(transport.sent().len(), 5);
        assert_eq!(transport.max_per_token.load(SeqCst), 1);
    }

    /// Одновременных обращений к провайдеру не больше заданного предела.
    #[tokio::test]
    async fn provider_calls_are_bounded() {
        use std::sync::atomic::Ordering::SeqCst;

        let transport = Arc::new(TrackingTransport::new(Duration::from_millis(30)));
        let tokens = Arc::new(InMemoryTokenStore::default());
        for seed in 50..56u8 {
            tokens.insert(user(seed), 1, format!("tok-{seed}"));
        }

        let scheduler = start_tracking(transport.clone(), tokens, 2);
        for seed in 50..56u8 {
            scheduler.on_undelivered(user(seed), 1, Some(MessagePriority::High), None);
        }

        for _ in 0..100 {
            if transport.sent().len() == 6 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(transport.sent().len(), 6);
        assert_eq!(transport.max_in_flight.load(SeqCst), 2);
    }
}
