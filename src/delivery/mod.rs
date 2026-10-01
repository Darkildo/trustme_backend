use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use async_nats::jetstream;
use async_nats::jetstream::AckKind;
use async_nats::jetstream::consumer;
use async_nats::jetstream::consumer::pull;
use async_nats::jetstream::stream;
use dashmap::DashMap;
use futures_util::StreamExt;
use prost::Message;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{error, info};

use crate::broker::BrokerMessage;
use crate::config::{Config, DeliveryBackendKind};
use crate::domain::priority::MessagePriority;
use crate::domain::wake::WakeHint;
use crate::net::framing::{decode_device_id, encode_auth_error, encode_device_id, encode_incoming};
use crate::observability;
use crate::push::PushScheduler;
use crate::state::push_tokens::PushTokenStore;
use crate::state::registry::{ConnRegistry, ConnectionId, DeviceId, OutboundFrame, UserId};
use crate::state::storage::Storage;

const ACCOUNT_SUBJECT_PREFIX: &str = "msg.user";
const USER_PUMP_POLL_TIMEOUT: Duration = Duration::from_secs(1);
/// Сколько ждать места в канале сессии, чтобы сообщить ей о смерти пула.
/// Дальше ждать бессмысленно: канал переполнен ровно тогда, когда задача
/// сессии сама застряла.
const CLOSE_NOTICE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub enum DeliveryBackend {
    Sled(SledBackend),
    JetStream(Arc<JetStreamBackend>),
}

#[derive(Clone)]
pub struct SledBackend {
    storage: Storage,
}

impl SledBackend {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

pub struct PublishedMessage {
    pub message_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryScope {
    Account {
        user_id: UserId,
    },
    Device {
        user_id: UserId,
        device_id: DeviceId,
    },
}

impl DeliveryScope {
    fn user_id(self) -> UserId {
        match self {
            Self::Account { user_id } | Self::Device { user_id, .. } => user_id,
        }
    }

    fn durable_name(self) -> String {
        let user = hex::encode(self.user_id());
        match self {
            Self::Account { .. } => format!("user_{user}"),
            Self::Device { device_id, .. } => format!("user_{user}_device_{device_id}"),
        }
    }

    fn subject(self) -> String {
        let user = hex::encode(self.user_id());
        match self {
            Self::Account { .. } => format!("{ACCOUNT_SUBJECT_PREFIX}.{user}"),
            Self::Device { device_id, .. } => {
                format!("{ACCOUNT_SUBJECT_PREFIX}.{user}.device.{device_id}")
            }
        }
    }

    fn key(self) -> String {
        match self {
            Self::Account { user_id } => format!("account:{}", hex::encode(user_id)),
            Self::Device { user_id, device_id } => {
                format!("device:{}:{device_id}", hex::encode(user_id))
            }
        }
    }

    fn is_online(self, registry: &ConnRegistry) -> bool {
        match self {
            Self::Account { user_id } => registry.has_user(&user_id),
            Self::Device { user_id, device_id } => registry.has_device(&user_id, device_id),
        }
    }

    fn matches_ack(self, user_id: &UserId, device_id: Option<DeviceId>) -> bool {
        match self {
            Self::Account { user_id: expected } => expected == *user_id,
            Self::Device {
                user_id: expected_user,
                device_id: expected_device,
            } => expected_user == *user_id && device_id == Some(expected_device),
        }
    }
}

struct PendingBrokerAck {
    message: Mutex<Option<jetstream::Message>>,
}

impl PendingBrokerAck {
    fn new(message: jetstream::Message) -> Self {
        Self {
            message: Mutex::new(Some(message)),
        }
    }

    async fn ack(&self) -> Result<bool> {
        let mut guard = self.message.lock().await;
        let Some(message) = guard.take() else {
            return Ok(false);
        };

        message
            .ack()
            .await
            .map_err(|err| anyhow!("failed to ack broker message: {err}"))?;
        Ok(true)
    }

    /// Вернуть конверт потоку немедленно, не дожидаясь `ack_wait`.
    ///
    /// Без `Nak` неподтверждённый конверт невидим до истечения `ack_wait`
    /// (по умолчанию 30 с), и переподключившийся получатель ждёт его всё
    /// это время.
    async fn nak(&self) -> Result<bool> {
        let mut guard = self.message.lock().await;
        let Some(message) = guard.take() else {
            return Ok(false);
        };

        message
            .ack_with(AckKind::Nak(None))
            .await
            .map_err(|err| anyhow!("failed to nak broker message: {err}"))?;
        Ok(true)
    }
}

struct InflightDelivery {
    scope: DeliveryScope,
    pending_ack: Arc<PendingBrokerAck>,
}

#[derive(Clone)]
pub struct JetStreamBackend {
    context: jetstream::Context,
    stream_name: String,
    ack_wait: Duration,
    consumer_inactive_threshold: Duration,
    stream_max_age: Duration,
    stream_max_bytes: i64,
    publish_timeout: Duration,
    inflight: Arc<DashMap<u64, InflightDelivery>>,
    pumps: Arc<DashMap<String, JoinHandle<()>>>,
    push_tokens: PushTokenStore,
    push_scheduler: PushScheduler,
}

#[derive(Debug, Clone)]
struct BrokerPayload {
    message_id: u64,
    sender_user_id: UserId,
    sender_device_id: Option<DeviceId>,
    recipient_user_id: UserId,
    recipient_device_id: Option<DeviceId>,
    body: Vec<u8>,
    created_at: u64,
    priority: Option<MessagePriority>,
    wake_hint: Option<WakeHint>,
    /// Node-header конверта v3: время жизни в очереди, секунды;
    /// 0 = не задан. Пул его не применяет: срок хранения на брокерном
    /// бэкенде задаёт `max_age` потока.
    ttl_seconds: u64,
}

impl DeliveryBackend {
    pub async fn from_config(
        cfg: &Config,
        storage: Storage,
        push_tokens: PushTokenStore,
        push_scheduler: PushScheduler,
    ) -> Result<Self> {
        match cfg.delivery.backend {
            DeliveryBackendKind::Sled => Ok(Self::Sled(SledBackend { storage })),
            DeliveryBackendKind::JetStream => {
                let client = async_nats::connect(&cfg.delivery.nats_url)
                    .await
                    .with_context(|| {
                        format!("failed to connect to NATS at {}", cfg.delivery.nats_url)
                    })?;
                let context = jetstream::new(client);
                let backend = Arc::new(JetStreamBackend {
                    context,
                    stream_name: cfg.delivery.nats_stream_name.clone(),
                    ack_wait: cfg.delivery.nats_ack_wait,
                    consumer_inactive_threshold: cfg.delivery.nats_consumer_inactive_threshold,
                    stream_max_age: cfg.delivery.nats_stream_max_age,
                    stream_max_bytes: cfg.delivery.nats_stream_max_bytes,
                    publish_timeout: cfg.delivery.nats_publish_timeout,
                    inflight: Arc::new(DashMap::new()),
                    pumps: Arc::new(DashMap::new()),
                    push_tokens,
                    push_scheduler,
                });
                backend.ensure_stream().await?;
                Ok(Self::JetStream(backend))
            }
        }
    }

    pub fn storage(&self) -> Option<&Storage> {
        match self {
            Self::Sled(backend) => Some(&backend.storage),
            Self::JetStream(_) => None,
        }
    }

    pub fn is_jetstream(&self) -> bool {
        matches!(self, Self::JetStream(_))
    }

    // Параметры зеркалят поля ClientSend.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish(
        &self,
        message_id: u64,
        sender_user_id: UserId,
        sender_device_id: Option<DeviceId>,
        recipient_user_id: UserId,
        recipient_device_id: Option<DeviceId>,
        body: &[u8],
        priority: Option<MessagePriority>,
        wake_hint: Option<WakeHint>,
        ttl_seconds: u64,
    ) -> Result<PublishedMessage> {
        match self {
            Self::Sled(_) => Ok(PublishedMessage { message_id }),
            Self::JetStream(backend) => {
                backend
                    .publish(
                        message_id,
                        sender_user_id,
                        sender_device_id,
                        recipient_user_id,
                        recipient_device_id,
                        body,
                        priority,
                        wake_hint,
                        ttl_seconds,
                    )
                    .await?;
                observability::observe_message_accepted();
                Ok(PublishedMessage { message_id })
            }
        }
    }

    pub async fn start_user_pump(&self, user_id: UserId, registry: ConnRegistry) -> Result<()> {
        if let Self::JetStream(backend) = self {
            backend
                .start_scope_pump(DeliveryScope::Account { user_id }, registry)
                .await?;
        }
        Ok(())
    }

    pub async fn start_device_pump(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        registry: ConnRegistry,
    ) -> Result<()> {
        if let Self::JetStream(backend) = self {
            backend
                .start_scope_pump(DeliveryScope::Device { user_id, device_id }, registry)
                .await?;
        }
        Ok(())
    }

    pub async fn ack_delivery(
        &self,
        user_id: UserId,
        device_id: Option<DeviceId>,
        message_id: u64,
    ) -> Result<bool> {
        match self {
            Self::Sled(_) => Ok(false),
            Self::JetStream(backend) => backend.ack_delivery(user_id, device_id, message_id).await,
        }
    }

    pub fn on_disconnect(&self, connection_id: ConnectionId) {
        if let Self::JetStream(backend) = self {
            backend.on_disconnect(connection_id);
        }
    }
}

impl JetStreamBackend {
    /// Конфиг для **создания** стрима с нуля.
    ///
    /// `max_age` + `max_bytes` при `DiscardPolicy::Old` дают нужный порядок
    /// вытеснения: уходит самое старое, приём новых сообщений при
    /// переполнении не блокируется. Безлимитные поля выставлены явными `-1`:
    /// `Config::default()` заполняет их нулями, а ноль для части лимитов
    /// JetStream трактует иначе, чем «без ограничения».
    fn new_stream_config(&self) -> stream::Config {
        stream::Config {
            name: self.stream_name.clone(),
            subjects: vec!["msg.user.*".to_string(), "msg.user.*.device.*".to_string()],
            storage: stream::StorageType::File,
            retention: stream::RetentionPolicy::Limits,
            discard: stream::DiscardPolicy::Old,
            max_age: self.stream_max_age,
            max_bytes: self.stream_max_bytes,
            max_messages: -1,
            max_messages_per_subject: -1,
            max_consumers: -1,
            max_message_size: -1,
            num_replicas: 1,
            ..Default::default()
        }
    }

    /// Создать стрим или привести лимиты существующего к конфигу ноды. Лимиты
    /// живут в конфиге, а не только в состоянии брокера, поэтому переживают
    /// пересоздание стрима.
    async fn ensure_stream(&self) -> Result<()> {
        let Ok(mut stream) = self.context.get_stream(&self.stream_name).await else {
            self.context
                .create_stream(self.new_stream_config())
                .await
                .with_context(|| format!("failed to create stream `{}`", self.stream_name))?;
            return Ok(());
        };

        // Правим ровно три поля поверх фактического конфига, а не отправляем
        // свой целиком: иначе поля, которых мы не касаемся (duplicate_window,
        // num_replicas, allow_direct, metadata...), уехали бы в дефолты.
        // `retention` не трогаем — JetStream не даёт менять его на живом
        // стриме.
        let current = stream
            .info()
            .await
            .with_context(|| format!("failed to read stream `{}` info", self.stream_name))?
            .config
            .clone();

        if current.max_age == self.stream_max_age
            && current.max_bytes == self.stream_max_bytes
            && current.discard == stream::DiscardPolicy::Old
        {
            return Ok(());
        }

        info!(
            stream = %self.stream_name,
            old_max_age_secs = current.max_age.as_secs(),
            new_max_age_secs = self.stream_max_age.as_secs(),
            old_max_bytes = current.max_bytes,
            new_max_bytes = self.stream_max_bytes,
            "applying stream retention limits"
        );

        self.context
            .update_stream(stream::Config {
                max_age: self.stream_max_age,
                max_bytes: self.stream_max_bytes,
                discard: stream::DiscardPolicy::Old,
                ..current
            })
            .await
            .with_context(|| format!("failed to update stream `{}` limits", self.stream_name))?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish(
        &self,
        message_id: u64,
        sender_user_id: UserId,
        sender_device_id: Option<DeviceId>,
        recipient_user_id: UserId,
        recipient_device_id: Option<DeviceId>,
        body: &[u8],
        priority: Option<MessagePriority>,
        wake_hint: Option<WakeHint>,
        ttl_seconds: u64,
    ) -> Result<()> {
        let subject = scope_subject(recipient_user_id, recipient_device_id);
        let payload = encode_broker_message(BrokerPayload {
            message_id,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            body: body.to_vec(),
            created_at: unix_timestamp_secs()?,
            priority,
            wake_hint,
            ttl_seconds,
        });
        // Таймаут — на всю публикацию целиком, включая ожидание ack от
        // стрима: без него мёртвый брокер держит задачу соединения на
        // дефолте клиента NATS, и отправитель всё это время не получает
        // даже входящих.
        let published = timeout(self.publish_timeout, async {
            self.context
                .publish(subject, payload.into())
                .await
                .context("failed to publish message to JetStream")?
                .await
                .context("failed to confirm JetStream publish")?;
            anyhow::Ok(())
        })
        .await;

        match published {
            Ok(result) => result,
            Err(_) => {
                observability::observe_broker_publish_timeout();
                Err(anyhow!(
                    "JetStream publish timed out after {:?}",
                    self.publish_timeout
                ))
            }
        }
    }

    async fn start_scope_pump(&self, scope: DeliveryScope, registry: ConnRegistry) -> Result<()> {
        let key = scope.key();
        let scope_label = match scope {
            DeliveryScope::Account { .. } => "account",
            DeliveryScope::Device { .. } => "device",
        };

        // The read guard must be dropped before the `insert` below: holding a
        // DashMap `Ref` across a write to the same shard deadlocks.
        let needs_spawn = {
            match self.pumps.get(&key) {
                Some(handle) => handle.is_finished(),
                None => true,
            }
        };

        if !needs_spawn {
            return Ok(());
        }

        let backend = self.clone();
        let task_key = key.clone();
        let notify_registry = registry.clone();
        let new_handle = tokio::spawn(async move {
            if let Err(err) = backend.run_scope_pump(scope, registry).await {
                // Снаружи упавший пул не виден — сессии остаются
                // установленными, — поэтому падение считается в метрике, а
                // не только пишется в лог.
                observability::observe_jetstream_pump_failed(scope_label);
                error!(scope = %task_key, error = %err, "delivery scope pump terminated with error");
            }
            // При любом исходе — ошибка или штатный выход — пул больше не
            // работает: сначала вернуть потоку неподтверждённые конверты,
            // затем закрыть сессии, которые он обслуживал. При выходе по
            // офлайну закрывать обычно некого; при закрытии потока у живой
            // сессии без этого шага она осталась бы без входящих.
            backend.release_inflight(scope, scope_label).await;
            JetStreamBackend::close_scope_sessions(scope, scope_label, &notify_registry).await;
            // The finished handle stays in `pumps`; the next start_scope_pump
            // for this key sees is_finished() == true and replaces it.
        });

        // One live pump per scope. The `get` above and this `insert` are not
        // atomic, so two sessions of the same scope connecting concurrently
        // can both spawn; the older still-running handle is then aborted.
        let log_key = key.clone();
        if let Some(previous) = self.pumps.insert(key, new_handle) {
            if previous.is_finished() {
                info!(scope = %log_key, "previous pump handle finished; revived");
                observability::observe_jetstream_pump_revived(scope_label);
            } else {
                tracing::warn!(
                    scope = %log_key,
                    "found a still-running pump while respawning; aborting older handle"
                );
                previous.abort();
            }
        }

        Ok(())
    }

    async fn run_scope_pump(&self, scope: DeliveryScope, registry: ConnRegistry) -> Result<()> {
        let stream = self
            .context
            .get_stream(&self.stream_name)
            .await
            .with_context(|| format!("failed to access stream `{}`", self.stream_name))?;

        let durable_name = scope.durable_name();
        // `create_consumer` (create-or-update), а не `get_or_create_consumer`:
        // второй возвращает существующий durable как есть, и изменения
        // конфига (например, `inactive_threshold`) не доходили бы до
        // durable'ов, созданных раньше. Неизменяемые поля (filter_subject,
        // deliver_policy, ack_policy) здесь не меняются.
        let consumer = stream
            .create_consumer(pull::Config {
                durable_name: Some(durable_name.clone()),
                filter_subject: scope.subject(),
                ack_policy: consumer::AckPolicy::Explicit,
                deliver_policy: consumer::DeliverPolicy::All,
                replay_policy: consumer::ReplayPolicy::Instant,
                ack_wait: self.ack_wait,
                max_ack_pending: 1024,
                // Без порога durable'ы (по одному на аккаунт и на устройство)
                // не удаляются никогда: retention стрима чистит сообщения, но
                // не consumer'ов. Порог обязан превышать `max_age` стрима —
                // это проверяется при загрузке конфига.
                inactive_threshold: self.consumer_inactive_threshold,
                ..Default::default()
            })
            .await
            .with_context(|| format!("failed to create durable consumer `{durable_name}`"))?;

        let mut messages = consumer
            .messages()
            .await
            .with_context(|| format!("failed to start consumer stream `{durable_name}`"))?;

        info!(scope = %scope.key(), subject = %scope.subject(), durable = %scope.durable_name(), "started JetStream delivery pump");

        let scope_label = match scope {
            DeliveryScope::Account { .. } => "account",
            DeliveryScope::Device { .. } => "device",
        };

        loop {
            if !scope.is_online(&registry) {
                info!(scope = %scope.key(), reason = "scope_offline", "delivery pump exiting");
                break;
            }

            let next = timeout(USER_PUMP_POLL_TIMEOUT, messages.next()).await;
            let Some(message) = (match next {
                Ok(Some(message)) => Some(message),
                Ok(None) => {
                    info!(scope = %scope.key(), reason = "messages_stream_closed", "delivery pump exiting");
                    break;
                }
                Err(_) => None,
            }) else {
                continue;
            };

            let message = message.context("failed to read JetStream message")?;
            let redelivered = message
                .info()
                .map(|info| info.delivered > 1)
                .unwrap_or(false);
            if redelivered {
                observability::observe_message_redelivered();
            }
            // Недекодируемый конверт — не повод убивать пул: он не
            // подтверждён, поэтому JetStream отдаст его снова, и пул будет
            // умирать на нём после каждого рестарта. Снимаем с потока
            // навсегда (Term) и считаем в метрике.
            let payload = match decode_broker_message(message.payload.as_ref()) {
                Ok(payload) => payload,
                Err(err) => {
                    observability::observe_broker_decode_error(scope_label);
                    error!(
                        scope = %scope.key(),
                        size = message.payload.len(),
                        error = %err,
                        "undecodable envelope in the stream; terminating it"
                    );
                    if let Err(term_err) = message.ack_with(AckKind::Term).await {
                        tracing::warn!(
                            scope = %scope.key(),
                            error = %term_err,
                            "failed to terminate an undecodable envelope; it will be redelivered"
                        );
                    }
                    continue;
                }
            };

            info!(
                scope = %scope.key(),
                message_id = payload.message_id,
                sender = %hex::encode(payload.sender_user_id),
                sender_device_id = ?payload.sender_device_id,
                recipient = %hex::encode(payload.recipient_user_id),
                recipient_device_id = ?payload.recipient_device_id,
                size = payload.body.len(),
                redelivered,
                "pump received envelope from JetStream"
            );

            let route_targets =
                registry.route_targets(&payload.recipient_user_id, payload.recipient_device_id);

            let online_device_ids: Vec<DeviceId> = route_targets
                .iter()
                .filter_map(|target| target.device_id)
                .collect();
            self.trigger_push_for_offline(
                payload.recipient_user_id,
                payload.recipient_device_id,
                payload.priority,
                payload.wake_hint,
                &online_device_ids,
            );

            if route_targets.is_empty() {
                observability::observe_jetstream_no_targets(scope_label);
                if !scope.is_online(&registry) {
                    info!(
                        scope = %scope.key(),
                        message_id = payload.message_id,
                        reason = "scope_offline_before_push",
                        "delivery pump exiting"
                    );
                    break;
                }
                tracing::warn!(
                    scope = %scope.key(),
                    message_id = payload.message_id,
                    recipient = %hex::encode(payload.recipient_user_id),
                    recipient_device_id = ?payload.recipient_device_id,
                    "no route targets for envelope; leaving un-acked for JetStream redelivery"
                );
                continue;
            }

            let pending_ack = Arc::new(PendingBrokerAck::new(message));
            self.inflight.insert(
                payload.message_id,
                InflightDelivery {
                    scope,
                    pending_ack: pending_ack.clone(),
                },
            );

            let outgoing = OutboundFrame {
                bytes: encode_incoming(
                    payload.sender_user_id,
                    payload.sender_device_id,
                    payload.message_id,
                    &payload.body,
                    payload.priority,
                ),
                message_id: Some(payload.message_id),
                close_after_send: false,
                sender_user_id: Some(payload.sender_user_id),
                sender_device_id: payload.sender_device_id,
            };

            let target_count = route_targets.len();
            let mut delivered = 0usize;
            for target in route_targets {
                match target.tx.send(outgoing.clone()).await {
                    Ok(()) => {
                        delivered += 1;
                    }
                    Err(_) => {
                        tracing::warn!(
                            scope = %scope.key(),
                            message_id = payload.message_id,
                            stale_connection_id = target.id,
                            target_device_id = ?target.device_id,
                            "peer mpsc send failed; removing stale registry entry"
                        );
                        registry.remove(&payload.recipient_user_id, target.id);
                    }
                }
            }

            if delivered == 0 {
                self.inflight.remove(&payload.message_id);
                tracing::warn!(
                    scope = %scope.key(),
                    message_id = payload.message_id,
                    target_count,
                    "envelope push failed for all targets; leaving un-acked for redelivery"
                );
                if !scope.is_online(&registry) {
                    info!(
                        scope = %scope.key(),
                        message_id = payload.message_id,
                        reason = "scope_offline_after_push_failure",
                        "delivery pump exiting"
                    );
                    break;
                }
                continue;
            }

            info!(
                scope = %scope.key(),
                message_id = payload.message_id,
                delivered,
                target_count,
                "pump pushed envelope to peer mpsc"
            );

            observability::observe_message_pushed_online();
        }

        Ok(())
    }

    /// Пул области видимости больше не работает, и подтвердить отданные им
    /// конверты некому. Они возвращаются потоку сразу (`Nak`), а не по
    /// истечении `ack_wait`, чтобы переподключившийся получатель не ждал.
    ///
    /// Потери нет в любом случае: неподтверждённый конверт будет выдан
    /// снова. Конверты, уже вытянутые в буфер pull-подписки, но не отданные
    /// сессиям, сюда не попадают и возвращаются по `ack_wait`.
    async fn release_inflight(&self, scope: DeliveryScope, scope_label: &'static str) {
        let owned: Vec<u64> = self
            .inflight
            .iter()
            .filter(|entry| entry.value().scope == scope)
            .map(|entry| *entry.key())
            .collect();

        let mut released = 0usize;
        for message_id in owned {
            let Some((_, inflight)) = self.inflight.remove(&message_id) else {
                continue;
            };
            match inflight.pending_ack.nak().await {
                Ok(true) => {
                    released += 1;
                    observability::observe_inflight_released(scope_label);
                }
                Ok(false) => {}
                // Обычный случай: пул умер вместе с брокером, и вернуть
                // конверт некому. Тогда его вернёт `ack_wait` — дольше, но
                // так же надёжно.
                Err(err) => tracing::warn!(
                    scope = %scope.key(),
                    message_id,
                    error = %err,
                    "failed to return an unacked envelope to the stream"
                ),
            }
        }

        if released > 0 {
            info!(
                scope = %scope.key(),
                released,
                "returned unacked envelopes to the stream ahead of ack_wait"
            );
        }
    }

    /// Пул области видимости больше не работает, а его сессии остаются
    /// установленными: клиент считает себя подключённым, но входящих не
    /// получит. Нода сообщает об этом явно (`AuthError(503)` с закрытием
    /// сессии), и клиент уходит на переподключение — к рабочему пулу или к
    /// отказу 503 на входе.
    async fn close_scope_sessions(
        scope: DeliveryScope,
        scope_label: &'static str,
        registry: &ConnRegistry,
    ) {
        let (user_id, device_id) = match scope {
            DeliveryScope::Account { user_id } => (user_id, None),
            DeliveryScope::Device { user_id, device_id } => (user_id, Some(device_id)),
        };

        let targets = registry.route_targets(&user_id, device_id);
        if targets.is_empty() {
            return;
        }

        let frame = OutboundFrame {
            bytes: encode_auth_error(503, "delivery pump failed"),
            message_id: None,
            sender_user_id: None,
            sender_device_id: None,
            close_after_send: true,
        };

        let mut closed = 0usize;
        for target in targets {
            // Канал сессии мог переполниться — например, потому что её
            // задача сама застряла на публикации в мёртвый брокер. Ждать
            // её здесь бесконечно значит подвесить ещё и эту задачу.
            match timeout(CLOSE_NOTICE_TIMEOUT, target.tx.send(frame.clone())).await {
                Ok(Ok(())) => {
                    closed += 1;
                    observability::observe_pump_session_closed(scope_label);
                }
                Ok(Err(_)) => registry.remove(&user_id, target.id),
                Err(_) => tracing::warn!(
                    scope = %scope.key(),
                    connection_id = target.id,
                    "session channel is full; could not deliver the pump-failure notice"
                ),
            }
        }

        tracing::warn!(
            scope = %scope.key(),
            closed,
            "delivery pump died; closing its sessions so the client reconnects"
        );
    }

    async fn ack_delivery(
        &self,
        user_id: UserId,
        device_id: Option<DeviceId>,
        message_id: u64,
    ) -> Result<bool> {
        let Some((_, inflight)) = self.inflight.remove(&message_id) else {
            return Ok(false);
        };

        if !inflight.scope.matches_ack(&user_id, device_id) {
            self.inflight.insert(message_id, inflight);
            return Ok(false);
        }

        let acked = inflight.pending_ack.ack().await?;
        if acked {
            observability::observe_message_broker_acked();
        }
        Ok(acked)
    }

    /// No per-connection state: unacked envelopes are released when the
    /// scope's pump exits.
    fn on_disconnect(&self, _connection_id: ConnectionId) {}

    /// Push-trigger for the recipient's devices that have no live session.
    /// Called for every envelope the pump receives, redeliveries included,
    /// before routing; the publish path fires its own trigger as well, since
    /// the pump only runs while the scope is online.
    ///
    /// - Device-scope message: push only when the target device has no session.
    /// - Account-scope message: enumerate every registered push token for the
    ///   user and push to each device whose `device_id` is not currently online.
    ///
    /// Account-only sessions (no `device_id`) cannot be matched against push
    /// tokens and do not suppress any pushes.
    fn trigger_push_for_offline(
        &self,
        user: UserId,
        target_device: Option<DeviceId>,
        priority: Option<MessagePriority>,
        wake_hint: Option<WakeHint>,
        online_devices: &[DeviceId],
    ) {
        match target_device {
            Some(device) => {
                if !online_devices.contains(&device) {
                    self.push_scheduler
                        .on_undelivered(user, device, priority, wake_hint);
                }
            }
            None => match self.push_tokens.list_user(&user) {
                Ok(devices) => {
                    for stored in devices {
                        if !online_devices.contains(&stored.device_id) {
                            self.push_scheduler.on_undelivered(
                                user,
                                stored.device_id,
                                priority,
                                wake_hint,
                            );
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        user = %hex::encode(user),
                        error = %err,
                        "failed to list push tokens for account-scope push fan-out"
                    );
                }
            },
        }
    }
}

fn scope_subject(user_id: UserId, device_id: Option<DeviceId>) -> String {
    match device_id {
        Some(device_id) => {
            format!(
                "{ACCOUNT_SUBJECT_PREFIX}.{}.device.{device_id}",
                hex::encode(user_id)
            )
        }
        None => format!("{ACCOUNT_SUBJECT_PREFIX}.{}", hex::encode(user_id)),
    }
}

fn encode_broker_message(payload: BrokerPayload) -> Vec<u8> {
    BrokerMessage {
        message_id: payload.message_id,
        sender_user_id: payload.sender_user_id.to_vec(),
        sender_device_id: encode_device_id(payload.sender_device_id),
        recipient_user_id: payload.recipient_user_id.to_vec(),
        recipient_device_id: encode_device_id(payload.recipient_device_id),
        body: payload.body,
        created_at: payload.created_at,
        priority: MessagePriority::to_wire(payload.priority),
        wake_hint: WakeHint::to_wire(payload.wake_hint),
        ttl_seconds: payload.ttl_seconds,
    }
    .encode_to_vec()
}

fn decode_broker_message(bytes: &[u8]) -> Result<BrokerPayload> {
    let message = BrokerMessage::decode(bytes).context("decode broker message")?;
    Ok(BrokerPayload {
        message_id: message.message_id,
        sender_user_id: data_to_fixed(&message.sender_user_id)?,
        sender_device_id: decode_device_id(message.sender_device_id)?,
        recipient_user_id: data_to_fixed(&message.recipient_user_id)?,
        recipient_device_id: decode_device_id(message.recipient_device_id)?,
        body: message.body,
        created_at: message.created_at,
        // Конверт от более нового узла с незнакомым приоритетом или
        // wake-значением — не ошибка, просто «обычное сообщение».
        priority: MessagePriority::from_wire(message.priority),
        wake_hint: WakeHint::from_wire(message.wake_hint),
        ttl_seconds: message.ttl_seconds,
    })
}

fn data_to_fixed(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", data.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(data);
    Ok(out)
}

fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::{
        BrokerPayload, Config, DeliveryBackend, DeliveryBackendKind, DeliveryScope,
        JetStreamBackend, MessagePriority, SledBackend, WakeHint, decode_broker_message,
        encode_broker_message, scope_subject,
    };
    use crate::state::registry::{ConnRegistry, OutboundFrame};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn user(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Пуши в этих тестах не участвуют, но конфиг обязателен по сигнатуре.
    fn push_off() -> crate::config::PushConfig {
        crate::config::PushConfig {
            enabled: false,
            gateway_url: None,
            gateway_timeout: Duration::from_secs(10),
            fcm_project_id: String::new(),
            fcm_service_account_path: String::new(),
            http_timeout: Duration::from_secs(5),
            min_gap_high: Duration::from_secs(0),
            min_gap_medium: Duration::from_secs(10),
            min_gap_low: Duration::from_secs(60),
            min_gap_none: Duration::from_secs(120),
            wake_on_unspecified: true,
            burst_high: 1,
            burst_medium: 3,
            burst_low: 8,
            burst_none: 15,
            suppress_initial: Duration::from_secs(30),
            suppress_max: Duration::from_secs(3600),
            channel_capacity: 64,
            apns: None,
            ring_cooldown: Duration::from_secs(3),
        }
    }

    fn temp_storage(label: &str) -> (crate::state::storage::Storage, String) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("trust_message_tcp_delivery_{label}_{nanos}"));
        let path = path.to_string_lossy().into_owned();
        let storage = crate::state::storage::Storage::open(
            &path,
            crate::config::RetentionPolicy::KeepFor(Duration::from_secs(3600)),
            crate::config::RetentionPolicy::KeepFor(Duration::from_secs(3600)),
        )
        .unwrap();
        (storage, path)
    }

    /// Прямой бэкенд подтверждений не ведёт: сообщение считается
    /// доставленным в момент записи в сокет, и подтверждать нечего.
    /// Клиент, приславший `DeliveryAck` в sled-режиме, не должен получить
    /// ни ошибку, ни ложное «подтверждено».
    #[tokio::test]
    async fn sled_backend_has_nothing_to_acknowledge() {
        let (storage, path) = temp_storage("sled_ack");
        let backend = DeliveryBackend::Sled(SledBackend::new(storage));

        assert!(!backend.is_jetstream());
        assert!(backend.storage().is_some());
        assert!(!backend.ack_delivery([1u8; 32], Some(3), 42).await.unwrap());
        // Отключение сессии для прямого бэкенда — не событие: насосов,
        // которые надо было бы гасить, у него нет.
        backend.on_disconnect(7);

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Брокерный бэкенд не поднимается без брокера, и это правильно:
    /// молча стартовать в режиме, где доставка идёт через поток, но потока
    /// нет, значило бы принимать конверты, которым некуда деться.
    #[tokio::test]
    async fn jetstream_backend_refuses_to_start_without_a_broker() {
        let (storage, path) = temp_storage("jetstream_down");
        let cfg = Config {
            queue_addressing_enabled: false,
            device_cert_max_ttl: Duration::from_secs(30 * 24 * 3600),
            bind_addr: "127.0.0.1:0".to_string(),
            storage_path: path.clone(),
            node_identity_key: None,
            server_config_ttl: Duration::from_secs(3600),
            advertised_address: None,
            handshake_timeout: Duration::from_secs(1),
            noise_allow_tofu: true,
            max_frame_len: 1024,
            metrics: crate::config::MetricsConfig {
                enabled: false,
                addr: String::new(),
            },
            deleted_messages_retention: crate::config::RetentionPolicy::Disabled,
            offline_messages_retention: crate::config::RetentionPolicy::Disabled,
            delivery: crate::config::DeliveryConfig {
                backend: DeliveryBackendKind::JetStream,
                // Порт, на котором заведомо никого нет.
                nats_url: "nats://127.0.0.1:1".to_string(),
                nats_stream_name: "test".to_string(),
                nats_ack_wait: Duration::from_secs(30),
                nats_consumer_inactive_threshold: Duration::from_secs(86_400),
                nats_stream_max_age: Duration::from_secs(3600),
                nats_stream_max_bytes: 1024,
                nats_publish_timeout: Duration::from_millis(500),
            },
            push: push_off(),
            limits: crate::config::LimitsConfig::default(),
        };

        let push_tokens = storage.push_token_store().unwrap();
        let scheduler = crate::push::PushScheduler::start(
            push_off(),
            Arc::new(crate::push::MockTransport::always_ok()),
            Arc::new(crate::push::InMemoryTokenStore::default()),
            Arc::new(crate::push::NoopStatePersistence),
        );

        let err = DeliveryBackend::from_config(&cfg, storage, push_tokens, scheduler)
            .await
            .map(|_| ())
            .expect_err("брокерный бэкенд не должен подниматься без брокера");
        assert!(
            err.to_string().contains("failed to connect to NATS"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn scope_subjects_match_account_and_device_routes() {
        assert_eq!(
            scope_subject(user(1), None),
            format!("msg.user.{}", hex::encode(user(1)))
        );
        assert_eq!(
            scope_subject(user(2), Some(7)),
            format!("msg.user.{}.device.7", hex::encode(user(2)))
        );
    }

    /// Конверт, который нода разобрать не может, обязан быть отвергнут, а
    /// не прочитан как набор чужих полей: пул снимает такой конверт с
    /// потока, и «частично понятый» конверт ушёл бы получателю мусором.
    ///
    /// Пустой payload — валидный protobuf (все поля по умолчанию), но
    /// бессмысленный конверт: 32-байтовых идентификаторов в нём нет, и
    /// именно на этом он отсекается.
    #[test]
    fn undecodable_envelope_is_rejected_not_misread() {
        // Нулевой тег невалиден в protobuf всегда.
        assert!(decode_broker_message(&[0x00, 0x00, 0x00, 0x00]).is_err());
        assert!(decode_broker_message(&[]).is_err());
        assert!(decode_broker_message(b"not a protobuf message at all").is_err());
    }

    #[test]
    fn broker_payload_roundtrips() {
        let payload = BrokerPayload {
            message_id: 99,
            sender_user_id: user(1),
            sender_device_id: Some(7),
            recipient_user_id: user(2),
            recipient_device_id: None,
            body: b"hello".to_vec(),
            created_at: 123,
            priority: Some(MessagePriority::High),
            wake_hint: Some(WakeHint::IncomingCall),
            ttl_seconds: 86_400,
        };

        let encoded = encode_broker_message(payload.clone());
        let decoded = decode_broker_message(&encoded).unwrap();

        assert_eq!(decoded.message_id, payload.message_id);
        assert_eq!(decoded.sender_user_id, payload.sender_user_id);
        assert_eq!(decoded.sender_device_id, payload.sender_device_id);
        assert_eq!(decoded.recipient_user_id, payload.recipient_user_id);
        assert_eq!(decoded.recipient_device_id, payload.recipient_device_id);
        assert_eq!(decoded.body, payload.body);
        assert_eq!(decoded.created_at, payload.created_at);
        assert_eq!(decoded.priority, payload.priority);
        assert_eq!(decoded.wake_hint, payload.wake_hint);
        assert_eq!(decoded.ttl_seconds, payload.ttl_seconds);
    }

    #[test]
    fn delivery_scope_validates_ack_scope() {
        assert!(DeliveryScope::Account { user_id: user(3) }.matches_ack(&user(3), None));
        assert!(DeliveryScope::Account { user_id: user(3) }.matches_ack(&user(3), Some(4)));
        assert!(
            DeliveryScope::Device {
                user_id: user(4),
                device_id: 9,
            }
            .matches_ack(&user(4), Some(9))
        );
        assert!(
            !DeliveryScope::Device {
                user_id: user(4),
                device_id: 9,
            }
            .matches_ack(&user(4), Some(10))
        );
    }

    /// Пул умер — сессии, которые он обслуживал, обязаны об этом узнать.
    /// Молчание здесь — худший из отказных режимов: клиент считает себя
    /// подключённым и просто перестаёт получать сообщения.
    #[tokio::test]
    async fn dead_pump_tells_its_sessions_to_reconnect() {
        let registry = ConnRegistry::default();
        let (tx_device, mut rx_device) = mpsc::channel::<OutboundFrame>(4);
        let (tx_other, mut rx_other) = mpsc::channel::<OutboundFrame>(4);
        registry.insert(user(1), Some(7), tx_device);
        registry.insert(user(1), Some(8), tx_other);

        JetStreamBackend::close_scope_sessions(
            DeliveryScope::Device {
                user_id: user(1),
                device_id: 7,
            },
            "device",
            &registry,
        )
        .await;

        let notice = rx_device
            .try_recv()
            .expect("сессия должна получить извещение");
        assert!(
            notice.close_after_send,
            "извещение без разрыва оставит клиента в том же неведении"
        );
        let frame = crate::net::framing::decode_frame(&notice.bytes).unwrap();
        match frame.payload {
            Some(crate::proto::trustmessage::wire::v1::frame::Payload::AuthError(err)) => {
                assert_eq!(err.code, 503);
            }
            other => panic!("ожидался AuthError, получено {other:?}"),
        }

        // Пул области видимости устройства не трогает чужие сессии того же
        // пользователя: их обслуживают другие пулы, и они живы.
        assert!(rx_other.try_recv().is_err());
    }

    /// Область видимости аккаунта закрывает все сессии пользователя: их
    /// входящие шли через один и тот же пул.
    #[tokio::test]
    async fn dead_account_pump_closes_every_session_of_the_user() {
        let registry = ConnRegistry::default();
        let (tx_a, mut rx_a) = mpsc::channel::<OutboundFrame>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<OutboundFrame>(4);
        let (tx_stranger, mut rx_stranger) = mpsc::channel::<OutboundFrame>(4);
        registry.insert(user(2), Some(1), tx_a);
        registry.insert(user(2), None, tx_b);
        registry.insert(user(3), Some(1), tx_stranger);

        JetStreamBackend::close_scope_sessions(
            DeliveryScope::Account { user_id: user(2) },
            "account",
            &registry,
        )
        .await;

        assert!(rx_a.try_recv().is_ok());
        assert!(rx_b.try_recv().is_ok());
        assert!(rx_stranger.try_recv().is_err());
    }

    /// Сессия, уже отвалившаяся к моменту смерти пула, вычищается из
    /// реестра, а не остаётся в нём маршрутом в никуда.
    #[tokio::test]
    async fn closing_a_dead_channel_evicts_it_from_the_registry() {
        let registry = ConnRegistry::default();
        let (tx, rx) = mpsc::channel::<OutboundFrame>(1);
        registry.insert(user(4), Some(2), tx);
        drop(rx);

        JetStreamBackend::close_scope_sessions(
            DeliveryScope::Account { user_id: user(4) },
            "account",
            &registry,
        )
        .await;

        assert!(!registry.has_user(&user(4)));
    }
}
