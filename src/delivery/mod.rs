use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use async_nats::connection::State as ConnectionState;
use async_nats::jetstream;
use async_nats::jetstream::AckKind;
use async_nats::jetstream::consumer;
use async_nats::jetstream::consumer::pull;
use async_nats::jetstream::consumer::pull::MessagesErrorKind;
use async_nats::jetstream::response::Response;
use async_nats::jetstream::stream;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use futures_util::StreamExt;
use prost::Message;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::broker::BrokerMessage;
use crate::config::{Config, DeliveryBackendKind};
use crate::domain::priority::MessagePriority;
use crate::domain::reject::SendRejectReason;
use crate::domain::wake::WakeHint;
use crate::net::framing::{decode_device_id, encode_auth_error, encode_device_id, encode_incoming};
use crate::observability;
use crate::push::PushScheduler;
use crate::state::push_tokens::PushTokenStore;
use crate::state::registry::{
    ConnRegistry, ConnectionId, DeviceId, OutboundFrame, RoutedConnection, UserId,
};
use crate::state::storage::Storage;

const ACCOUNT_SUBJECT_PREFIX: &str = "msg.user";
const USER_PUMP_POLL_TIMEOUT: Duration = Duration::from_secs(1);
/// Сколько ждать места в канале сессии, чтобы сообщить ей о смерти пула.
/// Дальше ждать бессмысленно: канал переполнен ровно тогда, когда задача
/// сессии сама застряла.
const CLOSE_NOTICE_TIMEOUT: Duration = Duration::from_secs(1);
/// Сколько пул ждёт ответа брокера на проверку consumer'а после ошибки
/// pull-подписки. `MissingHeartbeat` приходит после 30 с без heartbeat'ов
/// (два интервала по 15 с у async-nats); брокер, который всё это время
/// держал соединение, но молчал, получает ещё столько же на ответ, прежде
/// чем пул сочтёт его мёртвым. Мёртвый процесс брокера сюда не доходит:
/// соединение с ним уже разорвано, и это видно без запроса.
const PULL_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Сколько временных ошибок pull-подписки подряд, без единого конверта
/// между ними, пул терпит. Брокер и consumer при этом живы, а подписка не
/// оживает — дальше её чинит только новый пул: сессии получают 503 и
/// переподключаются.
const MAX_TRANSIENT_PULL_ERRORS: u32 = 5;

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

/// Отказ брокера принять конверт.
///
/// Переполнение отделено от остальных отказов: это не авария ноды, а
/// штатный ответ «места нет», и отправитель должен увидеть его как `FULL`,
/// а не как `INTERNAL`.
#[derive(Debug)]
pub enum PublishError {
    /// Ящик получателя (`max_messages_per_subject`) или поток целиком
    /// (`max_bytes`) заполнен. Поток работает по `DiscardPolicy::New`:
    /// отказ получает новый конверт, уже лежащие не трогаются.
    Full(anyhow::Error),
    /// Брокер недоступен, не ответил за `NATS_PUBLISH_TIMEOUT_MS` или
    /// отказал по иной причине.
    Failed(anyhow::Error),
}

impl PublishError {
    /// Причина отказа, которую увидит отправитель в `SendAck`.
    pub fn reject_reason(&self) -> SendRejectReason {
        match self {
            Self::Full(_) => SendRejectReason::Full,
            Self::Failed(_) => SendRejectReason::Internal,
        }
    }

    /// Разобрать отказ клиента NATS: переполнение потока или всё прочее.
    fn from_nats(err: jetstream::context::PublishError, stage: &'static str) -> Self {
        if is_stream_limit_rejection(&err) {
            Self::Full(anyhow::Error::new(err).context("JetStream stream limit reached"))
        } else {
            Self::Failed(anyhow::Error::new(err).context(stage))
        }
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(err) | Self::Failed(err) => write!(f, "{err:#}"),
        }
    }
}

impl std::error::Error for PublishError {}

/// JetStream отказал в записи из-за лимита потока.
///
/// На переполнение под `DiscardPolicy::New` nats-server отвечает кодом
/// 10077 (`JSStreamStoreFailedErr`) с текстом ошибки хранилища. Тот же код
/// несут и настоящие сбои записи (диск, I/O), поэтому лимит опознаётся по
/// тексту: `maximum messages per subject exceeded`, `maximum bytes
/// exceeded`, `maximum messages exceeded`. Поле описания у клиента
/// закрытое, текст доступен только через `Display`.
fn is_stream_limit_rejection(err: &jetstream::context::PublishError) -> bool {
    std::error::Error::source(err)
        .and_then(|source| source.downcast_ref::<jetstream::Error>())
        .is_some_and(is_limit_error)
}

fn is_limit_error(err: &jetstream::Error) -> bool {
    if err.error_code() != jetstream::ErrorCode::STREAM_STORE_FAILED {
        return false;
    }
    let text = err.to_string();
    text.starts_with("maximum messages") || text.starts_with("maximum bytes")
}

/// Ошибка pull-подписки, после которой ждать от неё конвертов бесполезно.
///
/// На `ConsumerDeleted` и `PushBasedConsumer` async-nats сам завершает
/// подписку. Остальные подписку не завершают и проходят сами, если брокер
/// жив: `MissingHeartbeat` (heartbeat'а не было дольше двух интервалов —
/// брокер замолчал или пул сам не опрашивал подписку, стоя на
/// переполненном канале сессии), `Pull` (не ушёл pull-запрос),
/// `NoResponders` (на pull-запрос не ответил ни один сервер JetStream),
/// `Other` (неожиданный служебный ответ брокера).
fn pull_error_is_fatal(kind: MessagesErrorKind) -> bool {
    match kind {
        MessagesErrorKind::ConsumerDeleted | MessagesErrorKind::PushBasedConsumer => true,
        MessagesErrorKind::MissingHeartbeat
        | MessagesErrorKind::Pull
        | MessagesErrorKind::NoResponders
        | MessagesErrorKind::Other => false,
    }
}

/// Будить ли офлайн-устройства пушем за конверт, вынутый пулом.
///
/// Будит публикация: она триггерит пуш в момент приёма конверта, с его
/// wake-подсказкой. Пул добавляет пуш только за обычный конверт и только
/// при первой выдаче — на случай, когда устройство ушло офлайн между
/// публикацией и доставкой. Передоставка не будит никого: это тот же
/// конверт, о котором устройство уже знает. Звонковый конверт пул не будит
/// вовсе: давний OFFER, вынутый из потока при подключении, звонить не
/// должен, а свежий уже прозвонил при публикации.
fn pump_should_push(redelivered: bool, wake_hint: Option<WakeHint>) -> bool {
    !redelivered && wake_hint.is_none()
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

    /// Обратное к [`Self::durable_name`]: чей ящик читает durable-consumer.
    /// `None` — consumer заведён не нодой.
    fn from_durable_name(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("user_")?;
        let (user_hex, tail) = rest.split_at_checked(64)?;
        let mut user_id = [0u8; 32];
        hex::decode_to_slice(user_hex, &mut user_id).ok()?;
        if tail.is_empty() {
            return Some(Self::Account { user_id });
        }
        let device_id = tail.strip_prefix("_device_")?.parse().ok()?;
        Some(Self::Device { user_id, device_id })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Account { .. } => "account",
            Self::Device { .. } => "device",
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

    /// Сессии, которые обслуживает пул этой области видимости.
    fn sessions(self, registry: &ConnRegistry) -> Vec<RoutedConnection> {
        match self {
            Self::Account { user_id } => registry.route_targets(&user_id, None),
            Self::Device { user_id, device_id } => {
                registry.route_targets(&user_id, Some(device_id))
            }
        }
    }
}

/// Живой пул области видимости. Поколение отличает его от пула, поднятого
/// на ту же область позже: запись в карте пулов и конверты в полёте
/// принадлежат ровно одному поколению.
struct PumpSlot {
    generation: u64,
    handle: JoinHandle<()>,
}

/// Исход попытки поднять пул.
#[derive(Debug, PartialEq, Eq)]
enum PumpStart {
    /// У области видимости уже есть живой пул.
    Running,
    /// Поднят новый пул; `revived` — на месте завершившегося, который не
    /// снял себя с учёта (паника, отмена).
    Spawned { revived: bool },
}

/// Исход попытки пула снять себя с учёта.
#[derive(Debug, PartialEq, Eq)]
enum Retire {
    /// Запись снята: новые сессии этой области поднимут новый пул.
    Retired,
    /// Пул ещё нужен — область видимости снова онлайн.
    Kept,
    /// Запись принадлежит другому поколению или её нет: этот пул лишний.
    NotOwner,
}

/// Учёт пулов: не больше одного живого пула на область видимости, и запись
/// живёт ровно столько, сколько пул.
///
/// Все решения «поднять» и «снять» принимаются под блокировкой записи
/// карты. Отсюда два свойства. Два одновременных подключения одной области
/// не поднимут два пула. И сессия не останется без пула: она
/// регистрируется в реестре до вызова `start`, поэтому уходящий пул либо
/// видит её при проверке и остаётся работать, либо уже снял запись — и
/// `start` поднимает новый.
#[derive(Default)]
struct PumpTable {
    slots: DashMap<String, PumpSlot>,
    generations: AtomicU64,
}

impl PumpTable {
    /// Поднять пул, если живого нет. `spawn` получает поколение нового пула
    /// и вызывается под блокировкой записи — он обязан только запустить
    /// задачу, не обращаясь к этой карте.
    fn start(&self, key: String, spawn: impl FnOnce(u64) -> JoinHandle<()>) -> PumpStart {
        match self.slots.entry(key) {
            Entry::Occupied(entry) if !entry.get().handle.is_finished() => PumpStart::Running,
            Entry::Occupied(mut entry) => {
                let generation = self.next_generation();
                entry.insert(PumpSlot {
                    generation,
                    handle: spawn(generation),
                });
                PumpStart::Spawned { revived: true }
            }
            Entry::Vacant(entry) => {
                let generation = self.next_generation();
                entry.insert(PumpSlot {
                    generation,
                    handle: spawn(generation),
                });
                PumpStart::Spawned { revived: false }
            }
        }
    }

    /// Снять пул `generation` с учёта, если `keep()` не просит его оставить.
    /// `keep` вызывается под блокировкой записи.
    fn retire_unless(&self, key: &str, generation: u64, keep: impl FnOnce() -> bool) -> Retire {
        match self.slots.entry(key.to_string()) {
            Entry::Occupied(entry) if entry.get().generation == generation => {
                if keep() {
                    return Retire::Kept;
                }
                entry.remove();
                Retire::Retired
            }
            _ => Retire::NotOwner,
        }
    }

    /// Снять умерший пул `generation` и под той же блокировкой снять
    /// `snapshot` — например, список сессий, которым надо сообщить о его
    /// смерти. Сессия, пришедшая позже, в снимок не попадёт и поднимет
    /// свой пул. `None` — запись уже не этого пула.
    fn retire_with<T>(
        &self,
        key: &str,
        generation: u64,
        snapshot: impl FnOnce() -> T,
    ) -> Option<T> {
        match self.slots.entry(key.to_string()) {
            Entry::Occupied(entry) if entry.get().generation == generation => {
                let taken = snapshot();
                entry.remove();
                Some(taken)
            }
            _ => None,
        }
    }

    fn next_generation(&self) -> u64 {
        self.generations.fetch_add(1, Ordering::Relaxed)
    }
}

struct PendingBrokerAck {
    message: Mutex<Option<jetstream::Message>>,
    /// Номер записи в потоке: по нему подтверждённый конверт удаляется.
    stream_sequence: Option<u64>,
}

impl PendingBrokerAck {
    fn new(message: jetstream::Message) -> Self {
        let stream_sequence = message.info().ok().map(|info| info.stream_sequence);
        Self {
            message: Mutex::new(Some(message)),
            stream_sequence,
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
    /// Поколение пула, отдавшего конверт: возвращает потоку при выходе
    /// только свои конверты, а не выданные пулом, поднятым ему на смену.
    generation: u64,
    pending_ack: Arc<PendingBrokerAck>,
}

/// Забрать конверт в полёте под подтверждение — только если подтверждает
/// получатель. Проверка и удаление атомарны: чужой `DeliveryAck` не
/// вынимает запись даже на мгновение, и подтверждение настоящего
/// получателя, пришедшее в тот же момент, не теряется.
fn claim_inflight(
    inflight: &DashMap<u64, InflightDelivery>,
    user_id: &UserId,
    device_id: Option<DeviceId>,
    message_id: u64,
) -> Option<InflightDelivery> {
    inflight
        .remove_if(&message_id, |_, delivery| {
            delivery.scope.matches_ack(user_id, device_id)
        })
        .map(|(_, delivery)| delivery)
}

#[derive(Clone)]
pub struct JetStreamBackend {
    client: async_nats::Client,
    context: jetstream::Context,
    stream_name: String,
    ack_wait: Duration,
    consumer_inactive_threshold: Duration,
    stream_max_age: Duration,
    stream_max_bytes: i64,
    max_messages_per_subject: i64,
    publish_timeout: Duration,
    inflight: Arc<DashMap<u64, InflightDelivery>>,
    pumps: Arc<PumpTable>,
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
                let context = jetstream::new(client.clone());
                let backend = Arc::new(JetStreamBackend {
                    client,
                    context,
                    stream_name: cfg.delivery.nats_stream_name.clone(),
                    ack_wait: cfg.delivery.nats_ack_wait,
                    consumer_inactive_threshold: cfg.delivery.nats_consumer_inactive_threshold,
                    stream_max_age: cfg.delivery.nats_stream_max_age,
                    stream_max_bytes: cfg.delivery.nats_stream_max_bytes,
                    max_messages_per_subject: cfg.delivery.nats_max_msgs_per_subject,
                    publish_timeout: cfg.delivery.nats_publish_timeout,
                    inflight: Arc::new(DashMap::new()),
                    pumps: Arc::new(PumpTable::default()),
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
    ) -> Result<PublishedMessage, PublishError> {
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
    /// Политика лимитов потока поверх `config`; остальные поля не трогает.
    ///
    /// `DiscardPolicy::New`: переполненный поток отказывает новому конверту,
    /// а не вытесняет самые старые — иначе любой отправитель, заполнив
    /// поток, стирал бы недоставленные конверты всех пользователей. Ящик
    /// получателя (`msg.user.<id>` и каждый `msg.user.<id>.device.<n>`)
    /// ограничен отдельно (`discard_new_per_subject`), чтобы заполнить
    /// поток целиком одним ящиком было нельзя. Лимиты меряют только
    /// недоставленное: подтверждённый конверт нода из потока удаляет.
    fn with_limits(&self, config: stream::Config, max_messages_per_subject: i64) -> stream::Config {
        stream::Config {
            max_age: self.stream_max_age,
            max_bytes: self.stream_max_bytes,
            max_messages_per_subject,
            discard: stream::DiscardPolicy::New,
            discard_new_per_subject: true,
            ..config
        }
    }

    /// Конфиг для **создания** стрима с нуля. Безлимитные поля выставлены
    /// явными `-1`: `Config::default()` заполняет их нулями, а ноль для
    /// части лимитов JetStream трактует иначе, чем «без ограничения».
    fn new_stream_config(&self) -> stream::Config {
        self.with_limits(
            stream::Config {
                name: self.stream_name.clone(),
                subjects: vec!["msg.user.*".to_string(), "msg.user.*.device.*".to_string()],
                storage: stream::StorageType::File,
                retention: stream::RetentionPolicy::Limits,
                max_messages: -1,
                max_consumers: -1,
                max_message_size: -1,
                num_replicas: 1,
                ..Default::default()
            },
            self.max_messages_per_subject,
        )
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

        // Правим только поля лимитов поверх фактического конфига, а не
        // отправляем свой целиком: иначе поля, которых мы не касаемся
        // (duplicate_window, num_replicas, allow_direct, metadata...), уехали
        // бы в дефолты. `retention` не трогаем — JetStream не даёт менять
        // его на живом стриме.
        let current = stream
            .info()
            .await
            .with_context(|| format!("failed to read stream `{}` info", self.stream_name))?
            .config
            .clone();

        // Поток, живший по `DiscardPolicy::Old`, хранит всё подтверждённое
        // до `max_age` и обычно заполнен до `max_bytes`. Переключённый на
        // `New` как есть, он отказывал бы всем новым конвертам, пока старые
        // не истекут, — поэтому сначала уходит уже доставленное.
        if current.discard != stream::DiscardPolicy::New {
            let purged = self.purge_acknowledged(&stream).await?;
            info!(
                stream = %self.stream_name,
                purged,
                "removed already acknowledged envelopes before switching the stream to discard-new"
            );
        }

        let max_messages_per_subject = self
            .safe_max_messages_per_subject(&stream, current.max_messages_per_subject)
            .await?;
        let wanted = self.with_limits(current.clone(), max_messages_per_subject);
        if wanted == current {
            return Ok(());
        }

        info!(
            stream = %self.stream_name,
            old_max_age_secs = current.max_age.as_secs(),
            new_max_age_secs = wanted.max_age.as_secs(),
            old_max_bytes = current.max_bytes,
            new_max_bytes = wanted.max_bytes,
            old_max_msgs_per_subject = current.max_messages_per_subject,
            new_max_msgs_per_subject = wanted.max_messages_per_subject,
            old_discard = ?current.discard,
            old_discard_new_per_subject = current.discard_new_per_subject,
            "applying stream retention limits"
        );

        self.context
            .update_stream(wanted)
            .await
            .with_context(|| format!("failed to update stream `{}` limits", self.stream_name))?;

        Ok(())
    }

    /// Снять с потока конверты, уже подтверждённые получателями.
    ///
    /// При `retention: limits` подтверждение записи не удаляет. Ящик
    /// читает ровно один durable-consumer ноды, и всё, что не выше его
    /// `ack_floor`, получатель уже подтвердил. Чужие consumer'ы (например,
    /// отладочный с широким фильтром) не учитываются: их подтверждение
    /// ничего не говорит о том, видел ли конверт получатель.
    async fn purge_acknowledged(&self, stream: &stream::Stream) -> Result<u64> {
        let mut consumers = stream.consumers();
        let mut purged = 0u64;
        while let Some(info) = consumers.next().await {
            let info = info.with_context(|| {
                format!("failed to list consumers of stream `{}`", self.stream_name)
            })?;
            let Some(scope) = DeliveryScope::from_durable_name(&info.name) else {
                continue;
            };
            if info.config.filter_subject != scope.subject() {
                continue;
            }
            let acked_up_to = info.ack_floor.stream_sequence;
            if acked_up_to == 0 {
                continue;
            }
            let response = stream
                .purge()
                .filter(scope.subject())
                .sequence(acked_up_to + 1)
                .await
                .with_context(|| {
                    format!("failed to purge acknowledged envelopes of `{}`", info.name)
                })?;
            purged += response.purged;
        }
        Ok(purged)
    }

    /// Потолок ящика, который можно выставить, не потеряв уже лежащее.
    ///
    /// JetStream приводит ящики к `max_messages_per_subject`, удаляя самые
    /// старые записи: сразу, если потолок снижается, и при следующем
    /// рестарте брокера, если потолка не было. Поэтому ящик глубже
    /// `NATS_MAX_MSGS_PER_SUBJECT` задаёт потолок по себе, пока не
    /// разгрузится, — каждый старт ноды сверяет это заново. Поднятие
    /// потолка ничего не удаляет и скана не требует.
    async fn safe_max_messages_per_subject(
        &self,
        stream: &stream::Stream,
        current: i64,
    ) -> Result<i64> {
        let wanted = self.max_messages_per_subject;
        if current > 0 && current <= wanted {
            return Ok(wanted);
        }

        let mut subjects = stream
            .info_with_subjects(">")
            .await
            .with_context(|| format!("failed to list subjects of stream `{}`", self.stream_name))?;
        let mut deepest = 0usize;
        while let Some(entry) = subjects.next().await {
            let (_, count) = entry.with_context(|| {
                format!("failed to list subjects of stream `{}`", self.stream_name)
            })?;
            deepest = deepest.max(count);
        }

        let deepest = i64::try_from(deepest).unwrap_or(i64::MAX);
        if deepest > wanted {
            warn!(
                stream = %self.stream_name,
                configured = wanted,
                deepest,
                "a mailbox already holds more envelopes than NATS_MAX_MSGS_PER_SUBJECT; \
                 the cap follows its depth until it drains, so JetStream drops nothing"
            );
            return Ok(deepest);
        }
        Ok(wanted)
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
    ) -> Result<(), PublishError> {
        let subject = scope_subject(recipient_user_id, recipient_device_id);
        let payload = encode_broker_message(BrokerPayload {
            message_id,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            body: body.to_vec(),
            created_at: unix_timestamp_secs().map_err(PublishError::Failed)?,
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
                .map_err(|err| {
                    PublishError::from_nats(err, "failed to publish message to JetStream")
                })?
                .await
                .map_err(|err| {
                    PublishError::from_nats(err, "failed to confirm JetStream publish")
                })?;
            Ok(())
        })
        .await;

        match published {
            Ok(result) => result,
            Err(_) => {
                observability::observe_broker_publish_timeout();
                Err(PublishError::Failed(anyhow!(
                    "JetStream publish timed out after {:?}",
                    self.publish_timeout
                )))
            }
        }
    }

    async fn start_scope_pump(&self, scope: DeliveryScope, registry: ConnRegistry) -> Result<()> {
        let key = scope.key();
        let backend = self.clone();
        let started = self.pumps.start(key.clone(), |generation| {
            tokio::spawn(async move { backend.run_pump_task(scope, generation, registry).await })
        });

        if started == (PumpStart::Spawned { revived: true }) {
            info!(scope = %key, "previous pump handle finished; revived");
            observability::observe_jetstream_pump_revived(scope.label());
        }

        Ok(())
    }

    /// Задача пула целиком: доставка, затем уборка за собой.
    async fn run_pump_task(&self, scope: DeliveryScope, generation: u64, registry: ConnRegistry) {
        let scope_label = scope.label();
        match self.run_scope_pump(scope, generation, &registry).await {
            // Штатный выход: область офлайн, и пул уже снял себя с учёта.
            // Сессии, пришедшие после этого, поднимут свой пул, — закрывать
            // некого.
            Ok(()) => self.release_inflight(scope, generation, scope_label).await,
            Err(err) => {
                // Снаружи упавший пул не виден — сессии остаются
                // установленными, — поэтому падение считается в метрике, а
                // не только пишется в лог.
                observability::observe_jetstream_pump_failed(scope_label);
                error!(scope = %scope.key(), error = %format!("{err:#}"), "delivery scope pump terminated with error");
                // Снять пул с учёта и запомнить его сессии одним шагом:
                // сессия, пришедшая после, поднимет новый пул и ложного
                // 503 не получит.
                let orphaned = self
                    .pumps
                    .retire_with(&scope.key(), generation, || scope.sessions(&registry));
                // Сначала вернуть потоку неподтверждённые конверты, затем
                // закрыть сессии, которые пул обслуживал: живая сессия без
                // пула осталась бы без входящих.
                self.release_inflight(scope, generation, scope_label).await;
                if let Some(sessions) = orphaned {
                    Self::close_sessions(scope, scope_label, &registry, sessions).await;
                }
            }
        }
    }

    /// Снять пул с учёта, если область видимости офлайн. Проверка повторяется
    /// под блокировкой записи пула (см. [`PumpTable`]): сессия, успевшая
    /// зарегистрироваться, оставляет пул работать. `true` — пулу пора выйти.
    fn retire_if_offline(
        &self,
        scope: DeliveryScope,
        generation: u64,
        registry: &ConnRegistry,
        reason: &'static str,
    ) -> bool {
        let retire = self
            .pumps
            .retire_unless(&scope.key(), generation, || scope.is_online(registry));
        if retire == Retire::Kept {
            return false;
        }
        info!(scope = %scope.key(), reason, "delivery pump exiting");
        true
    }

    /// `Ok(())` — пул вышел штатно и уже снят с учёта; `Err` — пул умер.
    async fn run_scope_pump(
        &self,
        scope: DeliveryScope,
        generation: u64,
        registry: &ConnRegistry,
    ) -> Result<()> {
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
        let mut consumer = stream
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

        let scope_label = scope.label();
        let mut transient_errors = 0u32;

        loop {
            if !scope.is_online(registry)
                && self.retire_if_offline(scope, generation, registry, "scope_offline")
            {
                return Ok(());
            }

            let message = match timeout(USER_PUMP_POLL_TIMEOUT, messages.next()).await {
                Err(_) => continue,
                Ok(None) => anyhow::bail!("JetStream consumer stream `{durable_name}` closed"),
                Ok(Some(Ok(message))) => {
                    transient_errors = 0;
                    message
                }
                Ok(Some(Err(err))) => {
                    transient_errors += 1;
                    self.survive_pull_error(scope, &mut consumer, err, transient_errors)
                        .await?;
                    continue;
                }
            };

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
            // навсегда (Term), удаляем и считаем в метрике.
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
                    let sequence = message.info().ok().map(|info| info.stream_sequence);
                    match message.ack_with(AckKind::Term).await {
                        Ok(()) => {
                            if let Some(sequence) = sequence {
                                self.forget_delivered(scope, sequence);
                            }
                        }
                        Err(term_err) => warn!(
                            scope = %scope.key(),
                            error = %term_err,
                            "failed to terminate an undecodable envelope; it will be redelivered"
                        ),
                    }
                    continue;
                }
            };

            debug!(
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

            if pump_should_push(redelivered, payload.wake_hint) {
                let online_device_ids: Vec<DeviceId> = route_targets
                    .iter()
                    .filter_map(|target| target.device_id)
                    .collect();
                self.trigger_push_for_offline(
                    payload.recipient_user_id,
                    payload.recipient_device_id,
                    payload.priority,
                    &online_device_ids,
                );
            }

            if route_targets.is_empty() {
                observability::observe_jetstream_no_targets(scope_label);
                if !scope.is_online(registry)
                    && self.retire_if_offline(
                        scope,
                        generation,
                        registry,
                        "scope_offline_before_push",
                    )
                {
                    return Ok(());
                }
                warn!(
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
                    generation,
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
                        warn!(
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
                self.inflight.remove_if(&payload.message_id, |_, entry| {
                    entry.generation == generation
                });
                warn!(
                    scope = %scope.key(),
                    message_id = payload.message_id,
                    target_count,
                    "envelope push failed for all targets; leaving un-acked for redelivery"
                );
                if !scope.is_online(registry)
                    && self.retire_if_offline(
                        scope,
                        generation,
                        registry,
                        "scope_offline_after_push_failure",
                    )
                {
                    return Ok(());
                }
                continue;
            }

            debug!(
                scope = %scope.key(),
                message_id = payload.message_id,
                delivered,
                target_count,
                "pump pushed envelope to peer mpsc"
            );

            observability::observe_message_pushed_online();
        }
    }

    /// Решить, переживёт ли пул ошибку pull-подписки. `Ok` — продолжать.
    ///
    /// Временная ошибка (см. [`pull_error_is_fatal`]) не повод закрывать
    /// сессии области видимости: подписка оживает сама, если жив брокер.
    /// Это и проверяется — соединением и запросом состояния consumer'а.
    /// Мёртвый брокер или исчезнувший consumer делают ошибку фатальной:
    /// пул выходит, сессии получают 503 и переподключаются к новому пулу.
    async fn survive_pull_error(
        &self,
        scope: DeliveryScope,
        consumer: &mut consumer::PullConsumer,
        err: pull::MessagesError,
        transient_errors: u32,
    ) -> Result<()> {
        if pull_error_is_fatal(err.kind()) {
            return Err(anyhow::Error::new(err).context("JetStream pull subscription terminated"));
        }
        if transient_errors > MAX_TRANSIENT_PULL_ERRORS {
            return Err(anyhow::Error::new(err).context(format!(
                "JetStream pull subscription failed {transient_errors} times in a row"
            )));
        }
        if self.client.connection_state() != ConnectionState::Connected {
            return Err(anyhow::Error::new(err)
                .context("JetStream pull subscription failed and the broker connection is down"));
        }
        match timeout(PULL_PROBE_TIMEOUT, consumer.info()).await {
            Ok(Ok(_)) => {
                warn!(
                    scope = %scope.key(),
                    error = %err,
                    transient_errors,
                    "transient JetStream pull error; the consumer is alive, the pump keeps running"
                );
                Ok(())
            }
            Ok(Err(probe)) => Err(anyhow::Error::new(err).context(format!(
                "JetStream pull subscription failed and the consumer is gone: {probe}"
            ))),
            Err(_) => Err(anyhow::Error::new(err).context(format!(
                "JetStream pull subscription failed and the broker did not answer within {PULL_PROBE_TIMEOUT:?}"
            ))),
        }
    }

    /// Пул области видимости больше не работает, и подтвердить отданные им
    /// конверты некому. Они возвращаются потоку сразу (`Nak`), а не по
    /// истечении `ack_wait`, чтобы переподключившийся получатель не ждал.
    /// Возвращаются только конверты этого поколения: выданные пулом,
    /// поднятым ему на смену, принадлежат тому.
    ///
    /// Потери нет в любом случае: неподтверждённый конверт будет выдан
    /// снова. Конверты, уже вытянутые в буфер pull-подписки, но не отданные
    /// сессиям, сюда не попадают и возвращаются по `ack_wait`.
    async fn release_inflight(
        &self,
        scope: DeliveryScope,
        generation: u64,
        scope_label: &'static str,
    ) {
        let owned: Vec<u64> = self
            .inflight
            .iter()
            .filter(|entry| entry.value().generation == generation)
            .map(|entry| *entry.key())
            .collect();

        let mut released = 0usize;
        for message_id in owned {
            let Some((_, inflight)) = self
                .inflight
                .remove_if(&message_id, |_, entry| entry.generation == generation)
            else {
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
                Err(err) => warn!(
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

    /// Пул области видимости умер, а его сессии остаются установленными:
    /// клиент считает себя подключённым, но входящих не получит. Нода
    /// сообщает об этом явно (`AuthError(503)` с закрытием сессии), и клиент
    /// уходит на переподключение — к рабочему пулу или к отказу 503 на
    /// входе.
    async fn close_sessions(
        scope: DeliveryScope,
        scope_label: &'static str,
        registry: &ConnRegistry,
        sessions: Vec<RoutedConnection>,
    ) {
        if sessions.is_empty() {
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
        for target in sessions {
            // Канал сессии мог переполниться — например, потому что её
            // задача сама застряла на публикации в мёртвый брокер. Ждать
            // её здесь бесконечно значит подвесить ещё и эту задачу.
            match timeout(CLOSE_NOTICE_TIMEOUT, target.tx.send(frame.clone())).await {
                Ok(Ok(())) => {
                    closed += 1;
                    observability::observe_pump_session_closed(scope_label);
                }
                Ok(Err(_)) => registry.remove(&scope.user_id(), target.id),
                Err(_) => warn!(
                    scope = %scope.key(),
                    connection_id = target.id,
                    "session channel is full; could not deliver the pump-failure notice"
                ),
            }
        }

        warn!(
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
        let Some(inflight) = claim_inflight(&self.inflight, &user_id, device_id, message_id) else {
            return Ok(false);
        };

        let acked = inflight.pending_ack.ack().await?;
        if acked {
            observability::observe_message_broker_acked();
            if let Some(sequence) = inflight.pending_ack.stream_sequence {
                self.forget_delivered(inflight.scope, sequence);
            }
        }
        Ok(acked)
    }

    /// Удалить из потока конверт, который больше никому не нужен:
    /// подтверждённый получателем или снятый как неразбираемый.
    ///
    /// При `retention: limits` подтверждение durable-consumer'а запись не
    /// удаляет: она лежала бы до `max_age`, занимая место в лимитах потока
    /// и ящика, и под `DiscardPolicy::New` из-за неё отказывали бы новым
    /// конвертам. Удаление идёт фоном — подтверждение уже состоялось, и
    /// сессия не ждёт ещё одного запроса к брокеру. Неудача ничего не
    /// теряет: запись уйдёт по `max_age`.
    fn forget_delivered(&self, scope: DeliveryScope, sequence: u64) {
        let context = self.context.clone();
        let stream_name = self.stream_name.clone();
        tokio::spawn(async move {
            if let Err(err) = delete_stream_message(&context, &stream_name, sequence).await {
                warn!(
                    scope = %scope.key(),
                    sequence,
                    error = %format!("{err:#}"),
                    "failed to delete a delivered envelope from the stream; it stays until max_age"
                );
            }
        });
    }

    /// No per-connection state: unacked envelopes are released when the
    /// scope's pump exits.
    fn on_disconnect(&self, _connection_id: ConnectionId) {}

    /// Push-trigger for the recipient's devices that have no live session,
    /// fired by the pump on the first delivery of a plain envelope (see
    /// [`pump_should_push`]). Never carries a wake hint: ringing is the
    /// publish path's job, done once when the envelope is accepted.
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
        online_devices: &[DeviceId],
    ) {
        match target_device {
            Some(device) => {
                if !online_devices.contains(&device) {
                    self.push_scheduler
                        .on_undelivered(user, device, priority, None);
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
                                None,
                            );
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        user = %hex::encode(user),
                        error = %err,
                        "failed to list push tokens for account-scope push fan-out"
                    );
                }
            },
        }
    }
}

/// Удалить запись из потока без затирания. Затирать нечего: тело
/// конверта зашифровано сквозным ключом, а затирание переписывает запись
/// случайными байтами целиком — для кусков медиа это вдвое больше записи
/// на диск. `Ok(false)` — записи уже нет (например, истекла по `max_age`).
async fn delete_stream_message(
    context: &jetstream::Context,
    stream_name: &str,
    sequence: u64,
) -> Result<bool> {
    let response: Response<stream::DeleteStatus> = context
        .request(
            format!("STREAM.MSG.DELETE.{stream_name}"),
            &serde_json::json!({ "seq": sequence, "no_erase": true }),
        )
        .await
        .context("delete request to JetStream failed")?;
    match response {
        Response::Ok(status) => Ok(status.success),
        Response::Err { error }
            if error.error_code() == jetstream::ErrorCode::SEQUENCE_NOT_FOUND =>
        {
            Ok(false)
        }
        Response::Err { error } => {
            Err(anyhow!("JetStream refused to delete the envelope: {error}"))
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
        InflightDelivery, JetStreamBackend, MessagePriority, PendingBrokerAck, PublishError,
        PumpStart, PumpTable, Retire, SledBackend, WakeHint, claim_inflight, decode_broker_message,
        encode_broker_message, is_limit_error, pull_error_is_fatal, pump_should_push,
        scope_subject,
    };
    use crate::domain::reject::SendRejectReason;
    use crate::state::registry::{ConnRegistry, OutboundFrame};
    use async_nats::jetstream;
    use async_nats::jetstream::consumer::pull::MessagesErrorKind;
    use dashmap::DashMap;
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
            send_concurrency: crate::push::DEFAULT_SEND_CONCURRENCY,
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
                nats_max_msgs_per_subject: 10_000,
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

        let scope = DeliveryScope::Device {
            user_id: user(1),
            device_id: 7,
        };
        JetStreamBackend::close_sessions(scope, "device", &registry, scope.sessions(&registry))
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

        let scope = DeliveryScope::Account { user_id: user(2) };
        JetStreamBackend::close_sessions(scope, "account", &registry, scope.sessions(&registry))
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

        let scope = DeliveryScope::Account { user_id: user(4) };
        JetStreamBackend::close_sessions(scope, "account", &registry, scope.sessions(&registry))
            .await;

        assert!(!registry.has_user(&user(4)));
    }

    /// Задача, которая не завершится сама: живой пул.
    fn live_task() -> tokio::task::JoinHandle<()> {
        tokio::spawn(std::future::pending())
    }

    async fn wait_finished(table: &PumpTable, key: &str) {
        while !table.slots.get(key).unwrap().handle.is_finished() {
            tokio::task::yield_now().await;
        }
    }

    /// Две сессии одной области видимости поднимают один пул, а не два.
    #[tokio::test]
    async fn pump_table_keeps_one_live_pump_per_scope() {
        let table = PumpTable::default();
        assert_eq!(
            table.start("k".into(), |_| live_task()),
            PumpStart::Spawned { revived: false }
        );
        assert_eq!(table.start("k".into(), |_| live_task()), PumpStart::Running);
        assert_eq!(table.slots.len(), 1);
    }

    /// Ушедший пул снимает свою запись: карта не растёт с каждым
    /// пользователем, когда-либо бывшим онлайн, и следующее подключение
    /// поднимает новый пул, а не «оживляет» старый.
    #[tokio::test]
    async fn retired_pump_leaves_no_entry_behind() {
        let table = PumpTable::default();
        let mut generation = None;
        table.start("k".into(), |g| {
            generation = Some(g);
            live_task()
        });

        assert_eq!(
            table.retire_unless("k", generation.unwrap(), || false),
            Retire::Retired
        );
        assert!(table.slots.is_empty());
        assert_eq!(
            table.start("k".into(), |_| live_task()),
            PumpStart::Spawned { revived: false }
        );
    }

    /// Сессия, зарегистрированная, пока пул решал выйти, оставляет его
    /// работать: иначе она полагалась бы на уходящий пул и осталась без
    /// входящих — или получила бы ложный 503 от его уборки.
    #[tokio::test]
    async fn session_arriving_during_retirement_keeps_the_pump() {
        let registry = ConnRegistry::default();
        let scope = DeliveryScope::Account { user_id: user(5) };
        let table = PumpTable::default();
        let mut generation = None;
        table.start(scope.key(), |g| {
            generation = Some(g);
            live_task()
        });
        let generation = generation.unwrap();

        // Пул увидел область офлайн и пошёл сниматься; сессия успела
        // зарегистрироваться (её `start` ещё впереди и увидит живой пул).
        let (tx, _rx) = mpsc::channel::<OutboundFrame>(1);
        registry.insert(user(5), Some(1), tx);
        assert_eq!(
            table.retire_unless(&scope.key(), generation, || scope.is_online(&registry)),
            Retire::Kept
        );
        assert_eq!(
            table.start(scope.key(), |_| live_task()),
            PumpStart::Running
        );
    }

    /// Пул, переживший свою запись (паника, отмена), не может снять пул,
    /// поднятый ему на смену, и не трогает его сессии.
    #[tokio::test]
    async fn stale_pump_cannot_evict_its_successor() {
        let table = PumpTable::default();
        let mut stale = None;
        table.start("k".into(), |g| {
            stale = Some(g);
            tokio::spawn(async {})
        });
        let stale = stale.unwrap();
        wait_finished(&table, "k").await;

        assert_eq!(
            table.start("k".into(), |_| live_task()),
            PumpStart::Spawned { revived: true }
        );
        assert_eq!(table.retire_unless("k", stale, || false), Retire::NotOwner);
        assert_eq!(table.retire_with("k", stale, || "sessions"), None);
        assert_eq!(table.slots.len(), 1);
        assert_ne!(table.slots.get("k").unwrap().generation, stale);
    }

    /// Умерший пул закрывает только те сессии, что были при нём. Сессия,
    /// пришедшая после, поднимает свой пул и ложного 503 не получает.
    #[tokio::test]
    async fn dead_pump_closes_only_the_sessions_it_served() {
        let registry = ConnRegistry::default();
        let scope = DeliveryScope::Account { user_id: user(6) };
        let table = PumpTable::default();
        let mut generation = None;
        table.start(scope.key(), |g| {
            generation = Some(g);
            live_task()
        });
        let (tx_old, _rx_old) = mpsc::channel::<OutboundFrame>(1);
        registry.insert(user(6), Some(1), tx_old);

        let orphaned = table
            .retire_with(&scope.key(), generation.unwrap(), || {
                scope.sessions(&registry)
            })
            .expect("запись принадлежит умершему пулу");

        let (tx_new, _rx_new) = mpsc::channel::<OutboundFrame>(1);
        registry.insert(user(6), Some(2), tx_new);
        assert_eq!(
            table.start(scope.key(), |_| live_task()),
            PumpStart::Spawned { revived: false }
        );
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].device_id, Some(1));
    }

    fn inflight_for(scope: DeliveryScope) -> InflightDelivery {
        InflightDelivery {
            scope,
            generation: 0,
            pending_ack: Arc::new(PendingBrokerAck {
                message: tokio::sync::Mutex::new(None),
                stream_sequence: None,
            }),
        }
    }

    /// Чужой `DeliveryAck` не снимает конверт: он остаётся в полёте и ждёт
    /// подтверждения получателя.
    #[test]
    fn foreign_delivery_ack_leaves_the_envelope_in_flight() {
        let bob = DeliveryScope::Device {
            user_id: user(7),
            device_id: 1,
        };
        let inflight = DashMap::new();
        inflight.insert(42, inflight_for(bob));

        assert!(claim_inflight(&inflight, &user(8), Some(1), 42).is_none());
        assert!(claim_inflight(&inflight, &user(7), Some(2), 42).is_none());
        assert!(inflight.contains_key(&42));

        assert!(claim_inflight(&inflight, &user(7), Some(1), 42).is_some());
        assert!(!inflight.contains_key(&42));
    }

    /// Поток чужих подтверждений не прячет конверт от получателя ни на
    /// мгновение: его подтверждение, пришедшее одновременно, всегда
    /// находит запись.
    #[test]
    fn concurrent_foreign_acks_never_hide_the_envelope_from_its_recipient() {
        let bob = DeliveryScope::Account { user_id: user(9) };
        let inflight = DashMap::new();
        for round in 0..2_000u64 {
            inflight.insert(round, inflight_for(bob));
            let claimed = std::thread::scope(|threads| {
                for _ in 0..3 {
                    threads.spawn(|| {
                        for _ in 0..50 {
                            assert!(claim_inflight(&inflight, &user(10), None, round).is_none());
                        }
                    });
                }
                threads
                    .spawn(|| claim_inflight(&inflight, &user(9), Some(3), round).is_some())
                    .join()
                    .unwrap()
            });
            assert!(
                claimed,
                "подтверждение получателя потерялось в раунде {round}"
            );
        }
    }

    fn jetstream_error(err_code: u64, description: &str) -> jetstream::Error {
        serde_json::from_value(serde_json::json!({
            "code": 503,
            "err_code": err_code,
            "description": description,
        }))
        .unwrap()
    }

    /// Переполнение — отказ `FULL`, а настоящий сбой записи с тем же кодом
    /// 10077 и нехватка места у самого брокера — `INTERNAL`: в первом
    /// случае ждать бесполезно, пока получатель не заберёт своё, во втором
    /// виновата нода.
    #[test]
    fn stream_limit_rejections_are_told_apart_from_store_failures() {
        for text in [
            "maximum messages per subject exceeded",
            "maximum bytes exceeded",
            "maximum messages exceeded",
        ] {
            assert!(is_limit_error(&jetstream_error(10077, text)), "{text}");
        }
        assert!(!is_limit_error(&jetstream_error(
            10077,
            "error opening msg block file"
        )));
        assert!(!is_limit_error(&jetstream_error(
            10047,
            "insufficient storage resources available"
        )));

        assert_eq!(
            PublishError::Full(anyhow::anyhow!("full")).reject_reason(),
            SendRejectReason::Full
        );
        assert_eq!(
            PublishError::Failed(anyhow::anyhow!("down")).reject_reason(),
            SendRejectReason::Internal
        );
    }

    /// Пул умирает только на ошибках, после которых подписка не оживёт.
    #[test]
    fn only_terminal_pull_errors_are_fatal() {
        assert!(pull_error_is_fatal(MessagesErrorKind::ConsumerDeleted));
        assert!(pull_error_is_fatal(MessagesErrorKind::PushBasedConsumer));
        assert!(!pull_error_is_fatal(MessagesErrorKind::MissingHeartbeat));
        assert!(!pull_error_is_fatal(MessagesErrorKind::Pull));
        assert!(!pull_error_is_fatal(MessagesErrorKind::NoResponders));
        assert!(!pull_error_is_fatal(MessagesErrorKind::Other));
    }

    /// Пул не звонит и не повторяет: звонковый конверт будит только
    /// публикация, передоставка не будит никого.
    #[test]
    fn pump_pushes_only_first_delivery_of_a_plain_envelope() {
        assert!(pump_should_push(false, None));
        assert!(!pump_should_push(true, None));
        assert!(!pump_should_push(false, Some(WakeHint::IncomingCall)));
        assert!(!pump_should_push(true, Some(WakeHint::IncomingCall)));
    }

    /// Уборка подтверждённого при смене политики потока опознаёт ящик по
    /// имени durable'а; чужие consumer'ы не опознаются.
    #[test]
    fn durable_names_map_back_to_their_scope() {
        for scope in [
            DeliveryScope::Account { user_id: user(11) },
            DeliveryScope::Device {
                user_id: user(12),
                device_id: 65_535,
            },
        ] {
            assert_eq!(
                DeliveryScope::from_durable_name(&scope.durable_name()),
                Some(scope)
            );
        }

        let hex = hex::encode(user(13));
        for foreign in [
            "orders".to_string(),
            "user_".to_string(),
            "user_zz".to_string(),
            format!("user_{hex}_device_"),
            format!("user_{hex}_device_70000"),
            format!("user_{hex}_extra"),
            format!("debug_{hex}"),
        ] {
            assert_eq!(
                DeliveryScope::from_durable_name(&foreign),
                None,
                "{foreign}"
            );
        }
    }
}
