use anyhow::{Context, anyhow, bail};
use config::{Config as ConfigSource, Environment, File, FileFormat};
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    /// Адрес `host:port` клиентского TCP-листенера (`BIND_ADDR`, либо
    /// `BIND_HOST` + `BIND_PORT`; CLI `--addr` / `--host` / `--port`
    /// перекрывают). Default: `0.0.0.0:443`.
    pub bind_addr: String,
    /// Каталог sled-хранилища и файла ключа ноды (`STORAGE_PATH`).
    /// Default: `data` (относительно рабочего каталога).
    pub storage_path: String,
    /// Identity-ключ ноды (Ed25519 seed, hex, 64 символа). Из него
    /// выводится и X25519-статик для Noise IK, и ключ подписи снапшота
    /// конфигурации. `None` — ключ читается из
    /// `storage_path/node_identity_key`, а при первом старте генерируется
    /// и сохраняется туда же.
    pub node_identity_key: Option<String>,
    /// Срок жизни подписанного снапшота конфигурации. Default: 24 ч.
    pub server_config_ttl: Duration,
    /// Адрес `host:port`, которым нода объявляет себя в подписанном
    /// снапшоте. `None` — не объявлять.
    pub advertised_address: Option<String>,
    /// Потолок времени на Noise-хендшейк. Default: 10 с.
    pub handshake_timeout: Duration,
    /// Принимать ли XX — путь первого контакта, где клиент узнаёт ключ
    /// ноды в ходе хендшейка. Default: `true`. Выключение оставляет только
    /// клиентов с пином.
    pub noise_allow_tofu: bool,
    /// Потолок длины одного кадра, байт (`MAX_FRAME_LEN`). Default: 8 MiB.
    pub max_frame_len: usize,
    /// Prometheus-экспортёр (`METRICS_ENABLED`, `METRICS_ADDR`).
    pub metrics: MetricsConfig,
    /// Сколько хранить удалённые сообщения (`DELETED_MESSAGES_RETENTION`:
    /// число дней, `disabled` — бессрочно, `instant` — не хранить).
    /// Default: 30 дней.
    pub deleted_messages_retention: RetentionPolicy,
    /// Сколько хранить недоставленные сообщения
    /// (`OFFLINE_MESSAGES_RETENTION`, формат тот же). Default: 30 дней.
    pub offline_messages_retention: RetentionPolicy,
    /// Бэкенд доставки и параметры JetStream.
    pub delivery: DeliveryConfig,
    /// Push-уведомления: транспорт, троттлинг, APNs voip.
    pub push: PushConfig,
    /// Лимиты и backpressure (квоты очередей, rate-limit, пол ttl).
    pub limits: LimitsConfig,
    /// Управляет ли `ClientSend.queueId` доставкой (`QUEUE_ADDRESSING_ENABLED`).
    /// Default: false.
    pub queue_addressing_enabled: bool,
    /// Потолок срока жизни сертификата устройства
    /// (`DEVICE_CERT_MAX_TTL_SECONDS`). Default: 30 суток. `0` выключает
    /// делегированный вход целиком: хендшейк с сертификатом отвергается, а
    /// в подписанном снапшоте возможность не объявляется.
    pub device_cert_max_ttl: Duration,
}

/// Лимиты и квоты. Все значения `0` означают «не ограничено», кроме
/// `ttl_min_seconds`, где 0 отключает проверку пола, и
/// `session_confirm_timeout_secs`, где 0 недопустим. Квоты очередей
/// (`max_messages_per_queue`, `max_bytes_per_queue`,
/// `max_messages_sender_pair`) действуют только в прямом (sled) бэкенде:
/// брокерный ограничен лимитами самого потока JetStream. Остальные лимиты
/// работают в обоих режимах.
#[derive(Clone, Copy, Debug)]
pub struct LimitsConfig {
    /// Пол `ttlSeconds` из node-header v3, сек. Депозит с меньшим ttl →
    /// reject `invalidTtl` (иначе пуш родился, а сообщение истекло до
    /// дренажа — push-спам без следов в очереди). Default: 24 ч.
    pub ttl_min_seconds: u64,
    /// Потолок количества сообщений в одной очереди (account- или
    /// device-scope). Default: 10 000.
    pub max_messages_per_queue: usize,
    /// Потолок суммарного размера хранимых записей очереди, байт.
    /// Default: 64 MiB.
    pub max_bytes_per_queue: u64,
    /// Под-квота одного отправителя на пару sender→recipient (сообщений).
    /// Default: 2 000.
    pub max_messages_sender_pair: usize,
    /// Rate-limit ClientSend: сообщений/с на пользователя. Default: 100.
    pub send_msgs_per_sec: u32,
    /// Rate-limit ClientSend: байт/UTC-сутки на пользователя. Default: 256 MiB.
    pub send_bytes_per_day: u64,
    /// Максимум одновременных сессий одного пользователя; лишние отклоняются
    /// AuthError до AuthOk. Default: 64.
    pub max_sessions_per_user: usize,
    /// Сколько нода ждёт первый кадр клиента после `AuthOk`, сек
    /// (`SESSION_CONFIRM_TIMEOUT_SECS`). Default: 30; `0` недопустим.
    ///
    /// Сессия считается подтверждённой только этим кадром: msg1 IK можно
    /// переиграть, а расшифровать `AuthOk` и ответить может лишь владелец
    /// эфемерного ключа. До подтверждения сессия не регистрируется и ничего
    /// не получает, но держит место на входе (`handshake_max_inflight*`) —
    /// таймаут ограничивает, сколько его занимает чужой повтор.
    pub session_confirm_timeout_secs: u64,
    /// Максимум Ping/с на соединение; сверх — pong не отправляется.
    /// Default: 50.
    pub ping_per_sec: u32,
    /// Потолок mailbox-очередей на пользователя (`MAX_QUEUES_PER_USER`).
    /// Default: 1024, `0` = без ограничения.
    ///
    /// Очередь заводится по одной на контакт, поэтому потолок — это по
    /// сути потолок списка контактов; занижать его больно, а не ставить
    /// вовсе нельзя: аллокация дёшева для клиента и вечна для ноды.
    pub max_queues_per_user: usize,
    /// Потолок устройств с push-токенами на пользователя, штук
    /// (`MAX_PUSH_DEVICES_PER_USER`). Default: 32, `0` = без ограничения.
    ///
    /// `deviceId` выбирает сам клиент, и без потолка один аккаунт заводил
    /// бы токены без счёта. Новое устройство сверх потолка получает
    /// `PushTokenAck { ok: false }`; смена токена уже известного устройства
    /// проходит всегда.
    pub max_push_devices_per_user: usize,
    /// Максимум одновременных Noise-хендшейков на ноду. Крипта IK платится
    /// до аутентификации, поэтому вход считается отдельно от сессий.
    /// Default: 256.
    pub handshake_max_inflight: usize,
    /// То же на один IP: один источник не должен занимать весь вход.
    /// Default: 32.
    ///
    /// Клиенты мобильные, и за carrier-grade NAT сотни живых устройств
    /// приходят с одного адреса: слишком низкий лимит отсекал бы честных
    /// пользователей вместо флудеров. Защитой от заливания остаётся
    /// глобальный потолок: при 32 один источник занимает не больше 1/8
    /// входа. За общим NAT значение нужно поднимать под фактическое число
    /// устройств — см. docs/deployment.md.
    pub handshake_max_inflight_per_ip: usize,
    /// Потолок одновременно открытых клиентских TCP-соединений на ноду, в
    /// том числе ещё не прошедших хендшейк (`LIMIT_MAX_CONNECTIONS`).
    /// Default: 4096, `0` = без ограничения.
    ///
    /// Сверх потолка соединение закрывается сразу после `accept`, до
    /// хендшейка. Это потолок памяти: простаивающая сессия держит буфер
    /// Noise (64 КиБ) и буферы кадров — порядка 80 КиБ, 4096 сессий — около
    /// 320 МиБ. Значение должно быть ниже `ulimit -n` процесса с запасом под
    /// файлы sled и исходящие соединения: упёршись в лимит дескрипторов
    /// раньше, нода перестаёт принимать вовсе, и соединения копятся в
    /// backlog вместо быстрого отказа.
    pub max_connections: usize,
    /// Простой соединения до первой TCP keepalive-пробы
    /// (`TCP_KEEPALIVE_SECS`), сек. Default: 60. `0` выключает keepalive.
    ///
    /// Без keepalive полуоткрытое соединение (телефон сменил сеть, не
    /// послав FIN) живёт, пока нода ему не пишет, то есть вечно: занимает
    /// место в лимите сессий пользователя и держит его «в сети» для
    /// маршрутизации. Проба уходит только после простоя, поэтому клиент,
    /// который пингует чаще, её не получает и радио лишний раз не будит.
    pub tcp_keepalive_secs: u64,
    /// Интервал между неотвеченными keepalive-пробами
    /// (`TCP_KEEPALIVE_INTERVAL_SECS`), сек. Default: 15.
    pub tcp_keepalive_interval_secs: u64,
    /// Сколько неотвеченных проб подряд рвут соединение
    /// (`TCP_KEEPALIVE_RETRIES`). Default: 4 — мёртвый пир обнаруживается
    /// примерно через `60 + 4 × 15 = 120` с простоя. На платформах без
    /// `TCP_KEEPCNT` действует системное значение.
    pub tcp_keepalive_retries: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            ttl_min_seconds: 24 * 60 * 60,
            max_messages_per_queue: 10_000,
            max_bytes_per_queue: 64 * 1024 * 1024,
            max_messages_sender_pair: 2_000,
            send_msgs_per_sec: 100,
            send_bytes_per_day: 256 * 1024 * 1024,
            max_sessions_per_user: 64,
            session_confirm_timeout_secs: 30,
            ping_per_sec: 50,
            max_queues_per_user: 1024,
            max_push_devices_per_user: 32,
            handshake_max_inflight: 256,
            handshake_max_inflight_per_ip: 32,
            max_connections: 4096,
            tcp_keepalive_secs: 60,
            tcp_keepalive_interval_secs: 15,
            tcp_keepalive_retries: 4,
        }
    }
}

/// Возможности ноды, объявляемые клиенту в подписанном снапшоте. Собирается
/// из [`Config`] (`Config::server_config_snapshot`); собственных дефолтов не
/// имеет.
#[derive(Clone, Debug)]
pub struct ServerConfigSnapshot {
    /// `Config::max_frame_len`, байт.
    pub max_frame_len: usize,
    /// Адресация по `deviceId`. Всегда `true`.
    pub supports_device_addressing: bool,
    /// `Config::deleted_messages_retention`.
    pub deleted_messages_retention: RetentionPolicy,
    /// `Config::offline_messages_retention`.
    pub offline_messages_retention: RetentionPolicy,
    /// Подтверждение доставки клиентом: `true` только для JetStream-бэкенда.
    pub supports_delivery_ack: bool,
    /// Включена ли адресация по очередям (`QUEUE_ADDRESSING_ENABLED`).
    /// Default: false — `queueId` принимается и игнорируется, доставка идёт
    /// по `recipientId`.
    ///
    /// Флаг существует ради порядка выкатки: нода и клиент обновляются
    /// врозь, и включать маршрутизацию по очередям осмысленно только после
    /// того, как клиенты их завели и разложили по контактам.
    pub supports_queue_addressing: bool,
    /// Потолок срока жизни сертификата устройства; ноль — делегированный
    /// вход выключен.
    pub device_cert_max_ttl: Duration,
    /// Срок жизни подписанного снапшота. Подписанный конфиг без срока —
    /// вечно предъявляемая запись, которую нечем отозвать, поэтому срок
    /// всегда ненулевой.
    pub config_ttl: Duration,
    /// Адрес, которым нода объявляет себя в подписанном снапшоте. `None` —
    /// не объявляет: нода слушает `0.0.0.0` и своего публичного адреса в
    /// общем случае не знает, а подписать неверный адрес хуже, чем не
    /// подписать никакого.
    pub advertised_address: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    /// Поднимать ли HTTP-экспортёр Prometheus (`METRICS_ENABLED`).
    /// Default: `true`, если задан `METRICS_ADDR`, иначе `false`.
    pub enabled: bool,
    /// Адрес `host:port` экспортёра (`METRICS_ADDR`). Default:
    /// `0.0.0.0:9000`. Эндпоинт без аутентификации.
    pub addr: String,
}

#[derive(Clone, Debug)]
pub struct DeliveryConfig {
    /// `sled` (прямая доставка) или `jetstream` (`DELIVERY_BACKEND`).
    /// Default: `sled`.
    pub backend: DeliveryBackendKind,
    /// Адрес брокера (`NATS_URL`). Default: `nats://nats:4222`.
    pub nats_url: String,
    /// Имя стрима JetStream (`NATS_STREAM_NAME`). Default: `messages`.
    pub nats_stream_name: String,
    /// `ack_wait` consumer'ов (`NATS_ACK_WAIT_SECS`), сек. Default: 30 с.
    pub nats_ack_wait: Duration,
    /// Сколько durable-consumer живёт без активности, прежде чем JetStream
    /// удалит его вместе с директорией состояния
    /// (`NATS_CONSUMER_INACTIVE_THRESHOLD_DAYS`, сутки). Default: 30 суток.
    ///
    /// Без этого порога consumer'ы копятся вечно: по одному на аккаунт и на
    /// каждое устройство, за каждого, кто хоть раз подключился, — и остаются
    /// после удаления пользователя, смены устройства и любого e2e-прогона.
    /// Сообщения при этом чистятся по stream retention, а consumer'ы — нет,
    /// так что store растёт директориями, а не данными.
    ///
    /// Порог обязан превышать `max_age` стрима (по умолчанию 14 дней):
    /// удалённый consumer пересоздаётся с `DeliverPolicy::All`, и всё ещё
    /// живое по его subject'у будет доставлено повторно. При threshold >
    /// max_age к моменту удаления доставлять уже нечего; конфигурация с
    /// threshold <= max_age отвергается на старте.
    pub nats_consumer_inactive_threshold: Duration,
    /// Возраст, после которого сообщение вытесняется из стрима, даже если его
    /// никто не забрал (`NATS_STREAM_MAX_AGE_DAYS`, сутки). Верхняя граница
    /// офлайн-доставки. Default: 14 суток.
    pub nats_stream_max_age: Duration,
    /// Потолок стрима в байтах (`NATS_STREAM_MAX_BYTES`). Поток работает по
    /// `DiscardPolicy::New`: при переполнении отказ получает новый конверт
    /// (отправителю — `FULL`), уже лежащие не вытесняются. Считается только
    /// недоставленное: подтверждённый конверт нода из потока удаляет.
    /// Default: 350 MiB.
    pub nats_stream_max_bytes: i64,
    /// Потолок ящика получателя, конвертов (`NATS_MAX_MSGS_PER_SUBJECT`).
    /// Ящик — subject `msg.user.<id>` (адресация на аккаунт) и каждый
    /// `msg.user.<id>.device.<n>` по отдельности; при переполнении отказ
    /// получает новый конверт (`FULL`), лежащие не трогаются. Считаются
    /// только недоставленные конверты. Default: 10 000 — как
    /// `QUOTA_MAX_MESSAGES_PER_QUEUE` прямого бэкенда.
    ///
    /// Без этого потолка один ящик мог бы занять весь `max_bytes` потока, и
    /// отказ получали бы отправители всем остальным получателям.
    pub nats_max_msgs_per_subject: i64,
    /// Сколько нода ждёт подтверждения публикации от JetStream, прежде чем
    /// считать отправку неудавшейся (`NATS_PUBLISH_TIMEOUT_MS`).
    /// Default: 2000 мс.
    ///
    /// Клиент NATS ждёт своим дефолтом около пяти секунд, и всё это время
    /// задача соединения занята публикацией: отправитель не получает не
    /// только `SendAck`, но и входящие. При мёртвом брокере короткий
    /// таймаут превращает аварию из «висит» в «быстро отказывает».
    pub nats_publish_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryBackendKind {
    Sled,
    JetStream,
}

/// Push notification configuration. Consumed by `crate::push::PushScheduler`.
///
/// All `min_gap_*` / `burst_*` knobs are per-priority: pick the entry matching
/// the **highest** priority seen in the current coalescing window. See
/// `crate::push::state::decide` for the exact decision rules.
#[derive(Clone, Debug)]
pub struct PushConfig {
    /// Master toggle (`PUSH_ENABLED`). When `false`, `on_undelivered` and
    /// `send_welcome` are no-ops and nothing reaches a push provider.
    /// Default: false.
    pub enabled: bool,

    /// Адрес внешнего push-шлюза (`PUSH_GATEWAY_URL`), например
    /// `https://push.example.org`. Default: None — нода будит устройства
    /// сама, своими кредами FCM/APNs.
    ///
    /// Задан — режим меняется целиком: креды на ноде не нужны и не
    /// допускаются, оба транспорта (wake и voip-ring) уезжают в шлюз по
    /// gRPC. Контракт — `schemas/trustmessage/push/v1/push.proto`.
    pub gateway_url: Option<String>,

    /// Таймаут одного вызова шлюза и установки соединения с ним
    /// (`PUSH_GATEWAY_TIMEOUT_MS`). Default: 10 000 мс. Осмысленно только
    /// при заданном `gateway_url`.
    pub gateway_timeout: Duration,

    /// FCM project ID (`FCM_PROJECT_ID`; Firebase console → Project settings
    /// → General). Required when `enabled == true` and no gateway is set;
    /// must be empty in gateway mode. Default: empty.
    pub fcm_project_id: String,

    /// Filesystem path to the FCM service account JSON key
    /// (`FCM_SERVICE_ACCOUNT_PATH`). Loaded once at startup to mint
    /// short-lived OAuth2 access tokens. Required when `enabled == true` and
    /// no gateway is set; must be empty in gateway mode. Default: empty.
    pub fcm_service_account_path: String,

    /// Timeout of a single outbound HTTP request (`PUSH_HTTP_TIMEOUT_MS`):
    /// FCM `messages:send`, the OAuth2 token exchange, and APNs voip pushes.
    /// Default: 10 s.
    pub http_timeout: Duration,

    /// Minimum gap between successive pushes for the same `(user, device)`
    /// when the highest pending priority is **High**
    /// (`PUSH_MIN_GAP_HIGH_MS`). Default: 0 s (instant). All `min_gap_*`
    /// values are applied with whole-second granularity.
    pub min_gap_high: Duration,
    /// Minimum gap for **Medium** priority recipients
    /// (`PUSH_MIN_GAP_MEDIUM_MS`). Default: 10 s.
    pub min_gap_medium: Duration,
    /// Minimum gap for **Low** priority recipients (`PUSH_MIN_GAP_LOW_MS`).
    /// Default: 60 s.
    pub min_gap_low: Duration,
    /// Minimum gap when no priority was set on any pending message in the
    /// window (`PUSH_MIN_GAP_NONE_MS`). Default: 120 s. Only applies when
    /// `wake_on_unspecified = true`.
    pub min_gap_none: Duration,
    /// Будить ли устройство на сообщениях без приоритета (`PUSH_WAKE_ON_UNSPECIFIED`).
    /// Default: true.
    ///
    /// `false` — время такие сообщения не будит: `min_gap_none` не истекает
    /// никогда и таймер под них не ставится. Пуш уйдёт, когда в том же окне
    /// появится сообщение с приоритетом (и унесёт с собой счётчик
    /// накопленных) либо когда их накопится `burst_none` — порог остаётся
    /// предохранителем, чтобы беззвучная переписка не пропала до следующего
    /// подключения.
    pub wake_on_unspecified: bool,

    /// Number of accumulated undelivered messages that force a push even before
    /// `min_gap_*` elapses, for **High**-priority recipients
    /// (`PUSH_BURST_HIGH`). Default: 1. All `burst_*` values are clamped to
    /// at least 1.
    pub burst_high: u32,
    /// Burst threshold for **Medium** priority recipients
    /// (`PUSH_BURST_MEDIUM`). Default: 3.
    pub burst_medium: u32,
    /// Burst threshold for **Low** priority recipients (`PUSH_BURST_LOW`).
    /// Default: 8.
    pub burst_low: u32,
    /// Burst threshold when no priority was set on any pending message
    /// (`PUSH_BURST_NONE`). Default: 15.
    pub burst_none: u32,

    /// First step of the exponential backoff applied after a failed wake
    /// send (5xx / quota exceeded / network failure)
    /// (`PUSH_SUPPRESS_INITIAL_MS`). Doubles on each consecutive failure up
    /// to `suppress_max`. Default: 30 s.
    pub suppress_initial: Duration,
    /// Upper bound on the backoff (`PUSH_SUPPRESS_MAX_MS`); must be
    /// `>= suppress_initial`. Default: 1 h.
    pub suppress_max: Duration,

    /// Capacity of the in-process trigger channel feeding the push worker
    /// (`PUSH_CHANNEL_CAPACITY`), in triggers. Triggers received when the
    /// channel is full are dropped (counted via the
    /// `push_dropped_total{reason=channel_full}` metric) so the hot delivery
    /// path is never blocked. Default: 8192.
    pub channel_capacity: usize,

    /// Upper bound on concurrent requests to the push provider
    /// (`PUSH_SEND_CONCURRENCY`), in requests. Sends to one device stay
    /// sequential; the bound applies across devices. Default: 32.
    pub send_concurrency: usize,

    /// APNs voip (PushKit ring) — `None` = voip выключен, ring-конверты идут
    /// обычным FCM-wake путём. Включается `APNS_ENABLED=true` плюс
    /// `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`.
    /// Default: None.
    pub apns: Option<ApnsConfig>,

    /// Окно подавления повторного voip-ring'а той же `(user, device)`
    /// (`PUSH_RING_COOLDOWN_MS`): mesh-леги/ре-офферы одной комнаты не должны
    /// слать очередь voip-пушей. Сравнивается с точностью до миллисекунды.
    /// Default: 3 с.
    pub ring_cooldown: Duration,
}

/// APNs voip transport configuration. Consumed by `crate::push::ApnsVoipClient`.
#[derive(Clone, Debug)]
pub struct ApnsConfig {
    /// Filesystem path to the APNs Auth Key (.p8, ES256 EC PEM)
    /// (`APNS_KEY_PATH`). Required, no default.
    pub key_path: String,
    /// Key ID выданного .p8 (`APNS_KEY_ID`; Apple Developer → Keys).
    /// Обязателен, дефолта нет.
    pub key_id: String,
    /// Apple Developer Team ID (`APNS_TEAM_ID`). Required, no default.
    pub team_id: String,
    /// Bundle identifier приложения (`APNS_BUNDLE_ID`); `apns-topic`
    /// строится как `<bundle>.voip`. Обязателен, дефолта нет.
    pub bundle_id: String,
    /// `sandbox` (dev-билды Xcode) или `production` (TestFlight/App Store)
    /// (`APNS_ENVIRONMENT`). Токен устройства работает только на «своём»
    /// хосте. Default: `production`.
    pub environment: String,
}

impl PushConfig {
    /// Project the throttling knobs into the pure-decision struct consumed by
    /// `crate::push::state::decide`. Excludes HTTP / OAuth fields so the
    /// decision layer stays free of I/O concerns.
    pub fn decision_config(&self) -> crate::push::DecisionConfig {
        crate::push::DecisionConfig {
            min_gap_high: self.min_gap_high,
            min_gap_medium: self.min_gap_medium,
            min_gap_low: self.min_gap_low,
            min_gap_none: self.min_gap_none,
            wake_on_unspecified: self.wake_on_unspecified,
            burst_high: self.burst_high,
            burst_medium: self.burst_medium,
            burst_low: self.burst_low,
            burst_none: self.burst_none,
            suppress_initial: self.suppress_initial,
            suppress_max: self.suppress_max,
        }
    }
}

/// Политика хранения сообщений.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Хранить бессрочно (`disabled` / `off` / `infinite`).
    Disabled,
    /// Не хранить: запись истекает сразу (`instant` / `0`).
    Immediate,
    /// Хранить указанный срок (число дней).
    KeepFor(Duration),
}

impl RetentionPolicy {
    pub fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    pub fn is_immediate(self) -> bool {
        matches!(self, Self::Immediate)
    }

    pub fn expires(self, created_at_secs: u64, now_secs: u64) -> bool {
        match self {
            Self::Disabled => false,
            Self::Immediate => true,
            Self::KeepFor(duration) => {
                now_secs.saturating_sub(created_at_secs) >= duration.as_secs()
            }
        }
    }
}

impl Config {
    /// Снапшот для подписанного кадра конфигурации. Ключи ноды сюда не
    /// попадают: они материализуются после загрузки конфигурации и
    /// подставляются в момент подписи.
    pub fn server_config_snapshot(&self) -> ServerConfigSnapshot {
        ServerConfigSnapshot {
            max_frame_len: self.max_frame_len,
            supports_device_addressing: true,
            deleted_messages_retention: self.deleted_messages_retention,
            offline_messages_retention: self.offline_messages_retention,
            supports_delivery_ack: matches!(self.delivery.backend, DeliveryBackendKind::JetStream),
            supports_queue_addressing: self.queue_addressing_enabled,
            device_cert_max_ttl: self.device_cert_max_ttl,
            config_ttl: self.server_config_ttl,
            advertised_address: self.advertised_address.clone(),
        }
    }
}

impl ServerConfigSnapshot {
    pub fn supports_offline_messages(&self) -> bool {
        !self.offline_messages_retention.is_immediate()
    }

    pub fn supports_deleted_message_archive(&self) -> bool {
        !self.deleted_messages_retention.is_immediate()
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    bind_addr: Option<String>,
    #[serde(default)]
    bind_host: Option<String>,
    #[serde(default)]
    bind_port: Option<u16>,
    #[serde(default)]
    storage_path: Option<String>,
    #[serde(default)]
    max_frame_len: Option<usize>,
    #[serde(default)]
    metrics_enabled: Option<bool>,
    #[serde(default)]
    metrics_addr: Option<String>,
    #[serde(default)]
    deleted_messages_retention: Option<String>,
    #[serde(default)]
    offline_messages_retention: Option<String>,
    #[serde(default)]
    delivery_backend: Option<String>,
    #[serde(default)]
    nats_url: Option<String>,
    #[serde(default)]
    nats_stream_name: Option<String>,
    #[serde(default)]
    nats_ack_wait_secs: Option<u64>,
    #[serde(default)]
    nats_consumer_inactive_threshold_days: Option<u64>,
    #[serde(default)]
    nats_stream_max_age_days: Option<u64>,
    #[serde(default)]
    nats_stream_max_bytes: Option<i64>,
    #[serde(default)]
    nats_max_msgs_per_subject: Option<i64>,
    #[serde(default)]
    nats_publish_timeout_ms: Option<u64>,
    #[serde(default)]
    push_enabled: Option<bool>,
    #[serde(default)]
    push_gateway_url: Option<String>,
    #[serde(default)]
    push_gateway_timeout_ms: Option<u64>,
    #[serde(default)]
    fcm_project_id: Option<String>,
    #[serde(default)]
    fcm_service_account_path: Option<String>,
    #[serde(default)]
    push_http_timeout_ms: Option<u64>,
    #[serde(default)]
    push_min_gap_high_ms: Option<u64>,
    #[serde(default)]
    push_min_gap_medium_ms: Option<u64>,
    #[serde(default)]
    push_min_gap_low_ms: Option<u64>,
    #[serde(default)]
    push_min_gap_none_ms: Option<u64>,
    #[serde(default)]
    push_wake_on_unspecified: Option<bool>,
    #[serde(default)]
    push_burst_high: Option<u32>,
    #[serde(default)]
    push_burst_medium: Option<u32>,
    #[serde(default)]
    push_burst_low: Option<u32>,
    #[serde(default)]
    push_burst_none: Option<u32>,
    #[serde(default)]
    push_suppress_initial_ms: Option<u64>,
    #[serde(default)]
    push_suppress_max_ms: Option<u64>,
    #[serde(default)]
    push_channel_capacity: Option<usize>,
    #[serde(default)]
    push_send_concurrency: Option<usize>,
    #[serde(default)]
    apns_enabled: Option<bool>,
    #[serde(default)]
    apns_key_path: Option<String>,
    #[serde(default)]
    apns_key_id: Option<String>,
    #[serde(default)]
    apns_team_id: Option<String>,
    #[serde(default)]
    apns_bundle_id: Option<String>,
    #[serde(default)]
    apns_environment: Option<String>,
    #[serde(default)]
    push_ring_cooldown_ms: Option<u64>,
    #[serde(default)]
    node_identity_key: Option<String>,
    #[serde(default)]
    noise_handshake_timeout_ms: Option<u64>,
    #[serde(default)]
    noise_allow_tofu: Option<bool>,
    #[serde(default)]
    server_config_ttl_seconds: Option<u64>,
    #[serde(default)]
    advertised_address: Option<String>,
    #[serde(default)]
    ttl_min_seconds: Option<u64>,
    #[serde(default)]
    quota_max_messages_per_queue: Option<usize>,
    #[serde(default)]
    quota_max_bytes_per_queue: Option<u64>,
    #[serde(default)]
    quota_max_messages_sender_pair: Option<usize>,
    #[serde(default)]
    rate_limit_send_msgs_per_sec: Option<u32>,
    #[serde(default)]
    rate_limit_send_bytes_per_day: Option<u64>,
    #[serde(default)]
    limit_max_sessions_per_user: Option<usize>,
    #[serde(default)]
    session_confirm_timeout_secs: Option<u64>,
    #[serde(default)]
    limit_ping_per_sec: Option<u32>,
    #[serde(default)]
    max_queues_per_user: Option<usize>,
    #[serde(default)]
    max_push_devices_per_user: Option<usize>,
    #[serde(default)]
    queue_addressing_enabled: Option<bool>,
    #[serde(default)]
    device_cert_max_ttl_seconds: Option<u64>,
    #[serde(default)]
    limit_handshake_inflight: Option<usize>,
    #[serde(default)]
    limit_handshake_inflight_per_ip: Option<usize>,
    #[serde(default)]
    limit_max_connections: Option<usize>,
    #[serde(default)]
    tcp_keepalive_secs: Option<u64>,
    #[serde(default)]
    tcp_keepalive_interval_secs: Option<u64>,
    #[serde(default)]
    tcp_keepalive_retries: Option<u32>,
}

pub fn load() -> anyhow::Result<Config> {
    let mut builder = ConfigSource::builder();

    let env_file = Path::new(".env");
    if env_file.exists() {
        builder = builder.add_source(File::new(&env_file.to_string_lossy(), FileFormat::Ini));
    }

    builder = builder.add_source(Environment::default().separator("__").try_parsing(true));

    let raw: RawConfig = builder
        .build()
        .context("failed to build configuration sources")?
        .try_deserialize()
        .context("failed to deserialize configuration")?;

    let RawConfig {
        bind_addr,
        bind_host,
        bind_port,
        storage_path,
        max_frame_len,
        metrics_enabled,
        metrics_addr,
        deleted_messages_retention,
        offline_messages_retention,
        delivery_backend,
        nats_url,
        nats_stream_name,
        nats_ack_wait_secs,
        nats_consumer_inactive_threshold_days,
        nats_stream_max_age_days,
        nats_stream_max_bytes,
        nats_max_msgs_per_subject,
        nats_publish_timeout_ms,
        push_enabled,
        push_gateway_url,
        push_gateway_timeout_ms,
        fcm_project_id,
        fcm_service_account_path,
        push_http_timeout_ms,
        push_min_gap_high_ms,
        push_min_gap_medium_ms,
        push_min_gap_low_ms,
        push_min_gap_none_ms,
        push_wake_on_unspecified,
        push_burst_high,
        push_burst_medium,
        push_burst_low,
        push_burst_none,
        push_suppress_initial_ms,
        push_suppress_max_ms,
        push_channel_capacity,
        push_send_concurrency,
        apns_enabled,
        apns_key_path,
        apns_key_id,
        apns_team_id,
        apns_bundle_id,
        apns_environment,
        push_ring_cooldown_ms,
        node_identity_key,
        noise_handshake_timeout_ms,
        noise_allow_tofu,
        server_config_ttl_seconds,
        advertised_address,
        ttl_min_seconds,
        quota_max_messages_per_queue,
        quota_max_bytes_per_queue,
        quota_max_messages_sender_pair,
        rate_limit_send_msgs_per_sec,
        rate_limit_send_bytes_per_day,
        limit_max_sessions_per_user,
        session_confirm_timeout_secs,
        limit_ping_per_sec,
        max_queues_per_user,
        max_push_devices_per_user,
        queue_addressing_enabled,
        device_cert_max_ttl_seconds,
        limit_handshake_inflight,
        limit_handshake_inflight_per_ip,
        limit_max_connections,
        tcp_keepalive_secs,
        tcp_keepalive_interval_secs,
        tcp_keepalive_retries,
    } = raw;

    let bind_addr = resolve_bind_addr(bind_addr, bind_host, bind_port)?;

    let storage_path = storage_path.unwrap_or_else(|| "data".to_string());

    let node_identity_key = normalize_optional_text(node_identity_key);
    let advertised_address = normalize_optional_text(advertised_address);
    let handshake_timeout = duration_from_millis(
        noise_handshake_timeout_ms,
        10_000,
        "NOISE_HANDSHAKE_TIMEOUT_MS",
    )?;
    let noise_allow_tofu = noise_allow_tofu.unwrap_or(true);
    let server_config_ttl = match server_config_ttl_seconds {
        None => Duration::from_secs(24 * 3600),
        Some(0) => bail!(
            "SERVER_CONFIG_TTL_SECONDS must be greater than zero: a signed config without \
             an expiry cannot be revoked"
        ),
        Some(seconds) => Duration::from_secs(seconds),
    };

    let max_frame_len = max_frame_len.unwrap_or(8 * 1024 * 1024);
    let metrics = resolve_metrics(metrics_enabled, metrics_addr)?;
    let deleted_messages_retention =
        parse_retention_policy(deleted_messages_retention, 30, "DELETED_MESSAGES_RETENTION")?;
    let offline_messages_retention =
        parse_retention_policy(offline_messages_retention, 30, "OFFLINE_MESSAGES_RETENTION")?;
    let delivery = resolve_delivery(
        delivery_backend,
        nats_url,
        nats_stream_name,
        nats_ack_wait_secs,
        nats_consumer_inactive_threshold_days,
        nats_stream_max_age_days,
        nats_stream_max_bytes,
        nats_max_msgs_per_subject,
        nats_publish_timeout_ms,
    )?;
    let push = resolve_push(PushRawConfig {
        enabled: push_enabled,
        gateway_url: push_gateway_url,
        gateway_timeout_ms: push_gateway_timeout_ms,
        fcm_project_id,
        fcm_service_account_path,
        http_timeout_ms: push_http_timeout_ms,
        min_gap_high_ms: push_min_gap_high_ms,
        min_gap_medium_ms: push_min_gap_medium_ms,
        min_gap_low_ms: push_min_gap_low_ms,
        min_gap_none_ms: push_min_gap_none_ms,
        wake_on_unspecified: push_wake_on_unspecified,
        burst_high: push_burst_high,
        burst_medium: push_burst_medium,
        burst_low: push_burst_low,
        burst_none: push_burst_none,
        suppress_initial_ms: push_suppress_initial_ms,
        suppress_max_ms: push_suppress_max_ms,
        channel_capacity: push_channel_capacity,
        send_concurrency: push_send_concurrency,
        apns_enabled,
        apns_key_path,
        apns_key_id,
        apns_team_id,
        apns_bundle_id,
        apns_environment,
        ring_cooldown_ms: push_ring_cooldown_ms,
    })?;

    let defaults = LimitsConfig::default();
    let session_confirm_timeout_secs = match session_confirm_timeout_secs {
        None => defaults.session_confirm_timeout_secs,
        Some(0) => bail!(
            "SESSION_CONFIRM_TIMEOUT_SECS must be greater than zero: an unconfirmed session \
             would hold its handshake admission slot forever"
        ),
        Some(seconds) => seconds,
    };
    let limits = LimitsConfig {
        ttl_min_seconds: ttl_min_seconds.unwrap_or(defaults.ttl_min_seconds),
        max_messages_per_queue: quota_max_messages_per_queue
            .unwrap_or(defaults.max_messages_per_queue),
        max_bytes_per_queue: quota_max_bytes_per_queue.unwrap_or(defaults.max_bytes_per_queue),
        max_messages_sender_pair: quota_max_messages_sender_pair
            .unwrap_or(defaults.max_messages_sender_pair),
        send_msgs_per_sec: rate_limit_send_msgs_per_sec.unwrap_or(defaults.send_msgs_per_sec),
        send_bytes_per_day: rate_limit_send_bytes_per_day.unwrap_or(defaults.send_bytes_per_day),
        max_sessions_per_user: limit_max_sessions_per_user
            .unwrap_or(defaults.max_sessions_per_user),
        session_confirm_timeout_secs,
        ping_per_sec: limit_ping_per_sec.unwrap_or(defaults.ping_per_sec),
        max_queues_per_user: max_queues_per_user.unwrap_or(defaults.max_queues_per_user),
        max_push_devices_per_user: max_push_devices_per_user
            .unwrap_or(defaults.max_push_devices_per_user),
        handshake_max_inflight: limit_handshake_inflight.unwrap_or(defaults.handshake_max_inflight),
        handshake_max_inflight_per_ip: limit_handshake_inflight_per_ip
            .unwrap_or(defaults.handshake_max_inflight_per_ip),
        max_connections: limit_max_connections.unwrap_or(defaults.max_connections),
        tcp_keepalive_secs: tcp_keepalive_secs.unwrap_or(defaults.tcp_keepalive_secs),
        tcp_keepalive_interval_secs: tcp_keepalive_interval_secs
            .unwrap_or(defaults.tcp_keepalive_interval_secs),
        tcp_keepalive_retries: tcp_keepalive_retries.unwrap_or(defaults.tcp_keepalive_retries),
    };
    check_tcp_keepalive(&limits)?;

    Ok(Config {
        queue_addressing_enabled: queue_addressing_enabled.unwrap_or(false),
        device_cert_max_ttl: Duration::from_secs(
            device_cert_max_ttl_seconds.unwrap_or(30 * 24 * 3600),
        ),
        bind_addr,
        storage_path,
        node_identity_key,
        server_config_ttl,
        advertised_address,
        handshake_timeout,
        noise_allow_tofu,
        max_frame_len,
        metrics,
        deleted_messages_retention,
        offline_messages_retention,
        delivery,
        push,
        limits,
    })
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
}

fn duration_from_millis(
    value: Option<u64>,
    default_ms: u64,
    field_name: &str,
) -> anyhow::Result<Duration> {
    let millis = match value {
        Some(v) => v,
        None => default_ms,
    };

    if millis == 0 {
        bail!("{field_name} must be greater than 0");
    }

    Ok(Duration::from_millis(millis))
}

fn resolve_bind_addr(
    bind_addr: Option<String>,
    bind_host: Option<String>,
    bind_port: Option<u16>,
) -> anyhow::Result<String> {
    if let Some(addr) = bind_addr {
        let trimmed = addr.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let host = bind_host
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let port = bind_port.unwrap_or(443);

    if port == 0 {
        bail!("BIND_PORT must be greater than 0");
    }

    Ok(format!("{host}:{port}"))
}

fn resolve_metrics(
    metrics_enabled: Option<bool>,
    metrics_addr: Option<String>,
) -> anyhow::Result<MetricsConfig> {
    let explicit_addr = metrics_addr.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    let enabled = metrics_enabled.unwrap_or(explicit_addr.is_some());
    let addr = explicit_addr.unwrap_or_else(|| "0.0.0.0:9000".to_string());

    if enabled && addr.is_empty() {
        bail!("METRICS_ADDR must be a non-empty host:port when metrics are enabled");
    }

    Ok(MetricsConfig { enabled, addr })
}

struct PushRawConfig {
    enabled: Option<bool>,
    gateway_url: Option<String>,
    gateway_timeout_ms: Option<u64>,
    fcm_project_id: Option<String>,
    fcm_service_account_path: Option<String>,
    http_timeout_ms: Option<u64>,
    min_gap_high_ms: Option<u64>,
    min_gap_medium_ms: Option<u64>,
    min_gap_low_ms: Option<u64>,
    min_gap_none_ms: Option<u64>,
    wake_on_unspecified: Option<bool>,
    burst_high: Option<u32>,
    burst_medium: Option<u32>,
    burst_low: Option<u32>,
    burst_none: Option<u32>,
    suppress_initial_ms: Option<u64>,
    suppress_max_ms: Option<u64>,
    channel_capacity: Option<usize>,
    send_concurrency: Option<usize>,
    apns_enabled: Option<bool>,
    apns_key_path: Option<String>,
    apns_key_id: Option<String>,
    apns_team_id: Option<String>,
    apns_bundle_id: Option<String>,
    apns_environment: Option<String>,
    ring_cooldown_ms: Option<u64>,
}

fn resolve_push(raw: PushRawConfig) -> anyhow::Result<PushConfig> {
    let enabled = raw.enabled.unwrap_or(false);

    let gateway_url = normalize_optional_text(raw.gateway_url);
    let gateway_timeout =
        duration_from_millis(raw.gateway_timeout_ms, 10_000, "PUSH_GATEWAY_TIMEOUT_MS")?;

    let fcm_project_id = normalize_optional_text(raw.fcm_project_id).unwrap_or_default();
    let fcm_service_account_path =
        normalize_optional_text(raw.fcm_service_account_path).unwrap_or_default();

    // Два режима, и они взаимоисключающие. Смешанная конфигурация — почти
    // наверняка незавершённая миграция, и молча выбрать за оператора один
    // из режимов хуже, чем упасть: «половина пушей идёт мимо шлюза» иначе
    // ничем не диагностируется.
    if enabled && let Some(url) = gateway_url.as_deref() {
        // Схема проверяется при разборе конфига, а не при сборке клиента:
        // нода с http-шлюзом в сети не должна стартовать вовсе.
        crate::push::gateway::parse_gateway_url(url)?;
        if !fcm_project_id.is_empty() || !fcm_service_account_path.is_empty() {
            bail!(
                "PUSH_GATEWAY_URL is set, so FCM credentials must not be: unset FCM_PROJECT_ID and FCM_SERVICE_ACCOUNT_PATH"
            );
        }
        if raw.apns_enabled.unwrap_or(false) {
            bail!(
                "PUSH_GATEWAY_URL is set, so APNS_ENABLED must be false: the gateway owns the APNs key"
            );
        }
    }

    if enabled && gateway_url.is_none() {
        if fcm_project_id.is_empty() {
            bail!(
                "FCM_PROJECT_ID is required when PUSH_ENABLED=true and PUSH_GATEWAY_URL is unset"
            );
        }
        if fcm_service_account_path.is_empty() {
            bail!(
                "FCM_SERVICE_ACCOUNT_PATH is required when PUSH_ENABLED=true and PUSH_GATEWAY_URL is unset"
            );
        }
    }

    let http_timeout = duration_from_millis(raw.http_timeout_ms, 10_000, "PUSH_HTTP_TIMEOUT_MS")?;

    let min_gap_high = duration_from_millis_or_zero(raw.min_gap_high_ms, 0);
    let min_gap_medium = duration_from_millis_or_zero(raw.min_gap_medium_ms, 10_000);
    let min_gap_low = duration_from_millis_or_zero(raw.min_gap_low_ms, 60_000);
    let min_gap_none = duration_from_millis_or_zero(raw.min_gap_none_ms, 120_000);
    // По умолчанию сообщение без приоритета будит так же, как любое другое,
    // только реже (`min_gap_none`). Выключается осознанно на конкретном
    // развёртывании.
    let wake_on_unspecified = raw.wake_on_unspecified.unwrap_or(true);

    let burst_high = raw.burst_high.unwrap_or(1).max(1);
    let burst_medium = raw.burst_medium.unwrap_or(3).max(1);
    let burst_low = raw.burst_low.unwrap_or(8).max(1);
    let burst_none = raw.burst_none.unwrap_or(15).max(1);

    let suppress_initial =
        duration_from_millis(raw.suppress_initial_ms, 30_000, "PUSH_SUPPRESS_INITIAL_MS")?;
    let suppress_max =
        duration_from_millis(raw.suppress_max_ms, 3_600_000, "PUSH_SUPPRESS_MAX_MS")?;

    if suppress_max < suppress_initial {
        bail!("PUSH_SUPPRESS_MAX_MS must be >= PUSH_SUPPRESS_INITIAL_MS");
    }

    let channel_capacity = raw.channel_capacity.unwrap_or(8192).max(1);
    let send_concurrency = raw
        .send_concurrency
        .unwrap_or(crate::push::DEFAULT_SEND_CONCURRENCY)
        .max(1);

    let apns_enabled = raw.apns_enabled.unwrap_or(false);
    let apns = if apns_enabled {
        let key_path = normalize_optional_text(raw.apns_key_path)
            .ok_or_else(|| anyhow::anyhow!("APNS_KEY_PATH is required when APNS_ENABLED=true"))?;
        let key_id = normalize_optional_text(raw.apns_key_id)
            .ok_or_else(|| anyhow::anyhow!("APNS_KEY_ID is required when APNS_ENABLED=true"))?;
        let team_id = normalize_optional_text(raw.apns_team_id)
            .ok_or_else(|| anyhow::anyhow!("APNS_TEAM_ID is required when APNS_ENABLED=true"))?;
        let bundle_id = normalize_optional_text(raw.apns_bundle_id)
            .ok_or_else(|| anyhow::anyhow!("APNS_BUNDLE_ID is required when APNS_ENABLED=true"))?;
        let environment =
            normalize_optional_text(raw.apns_environment).unwrap_or_else(|| "production".into());
        Some(ApnsConfig {
            key_path,
            key_id,
            team_id,
            bundle_id,
            environment,
        })
    } else {
        None
    };

    let ring_cooldown = duration_from_millis_or_zero(raw.ring_cooldown_ms, 3_000);

    Ok(PushConfig {
        enabled,
        gateway_url,
        gateway_timeout,
        fcm_project_id,
        fcm_service_account_path,
        http_timeout,
        min_gap_high,
        min_gap_medium,
        min_gap_low,
        min_gap_none,
        wake_on_unspecified,
        burst_high,
        burst_medium,
        burst_low,
        burst_none,
        suppress_initial,
        suppress_max,
        channel_capacity,
        send_concurrency,
        apns,
        ring_cooldown,
    })
}

fn duration_from_millis_or_zero(value: Option<u64>, default_ms: u64) -> Duration {
    Duration::from_millis(value.unwrap_or(default_ms))
}

// Плоское зеркало DELIVERY_*/NATS_* переменных: аргументы растут вместе с
// их числом, и группировать их в структуру значило бы заводить второй
// список тех же имён.
#[allow(clippy::too_many_arguments)]
fn resolve_delivery(
    delivery_backend: Option<String>,
    nats_url: Option<String>,
    nats_stream_name: Option<String>,
    nats_ack_wait_secs: Option<u64>,
    nats_consumer_inactive_threshold_days: Option<u64>,
    nats_stream_max_age_days: Option<u64>,
    nats_stream_max_bytes: Option<i64>,
    nats_max_msgs_per_subject: Option<i64>,
    nats_publish_timeout_ms: Option<u64>,
) -> anyhow::Result<DeliveryConfig> {
    let backend = match delivery_backend
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("sled")
        .to_ascii_lowercase()
        .as_str()
    {
        "sled" => DeliveryBackendKind::Sled,
        "jetstream" => DeliveryBackendKind::JetStream,
        other => bail!("DELIVERY_BACKEND must be `sled` or `jetstream` (got `{other}`)"),
    };

    let nats_url = nats_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("nats://nats:4222")
        .to_string();

    let nats_stream_name = nats_stream_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("messages")
        .to_string();

    let ack_wait_secs = nats_ack_wait_secs.unwrap_or(30);
    if ack_wait_secs == 0 {
        bail!("NATS_ACK_WAIT_SECS must be greater than 0");
    }

    // 30 дней по умолчанию — с запасом над `max_age` стрима (14 дней), чтобы
    // пересозданный после удаления consumer не перевыдавал ещё живые
    // сообщения (см. `DeliveryConfig::nats_consumer_inactive_threshold`).
    // Совпадает с дефолтом retention-политик выше.
    let inactive_threshold_days = nats_consumer_inactive_threshold_days.unwrap_or(30);
    if inactive_threshold_days == 0 {
        bail!("NATS_CONSUMER_INACTIVE_THRESHOLD_DAYS must be greater than 0");
    }

    // Лимиты стрима задаются явно: стрим с `Default::default()` безлимитен
    // и копит сообщения до заполнения диска.
    let stream_max_age_days = nats_stream_max_age_days.unwrap_or(14);
    if stream_max_age_days == 0 {
        bail!("NATS_STREAM_MAX_AGE_DAYS must be greater than 0");
    }
    if stream_max_age_days >= inactive_threshold_days {
        bail!(
            "NATS_CONSUMER_INACTIVE_THRESHOLD_DAYS ({inactive_threshold_days}) must exceed \
             NATS_STREAM_MAX_AGE_DAYS ({stream_max_age_days}): a consumer removed while its \
             messages are still alive is recreated with DeliverPolicy::All and redelivers them"
        );
    }

    let stream_max_bytes = nats_stream_max_bytes.unwrap_or(350 * 1024 * 1024);
    if stream_max_bytes <= 0 {
        bail!("NATS_STREAM_MAX_BYTES must be greater than 0");
    }

    // Тот же потолок, что у очереди прямого бэкенда: оба бэкенда отвечают
    // `FULL` на одной глубине. Считаются только недоставленные конверты, и
    // 10 000 — с большим запасом над тем, что получатель копит за `max_age`
    // потока в обычной переписке, а ящик, забиваемый мелкими конвертами,
    // упирается в свой потолок, не трогая остальных. «Без ограничения» не
    // предусмотрено: тогда один ящик снова мог бы занять поток целиком.
    let max_msgs_per_subject = nats_max_msgs_per_subject.unwrap_or(10_000);
    if max_msgs_per_subject <= 0 {
        bail!("NATS_MAX_MSGS_PER_SUBJECT must be greater than 0");
    }

    // Две секунды — заметно меньше дефолта самого клиента NATS (~5 с) и
    // заметно больше round-trip до здорового брокера в той же сети:
    // отправитель узнаёт о мёртвом брокере за две секунды, а не за пять.
    let publish_timeout_ms = nats_publish_timeout_ms.unwrap_or(2_000);
    if publish_timeout_ms == 0 {
        bail!("NATS_PUBLISH_TIMEOUT_MS must be greater than 0");
    }

    Ok(DeliveryConfig {
        backend,
        nats_url,
        nats_stream_name,
        nats_ack_wait: Duration::from_secs(ack_wait_secs),
        nats_consumer_inactive_threshold: Duration::from_secs(
            inactive_threshold_days * 24 * 60 * 60,
        ),
        nats_stream_max_age: Duration::from_secs(stream_max_age_days * 24 * 60 * 60),
        nats_stream_max_bytes: stream_max_bytes,
        nats_max_msgs_per_subject: max_msgs_per_subject,
        nats_publish_timeout: Duration::from_millis(publish_timeout_ms),
    })
}

fn parse_retention_policy(
    value: Option<String>,
    default_days: u64,
    field_name: &str,
) -> anyhow::Result<RetentionPolicy> {
    let Some(raw) = value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return retention_days(default_days, field_name);
    };

    let normalized = raw.to_ascii_lowercase();
    match normalized.as_str() {
        "disabled" | "disable" | "off" | "none" | "false" | "infinite" | "infinity" => {
            return Ok(RetentionPolicy::Disabled);
        }
        "instant" | "immediate" | "0" | "0d" | "0day" | "0days" => {
            return Ok(RetentionPolicy::Immediate);
        }
        _ => {}
    }

    let days = normalized
        .strip_suffix("days")
        .or_else(|| normalized.strip_suffix("day"))
        .or_else(|| normalized.strip_suffix('d'))
        .unwrap_or(&normalized)
        .trim();

    let days = days.parse::<u64>().map_err(|err| {
        anyhow!(
            "{field_name} must be a positive number of days or one of: disabled, instant ({err})"
        )
    })?;

    if days == 0 {
        return Ok(RetentionPolicy::Immediate);
    }

    retention_days(days, field_name)
}

fn retention_days(days: u64, field_name: &str) -> anyhow::Result<RetentionPolicy> {
    let secs = days
        .checked_mul(24 * 60 * 60)
        .ok_or_else(|| anyhow!("{field_name} is too large"))?;
    Ok(RetentionPolicy::KeepFor(Duration::from_secs(secs)))
}

/// Границы keepalive — те, что принимает Linux (`TCP_KEEPIDLE` и
/// `TCP_KEEPINTVL` до 32 767 с, `TCP_KEEPCNT` до 127). Значение вне них
/// ядро отвергает на каждом принятом сокете, и нода работала бы без
/// keepalive, сообщая об этом только предупреждениями в логе.
fn check_tcp_keepalive(limits: &LimitsConfig) -> anyhow::Result<()> {
    const MAX_SECS: u64 = 32_767;
    const MAX_RETRIES: u32 = 127;
    if limits.tcp_keepalive_secs == 0 {
        return Ok(());
    }
    if limits.tcp_keepalive_secs > MAX_SECS {
        bail!("TCP_KEEPALIVE_SECS must be at most {MAX_SECS} (0 disables keepalive)");
    }
    if !(1..=MAX_SECS).contains(&limits.tcp_keepalive_interval_secs) {
        bail!("TCP_KEEPALIVE_INTERVAL_SECS must be between 1 and {MAX_SECS}");
    }
    if !(1..=MAX_RETRIES).contains(&limits.tcp_keepalive_retries) {
        bail!("TCP_KEEPALIVE_RETRIES must be between 1 and {MAX_RETRIES}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LimitsConfig, PushRawConfig, RetentionPolicy, check_tcp_keepalive, parse_retention_policy,
        resolve_delivery, resolve_push,
    };
    use std::time::Duration;

    fn push_raw(enabled: bool) -> PushRawConfig {
        PushRawConfig {
            enabled: Some(enabled),
            gateway_url: None,
            gateway_timeout_ms: None,
            fcm_project_id: None,
            fcm_service_account_path: None,
            http_timeout_ms: None,
            min_gap_high_ms: None,
            min_gap_medium_ms: None,
            min_gap_low_ms: None,
            min_gap_none_ms: None,
            wake_on_unspecified: None,
            burst_high: None,
            burst_medium: None,
            burst_low: None,
            burst_none: None,
            suppress_initial_ms: None,
            suppress_max_ms: None,
            channel_capacity: None,
            send_concurrency: None,
            apns_enabled: None,
            apns_key_path: None,
            apns_key_id: None,
            apns_team_id: None,
            apns_bundle_id: None,
            apns_environment: None,
            ring_cooldown_ms: None,
        }
    }

    /// Локальный режим: без шлюза креды FCM обязательны.
    #[test]
    fn local_mode_still_requires_fcm_credentials() {
        let err = resolve_push(push_raw(true)).unwrap_err().to_string();
        assert!(err.contains("FCM_PROJECT_ID"), "unexpected error: {err}");

        let mut raw = push_raw(true);
        raw.fcm_project_id = Some("proj".into());
        raw.fcm_service_account_path = Some("/secrets/sa.json".into());
        let cfg = resolve_push(raw).unwrap();
        assert!(cfg.gateway_url.is_none());
    }

    /// Режим шлюза: кредов на ноде нет, и это не ошибка конфигурации.
    #[test]
    fn gateway_mode_needs_no_local_credentials() {
        let mut raw = push_raw(true);
        raw.gateway_url = Some("https://push.example.org".into());
        let cfg = resolve_push(raw).unwrap();
        assert_eq!(cfg.gateway_url.as_deref(), Some("https://push.example.org"));
        assert_eq!(cfg.gateway_timeout, Duration::from_millis(10_000));
    }

    /// Смешанная конфигурация отвергается: молча выбрать за оператора один
    /// из режимов нельзя — «половина пушей мимо шлюза» иначе ничем не
    /// диагностируется.
    #[test]
    fn gateway_and_local_credentials_are_mutually_exclusive() {
        let mut raw = push_raw(true);
        raw.gateway_url = Some("https://push.example.org".into());
        raw.fcm_project_id = Some("proj".into());
        let err = resolve_push(raw).unwrap_err().to_string();
        assert!(err.contains("must not be"), "unexpected error: {err}");

        let mut raw = push_raw(true);
        raw.gateway_url = Some("https://push.example.org".into());
        raw.apns_enabled = Some(true);
        let err = resolve_push(raw).unwrap_err().to_string();
        assert!(err.contains("APNS_ENABLED"), "unexpected error: {err}");
    }

    /// Шлюз по http в сети отвергается уже при разборе конфига: по нему
    /// открытым текстом уезжали бы push-токены устройств.
    #[test]
    fn plaintext_gateway_outside_loopback_is_rejected() {
        let mut raw = push_raw(true);
        raw.gateway_url = Some("http://push.example.org".into());
        let err = resolve_push(raw).unwrap_err().to_string();
        assert!(err.contains("must use https"), "unexpected error: {err}");

        let mut raw = push_raw(true);
        raw.gateway_url = Some("http://127.0.0.1:50051".into());
        assert!(resolve_push(raw).is_ok());
    }

    /// Выключенные пуши не обязаны иметь ни кредов, ни шлюза — dev и CI
    /// поднимаются без единого секрета.
    #[test]
    fn disabled_push_needs_nothing() {
        let cfg = resolve_push(push_raw(false)).unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.gateway_url.is_none());
    }

    fn delivery(
        inactive_days: Option<u64>,
        max_age_days: Option<u64>,
        max_bytes: Option<i64>,
    ) -> anyhow::Result<super::DeliveryConfig> {
        resolve_delivery(
            Some("jetstream".to_string()),
            None,
            None,
            None,
            inactive_days,
            max_age_days,
            max_bytes,
            None,
            None,
        )
    }

    /// Дефолты лимитов стрима (14 дней / 350 MiB / 10 000 конвертов на ящик)
    /// зафиксированы тестом:
    /// `ensure_stream` применяет их и к уже существующему стриму, так что их
    /// смена молча переконфигурирует развёрнутые ноды при следующем деплое.
    #[test]
    fn delivery_defaults_match_production_stream_limits() {
        let cfg = delivery(None, None, None).unwrap();
        assert_eq!(cfg.nats_stream_max_age, Duration::from_secs(14 * 24 * 3600));
        assert_eq!(cfg.nats_stream_max_bytes, 350 * 1024 * 1024);
        assert_eq!(cfg.nats_max_msgs_per_subject, 10_000);
        assert_eq!(
            cfg.nats_consumer_inactive_threshold,
            Duration::from_secs(30 * 24 * 3600)
        );
        // Дефолт таймаута публикации обязан быть заметно короче дефолта
        // самого клиента NATS (~5 с) — иначе он не меняет ничего.
        assert_eq!(cfg.nats_publish_timeout, Duration::from_millis(2_000));
        assert!(cfg.nats_publish_timeout < Duration::from_secs(5));
    }

    /// Нулевой таймаут публикации означал бы «отказывать всегда»; такую
    /// конфигурацию нода не должна принимать молча.
    #[test]
    fn rejects_zero_publish_timeout() {
        let err = resolve_delivery(
            Some("jetstream".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("NATS_PUBLISH_TIMEOUT_MS"), "got: {err}");
    }

    /// Consumer, удалённый раньше, чем истекли его сообщения, пересоздаётся
    /// с `DeliverPolicy::All` и выдаёт их повторно. Конфигурация, допускающая
    /// это, должна падать на старте, а не в проде дублями у пользователя.
    #[test]
    fn rejects_consumer_threshold_below_stream_max_age() {
        let err = delivery(Some(7), Some(14), None).unwrap_err().to_string();
        assert!(
            err.contains("must exceed"),
            "expected threshold-vs-max-age complaint, got: {err}"
        );

        // Равенство тоже отвергаем: гонка на границе даёт тот же дубль.
        assert!(delivery(Some(14), Some(14), None).is_err());
        assert!(delivery(Some(15), Some(14), None).is_ok());
    }

    /// Потолок ящика обязателен: без него один ящик снова занимал бы поток
    /// целиком, и отказ получали бы все отправители.
    #[test]
    fn rejects_non_positive_mailbox_cap() {
        let cap = |value: i64| {
            resolve_delivery(
                Some("jetstream".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
                Some(value),
                None,
            )
        };
        for value in [0, -1] {
            let err = cap(value).unwrap_err().to_string();
            assert!(err.contains("NATS_MAX_MSGS_PER_SUBJECT"), "got: {err}");
        }
        assert_eq!(cap(3).unwrap().nats_max_msgs_per_subject, 3);
    }

    #[test]
    fn rejects_non_positive_stream_limits() {
        assert!(delivery(Some(0), None, None).is_err());
        assert!(delivery(None, Some(0), None).is_err());
        assert!(delivery(None, None, Some(0)).is_err());
        assert!(delivery(None, None, Some(-1)).is_err());
    }

    #[test]
    fn parses_default_retention_policy_as_30_days() {
        assert_eq!(
            parse_retention_policy(None, 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::KeepFor(Duration::from_secs(30 * 24 * 60 * 60))
        );
    }

    #[test]
    fn parses_disabled_retention_policy_aliases() {
        assert_eq!(
            parse_retention_policy(Some("disabled".to_string()), 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::Disabled
        );
        assert_eq!(
            parse_retention_policy(Some("off".to_string()), 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::Disabled
        );
    }

    #[test]
    fn parses_immediate_retention_policy_aliases() {
        assert_eq!(
            parse_retention_policy(Some("instant".to_string()), 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::Immediate
        );
        assert_eq!(
            parse_retention_policy(Some("0".to_string()), 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::Immediate
        );
    }

    #[test]
    fn parses_numeric_retention_policy_in_days() {
        assert_eq!(
            parse_retention_policy(Some("45d".to_string()), 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::KeepFor(Duration::from_secs(45 * 24 * 60 * 60))
        );
        assert_eq!(
            parse_retention_policy(Some("15".to_string()), 30, "TEST_RETENTION").unwrap(),
            RetentionPolicy::KeepFor(Duration::from_secs(15 * 24 * 60 * 60))
        );
    }

    /// Дефолт keepalive проходит проверку, `0` выключает её целиком, а
    /// значения, которые ядро отвергло бы на каждом сокете, ловятся на
    /// старте.
    #[test]
    fn tcp_keepalive_bounds_are_checked_at_startup() {
        let defaults = LimitsConfig::default();
        assert!(check_tcp_keepalive(&defaults).is_ok());

        let disabled = LimitsConfig {
            tcp_keepalive_secs: 0,
            tcp_keepalive_interval_secs: 0,
            tcp_keepalive_retries: 0,
            ..defaults
        };
        assert!(check_tcp_keepalive(&disabled).is_ok());

        for (secs, interval, retries, field) in [
            (32_768, 15, 4, "TCP_KEEPALIVE_SECS"),
            (60, 0, 4, "TCP_KEEPALIVE_INTERVAL_SECS"),
            (60, 32_768, 4, "TCP_KEEPALIVE_INTERVAL_SECS"),
            (60, 15, 0, "TCP_KEEPALIVE_RETRIES"),
            (60, 15, 128, "TCP_KEEPALIVE_RETRIES"),
        ] {
            let limits = LimitsConfig {
                tcp_keepalive_secs: secs,
                tcp_keepalive_interval_secs: interval,
                tcp_keepalive_retries: retries,
                ..defaults
            };
            let err = check_tcp_keepalive(&limits).unwrap_err().to_string();
            assert!(
                err.contains(field),
                "expected {field} complaint, got: {err}"
            );
        }
    }
}
