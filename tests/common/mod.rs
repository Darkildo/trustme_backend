//! Общий каркас интеграционных тестов: поднять ноду на loopback, открыть
//! Noise-сессию, послать/принять кадр. Живёт отдельно, потому что им
//! пользуются и тесты сессии, и флуд-тест квот.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use trust_message_tcp::config::{
    Config, DeliveryBackendKind, DeliveryConfig, LimitsConfig, MetricsConfig, PushConfig,
    RetentionPolicy, ServerConfigSnapshot,
};
use trust_message_tcp::delivery::{DeliveryBackend, SledBackend};
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::net::framing::verify_signed_server_config;
use trust_message_tcp::net::listener::accept_loop;
use trust_message_tcp::net::noise::{NodeIdentity, NoiseFramed};
use trust_message_tcp::push::{
    InMemoryTokenStore, MockTransport, NoopStatePersistence, PushScheduler,
};
use trust_message_tcp::state::{registry::ConnRegistry, storage::Storage};
use trust_message_tcp::wire::{self, Frame, frame};

pub const FRAME_MAX: usize = 1024 * 1024;
/// Версия wire-протокола, которую заявляет тестовый клиент. Должна
/// совпадать с версией ноды: несовпадение — отказ на хендшейке.
pub const PROTO_VERSION: u32 = 1;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

pub fn disabled_push_config() -> PushConfig {
    PushConfig {
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

/// Конфигурация тестовой ноды. Собирается целиком, потому что тесты
/// поднимают настоящий `accept_loop`: копия accept-цикла в харнессе
/// оставила бы боевой цикл непроверенным.
pub fn test_config(storage_path: &str, limits: LimitsConfig) -> Config {
    Config {
        queue_addressing_enabled: false,
        bind_addr: "127.0.0.1:0".to_string(),
        storage_path: storage_path.to_string(),
        node_identity_key: None,
        server_config_ttl: Duration::from_secs(3600),
        advertised_address: None,
        handshake_timeout: HANDSHAKE_TIMEOUT,
        noise_allow_tofu: true,
        max_frame_len: FRAME_MAX,
        metrics: MetricsConfig {
            enabled: false,
            addr: String::new(),
        },
        deleted_messages_retention: RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
        offline_messages_retention: RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
        delivery: DeliveryConfig {
            backend: DeliveryBackendKind::Sled,
            nats_url: String::new(),
            nats_stream_name: "test".to_string(),
            nats_ack_wait: Duration::from_secs(30),
            nats_consumer_inactive_threshold: Duration::from_secs(30 * 86_400),
            nats_stream_max_age: Duration::from_secs(14 * 86_400),
            nats_stream_max_bytes: 1024 * 1024,
            nats_publish_timeout: Duration::from_millis(500),
        },
        push: disabled_push_config(),
        limits,
    }
}

pub fn snapshot() -> ServerConfigSnapshot {
    ServerConfigSnapshot {
        supports_queue_addressing: false,
        max_frame_len: FRAME_MAX,
        supports_device_addressing: true,
        deleted_messages_retention: RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
        offline_messages_retention: RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
        supports_delivery_ack: false,
        config_ttl: Duration::from_secs(3600),
        advertised_address: None,
    }
}

pub fn temp_storage_path(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("trust_message_tcp_noise_{label}_{nanos}"));
    path.to_string_lossy().into_owned()
}

pub struct ServerHandle {
    pub addr: std::net::SocketAddr,
    pub node_public: [u8; 32],
    pub storage_path: String,
}

/// Проверить подписанный снапшот так, как это обязан делать клиент, и
/// вернуть его содержимое.
pub fn expect_signed_config(
    bytes: &[u8],
    pinned_static: &[u8; 32],
) -> Result<trust_message_tcp::wire::ServerConfig> {
    match decode(bytes)? {
        frame::Payload::SignedServerConfig(signed) => {
            verify_signed_server_config(&signed, pinned_static, unix_now_secs())
        }
        frame::Payload::AuthError(err) => bail!("unexpected AuthError: {}", err.message),
        _ => bail!("expected SignedServerConfig"),
    }
}

pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.storage_path);
    }
}

pub async fn spawn_server(label: &str, limits: LimitsConfig) -> Result<ServerHandle> {
    spawn_node(label, limits, None, false).await
}

/// Нода с включённой адресацией по очередям. Отдельный конструктор, а не
/// поле в `LimitsConfig`: это не лимит, а режим маршрутизации, и тесты
/// обеих веток должны стоять рядом.
pub async fn spawn_server_with_queue_addressing(
    label: &str,
    limits: LimitsConfig,
) -> Result<ServerHandle> {
    spawn_node(label, limits, None, true).await
}

/// Нода на брокерном бэкенде. `ack_wait` задаётся тестом: передоставку с
/// боевыми тридцатью секундами не проверить, а суть брокерного тракта
/// именно в ней.
pub async fn spawn_jetstream_server(
    label: &str,
    limits: LimitsConfig,
    nats_url: &str,
    ack_wait: Duration,
) -> Result<ServerHandle> {
    spawn_node(
        label,
        limits,
        Some(JetStreamSetup {
            nats_url: nats_url.to_string(),
            ack_wait,
        }),
        false,
    )
    .await
}

pub struct JetStreamSetup {
    pub nats_url: String,
    pub ack_wait: Duration,
}

/// Имя потока общее для всех тестов: JetStream запрещает двум
/// потокам разделять subject, а subject'ы ноды фиксированы (`msg.user.*`).
/// Изоляция тестов держится на разных ключах пользователей — у каждого
/// свой subject и свой durable-consumer.
pub const TEST_STREAM_NAME: &str = "trust_message_tcp_tests";

async fn spawn_node(
    label: &str,
    limits: LimitsConfig,
    jetstream: Option<JetStreamSetup>,
    queue_addressing: bool,
) -> Result<ServerHandle> {
    let storage_path = temp_storage_path(label);
    let storage = Storage::open(
        &storage_path,
        RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
        RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
    )?;
    let registry = ConnRegistry::default();
    let push_tokens = storage.push_token_store()?;
    let push_scheduler = PushScheduler::start(
        disabled_push_config(),
        Arc::new(MockTransport::always_ok()),
        Arc::new(InMemoryTokenStore::default()),
        Arc::new(NoopStatePersistence),
    );

    let node = Arc::new(NodeIdentity::load_or_generate(&storage_path, None)?);
    let node_public = node.public();
    let mut cfg = test_config(&storage_path, limits);
    cfg.queue_addressing_enabled = queue_addressing;
    if let Some(setup) = &jetstream {
        cfg.delivery.backend = DeliveryBackendKind::JetStream;
        cfg.delivery.nats_url = setup.nats_url.clone();
        cfg.delivery.nats_stream_name = TEST_STREAM_NAME.to_string();
        cfg.delivery.nats_ack_wait = setup.ack_wait;
    }

    let delivery = if jetstream.is_some() {
        DeliveryBackend::from_config(
            &cfg,
            storage.clone(),
            push_tokens.clone(),
            push_scheduler.clone(),
        )
        .await?
    } else {
        DeliveryBackend::Sled(SledBackend::new(storage.clone()))
    };

    let listener = TcpListener::bind(&cfg.bind_addr).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(accept_loop(
        listener,
        registry,
        storage,
        delivery,
        push_tokens,
        push_scheduler,
        node,
        cfg,
    ));

    Ok(ServerHandle {
        addr,
        node_public,
        storage_path,
    })
}

pub async fn connect(
    server: &ServerHandle,
    identity: &SigningKey,
) -> Result<NoiseFramed<TcpStream>> {
    connect_as(server, identity, Some(1), FRAME_MAX).await
}

/// Подключиться с произвольным device_id и потолком кадра. Потолок нужен
/// тестам, которые проверяют реакцию ноды на слишком большой кадр: чтобы
/// его отправить, клиент должен считать его допустимым.
pub async fn connect_as(
    server: &ServerHandle,
    identity: &SigningKey,
    device_id: Option<u16>,
    max_frame_len: usize,
) -> Result<NoiseFramed<TcpStream>> {
    let stream = TcpStream::connect(server.addr).await?;
    NoiseFramed::connect(
        stream,
        &server.node_public,
        identity,
        device_id,
        HANDSHAKE_TIMEOUT,
        max_frame_len,
    )
    .await
}

/// Дождаться кадра, ожидая, что соединение закроется или сломается.
/// Возвращает `true`, если нода прекратила диалог.
pub async fn expect_connection_gone(conn: &mut NoiseFramed<TcpStream>) -> bool {
    match timeout(SOCKET_TIMEOUT, conn.next_frame()).await {
        // Закрыт штатно либо с ошибкой чтения — оба случая означают
        // «нода прекратила диалог».
        Ok(Ok(None)) | Ok(Err(_)) => true,
        Ok(Ok(Some(_))) => false,
        Err(_) => false,
    }
}

pub async fn next_frame(conn: &mut NoiseFramed<TcpStream>) -> Result<Vec<u8>> {
    let frame = timeout(SOCKET_TIMEOUT, conn.next_frame())
        .await
        .context("read frame timed out")?
        .context("read frame failed")?
        .ok_or_else(|| anyhow::anyhow!("connection closed without a frame"))?;
    Ok(frame.to_vec())
}

pub fn encode_get_server_config() -> Result<Vec<u8>> {
    Ok(wrap(frame::Payload::GetServerConfig(
        wire::GetServerConfig {},
    )))
}

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

pub fn decode(bytes: &[u8]) -> Result<frame::Payload> {
    Frame::decode(bytes)
        .context("decode frame")?
        .payload
        .context("frame carries no payload")
}

pub fn expect_auth_ok(bytes: &[u8], expected_user: &[u8; 32]) -> Result<()> {
    match decode(bytes)? {
        frame::Payload::AuthOk(ok) => {
            if ok.user_id != expected_user.as_slice() {
                bail!("AuthOk carries a different user id");
            }
            if ok.server_time == 0 {
                bail!("AuthOk carries no server time");
            }
            Ok(())
        }
        frame::Payload::AuthError(err) => bail!("unexpected AuthError: {}", err.message),
        _ => bail!("expected AuthOk as the first frame of a noise session"),
    }
}

/// Кадр `ClientSend`. `ttl_seconds = 0` — «срок не задан» (legacy-значение),
/// им пользуются проверки, которым пол ttl мешать не должен.
pub fn encode_client_send(
    recipient: &[u8; 32],
    device_id: Option<u16>,
    body: &[u8],
    ttl_seconds: u64,
) -> Result<Vec<u8>> {
    Ok(wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: recipient.to_vec(),
        body: body.to_vec(),
        recipient_device_id: device_id.map(u32::from),
        ttl_seconds,
        ..wire::ClientSend::default()
    })))
}

/// Ответ ноды на отправку, разобранный до полей.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub ok: bool,
    pub queued: bool,
    pub queue_id: u64,
    pub reason: SendRejectReason,
}

/// Отправить готовый кадр и дождаться `SendAck`. Нужен там, где кадр
/// собирается тестом целиком — например, с пустым `recipientId` и
/// заполненным `queueId`.
pub async fn send_raw_and_read_ack(
    conn: &mut NoiseFramed<TcpStream>,
    frame_bytes: &[u8],
) -> Result<Ack> {
    conn.send_frame(frame_bytes).await?;
    let bytes = next_frame(conn).await?;
    match decode(&bytes)? {
        frame::Payload::SendAck(ack) => Ok(Ack {
            ok: ack.ok,
            queued: ack.queued,
            queue_id: ack.queue_id,
            reason: SendRejectReason::from_wire(ack.reason),
        }),
        _ => bail!("expected SendAck"),
    }
}

/// Отправить `ClientSend` и дождаться `SendAck` — то, чем меряется любая
/// квота: клиент видит отказ именно так.
pub async fn send_and_read_ack(
    conn: &mut NoiseFramed<TcpStream>,
    recipient: &[u8; 32],
    body: &[u8],
    ttl_seconds: u64,
) -> Result<Ack> {
    conn.send_frame(&encode_client_send(recipient, None, body, ttl_seconds)?)
        .await?;
    let bytes = next_frame(conn).await?;
    match decode(&bytes)? {
        frame::Payload::SendAck(ack) => Ok(Ack {
            ok: ack.ok,
            queued: ack.queued,
            queue_id: ack.queue_id,
            reason: SendRejectReason::from_wire(ack.reason),
        }),
        _ => bail!("expected SendAck"),
    }
}

/// Идентичность со случайным ключом. В брокерных тестах она заодно и
/// изоляция: у каждого пользователя свой subject в общем потоке, поэтому
/// прогоны не видят чужих конвертов и не зависят от порядка.
pub fn random_identity() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("system randomness");
    SigningKey::from_bytes(&seed)
}

pub fn encode_delivery_ack(message_id: u64) -> Vec<u8> {
    wrap(frame::Payload::DeliveryAck(wire::DeliveryAck {
        message_id,
    }))
}

/// Входящий конверт, разобранный до полей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub from_user_id: Vec<u8>,
    pub message_id: u64,
    pub body: Vec<u8>,
}

pub fn expect_incoming(bytes: &[u8]) -> Result<Incoming> {
    match decode(bytes)? {
        frame::Payload::Incoming(incoming) => Ok(Incoming {
            from_user_id: incoming.from_user_id,
            message_id: incoming.message_id,
            body: incoming.body,
        }),
        frame::Payload::AuthError(err) => {
            bail!("unexpected AuthError {}: {}", err.code, err.message)
        }
        other => bail!("expected IncomingMessage, got {other:?}"),
    }
}

/// Дождаться входящего конверта не дольше `within`. `None` — не пришло
/// ничего: для теста «конверт больше не приходит» это ожидаемый исход, и
/// отличать его от ошибки чтения обязательно.
pub async fn next_incoming_within(
    conn: &mut NoiseFramed<TcpStream>,
    within: Duration,
) -> Result<Option<Incoming>> {
    match timeout(within, conn.next_frame()).await {
        Ok(Ok(Some(frame))) => Ok(Some(expect_incoming(&frame)?)),
        Ok(Ok(None)) => bail!("connection closed while waiting for an envelope"),
        Ok(Err(err)) => Err(err).context("read frame failed"),
        Err(_) => Ok(None),
    }
}

/// `user_id` клиента — его Ed25519-ключ как есть; статик Noise нода
/// получает из него конверсией.
pub fn user_id_of(identity: &SigningKey) -> [u8; 32] {
    identity.verifying_key().to_bytes()
}
