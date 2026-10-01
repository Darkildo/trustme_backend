//! Общий каркас интеграционных тестов: поднять ноду на loopback, открыть
//! Noise-сессию, послать/принять кадр. Живёт отдельно, потому что им
//! пользуются и тесты сессии, и флуд-тест квот.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        send_concurrency: trust_message_tcp::push::DEFAULT_SEND_CONCURRENCY,
        apns: None,
        ring_cooldown: Duration::from_secs(3),
    }
}

/// Включённый push без пауз между отправками: тестам нужен исход, а не
/// троттлинг.
pub fn enabled_push_config() -> PushConfig {
    PushConfig {
        enabled: true,
        min_gap_medium: Duration::ZERO,
        suppress_initial: Duration::from_secs(1),
        suppress_max: Duration::from_secs(8),
        ..disabled_push_config()
    }
}

/// Конфигурация тестовой ноды. Собирается целиком, потому что тесты
/// поднимают настоящий `accept_loop`: копия accept-цикла в харнессе
/// оставила бы боевой цикл непроверенным.
pub fn test_config(storage_path: &str, limits: LimitsConfig) -> Config {
    Config {
        queue_addressing_enabled: false,
        device_cert_max_ttl: Duration::from_secs(30 * 24 * 3600),
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
            nats_max_msgs_per_subject: 10_000,
            nats_publish_timeout: Duration::from_millis(500),
        },
        push: disabled_push_config(),
        limits,
    }
}

pub fn snapshot() -> ServerConfigSnapshot {
    ServerConfigSnapshot {
        supports_queue_addressing: false,
        device_cert_max_ttl: Duration::from_secs(30 * 24 * 3600),
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
    spawn_node(label, limits, NodeOptions::default()).await
}

/// Нода с включённой адресацией по очередям. Отдельный конструктор, а не
/// поле в `LimitsConfig`: это не лимит, а режим маршрутизации, и тесты
/// обеих веток должны стоять рядом.
pub async fn spawn_server_with_queue_addressing(
    label: &str,
    limits: LimitsConfig,
) -> Result<ServerHandle> {
    spawn_node(
        label,
        limits,
        NodeOptions {
            queue_addressing: true,
            ..NodeOptions::default()
        },
    )
    .await
}

/// Нода с включённым push. Планировщик разрешает токены из того же
/// хранилища, куда их пишет сессия, а отправленное видно в возвращённом
/// транспорте.
pub async fn spawn_server_with_push(
    label: &str,
    limits: LimitsConfig,
) -> Result<(ServerHandle, Arc<MockTransport>)> {
    let transport = Arc::new(MockTransport::always_ok());
    let server = spawn_node(
        label,
        limits,
        NodeOptions {
            push: Some(transport.clone()),
            ..NodeOptions::default()
        },
    )
    .await?;
    Ok((server, transport))
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
        NodeOptions {
            jetstream: Some(JetStreamSetup {
                nats_url: nats_url.to_string(),
                ack_wait,
            }),
            ..NodeOptions::default()
        },
    )
    .await
}

pub struct JetStreamSetup {
    pub nats_url: String,
    pub ack_wait: Duration,
}

#[derive(Default)]
struct NodeOptions {
    jetstream: Option<JetStreamSetup>,
    queue_addressing: bool,
    /// `Some` — push включён и отправляет в этот транспорт.
    push: Option<Arc<MockTransport>>,
}

/// Имя потока общее для всех тестов: JetStream запрещает двум
/// потокам разделять subject, а subject'ы ноды фиксированы (`msg.user.*`).
/// Изоляция тестов держится на разных ключах пользователей — у каждого
/// свой subject и свой durable-consumer.
pub const TEST_STREAM_NAME: &str = "trust_message_tcp_tests";

async fn spawn_node(
    label: &str,
    limits: LimitsConfig,
    options: NodeOptions,
) -> Result<ServerHandle> {
    let NodeOptions {
        jetstream,
        queue_addressing,
        push,
    } = options;
    let storage_path = temp_storage_path(label);
    let storage = Storage::open(
        &storage_path,
        RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
        RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400)),
    )?;
    let registry = ConnRegistry::default();
    let push_tokens = storage.push_token_store()?;
    let push_scheduler = match push {
        Some(transport) => PushScheduler::start(
            enabled_push_config(),
            transport,
            Arc::new(push_tokens.clone()),
            Arc::new(NoopStatePersistence),
        ),
        None => PushScheduler::start(
            disabled_push_config(),
            Arc::new(MockTransport::always_ok()),
            Arc::new(InMemoryTokenStore::default()),
            Arc::new(NoopStatePersistence),
        ),
    };

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

/// Клиентская сторона Noise-сессии в тестах.
///
/// Нода считает сессию своей только после первого кадра клиента, поэтому
/// хелперы подключения подтверждают её сами (см. [`confirm`]) и по ходу
/// читают кадры раньше теста. Прочитанное не теряется: оно лежит здесь и
/// отдаётся первым, в исходном порядке. Методы повторяют `NoiseFramed`,
/// так что тест работает с соединением как с обычным каналом.
pub struct Conn {
    inner: NoiseFramed<TcpStream>,
    early: VecDeque<BytesMut>,
}

impl Conn {
    /// Канал как есть: ничего не прочитано и не отправлено.
    pub fn raw(inner: NoiseFramed<TcpStream>) -> Self {
        Self {
            inner,
            early: VecDeque::new(),
        }
    }

    /// Cancel-safe, как и `NoiseFramed::next_frame`: отложенный кадр
    /// отдаётся без ожидания.
    pub async fn next_frame(&mut self) -> io::Result<Option<BytesMut>> {
        match self.early.pop_front() {
            Some(frame) => Ok(Some(frame)),
            None => self.inner.next_frame().await,
        }
    }

    pub async fn send_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        self.inner.send_frame(payload).await
    }
}

pub async fn connect(server: &ServerHandle, identity: &SigningKey) -> Result<Conn> {
    connect_as(server, identity, Some(1), FRAME_MAX).await
}

/// Подключиться с произвольным device_id и потолком кадра и подтвердить
/// сессию. Потолок нужен тестам, которые проверяют реакцию ноды на слишком
/// большой кадр: чтобы его отправить, клиент должен считать его допустимым.
pub async fn connect_as(
    server: &ServerHandle,
    identity: &SigningKey,
    device_id: Option<u16>,
    max_frame_len: usize,
) -> Result<Conn> {
    confirm(handshake(server, identity, device_id, max_frame_len).await?).await
}

/// Подключиться, но сессию не подтверждать: после хендшейка ни одного кадра
/// не отправлено и не прочитано. Для тестов того, что нода делает до
/// подтверждения.
pub async fn connect_unconfirmed(
    server: &ServerHandle,
    identity: &SigningKey,
    device_id: Option<u16>,
) -> Result<Conn> {
    Ok(Conn::raw(
        handshake(server, identity, device_id, FRAME_MAX).await?,
    ))
}

async fn handshake(
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

/// Подтвердить сессию так, как обязан клиент: получив `AuthOk`, сразу
/// отправить `Ping` и дождаться `Pong`.
///
/// `AuthOk` и всё, что нода прислала до `Pong` (офлайн-реплей приходит
/// раньше него), остаётся тесту; сам `Pong` поглощается — его ждал хелпер,
/// а не тест. Если первым пришёл не `AuthOk` или соединение закрылось,
/// подтверждать нечего: что именно случилось, тест увидит сам.
pub async fn confirm(inner: NoiseFramed<TcpStream>) -> Result<Conn> {
    let mut conn = Conn::raw(inner);
    let Some(first) = read_or_closed(&mut conn.inner).await? else {
        return Ok(conn);
    };
    let auth_ok = matches!(decode(&first), Ok(frame::Payload::AuthOk(_)));
    conn.early.push_back(first);
    if !auth_ok {
        return Ok(conn);
    }

    conn.inner
        .send_frame(&encode_ping())
        .await
        .context("send the confirming ping")?;
    while let Some(frame) = read_or_closed(&mut conn.inner).await? {
        if matches!(decode(&frame), Ok(frame::Payload::Pong(_))) {
            break;
        }
        conn.early.push_back(frame);
    }
    Ok(conn)
}

/// Следующий кадр либо `None`, если нода закрыла соединение — штатно или
/// так, что чтение сломалось: разбираться с закрытием будет тест.
async fn read_or_closed(inner: &mut NoiseFramed<TcpStream>) -> Result<Option<BytesMut>> {
    match timeout(SOCKET_TIMEOUT, inner.next_frame()).await {
        Ok(Ok(Some(frame))) => Ok(Some(frame)),
        Ok(Ok(None)) | Ok(Err(_)) => Ok(None),
        Err(_) => bail!("node sent nothing for {SOCKET_TIMEOUT:?} while the session was confirmed"),
    }
}

pub fn encode_ping() -> Vec<u8> {
    wrap(frame::Payload::Ping(wire::Ping {}))
}

/// Дождаться кадра, ожидая, что соединение закроется или сломается.
/// Возвращает `true`, если нода прекратила диалог.
pub async fn expect_connection_gone(conn: &mut Conn) -> bool {
    match timeout(SOCKET_TIMEOUT, conn.next_frame()).await {
        // Закрыт штатно либо с ошибкой чтения — оба случая означают
        // «нода прекратила диалог».
        Ok(Ok(None)) | Ok(Err(_)) => true,
        Ok(Ok(Some(_))) => false,
        Err(_) => false,
    }
}

pub async fn next_frame(conn: &mut Conn) -> Result<Vec<u8>> {
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
pub async fn send_raw_and_read_ack(conn: &mut Conn, frame_bytes: &[u8]) -> Result<Ack> {
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
    conn: &mut Conn,
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
pub async fn next_incoming_within(conn: &mut Conn, within: Duration) -> Result<Option<Incoming>> {
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

// ---- запись и повтор трафика клиента ----

/// `MAGIC(4) || protoVersion(u16) || pattern(u8)` перед первым сообщением
/// хендшейка.
const PROLOGUE_LEN: usize = 7;

/// Честный вход через прокси, который записывает всё, что клиент отправил
/// ноде, — ровно то, что видит на проводе наблюдатель. Возвращается запись:
/// пролог и msg1, а с `confirm` — ещё и подтверждающий кадр. Без `confirm`
/// клиент уходит сразу после `AuthOk`, и нода его так и не регистрирует.
pub async fn record_session(
    server: &ServerHandle,
    identity: &SigningKey,
    confirm_session: bool,
) -> Result<Vec<u8>> {
    let proxy = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy.local_addr()?;
    let node_addr = server.addr;
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let tap = recorded.clone();
    tokio::spawn(async move {
        let Ok((client, _)) = proxy.accept().await else {
            return;
        };
        let Ok(upstream) = TcpStream::connect(node_addr).await else {
            return;
        };
        let (mut from_client, mut to_client) = client.into_split();
        let (mut from_node, mut to_node) = upstream.into_split();
        let forward = async {
            let mut chunk = [0u8; 4096];
            loop {
                let read = match from_client.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                // Запись до пересылки: раз нода ответила на кадр, он уже
                // записан.
                tap.lock().unwrap().extend_from_slice(&chunk[..read]);
                if to_node.write_all(&chunk[..read]).await.is_err() {
                    break;
                }
            }
            let _ = to_node.shutdown().await;
        };
        let backward = async {
            let _ = tokio::io::copy(&mut from_node, &mut to_client).await;
            let _ = to_client.shutdown().await;
        };
        tokio::join!(forward, backward);
    });

    let stream = TcpStream::connect(proxy_addr).await?;
    let raw = NoiseFramed::connect(
        stream,
        &server.node_public,
        identity,
        Some(1),
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await?;
    let mut honest = if confirm_session {
        confirm(raw).await?
    } else {
        Conn::raw(raw)
    };
    expect_auth_ok(&next_frame(&mut honest).await?, &user_id_of(identity))?;
    drop(honest);

    let recorded = recorded.lock().unwrap().clone();
    Ok(recorded)
}

/// Префикс записи до конца msg1.
pub fn msg1_of(recorded: &[u8]) -> Result<&[u8]> {
    let len_bytes = recorded
        .get(PROLOGUE_LEN..PROLOGUE_LEN + 2)
        .context("recording is shorter than the prologue")?;
    let end = PROLOGUE_LEN + 2 + usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
    recorded.get(..end).context("recording ends inside msg1")
}

/// Отправить ноде записанный msg1 и дождаться ответа на него: msg2 и
/// зашифрованного `AuthOk`. Нода принимает повтор за вход — прочитать
/// ответ повторяющий не может, но соединение остаётся у него.
pub async fn replay_msg1(server: &ServerHandle, recorded: &[u8]) -> Result<TcpStream> {
    let mut replay = TcpStream::connect(server.addr).await?;
    replay.write_all(msg1_of(recorded)?).await?;
    read_noise_message(&mut replay)
        .await
        .context("no msg2 for the replayed msg1")?;
    read_noise_message(&mut replay)
        .await
        .context("no AuthOk for the replayed msg1")?;
    Ok(replay)
}

/// Одно Noise-сообщение с провода (`u16 LE` длина + тело) — как его видит
/// тот, у кого нет ключей.
pub async fn read_noise_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    timeout(SOCKET_TIMEOUT, stream.read_exact(&mut len))
        .await
        .context("no noise message from the node")??;
    let mut body = vec![0u8; usize::from(u16::from_le_bytes(len))];
    timeout(SOCKET_TIMEOUT, stream.read_exact(&mut body))
        .await
        .context("noise message cut short")??;
    Ok(body)
}

/// Дождаться, пока нода закроет сырое соединение. Возвращает, сколько
/// прошло.
pub async fn expect_raw_close(stream: &mut TcpStream, within: Duration) -> Result<Duration> {
    let started = Instant::now();
    let mut sink = [0u8; 1024];
    loop {
        let left = within.saturating_sub(started.elapsed());
        match timeout(left, stream.read(&mut sink)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Ok(started.elapsed()),
            Ok(Ok(_)) => continue,
            Err(_) => bail!("the node kept the connection open for {within:?}"),
        }
    }
}
