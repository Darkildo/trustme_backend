//! Тесты брокерного тракта доставки. Требуют живого NATS с JetStream,
//! поэтому помечены `#[ignore]`: без него они не «пропускаются молча», а
//! просто не запускаются, и зелёный прогон без брокера не выдаёт себя за
//! проверенную доставку.
//!
//! Запуск:
//!
//! ```sh
//! nats-server -js -sd /tmp/nats-test &
//! cargo test --test jetstream_delivery -- --ignored --test-threads=1
//! ```
//!
//! Адрес переопределяется переменной `TRUST_MESSAGE_TEST_NATS_URL`.
//! `--test-threads=1` обязателен: поток в JetStream один на все тесты (два
//! потока не могут делить subject), и параллельные прогоны спорили бы за
//! его конфигурацию.

mod common;

use std::time::Duration;

use anyhow::{Context, Result};
use async_nats::jetstream;
use common::{
    Incoming, encode_client_send, encode_delivery_ack, expect_auth_ok, next_frame,
    next_incoming_within, random_identity, send_and_read_ack, spawn_jetstream_server, user_id_of,
};
use trust_message_tcp::config::LimitsConfig;

/// Короткий `ack_wait`: передоставка — главное свойство брокерного тракта,
/// и ждать её боевые 30 секунд в тесте невозможно.
const ACK_WAIT: Duration = Duration::from_secs(2);
/// Запас поверх `ack_wait`: JetStream проверяет истёкшие подтверждения не
/// мгновенно, а на своём такте.
const REDELIVERY_WINDOW: Duration = Duration::from_secs(8);
/// Сколько ждать конверт, которого быть не должно. Заведомо больше
/// `ack_wait`, иначе «не пришло» означало бы всего лишь «ещё не успело».
const SILENCE_WINDOW: Duration = Duration::from_secs(6);

fn nats_url() -> String {
    std::env::var("TRUST_MESSAGE_TEST_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into())
}

/// Конверт, не подтверждённый клиентом, обязан приехать снова.
///
/// Ради этого свойства в тракте стоит брокер: конверт снимается с потока
/// только по `DeliveryAck`, а не в момент записи в сокет, поэтому клиент,
/// упавший на обработке, получает сообщение снова.
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn unacked_envelope_comes_back() -> Result<()> {
    let server = spawn_jetstream_server(
        "js_redeliver",
        LimitsConfig::default(),
        &nats_url(),
        ACK_WAIT,
    )
    .await?;

    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = common::connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;

    let mut alice_conn = common::connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;

    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"redelivery", 0).await?;
    assert!(ack.ok, "брокер не принял конверт: {ack:?}");

    let first = next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
        .await?
        .expect("получатель онлайн — конверт должен прийти");
    assert_eq!(first.body, b"redelivery");
    assert_ne!(
        first.message_id, 0,
        "конверт из брокера обязан нести message_id: без него его нечем подтвердить"
    );

    // Боб молчит — подтверждения нет, и по истечении ack_wait поток обязан
    // выдать конверт заново.
    let second = next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
        .await?
        .expect("неподтверждённый конверт обязан быть передоставлен");
    assert_eq!(second.message_id, first.message_id);
    assert_eq!(second.body, first.body);

    Ok(())
}

/// `DeliveryAck` снимает конверт с потока: повторной доставки нет.
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn acked_envelope_is_not_redelivered() -> Result<()> {
    let server =
        spawn_jetstream_server("js_ack", LimitsConfig::default(), &nats_url(), ACK_WAIT).await?;

    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = common::connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;

    let mut alice_conn = common::connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;

    send_and_read_ack(&mut alice_conn, &bob_id, b"acked once", 0).await?;

    let incoming = next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
        .await?
        .expect("получатель онлайн — конверт должен прийти");
    bob_conn
        .send_frame(&encode_delivery_ack(incoming.message_id))
        .await?;

    let repeat = next_incoming_within(&mut bob_conn, SILENCE_WINDOW).await?;
    assert_eq!(
        repeat, None,
        "подтверждённый конверт приехал снова: подтверждение не дошло до потока"
    );

    Ok(())
}

/// Конверт, который нода разобрать не может, снимается с потока навсегда и
/// не заклинивает доставку: следующее нормальное сообщение доходит.
///
/// Такой конверт нода сама произвести не может, поэтому он публикуется в
/// поток напрямую — ровно так он и появился бы от чужого узла или от
/// разъехавшейся схемы.
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn undecodable_envelope_does_not_wedge_the_pump() -> Result<()> {
    let server =
        spawn_jetstream_server("js_poison", LimitsConfig::default(), &nats_url(), ACK_WAIT).await?;

    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = common::connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;

    // Нулевой тег невалиден в protobuf всегда — разобрать это нельзя.
    let context = jetstream::new(async_nats::connect(nats_url()).await?);
    context
        .publish(
            format!("msg.user.{}", hex::encode(bob_id)),
            vec![0u8, 0, 0, 0].into(),
        )
        .await?
        .await?;

    let mut alice_conn = common::connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;
    send_and_read_ack(&mut alice_conn, &bob_id, b"after the poison", 0).await?;

    let incoming = next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
        .await?
        .expect("нормальный конверт после неразбираемого обязан дойти");
    assert_eq!(incoming.body, b"after the poison");

    Ok(())
}

/// Конверт, отправленный офлайн-получателю, ждёт его в потоке и приезжает
/// при подключении. Проверяет ту же дорогу, что и push-тракт, но с другой
/// стороны: сообщение не теряется, пока получателя нет.
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn envelope_for_an_offline_recipient_arrives_on_connect() -> Result<()> {
    let server =
        spawn_jetstream_server("js_offline", LimitsConfig::default(), &nats_url(), ACK_WAIT)
            .await?;

    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut alice_conn = common::connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;

    // Боб ещё ни разу не подключался: его пула не существует, конверт
    // ложится в поток и ждёт.
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"while offline", 0).await?;
    assert!(ack.ok && ack.queued, "ожидался приём в поток: {ack:?}");

    let mut bob_conn = common::connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;

    let incoming: Incoming = next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
        .await?
        .expect("конверт, положенный в поток до подключения, обязан дойти");
    assert_eq!(incoming.body, b"while offline");
    assert_eq!(incoming.from_user_id, user_id_of(&alice).to_vec());

    Ok(())
}

/// Кадр `ClientSend` с адресацией на устройство едет своим subject'ом и
/// доезжает до сессии этого устройства.
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn device_addressed_envelope_reaches_that_device() -> Result<()> {
    let server =
        spawn_jetstream_server("js_device", LimitsConfig::default(), &nats_url(), ACK_WAIT).await?;

    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_device = common::connect_as(&server, &bob, Some(42), common::FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut bob_device).await?, &bob_id)?;

    let mut alice_conn = common::connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;

    alice_conn
        .send_frame(&encode_client_send(&bob_id, Some(42), b"to device 42", 0)?)
        .await?;
    let _ack = next_frame(&mut alice_conn).await?;

    let incoming = next_incoming_within(&mut bob_device, REDELIVERY_WINDOW)
        .await?
        .expect("адресованный устройству конверт обязан дойти до его сессии");
    assert_eq!(incoming.body, b"to device 42");

    Ok(())
}

/// Смерть брокера обязана дойти до клиента.
///
/// Пул доставки поднимается асинхронно и умирает уже после того, как
/// сессия установлена, — снаружи она выглядит здоровой, а входящих не
/// получает. Тест поднимает собственный NATS (общий убивать нельзя) и
/// проверяет, что клиент узнаёт об аварии кадром, а не тишиной.
#[tokio::test]
#[ignore = "требует бинарь nats-server в TRUST_MESSAGE_TEST_NATS_BIN"]
async fn dead_broker_closes_live_sessions() -> Result<()> {
    let binary = std::env::var("TRUST_MESSAGE_TEST_NATS_BIN").expect(
        "этому тесту нужен собственный брокер: путь к бинарю nats-server \
         в TRUST_MESSAGE_TEST_NATS_BIN",
    );

    let port = free_port()?;
    let store_dir = std::env::temp_dir().join(format!("trust_message_tcp_nats_{port}"));
    let mut broker = std::process::Command::new(binary)
        .args([
            "-js",
            "-p",
            &port.to_string(),
            "-sd",
            &store_dir.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("не удалось запустить nats-server")?;

    let url = format!("nats://127.0.0.1:{port}");
    wait_until_ready(&url).await?;

    let result = async {
        let server =
            spawn_jetstream_server("js_broker_death", LimitsConfig::default(), &url, ACK_WAIT)
                .await?;

        let bob = random_identity();
        let mut bob_conn = common::connect(&server, &bob).await?;
        expect_auth_ok(&next_frame(&mut bob_conn).await?, &user_id_of(&bob))?;

        broker.kill().context("не удалось убить брокер")?;
        let _ = broker.wait();

        // Пул Боба остаётся без потока. Клиент обязан получить явный отказ
        // и закрытие, а не молчание на живом сокете.
        let notice = tokio::time::timeout(Duration::from_secs(20), bob_conn.next_frame())
            .await
            .context("клиент не узнал о смерти брокера: за 20 секунд не пришло ничего")?
            .context("чтение кадра сломалось")?
            .context("соединение закрылось без объяснения")?;

        match common::decode(&notice)? {
            trust_message_tcp::wire::frame::Payload::AuthError(err) => {
                assert_eq!(err.code, 503, "ожидался отказ доставки: {}", err.message);
            }
            other => anyhow::bail!("ожидался AuthError(503), пришло {other:?}"),
        }

        anyhow::Ok(())
    }
    .await;

    let _ = broker.kill();
    let _ = std::fs::remove_dir_all(&store_dir);
    result
}

/// Конверт, не подтверждённый ушедшим клиентом, возвращается потоку
/// сразу, а не по истечении `ack_wait`.
///
/// `ack_wait` здесь боевой (30 с), и в этом весь тест: без возврата
/// конверта переподключившийся получатель ждал бы полминуты. Пул
/// выходит штатно — получатель просто отключился, — и именно поэтому
/// возврат не может висеть на ветке «пул упал».
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn unacked_envelope_returns_to_the_stream_when_the_pump_exits() -> Result<()> {
    let server = spawn_jetstream_server(
        "js_release",
        LimitsConfig::default(),
        &nats_url(),
        Duration::from_secs(30),
    )
    .await?;

    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = common::connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;

    let mut alice_conn = common::connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;
    send_and_read_ack(&mut alice_conn, &bob_id, b"left unacked", 0).await?;

    let first = next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
        .await?
        .expect("получатель онлайн — конверт должен прийти");
    assert_eq!(first.body, b"left unacked");

    // Боб уходит, не подтвердив: его пул выходит, конверт остаётся
    // невыданным никому.
    drop(bob_conn);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut bob_again = common::connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_again).await?, &bob_id)?;

    let repeat = next_incoming_within(&mut bob_again, Duration::from_secs(10))
        .await?
        .expect("конверт обязан вернуться сразу, а не по истечении ack_wait");
    assert_eq!(repeat.message_id, first.message_id);

    Ok(())
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_until_ready(url: &str) -> Result<()> {
    for _ in 0..50 {
        if async_nats::connect(url).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("брокер на {url} не поднялся")
}

/// Лимиты потока, передоставка и живучесть пула.
///
/// Свой блок со своими хелперами: тестам нужна нода с конфигурацией под
/// тест (потолок ящика, объём потока, включённые пуши), а части из них —
/// собственный брокер, который можно заморозить или перезапустить.
/// Сессия считается рабочей после ответа на первый кадр клиента (Ping →
/// Pong): так тесты не зависят от того, в какой момент входа нода
/// регистрирует сессию и поднимает пулы.
mod broker_guarantees {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result, bail, ensure};
    use async_nats::jetstream::{self, consumer, stream};
    use ed25519_dalek::SigningKey;
    use futures_util::StreamExt;
    use prost::Message;
    use tokio::net::TcpListener;
    use trust_message_tcp::config::{Config, DeliveryBackendKind, LimitsConfig, RetentionPolicy};
    use trust_message_tcp::delivery::DeliveryBackend;
    use trust_message_tcp::domain::push::PushPlatform;
    use trust_message_tcp::domain::reject::SendRejectReason;
    use trust_message_tcp::domain::wake::WakeHint;
    use trust_message_tcp::net::listener::accept_loop;
    use trust_message_tcp::net::noise::NodeIdentity;
    use trust_message_tcp::push::{MockTransport, NoopStatePersistence, PushScheduler};
    use trust_message_tcp::state::push_tokens::PushTokenStore;
    use trust_message_tcp::state::{registry::ConnRegistry, storage::Storage};
    use trust_message_tcp::wire::{self, frame::Payload};

    use super::common::{self, Ack, Incoming};
    use super::{
        ACK_WAIT, REDELIVERY_WINDOW, SILENCE_WINDOW, free_port, nats_url, wait_until_ready,
    };

    /// Сколько ждать, пока фоновое удаление подтверждённого конверта
    /// освободит место в ящике.
    const DELETE_WINDOW: Duration = Duration::from_secs(5);
    /// Сколько ждать, пока планировщик пушей разберёт триггеры.
    const PUSH_SETTLE: Duration = Duration::from_millis(500);

    /// Нода на брокерном бэкенде с конфигурацией под тест. Пуши идут в
    /// `MockTransport`, токены — в настоящее хранилище ноды.
    struct Node {
        handle: common::ServerHandle,
        push: Arc<MockTransport>,
        push_tokens: PushTokenStore,
    }

    async fn spawn_node(
        label: &str,
        nats_url: &str,
        tune: impl FnOnce(&mut Config),
    ) -> Result<Node> {
        let storage_path = common::temp_storage_path(label);
        let keep = RetentionPolicy::KeepFor(Duration::from_secs(30 * 86_400));
        let storage = Storage::open(&storage_path, keep, keep)?;
        let push_tokens = storage.push_token_store()?;
        let identity = Arc::new(NodeIdentity::load_or_generate(&storage_path, None)?);
        let node_public = identity.public();

        let mut cfg = common::test_config(&storage_path, LimitsConfig::default());
        cfg.delivery.backend = DeliveryBackendKind::JetStream;
        cfg.delivery.nats_url = nats_url.to_string();
        cfg.delivery.nats_stream_name = common::TEST_STREAM_NAME.to_string();
        cfg.delivery.nats_ack_wait = ACK_WAIT;
        tune(&mut cfg);

        let push = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            cfg.push.clone(),
            push.clone(),
            Arc::new(push_tokens.clone()),
            Arc::new(NoopStatePersistence),
        );
        let delivery = DeliveryBackend::from_config(
            &cfg,
            storage.clone(),
            push_tokens.clone(),
            scheduler.clone(),
        )
        .await?;

        let listener = TcpListener::bind(&cfg.bind_addr).await?;
        let addr = listener.local_addr()?;
        tokio::spawn(accept_loop(
            listener,
            ConnRegistry::default(),
            storage,
            delivery,
            push_tokens.clone(),
            scheduler,
            identity,
            cfg,
        ));

        Ok(Node {
            handle: common::ServerHandle {
                addr,
                node_public,
                storage_path,
            },
            push,
            push_tokens,
        })
    }

    /// Собственный nats-server теста: свой порт и свой store. Нужен, когда
    /// тест меняет лимиты потока, замораживает или перезапускает брокер, —
    /// с общим брокером других тестов так нельзя.
    struct OwnBroker {
        binary: String,
        port: u16,
        store_dir: PathBuf,
        process: Child,
    }

    impl OwnBroker {
        async fn start() -> Result<Self> {
            let binary = std::env::var("TRUST_MESSAGE_TEST_NATS_BIN").context(
                "этому тесту нужен собственный брокер: путь к бинарю nats-server \
                 в TRUST_MESSAGE_TEST_NATS_BIN",
            )?;
            let port = free_port()?;
            let store_dir = std::env::temp_dir().join(format!("trust_message_tcp_nats_{port}"));
            let process = spawn_nats(&binary, port, &store_dir)?;
            let broker = Self {
                binary,
                port,
                store_dir,
                process,
            };
            wait_until_ready(&broker.url()).await?;
            Ok(broker)
        }

        fn url(&self) -> String {
            format!("nats://127.0.0.1:{}", self.port)
        }

        async fn jetstream(&self) -> Result<jetstream::Context> {
            Ok(jetstream::new(async_nats::connect(self.url()).await?))
        }

        /// Перезапуск с тем же store: именно при подъёме с диска JetStream
        /// приводит ящики к потолку потока.
        async fn restart(&mut self) -> Result<()> {
            self.kill()?;
            self.process = spawn_nats(&self.binary, self.port, &self.store_dir)?;
            wait_until_ready(&self.url()).await
        }

        fn kill(&mut self) -> Result<()> {
            self.process.kill().context("не удалось убить брокер")?;
            self.process.wait()?;
            Ok(())
        }

        /// `-STOP` замораживает брокер: соединения открыты, но он молчит, —
        /// ровно то, что видит пул при пропавших heartbeat'ах. `-CONT`
        /// размораживает.
        fn signal(&self, signal: &str) -> Result<()> {
            let status = Command::new("kill")
                .args([signal, &self.process.id().to_string()])
                .status()
                .context("не удалось послать сигнал брокеру")?;
            ensure!(status.success(), "kill {signal} завершился с ошибкой");
            Ok(())
        }
    }

    impl Drop for OwnBroker {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let _ = self.process.wait();
            let _ = std::fs::remove_dir_all(&self.store_dir);
        }
    }

    fn spawn_nats(binary: &str, port: u16, store_dir: &Path) -> Result<Child> {
        Command::new(binary)
            .args([
                "-js",
                "-p",
                &port.to_string(),
                "-sd",
                &store_dir.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("не удалось запустить nats-server")
    }

    fn frame(payload: Payload) -> Vec<u8> {
        wire::Frame {
            proto_version: common::PROTO_VERSION,
            payload: Some(payload),
        }
        .encode_to_vec()
    }

    /// Подключиться и дождаться, пока сессия заработает. Входящие, пришедшие
    /// раньше Pong, возвращаются вместе с соединением: пул мог начать
    /// доставку до ответа на Ping.
    async fn connect_ready(
        node: &Node,
        identity: &SigningKey,
        device_id: Option<u16>,
    ) -> Result<(common::Conn, Vec<Incoming>)> {
        let mut conn =
            common::connect_as(&node.handle, identity, device_id, common::FRAME_MAX).await?;
        conn.send_frame(&frame(Payload::Ping(wire::Ping {})))
            .await?;

        let user_id = common::user_id_of(identity);
        let mut authenticated = false;
        let mut early = Vec::new();
        loop {
            let bytes = common::next_frame(&mut conn).await?;
            match common::decode(&bytes)? {
                Payload::AuthOk(_) => {
                    common::expect_auth_ok(&bytes, &user_id)?;
                    authenticated = true;
                }
                Payload::Pong(_) => break,
                Payload::Incoming(_) => early.push(common::expect_incoming(&bytes)?),
                Payload::AuthError(err) => bail!("AuthError {}: {}", err.code, err.message),
                other => bail!("неожиданный кадр на входе в сессию: {other:?}"),
            }
        }
        ensure!(authenticated, "сессия ответила Pong без AuthOk");
        Ok((conn, early))
    }

    /// Дочитать входящие до `count` штук.
    async fn collect_incoming(
        conn: &mut common::Conn,
        mut received: Vec<Incoming>,
        count: usize,
    ) -> Result<Vec<Incoming>> {
        while received.len() < count {
            match common::next_incoming_within(conn, REDELIVERY_WINDOW).await? {
                Some(incoming) => received.push(incoming),
                None => bail!("пришло {} конвертов из {count}", received.len()),
            }
        }
        Ok(received)
    }

    async fn send(
        conn: &mut common::Conn,
        recipient: &[u8; 32],
        device_id: Option<u16>,
        body: &[u8],
    ) -> Result<Ack> {
        send_with(
            conn,
            recipient,
            device_id,
            body,
            wire::MessagePriority::Unspecified,
            wire::WakeHint::Unspecified,
        )
        .await
    }

    async fn send_with(
        conn: &mut common::Conn,
        recipient: &[u8; 32],
        device_id: Option<u16>,
        body: &[u8],
        priority: wire::MessagePriority,
        wake_hint: wire::WakeHint,
    ) -> Result<Ack> {
        let bytes = frame(Payload::ClientSend(wire::ClientSend {
            recipient_id: recipient.to_vec(),
            body: body.to_vec(),
            recipient_device_id: device_id.map(u32::from),
            priority: priority as i32,
            wake_hint: wake_hint as i32,
            ..wire::ClientSend::default()
        }));
        common::send_raw_and_read_ack(conn, &bytes).await
    }

    fn mailbox(user_id: &[u8; 32]) -> String {
        format!("msg.user.{}", hex::encode(user_id))
    }

    async fn mailbox_depths(js: &jetstream::Context) -> Result<HashMap<String, usize>> {
        let stream = js.get_stream(common::TEST_STREAM_NAME).await?;
        let mut subjects = stream.info_with_subjects(">").await?;
        let mut depths = HashMap::new();
        while let Some(entry) = subjects.next().await {
            let (subject, count) = entry?;
            depths.insert(subject, count);
        }
        Ok(depths)
    }

    /// Переполненный ящик отказывает отправителю явным `FULL` и не трогает
    /// ни уже лежащие в нём конверты, ни чужие ящики. Подтверждённый
    /// конверт освобождает место.
    #[tokio::test]
    #[ignore = "требует бинарь nats-server в TRUST_MESSAGE_TEST_NATS_BIN"]
    async fn full_mailbox_refuses_new_envelopes_and_keeps_the_old() -> Result<()> {
        let broker = OwnBroker::start().await?;
        let node = spawn_node("js_mailbox_cap", &broker.url(), |cfg| {
            cfg.delivery.nats_max_msgs_per_subject = 3;
        })
        .await?;

        let alice = common::random_identity();
        let bob = common::random_identity();
        let carol = common::random_identity();
        let bob_id = common::user_id_of(&bob);
        let carol_id = common::user_id_of(&carol);

        let (mut alice_conn, _) = connect_ready(&node, &alice, Some(1)).await?;
        for body in [b"m0", b"m1", b"m2"] {
            let ack = send(&mut alice_conn, &bob_id, None, body).await?;
            assert!(ack.ok && ack.queued, "ящик ещё не полон: {ack:?}");
        }

        let refused = send(&mut alice_conn, &bob_id, None, b"m3").await?;
        assert!(!refused.ok, "четвёртый конверт сверх потолка 3 принят");
        assert_eq!(
            refused.reason,
            SendRejectReason::Full,
            "переполнение — это FULL, а не авария ноды"
        );

        // Чужой ящик и ящик устройства того же получателя считаются
        // отдельно и принимают как обычно.
        let to_carol = send(&mut alice_conn, &carol_id, None, b"for carol").await?;
        assert!(to_carol.ok, "переполнение ящика Боба задело ящик Кэрол");
        let to_bob_device = send(&mut alice_conn, &bob_id, Some(7), b"to device 7").await?;
        assert!(to_bob_device.ok, "ящик устройства — отдельный ящик");

        // Отказ новому не вытеснил старое: Боб получает ровно первые три.
        let (mut bob_conn, early) = connect_ready(&node, &bob, Some(1)).await?;
        let received = collect_incoming(&mut bob_conn, early, 3).await?;
        let bodies: Vec<&[u8]> = received.iter().map(|i| i.body.as_slice()).collect();
        assert_eq!(bodies, [b"m0".as_slice(), b"m1", b"m2"]);

        // Подтверждённое уходит из потока, и ящик снова принимает.
        for incoming in &received {
            bob_conn
                .send_frame(&common::encode_delivery_ack(incoming.message_id))
                .await?;
        }
        let deadline = tokio::time::Instant::now() + DELETE_WINDOW;
        loop {
            let ack = send(&mut alice_conn, &bob_id, None, b"after ack").await?;
            if ack.ok {
                break;
            }
            assert_eq!(ack.reason, SendRejectReason::Full);
            ensure!(
                tokio::time::Instant::now() < deadline,
                "подтверждённые конверты не освободили ящик"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let (mut carol_conn, early) = connect_ready(&node, &carol, Some(1)).await?;
        let received = collect_incoming(&mut carol_conn, early, 1).await?;
        assert_eq!(received[0].body, b"for carol");

        Ok(())
    }

    /// Переполненный поток целиком отказывает всем новым конвертам `FULL`,
    /// но не стирает уже принятые.
    #[tokio::test]
    #[ignore = "требует бинарь nats-server в TRUST_MESSAGE_TEST_NATS_BIN"]
    async fn full_stream_refuses_new_envelopes_and_keeps_the_old() -> Result<()> {
        let broker = OwnBroker::start().await?;
        let node = spawn_node("js_stream_full", &broker.url(), |cfg| {
            cfg.delivery.nats_stream_max_bytes = 4 * 1024;
        })
        .await?;

        let alice = common::random_identity();
        let bob = common::random_identity();
        let bob_id = common::user_id_of(&bob);
        let carol_id = common::user_id_of(&common::random_identity());

        let (mut alice_conn, _) = connect_ready(&node, &alice, Some(1)).await?;
        let mut accepted = Vec::new();
        let refused = loop {
            ensure!(
                accepted.len() < 16,
                "поток в 4 KiB принял 16 конвертов по 1 KiB"
            );
            let body = vec![accepted.len() as u8; 1024];
            let ack = send(&mut alice_conn, &bob_id, None, &body).await?;
            if !ack.ok {
                break ack;
            }
            accepted.push(body);
        };
        assert!(
            accepted.len() >= 2,
            "поток отказал слишком рано: {accepted:?}"
        );
        assert_eq!(refused.reason, SendRejectReason::Full);

        // Лимит общий: такой же конверт в чужой пустой ящик тоже не влезает.
        let to_carol = send(&mut alice_conn, &carol_id, None, &[0xc0; 1024]).await?;
        assert!(!to_carol.ok);
        assert_eq!(to_carol.reason, SendRejectReason::Full);

        let (mut bob_conn, early) = connect_ready(&node, &bob, Some(1)).await?;
        let received = collect_incoming(&mut bob_conn, early, accepted.len()).await?;
        let bodies: Vec<Vec<u8>> = received.into_iter().map(|i| i.body).collect();
        assert_eq!(
            bodies, accepted,
            "принятые конверты обязаны дойти все и по порядку"
        );

        Ok(())
    }

    fn raw_envelope(message_id: u64, sender: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
        trust_message_tcp::broker::BrokerMessage {
            message_id,
            sender_user_id: sender.to_vec(),
            recipient_user_id: recipient.to_vec(),
            body: format!("envelope {message_id}").into_bytes(),
            created_at: common::unix_now_secs(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// Поток, созданный прежней политикой (`DiscardPolicy::Old`, без
    /// потолка ящика), при старте ноды переходит на новую и ничего не
    /// теряет: ни сейчас, ни после рестарта брокера.
    ///
    /// Прежняя нода оставляла в потоке и подтверждённые конверты — они
    /// снимаются, иначе поток, полный доставленного, отказывал бы всем.
    /// Ящик глубже нового потолка задаёт потолок по себе: JetStream,
    /// поднимая поток с диска, иначе срезал бы его старейшие конверты.
    #[tokio::test]
    #[ignore = "требует бинарь nats-server в TRUST_MESSAGE_TEST_NATS_BIN"]
    async fn old_stream_switches_to_discard_new_without_losing_envelopes() -> Result<()> {
        let mut broker = OwnBroker::start().await?;
        let js = broker.jetstream().await?;
        let stream = js
            .create_stream(stream::Config {
                name: common::TEST_STREAM_NAME.to_string(),
                subjects: vec!["msg.user.*".into(), "msg.user.*.device.*".into()],
                storage: stream::StorageType::File,
                retention: stream::RetentionPolicy::Limits,
                discard: stream::DiscardPolicy::Old,
                max_age: Duration::from_secs(14 * 86_400),
                max_bytes: 1024 * 1024,
                max_messages: -1,
                max_messages_per_subject: -1,
                max_consumers: -1,
                max_message_size: -1,
                num_replicas: 1,
                ..Default::default()
            })
            .await?;

        let alice_id = common::user_id_of(&common::random_identity());
        let bob = common::random_identity();
        let bob_id = common::user_id_of(&bob);
        let carol_id = common::user_id_of(&common::random_identity());

        for id in 1..=5 {
            js.publish(
                mailbox(&bob_id),
                raw_envelope(id, &alice_id, &bob_id).into(),
            )
            .await?
            .await?;
        }
        for id in 11..=15 {
            js.publish(
                mailbox(&carol_id),
                raw_envelope(id, &alice_id, &carol_id).into(),
            )
            .await?
            .await?;
        }

        // Боб уже получил и подтвердил первые два — так, как это делала
        // прежняя нода своим durable-consumer'ом.
        let durable = stream
            .create_consumer(consumer::pull::Config {
                durable_name: Some(format!("user_{}", hex::encode(bob_id))),
                filter_subject: mailbox(&bob_id),
                ack_policy: consumer::AckPolicy::Explicit,
                deliver_policy: consumer::DeliverPolicy::All,
                ack_wait: ACK_WAIT,
                ..Default::default()
            })
            .await?;
        let mut batch = durable.fetch().max_messages(2).messages().await?;
        while let Some(message) = batch.next().await {
            message
                .map_err(|err| anyhow::anyhow!(err))?
                .double_ack()
                .await
                .map_err(|err| anyhow::anyhow!(err))?;
        }

        let node = spawn_node("js_old_stream", &broker.url(), |cfg| {
            cfg.delivery.nats_max_msgs_per_subject = 3;
        })
        .await?;

        let config = js
            .get_stream(common::TEST_STREAM_NAME)
            .await?
            .info()
            .await?
            .config
            .clone();
        assert_eq!(config.discard, stream::DiscardPolicy::New);
        assert!(config.discard_new_per_subject);
        assert_eq!(
            config.max_messages_per_subject, 5,
            "ящик Кэрол глубже потолка 3 — потолок обязан пойти по нему"
        );

        let depths = mailbox_depths(&js).await?;
        assert_eq!(
            depths.get(&mailbox(&bob_id)),
            Some(&3),
            "подтверждённые не сняты"
        );
        assert_eq!(depths.get(&mailbox(&carol_id)), Some(&5));

        // Боб получает ровно неподтверждённое.
        let (mut bob_conn, early) = connect_ready(&node, &bob, Some(1)).await?;
        let received = collect_incoming(&mut bob_conn, early, 3).await?;
        let ids: Vec<u64> = received.iter().map(|i| i.message_id).collect();
        assert_eq!(ids, [3, 4, 5]);
        drop(bob_conn);

        broker.restart().await?;
        let js = broker.jetstream().await?;
        let depths = mailbox_depths(&js).await?;
        assert_eq!(depths.get(&mailbox(&bob_id)), Some(&3));
        assert_eq!(
            depths.get(&mailbox(&carol_id)),
            Some(&5),
            "рестарт брокера срезал ящик под потолок"
        );

        Ok(())
    }

    /// `DeliveryAck` чужого пользователя не подтверждает конверт: он
    /// возвращается получателю, а подтверждение самого получателя после
    /// этого срабатывает.
    #[tokio::test]
    #[ignore = "требует живого NATS с JetStream"]
    async fn foreign_delivery_ack_does_not_acknowledge_the_envelope() -> Result<()> {
        let node = spawn_node("js_foreign_ack", &nats_url(), |_| {}).await?;

        let alice = common::random_identity();
        let bob = common::random_identity();
        let mallory = common::random_identity();
        let bob_id = common::user_id_of(&bob);

        let (mut bob_conn, _) = connect_ready(&node, &bob, Some(1)).await?;
        let (mut mallory_conn, _) = connect_ready(&node, &mallory, Some(1)).await?;
        let (mut alice_conn, _) = connect_ready(&node, &alice, Some(1)).await?;

        assert!(send(&mut alice_conn, &bob_id, None, b"for bob").await?.ok);
        let first = common::next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
            .await?
            .expect("получатель онлайн — конверт должен прийти");

        mallory_conn
            .send_frame(&common::encode_delivery_ack(first.message_id))
            .await?;

        let again = common::next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
            .await?
            .expect("чужое подтверждение сняло конверт Боба с потока");
        assert_eq!(again.message_id, first.message_id);

        bob_conn
            .send_frame(&common::encode_delivery_ack(again.message_id))
            .await?;
        let repeat = common::next_incoming_within(&mut bob_conn, SILENCE_WINDOW).await?;
        assert_eq!(repeat, None, "подтверждение получателя потерялось");

        Ok(())
    }

    /// Нода с включёнными пушами: высокий приоритет будит сразу, без
    /// коалесинга, — каждый лишний триггер виден как лишний пуш.
    async fn spawn_push_node(label: &str) -> Result<Node> {
        spawn_node(label, &nats_url(), |cfg| {
            cfg.push.enabled = true;
            cfg.push.min_gap_high = Duration::ZERO;
            cfg.push.burst_high = 1;
        })
        .await
    }

    /// Звонковый конверт будит офлайн-устройство один раз — при публикации.
    /// Ни первая выдача пулом, ни передоставка не звонят снова.
    #[tokio::test]
    #[ignore = "требует живого NATS с JetStream"]
    async fn call_envelope_rings_an_offline_device_once() -> Result<()> {
        let node = spawn_push_node("js_ring_once").await?;
        let alice = common::random_identity();
        let bob = common::random_identity();
        let bob_id = common::user_id_of(&bob);
        // Второе устройство Боба офлайн, но с токеном — его и будят.
        node.push_tokens
            .add(&bob_id, 2, PushPlatform::AndroidFcm, "bob-device-2")?;

        let (mut bob_conn, _) = connect_ready(&node, &bob, Some(1)).await?;
        let (mut alice_conn, _) = connect_ready(&node, &alice, Some(1)).await?;

        let ack = send_with(
            &mut alice_conn,
            &bob_id,
            None,
            b"offer",
            wire::MessagePriority::High,
            wire::WakeHint::IncomingCall,
        )
        .await?;
        assert!(ack.ok);

        let first = common::next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
            .await?
            .expect("конверт должен дойти до первого устройства");
        // Боб не подтверждает: конверт обязан вернуться передоставкой.
        let again = common::next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
            .await?
            .expect("неподтверждённый конверт обязан быть передоставлен");
        assert_eq!(again.message_id, first.message_id);
        tokio::time::sleep(PUSH_SETTLE).await;

        let pushes = node.push.sent_payloads();
        assert_eq!(
            pushes.len(),
            1,
            "звонок разбудил устройство больше одного раза: {pushes:?}"
        );
        assert_eq!(pushes[0].device_id, 2);
        assert_eq!(pushes[0].wake_hint, Some(WakeHint::IncomingCall));

        bob_conn
            .send_frame(&common::encode_delivery_ack(again.message_id))
            .await?;
        Ok(())
    }

    /// Передоставка обычного конверта никого не будит: о нём офлайн-
    /// устройства уже знают.
    #[tokio::test]
    #[ignore = "требует живого NATS с JetStream"]
    async fn redelivered_envelope_wakes_nobody() -> Result<()> {
        let node = spawn_push_node("js_redelivery_silent").await?;
        let alice = common::random_identity();
        let bob = common::random_identity();
        let bob_id = common::user_id_of(&bob);
        node.push_tokens
            .add(&bob_id, 2, PushPlatform::AndroidFcm, "bob-device-2")?;

        let (mut bob_conn, _) = connect_ready(&node, &bob, Some(1)).await?;
        let (mut alice_conn, _) = connect_ready(&node, &alice, Some(1)).await?;

        let ack = send_with(
            &mut alice_conn,
            &bob_id,
            None,
            b"hello",
            wire::MessagePriority::High,
            wire::WakeHint::Unspecified,
        )
        .await?;
        assert!(ack.ok);

        let first = common::next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
            .await?
            .expect("конверт должен дойти до первого устройства");
        tokio::time::sleep(PUSH_SETTLE).await;
        let after_first = node.push.sent_payloads();
        assert!(
            !after_first.is_empty(),
            "офлайн-устройство не разбудили вовсе"
        );

        let again = common::next_incoming_within(&mut bob_conn, REDELIVERY_WINDOW)
            .await?
            .expect("неподтверждённый конверт обязан быть передоставлен");
        assert_eq!(again.message_id, first.message_id);
        tokio::time::sleep(PUSH_SETTLE).await;

        let after_redelivery = node.push.sent_payloads();
        assert_eq!(
            after_redelivery.len(),
            after_first.len(),
            "передоставка разбудила устройство снова: {after_redelivery:?}"
        );
        assert!(after_redelivery.iter().all(|push| push.wake_hint.is_none()));

        bob_conn
            .send_frame(&common::encode_delivery_ack(again.message_id))
            .await?;
        Ok(())
    }

    /// Пул переживает брокер, замолчавший дольше интервала heartbeat'ов, но
    /// не умерший: сессия не получает ложного 503, и доставка идёт дальше.
    ///
    /// Брокер замораживается на 32 с: heartbeat'ы пропадают наверняка
    /// (async-nats ждёт их 30 с), а ответ на проверку consumer'а приходит в
    /// пределах `PULL_PROBE_TIMEOUT` (20 с от пропажи, наступающей не
    /// раньше 15 с от заморозки).
    #[tokio::test]
    #[ignore = "требует бинарь nats-server в TRUST_MESSAGE_TEST_NATS_BIN"]
    async fn pump_survives_a_broker_that_stalls_but_lives() -> Result<()> {
        let broker = OwnBroker::start().await?;
        let node = spawn_node("js_stall", &broker.url(), |_| {}).await?;
        let alice = common::random_identity();
        let bob = common::random_identity();
        let bob_id = common::user_id_of(&bob);

        let (mut bob_conn, _) = connect_ready(&node, &bob, Some(1)).await?;
        let (mut alice_conn, _) = connect_ready(&node, &alice, Some(1)).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        broker.signal("-STOP")?;
        tokio::time::sleep(Duration::from_secs(32)).await;
        broker.signal("-CONT")?;

        let ack = send(&mut alice_conn, &bob_id, None, b"after the stall").await?;
        assert!(ack.ok, "брокер ожил, а публикация не прошла: {ack:?}");
        let incoming = common::next_incoming_within(&mut bob_conn, Duration::from_secs(15))
            .await?
            .expect("пул не пережил заминку брокера");
        assert_eq!(incoming.body, b"after the stall");

        Ok(())
    }

    /// Смерть брокера под уже работающим пулом по-прежнему доходит до
    /// клиента: временные ошибки подписки пул терпит, только пока брокер
    /// на связи.
    #[tokio::test]
    #[ignore = "требует бинарь nats-server в TRUST_MESSAGE_TEST_NATS_BIN"]
    async fn dead_broker_still_closes_sessions_of_a_running_pump() -> Result<()> {
        let mut broker = OwnBroker::start().await?;
        let node = spawn_node("js_broker_death_running", &broker.url(), |_| {}).await?;
        let bob = common::random_identity();
        let (mut bob_conn, _) = connect_ready(&node, &bob, Some(1)).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;

        broker.kill()?;

        let notice = tokio::time::timeout(Duration::from_secs(60), bob_conn.next_frame())
            .await
            .context("клиент не узнал о смерти брокера за 60 секунд")?
            .context("чтение кадра сломалось")?
            .context("соединение закрылось без объяснения")?;
        match common::decode(&notice)? {
            Payload::AuthError(err) => assert_eq!(err.code, 503, "{}", err.message),
            other => bail!("ожидался AuthError(503), пришло {other:?}"),
        }
        Ok(())
    }
}
