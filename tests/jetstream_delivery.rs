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
