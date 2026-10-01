//! Доставка через переподключение: то, ради чего офлайн-очередь вообще
//! существует.
//!
//! Проверяется на живой ноде через настоящий Noise-канал, а не на
//! хранилище напрямую: между «сообщение лежит в sled» и «клиент его
//! получил» есть реестр сессий, дренаж очереди и кадрирование, и ошибка
//! может жить в любом из них.

mod common;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, connect, connect_as, decode, expect_auth_ok, next_frame, send_and_read_ack,
    spawn_server,
};
use ed25519_dalek::SigningKey;
use tokio::time::{Duration, timeout};
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::wire::frame;

/// Собрать все входящие, которые нода отдаст за отведённое окно.
async fn drain_incoming(conn: &mut Conn, window: Duration) -> Result<Vec<Vec<u8>>> {
    let mut bodies = Vec::new();
    loop {
        match timeout(window, conn.next_frame()).await {
            Ok(Ok(Some(bytes))) => match decode(&bytes)? {
                frame::Payload::Incoming(msg) => bodies.push(msg.body),
                // Прочие кадры сессии в счёт не идут.
                _ => continue,
            },
            // Окно вышло — больше нода ничего не отдаёт.
            Err(_) => break,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => bail!("read failed: {err}"),
        }
    }
    Ok(bodies)
}

/// Сообщение, отправленное офлайн-получателю, лежит в очереди и
/// доставляется, когда тот подключается.
#[tokio::test]
async fn offline_message_is_replayed_on_reconnect() -> Result<()> {
    let server = spawn_server("replay", LimitsConfig::default()).await?;
    let sender = SigningKey::from_bytes(&[31u8; 32]);
    let recipient = SigningKey::from_bytes(&[32u8; 32]);
    let recipient_id = recipient.verifying_key().to_bytes();

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    // Получателя нет онлайн — сообщение обязано лечь в очередь.
    let ack = send_and_read_ack(&mut sender_conn, &recipient_id, b"while-you-were-out", 0).await?;
    assert!(!ack.ok, "получателя нет онлайн, доставки быть не могло");
    assert!(ack.queued, "сообщение обязано лечь в очередь");

    // Получатель приходит и забирает его.
    let mut recipient_conn = connect(&server, &recipient).await?;
    expect_auth_ok(&next_frame(&mut recipient_conn).await?, &recipient_id)?;

    let bodies = drain_incoming(&mut recipient_conn, Duration::from_millis(400)).await?;
    assert_eq!(bodies, vec![b"while-you-were-out".to_vec()]);

    Ok(())
}

/// Повторное подключение не отдаёт то же сообщение второй раз: очередь
/// вычищается по мере доставки, а не по факту дренажа.
#[tokio::test]
async fn replayed_message_is_not_delivered_twice() -> Result<()> {
    let server = spawn_server("replay_once", LimitsConfig::default()).await?;
    let sender = SigningKey::from_bytes(&[33u8; 32]);
    let recipient = SigningKey::from_bytes(&[34u8; 32]);
    let recipient_id = recipient.verifying_key().to_bytes();

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;
    send_and_read_ack(&mut sender_conn, &recipient_id, b"once", 0).await?;

    {
        let mut first = connect(&server, &recipient).await?;
        expect_auth_ok(&next_frame(&mut first).await?, &recipient_id)?;
        let bodies = drain_incoming(&mut first, Duration::from_millis(400)).await?;
        assert_eq!(bodies, vec![b"once".to_vec()]);
    }

    // Соединение закрыто; приходим заново.
    let mut second = connect(&server, &recipient).await?;
    expect_auth_ok(&next_frame(&mut second).await?, &recipient_id)?;
    let bodies = drain_incoming(&mut second, Duration::from_millis(400)).await?;
    assert!(
        bodies.is_empty(),
        "повторное подключение не должно отдавать уже доставленное: {bodies:?}"
    );

    Ok(())
}

/// Очередь конкретного устройства отдельна от общей: сообщение,
/// адресованное устройству, ждёт именно его и не достаётся другому.
#[tokio::test]
async fn device_scoped_message_waits_for_its_device() -> Result<()> {
    let server = spawn_server("replay_device", LimitsConfig::default()).await?;
    let sender = SigningKey::from_bytes(&[35u8; 32]);
    let recipient = SigningKey::from_bytes(&[36u8; 32]);
    let recipient_id = recipient.verifying_key().to_bytes();

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    sender_conn
        .send_frame(&common::encode_client_send(
            &recipient_id,
            Some(7),
            b"for-device-7",
            0,
        )?)
        .await?;
    match decode(&next_frame(&mut sender_conn).await?)? {
        frame::Payload::SendAck(ack) => assert!(ack.queued, "device-scope должен лечь в очередь"),
        other => bail!("expected SendAck, got {other:?}"),
    }

    // Чужое устройство приходит первым и ничего не получает.
    {
        let mut other_device = connect_as(&server, &recipient, Some(9), FRAME_MAX).await?;
        expect_auth_ok(&next_frame(&mut other_device).await?, &recipient_id)?;
        let bodies = drain_incoming(&mut other_device, Duration::from_millis(300)).await?;
        assert!(
            bodies.is_empty(),
            "устройство 9 не должно получать очередь устройства 7: {bodies:?}"
        );
    }

    let mut target = connect_as(&server, &recipient, Some(7), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut target).await?, &recipient_id)?;
    let bodies = drain_incoming(&mut target, Duration::from_millis(400)).await?;
    assert_eq!(bodies, vec![b"for-device-7".to_vec()]);

    Ok(())
}

/// Сообщение живому получателю уходит в его сессию, а не в очередь.
#[tokio::test]
async fn online_recipient_receives_without_queueing() -> Result<()> {
    let server = spawn_server("online_route", LimitsConfig::default()).await?;
    let sender = SigningKey::from_bytes(&[37u8; 32]);
    let recipient = SigningKey::from_bytes(&[38u8; 32]);
    let recipient_id = recipient.verifying_key().to_bytes();

    let mut recipient_conn = connect(&server, &recipient).await?;
    expect_auth_ok(&next_frame(&mut recipient_conn).await?, &recipient_id)?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    let ack = send_and_read_ack(&mut sender_conn, &recipient_id, b"live", 0).await?;
    assert!(ack.ok, "получатель онлайн — доставка должна быть прямой");
    assert!(!ack.queued, "в очередь класть было незачем");

    let bodies = drain_incoming(&mut recipient_conn, Duration::from_millis(400)).await?;
    assert_eq!(bodies, vec![b"live".to_vec()]);

    Ok(())
}
