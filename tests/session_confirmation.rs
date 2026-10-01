//! Подтверждение сессии первым кадром клиента.
//!
//! В IK клиент представляется в первом же сообщении, и записанный msg1
//! можно отправить ноде ещё раз: она ответит msg2 и `AuthOk`, не отличив
//! повтор от настоящего входа. Расшифровать ответ и прислать валидный кадр
//! может только владелец эфемерного ключа клиента, поэтому сессией
//! соединение становится лишь после этого кадра. До него — ни регистрации,
//! ни доставки, ни дренажа офлайн-очереди.

mod common;

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use common::{
    Conn, SOCKET_TIMEOUT, connect, connect_unconfirmed, decode, encode_client_send, encode_ping,
    expect_auth_ok, expect_connection_gone, expect_raw_close, msg1_of, next_frame,
    next_incoming_within, random_identity, record_session, replay_msg1, send_and_read_ack,
    spawn_server, user_id_of,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::wire::frame;

/// Слать, пока отправка не ляжет в очередь: так видно, что нода забыла
/// прежние сессии получателя. Попытки, ушедшие в закрывающуюся сессию,
/// пропадают вместе с ней — в очереди остаётся ровно последняя.
async fn send_until_queued(conn: &mut Conn, recipient: &[u8; 32], body: &[u8]) -> Result<()> {
    for _ in 0..100 {
        let ack = send_and_read_ack(conn, recipient, body, 0).await?;
        if ack.queued {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bail!("the recipient's old session never left the registry")
}

/// Все входящие, которые нода отдаёт подряд, пока не замолчит.
async fn drain_bodies(conn: &mut Conn) -> Result<Vec<Vec<u8>>> {
    let mut bodies = Vec::new();
    while let Some(incoming) = next_incoming_within(conn, Duration::from_millis(300)).await? {
        bodies.push(incoming.body);
    }
    Ok(bodies)
}

/// Повтор записанного msg1: нода отвечает, но сессии нет — онлайн-доставки
/// в повтор не бывает, офлайн-очередь он не забирает, а молчащее
/// соединение закрывается по таймауту.
#[tokio::test]
async fn replayed_msg1_neither_registers_nor_drains_the_inbox() -> Result<()> {
    let limits = LimitsConfig {
        session_confirm_timeout_secs: 2,
        ..LimitsConfig::default()
    };
    let server = spawn_server("confirm_replay_msg1", limits).await?;
    let alice = random_identity();
    let alice_id = user_id_of(&alice);
    let bob = random_identity();
    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &user_id_of(&bob))?;

    let recorded = record_session(&server, &alice, true).await?;
    send_until_queued(&mut bob_conn, &alice_id, b"before the replay").await?;

    let mut replay = replay_msg1(&server, &recorded).await?;
    // Прежде нода сразу после `AuthOk` регистрировала сессию и отдавала ей
    // очередь; пауза даёт этому время случиться, если оно случается.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let ack = send_and_read_ack(&mut bob_conn, &alice_id, b"during the replay", 0).await?;
    assert!(
        !ack.ok && ack.queued,
        "a replayed msg1 must not receive online delivery: {ack:?}"
    );

    let closed_after = expect_raw_close(&mut replay, Duration::from_secs(8)).await?;
    assert!(
        closed_after < Duration::from_secs(6),
        "unconfirmed replay outlived the confirmation timeout: {closed_after:?}"
    );

    let mut alice_conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &alice_id)?;
    assert_eq!(
        drain_bodies(&mut alice_conn).await?,
        vec![b"before the replay".to_vec(), b"during the replay".to_vec()],
        "the honest client must get everything the replay was offered"
    );
    Ok(())
}

/// Повтор вместе с записанным подтверждающим кадром тоже ничего не даёт:
/// транспортные ключи зависят от свежего эфемерала ноды, и старый кадр под
/// ними не расшифровывается. Нода закрывает соединение сразу, не дожидаясь
/// таймаута.
#[tokio::test]
async fn replayed_confirming_frame_does_not_confirm_the_replay() -> Result<()> {
    let server = spawn_server("confirm_replay_frame", LimitsConfig::default()).await?;
    let alice = random_identity();
    let alice_id = user_id_of(&alice);
    let bob = random_identity();
    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &user_id_of(&bob))?;

    let recorded = record_session(&server, &alice, true).await?;
    assert!(
        recorded.len() > msg1_of(&recorded)?.len(),
        "the recording must carry the confirming frame"
    );
    send_until_queued(&mut bob_conn, &alice_id, b"kept for alice").await?;

    let mut replay = TcpStream::connect(server.addr).await?;
    replay.write_all(&recorded).await?;
    let closed_after = expect_raw_close(&mut replay, SOCKET_TIMEOUT).await?;
    assert!(
        closed_after < Duration::from_secs(3),
        "a frame that does not decrypt must end the connection at once: {closed_after:?}"
    );

    let mut alice_conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &alice_id)?;
    assert_eq!(
        drain_bodies(&mut alice_conn).await?,
        vec![b"kept for alice".to_vec()]
    );
    Ok(())
}

/// Клиент, получивший `AuthOk` и замолчавший, отключается по таймауту
/// подтверждения.
#[tokio::test]
async fn unconfirmed_session_is_closed_by_the_timeout() -> Result<()> {
    let limits = LimitsConfig {
        session_confirm_timeout_secs: 1,
        ..LimitsConfig::default()
    };
    let server = spawn_server("confirm_timeout", limits).await?;
    let alice = random_identity();

    let mut conn = connect_unconfirmed(&server, &alice, Some(1)).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(&alice))?;
    let started = Instant::now();
    assert!(
        expect_connection_gone(&mut conn).await,
        "an unconfirmed session must not stay open"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "closed before the timeout: {:?}",
        started.elapsed()
    );
    Ok(())
}

/// Офлайн-реплей начинается только после первого кадра клиента и приходит
/// раньше ответа на этот кадр.
#[tokio::test]
async fn offline_replay_starts_after_the_confirming_frame() -> Result<()> {
    let server = spawn_server("confirm_replay_order", LimitsConfig::default()).await?;
    let alice = random_identity();
    let alice_id = user_id_of(&alice);
    let bob = random_identity();
    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &user_id_of(&bob))?;
    let ack = send_and_read_ack(&mut bob_conn, &alice_id, b"waiting", 0).await?;
    assert!(ack.queued, "alice is offline: {ack:?}");

    let mut conn = connect_unconfirmed(&server, &alice, Some(1)).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &alice_id)?;
    assert_eq!(
        next_incoming_within(&mut conn, Duration::from_millis(300)).await?,
        None,
        "nothing may be delivered before the session is confirmed"
    );

    conn.send_frame(&encode_ping()).await?;
    let incoming = next_incoming_within(&mut conn, SOCKET_TIMEOUT)
        .await?
        .context("the offline replay must follow the confirming frame")?;
    assert_eq!(incoming.body, b"waiting");
    match decode(&next_frame(&mut conn).await?)? {
        frame::Payload::Pong(_) => {}
        other => bail!("expected Pong after the replay, got {other:?}"),
    }
    Ok(())
}

/// Подтверждающим может быть любой кадр, и обрабатывается он как обычно.
#[tokio::test]
async fn any_client_frame_confirms_and_is_served() -> Result<()> {
    let server = spawn_server("confirm_by_send", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;

    let mut conn = connect_unconfirmed(&server, &alice, Some(1)).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(&alice))?;
    conn.send_frame(&encode_client_send(&bob_id, None, b"first frame", 0)?)
        .await?;
    match decode(&next_frame(&mut conn).await?)? {
        frame::Payload::SendAck(ack) => assert!(ack.ok, "bob is online: {ack:?}"),
        other => bail!("expected SendAck, got {other:?}"),
    }
    let incoming = next_incoming_within(&mut bob_conn, SOCKET_TIMEOUT)
        .await?
        .context("bob must receive the confirming send")?;
    assert_eq!(incoming.body, b"first frame");
    Ok(())
}

/// Лимит сессий проверяется и при подтверждении: пока одна сессия ждала
/// своего первого кадра, лимит выбрала другая — первая получает
/// `AuthError(401)` уже после `AuthOk`.
#[tokio::test]
async fn session_limit_is_rechecked_on_confirmation() -> Result<()> {
    let limits = LimitsConfig {
        max_sessions_per_user: 1,
        ..LimitsConfig::default()
    };
    let server = spawn_server("confirm_session_limit", limits).await?;
    let alice = random_identity();
    let alice_id = user_id_of(&alice);

    let mut waiting = connect_unconfirmed(&server, &alice, Some(1)).await?;
    expect_auth_ok(&next_frame(&mut waiting).await?, &alice_id)?;

    let mut first = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut first).await?, &alice_id)?;

    waiting.send_frame(&encode_ping()).await?;
    match decode(&next_frame(&mut waiting).await?)? {
        frame::Payload::AuthError(err) => assert_eq!(err.code, 401),
        other => bail!("expected AuthError(401), got {other:?}"),
    }
    assert!(expect_connection_gone(&mut waiting).await);

    // Подтверждённая сессия при этом жива.
    first.send_frame(&encode_ping()).await?;
    match decode(&next_frame(&mut first).await?)? {
        frame::Payload::Pong(_) => Ok(()),
        other => bail!("expected Pong, got {other:?}"),
    }
}

/// До подтверждения соединение держит место на входе: лимит одновременных
/// хендшейков нельзя обойти, открывая сессии и не подтверждая их.
#[tokio::test]
async fn unconfirmed_session_keeps_its_handshake_admission() -> Result<()> {
    let limits = LimitsConfig {
        handshake_max_inflight_per_ip: 1,
        ..LimitsConfig::default()
    };
    let server = spawn_server("confirm_admission", limits).await?;
    let alice = random_identity();
    let bob = random_identity();

    let mut waiting = connect_unconfirmed(&server, &alice, Some(1)).await?;
    expect_auth_ok(&next_frame(&mut waiting).await?, &user_id_of(&alice))?;

    assert!(
        connect_unconfirmed(&server, &bob, Some(1)).await.is_err(),
        "the only admission slot is held by the unconfirmed session"
    );

    waiting.send_frame(&encode_ping()).await?;
    match decode(&next_frame(&mut waiting).await?)? {
        frame::Payload::Pong(_) => {}
        other => bail!("expected Pong, got {other:?}"),
    }

    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &user_id_of(&bob))?;
    Ok(())
}
