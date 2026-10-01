//! Потолок тела сообщения относительно потолка кадра.
//!
//! Тело едет в двух кадрах: отправитель присылает его в `ClientSend`,
//! получателю оно уходит в `IncomingMessage`. Служебных полей у кадра
//! доставки больше, поэтому тело, заполняющее `ClientSend` до
//! `max_frame_len`, в `IncomingMessage` уже не помещается. Раньше нода
//! такое тело принимала, а запись кадра получателю рвала его сессию.
//! Теперь тело ограничено на входе: отказ получает отправитель, а
//! получатель ничего не замечает.

mod common;

use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    FRAME_MAX, connect, decode, encode_ping, expect_auth_ok, next_frame, next_incoming_within,
    random_identity, send_and_read_ack, spawn_server, spawn_server_with_internals, user_id_of,
};
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::net::framing::max_send_body_len;
use trust_message_tcp::state::registry::OutboundFrame;
use trust_message_tcp::wire::frame;

const DELIVERY_WINDOW: Duration = Duration::from_secs(5);

/// Сессия жива: на `Ping` приходит `Pong`.
async fn expect_alive(conn: &mut common::Conn) -> Result<()> {
    conn.send_frame(&encode_ping()).await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::Pong(_) => Ok(()),
        other => bail!("expected Pong from a live session, got {other:?}"),
    }
}

/// Тело на один байт длиннее потолка отклоняется отправителю как
/// `TOO_LARGE`, хотя его `ClientSend` помещается в кадр. Получатель при
/// этом остаётся подключён и получает следующее сообщение — тело ровно на
/// потолке.
#[tokio::test]
async fn body_over_the_ceiling_is_rejected_and_the_recipient_stays_connected() -> Result<()> {
    let server = spawn_server("size_limit_online", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;
    let mut alice_conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;

    let ceiling = max_send_body_len(FRAME_MAX);

    let too_large = vec![0x5Au8; ceiling + 1];
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, &too_large, 0).await?;
    assert!(
        !ack.ok && !ack.queued,
        "тело сверх потолка принято: {ack:?}"
    );
    assert_eq!(ack.reason, SendRejectReason::TooLarge);

    let at_ceiling = vec![0xA5u8; ceiling];
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, &at_ceiling, 0).await?;
    assert!(ack.ok, "тело на потолке не доставлено: {ack:?}");

    let incoming = next_incoming_within(&mut bob_conn, DELIVERY_WINDOW)
        .await?
        .expect("тело на потолке обязано дойти до получателя");
    assert_eq!(incoming.body.len(), ceiling);
    assert!(incoming.body == at_ceiling);

    expect_alive(&mut bob_conn).await?;
    expect_alive(&mut alice_conn).await?;
    Ok(())
}

/// Тело на потолке переживает офлайн-очередь. Кадр реплея длиннее кадра
/// онлайн-доставки на `message_id`, и запас обязан покрывать и его: запись
/// доходит до получателя при подключении, а сессия остаётся жива.
#[tokio::test]
async fn body_at_the_ceiling_survives_the_offline_queue() -> Result<()> {
    let server = spawn_server("size_limit_offline", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut alice_conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;

    let ceiling = max_send_body_len(FRAME_MAX);
    let body = vec![0x3Cu8; ceiling];
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, &body, 0).await?;
    assert!(ack.queued, "тело на потолке не легло в очередь: {ack:?}");

    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;
    let incoming = next_incoming_within(&mut bob_conn, DELIVERY_WINDOW)
        .await?
        .expect("запись из офлайн-очереди обязана прийти при подключении");
    assert_ne!(incoming.message_id, 0);
    assert!(incoming.body == body);

    expect_alive(&mut bob_conn).await?;
    Ok(())
}

/// Запись офлайн-очереди, чей кадр длиннее потолка, при дренаже удаляется,
/// а не отправляется: сессия получателя остаётся жива, запись за ней
/// доходит, и очередь после этого пуста.
///
/// Через `ClientSend` такую запись не создать — тело ограничено на входе, —
/// поэтому она кладётся в хранилище напрямую. Так выглядит очередь после
/// снижения `MAX_FRAME_LEN` и запись, принятая до появления потолка тела.
#[tokio::test]
async fn oversized_offline_record_is_dropped_on_replay() -> Result<()> {
    let (server, node) =
        spawn_server_with_internals("size_limit_replay", LimitsConfig::default()).await?;
    let alice_id = user_id_of(&random_identity());
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let oversized = vec![0x11u8; FRAME_MAX];
    node.storage
        .enqueue_inbox(&bob_id, &alice_id, Some(1), &oversized, None, 0)?;
    node.storage
        .enqueue_inbox(&bob_id, &alice_id, Some(1), b"after the oversized", None, 0)?;

    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;
    let incoming = next_incoming_within(&mut bob_conn, DELIVERY_WINDOW)
        .await?
        .expect("запись после негабаритной обязана дойти");
    assert_eq!(incoming.body, b"after the oversized");

    expect_alive(&mut bob_conn).await?;
    assert!(
        node.storage.drain_inbox(&bob_id, 16)?.is_empty(),
        "негабаритная запись осталась в очереди"
    );
    Ok(())
}

/// Страховка в канале сессии: кадр длиннее потолка, попавший в канал мимо
/// всех проверок, отбрасывается, а сессия продолжает работать — следующий
/// кадр из того же канала доходит.
///
/// Штатно такой кадр в канал не попадает, поэтому он кладётся туда через
/// реестр сессий напрямую.
#[tokio::test]
async fn oversized_frame_in_the_session_channel_does_not_close_the_session() -> Result<()> {
    let (server, node) =
        spawn_server_with_internals("size_limit_channel", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &bob_id)?;
    expect_alive(&mut bob_conn).await?;

    let targets = node.registry.route_targets(&bob_id, None);
    assert_eq!(targets.len(), 1, "у получателя ровно одна сессия");
    targets[0]
        .tx
        .send(OutboundFrame {
            bytes: vec![0u8; FRAME_MAX + 1],
            message_id: None,
            sender_user_id: None,
            sender_device_id: None,
            close_after_send: false,
        })
        .await
        .map_err(|_| anyhow::anyhow!("session channel is closed"))?;

    let mut alice_conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &user_id_of(&alice))?;
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"after the oversized", 0).await?;
    assert!(ack.ok, "сообщение живой сессии не доставлено: {ack:?}");

    let incoming = next_incoming_within(&mut bob_conn, DELIVERY_WINDOW)
        .await?
        .expect("кадр после негабаритного обязан дойти");
    assert_eq!(incoming.body, b"after the oversized");
    expect_alive(&mut bob_conn).await?;
    Ok(())
}
