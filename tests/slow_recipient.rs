//! Медленный получатель на прямом (sled) бэкенде.
//!
//! Онлайн-доставка кладёт конверт в канал сессии получателя. Если получатель
//! не читает сокет, канал рано или поздно заполняется — и отправитель не
//! должен из-за этого висеть, а сообщение не должно пропасть: оно уходит в
//! офлайн-очередь, а отставшая сессия выписывается и закрывается.

mod common;

use std::time::Duration;

use anyhow::{Context, Result};
use common::{
    FRAME_MAX, HANDSHAKE_TIMEOUT, confirm, connect, expect_auth_ok, next_frame,
    next_incoming_within, random_identity, send_and_read_ack, spawn_server, user_id_of,
};
use tokio::net::TcpSocket;
use tokio::time::{Instant, timeout};
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::net::noise::NoiseFramed;

/// Лимиты не мешают: тест меряет канал получателя, а не квоты.
fn open_limits() -> LimitsConfig {
    LimitsConfig {
        send_msgs_per_sec: 0,
        send_bytes_per_day: 0,
        max_messages_per_queue: 0,
        max_bytes_per_queue: 0,
        max_messages_sender_pair: 0,
        ..LimitsConfig::default()
    }
}

#[tokio::test]
async fn slow_recipient_does_not_stall_the_sender_or_lose_messages() -> Result<()> {
    let server = spawn_server("slow_recipient", open_limits()).await?;
    let sender = random_identity();
    let recipient = random_identity();
    let recipient_id = user_id_of(&recipient);

    // Маленький приёмный буфер: сокет получателя забивается за несколько
    // конвертов, дальше копится только канал его сессии на ноде.
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(4096)?;
    let stream = socket.connect(server.addr).await?;
    let raw = NoiseFramed::connect(
        stream,
        &server.node_public,
        &recipient,
        Some(1),
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await?;
    let mut slow = confirm(raw).await?;
    expect_auth_ok(&next_frame(&mut slow).await?, &recipient_id)?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(&next_frame(&mut sender_conn).await?, &user_id_of(&sender))?;

    // Каждый ack обязан прийти за `SOCKET_TIMEOUT` (его ждёт
    // `send_and_read_ack`): отправитель, повисший на чужом канале, упал бы
    // здесь по таймауту.
    let filler = vec![0x5Au8; 1024];
    let mut delivered_online = 0usize;
    let mut first_queued = None;
    for index in 0..20_000usize {
        let mut body = format!("{index:08}:").into_bytes();
        body.extend_from_slice(&filler);
        let ack = send_and_read_ack(&mut sender_conn, &recipient_id, &body, 0)
            .await
            .with_context(|| format!("sender stalled on message {index}"))?;
        if ack.queued {
            first_queued = Some(body);
            break;
        }
        assert!(ack.ok, "unexpected reject: {ack:?}");
        delivered_online += 1;
    }
    let first_queued =
        first_queued.context("the lagging session was never evicted; everything went online")?;
    assert!(
        delivered_online >= 1024,
        "eviction must come from a full channel, not earlier: {delivered_online}"
    );

    // Выписанная сессия отдаёт принятое в её канал и закрывается — живой,
    // но недостижимой для новых сообщений она не остаётся.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut drained = 0usize;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, slow.next_frame()).await {
            Ok(Ok(Some(_))) => drained += 1,
            Ok(Ok(None)) | Ok(Err(_)) => break,
            Err(_) => anyhow::bail!(
                "the evicted session stayed open after delivering {drained} envelopes"
            ),
        }
    }
    assert_eq!(
        drained, delivered_online,
        "everything accepted online must reach the slow client before the close"
    );

    // Сообщение, которое канал не принял, ждёт в офлайн-очереди.
    let mut again = connect(&server, &recipient).await?;
    expect_auth_ok(&next_frame(&mut again).await?, &recipient_id)?;
    let replayed = next_incoming_within(&mut again, Duration::from_secs(5))
        .await?
        .context("the message refused by the full channel was lost")?;
    assert_eq!(replayed.body, first_queued);
    Ok(())
}
