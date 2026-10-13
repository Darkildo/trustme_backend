//! Медленный получатель на прямом (sled) бэкенде.
//!
//! Конверт ложится в очередь получателя, а его сессии уходит уведомление.
//! Если получатель не читает сокет, сначала заполняется окно
//! неподтверждённых (дальше выдача ждёт подтверждений, сессия живёт), а
//! если встал сам сокет — канал сессии, и тогда сессия выписывается и
//! закрывается. В обоих случаях отправитель не висит на чужом сокете, а
//! сообщения не пропадают: всё неподтверждённое лежит в очереди.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use common::{
    FRAME_MAX, HANDSHAKE_TIMEOUT, confirm, connect, connect_as, encode_delivery_ack,
    expect_auth_ok, expect_incoming, next_frame, next_incoming_within, random_identity,
    send_and_read_ack, spawn_server, user_id_of,
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

/// Сколько конвертов шлёт тест: заведомо больше окна неподтверждённых
/// (1024) и больше, чем помещается в сокетные буферы loopback при
/// приёмном буфере в 4 КиБ.
const SENT: usize = 3_000;

#[tokio::test]
async fn slow_recipient_does_not_stall_the_sender_or_lose_messages() -> Result<()> {
    let server = spawn_server("slow_recipient", open_limits()).await?;
    let sender = random_identity();
    let recipient = random_identity();
    let recipient_id = user_id_of(&recipient);

    // Маленький приёмный буфер: сокет получателя забивается за несколько
    // конвертов, дальше копятся окно и канал его сессии на ноде.
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
    // здесь по таймауту. Принят обязан быть каждый конверт: онлайн, а если
    // отставшую сессию выписали за переполненный канал, — в очередь.
    let filler = vec![0x5Au8; 1024];
    let mut sent = HashSet::new();
    for index in 0..SENT {
        let mut body = format!("{index:08}:").into_bytes();
        body.extend_from_slice(&filler);
        let ack = send_and_read_ack(&mut sender_conn, &recipient_id, &body, 0)
            .await
            .with_context(|| format!("sender stalled on message {index}"))?;
        assert!(ack.ok || ack.queued, "unexpected reject: {ack:?}");
        sent.insert(body);
    }

    // Получатель начинает читать и подтверждать. Конверты, которые не
    // поместились в окно, лежат в очереди и дочитываются по мере
    // подтверждений; если сессию выписали, остальное приходит следующей.
    let mut received = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut conn = slow;
    while received.len() < sent.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        anyhow::ensure!(
            !left.is_zero(),
            "only {} of {} envelopes arrived",
            received.len(),
            sent.len()
        );
        match timeout(left, conn.next_frame()).await {
            Ok(Ok(Some(bytes))) => {
                let incoming = expect_incoming(&bytes)?;
                assert_ne!(
                    incoming.message_id, 0,
                    "every envelope must be acknowledgeable"
                );
                conn.send_frame(&encode_delivery_ack(incoming.message_id))
                    .await?;
                received.insert(incoming.body);
            }
            Ok(Ok(None)) | Ok(Err(_)) => {
                conn = connect_as(&server, &recipient, Some(1), FRAME_MAX).await?;
                expect_auth_ok(&next_frame(&mut conn).await?, &recipient_id)?;
            }
            Err(_) => anyhow::bail!(
                "only {} of {} envelopes arrived",
                received.len(),
                sent.len()
            ),
        }
    }
    assert_eq!(received, sent);

    // Всё подтверждено — новая сессия не получает ничего.
    drop(conn);
    let mut again = connect_as(&server, &recipient, Some(1), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut again).await?, &recipient_id)?;
    assert!(
        next_incoming_within(&mut again, Duration::from_millis(500))
            .await?
            .is_none(),
        "acknowledged envelopes must not come back"
    );
    Ok(())
}
