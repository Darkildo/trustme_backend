//! Флуд-тест квот.
//!
//! Каждая квота проверяется одинаково: клиент упирается в неё и получает
//! на проводе `SendAck { ok: false, queued: false, reason }` — то есть
//! отказ виден клиенту как отказ, а не как «принято и потерялось».
//! Соединение при этом остаётся рабочим: лимиты гасят поток, а не сессию.
//!
//! Лимиты в тестах маленькие — упираться в дефолты (10 000 сообщений,
//! 256 MiB/сутки) в CI незачем: проверяется поведение на границе, а сама
//! граница берётся из конфига.

mod common;

use anyhow::Result;
use common::{Ack, connect, decode, next_frame, send_and_read_ack, spawn_server};
use ed25519_dalek::SigningKey;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::wire::frame;

fn open_limits() -> LimitsConfig {
    LimitsConfig {
        ttl_min_seconds: 0,
        max_messages_per_queue: 0,
        max_bytes_per_queue: 0,
        max_messages_sender_pair: 0,
        send_msgs_per_sec: 0,
        send_bytes_per_day: 0,
        max_sessions_per_user: 0,
        ping_per_sec: 0,
        max_queues_per_user: 0,
        // Вход не ограничиваем: тест меряет квоты сообщений, а не admission.
        handshake_max_inflight: 0,
        handshake_max_inflight_per_ip: 0,
    }
}

fn recipient(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

/// Rate-limit msg/s: первые сообщения проходят, следующее упирается в
/// секундное окно и приходит `rateLimited`.
#[tokio::test]
async fn message_rate_limit_is_reported_as_rate_limited() -> Result<()> {
    let limits = LimitsConfig {
        send_msgs_per_sec: 3,
        ..open_limits()
    };
    let server = spawn_server("flood_rate", limits).await?;
    let sender = SigningKey::from_bytes(&[21u8; 32]);
    let mut conn = connect(&server, &sender).await?;
    next_frame(&mut conn).await?; // AuthOk

    let target = recipient(22);
    for i in 0..3 {
        let ack = send_and_read_ack(&mut conn, &target, b"burst", 0).await?;
        assert_eq!(
            ack.reason,
            SendRejectReason::Unspecified,
            "message {i} must be accepted"
        );
    }

    let rejected = send_and_read_ack(&mut conn, &target, b"burst", 0).await?;
    assert_eq!(
        rejected,
        Ack {
            ok: false,
            queued: false,
            queue_id: 0,
            reason: SendRejectReason::RateLimited
        }
    );

    // Сессия жива: отказ гасит поток, а не соединение.
    let config_still_served = {
        conn.send_frame(&common::encode_get_server_config()?)
            .await?;
        let bytes = next_frame(&mut conn).await?;
        matches!(decode(&bytes)?, frame::Payload::SignedServerConfig(_))
    };
    assert!(
        config_still_served,
        "connection must survive a rate-limit reject"
    );

    Ok(())
}

/// Байтовый бюджет за сутки: он считается по объёму, а не по числу
/// сообщений, поэтому упереться можно и одним крупным телом.
#[tokio::test]
async fn daily_byte_budget_is_reported_as_rate_limited() -> Result<()> {
    let limits = LimitsConfig {
        send_bytes_per_day: 1024,
        ..open_limits()
    };
    let server = spawn_server("flood_bytes", limits).await?;
    let sender = SigningKey::from_bytes(&[23u8; 32]);
    let mut conn = connect(&server, &sender).await?;
    next_frame(&mut conn).await?;

    let target = recipient(24);
    let body = vec![7u8; 600];

    let first = send_and_read_ack(&mut conn, &target, &body, 0).await?;
    assert_eq!(first.reason, SendRejectReason::Unspecified);

    // 600 + 600 > 1024 — второе тело в бюджет уже не влезает.
    let second = send_and_read_ack(&mut conn, &target, &body, 0).await?;
    assert_eq!(second.reason, SendRejectReason::RateLimited);
    assert!(!second.ok && !second.queued);

    Ok(())
}

/// Пол ttl: ненулевой срок ниже порога ноды отвергается до маршрутизации,
/// а `ttl = 0` (legacy-клиент) проходит — проверка не должна ломать старых.
#[tokio::test]
async fn ttl_below_floor_is_reported_as_invalid_ttl() -> Result<()> {
    let limits = LimitsConfig {
        ttl_min_seconds: 86_400,
        ..open_limits()
    };
    let server = spawn_server("flood_ttl", limits).await?;
    let sender = SigningKey::from_bytes(&[25u8; 32]);
    let mut conn = connect(&server, &sender).await?;
    next_frame(&mut conn).await?;

    let target = recipient(26);

    let rejected = send_and_read_ack(&mut conn, &target, b"short ttl", 600).await?;
    assert_eq!(rejected.reason, SendRejectReason::InvalidTtl);
    assert!(!rejected.ok && !rejected.queued);

    let legacy = send_and_read_ack(&mut conn, &target, b"no ttl", 0).await?;
    assert_eq!(legacy.reason, SendRejectReason::Unspecified);

    let at_floor = send_and_read_ack(&mut conn, &target, b"at floor", 86_400).await?;
    assert_eq!(at_floor.reason, SendRejectReason::Unspecified);

    Ok(())
}

/// Квота очереди получателя: пока он офлайн, сообщения копятся, и на
/// границе нода начинает отвечать `full`.
#[tokio::test]
async fn queue_quota_is_reported_as_full() -> Result<()> {
    let limits = LimitsConfig {
        max_messages_per_queue: 3,
        ..open_limits()
    };
    let server = spawn_server("flood_queue", limits).await?;
    let sender = SigningKey::from_bytes(&[27u8; 32]);
    let mut conn = connect(&server, &sender).await?;
    next_frame(&mut conn).await?;

    // Получатель офлайн: всё уходит в очередь.
    let target = recipient(28);
    for i in 0..3 {
        let ack = send_and_read_ack(&mut conn, &target, b"queued", 0).await?;
        assert!(ack.queued, "message {i} must be queued");
        assert_eq!(ack.reason, SendRejectReason::Unspecified);
    }

    let overflow = send_and_read_ack(&mut conn, &target, b"overflow", 0).await?;
    assert_eq!(overflow.reason, SendRejectReason::Full);
    assert!(!overflow.ok && !overflow.queued);

    Ok(())
}

/// Под-квота пары sender→recipient: один болтливый отправитель упирается
/// в свой потолок, а очередь получателя остаётся открытой для других.
#[tokio::test]
async fn sender_pair_subquota_is_reported_as_full() -> Result<()> {
    let limits = LimitsConfig {
        max_messages_sender_pair: 2,
        ..open_limits()
    };
    let server = spawn_server("flood_pair", limits).await?;
    let loud = SigningKey::from_bytes(&[29u8; 32]);
    let quiet = SigningKey::from_bytes(&[30u8; 32]);
    let target = recipient(31);

    let mut loud_conn = connect(&server, &loud).await?;
    next_frame(&mut loud_conn).await?;
    for _ in 0..2 {
        let ack = send_and_read_ack(&mut loud_conn, &target, b"spam", 0).await?;
        assert!(ack.queued);
    }
    let rejected = send_and_read_ack(&mut loud_conn, &target, b"spam", 0).await?;
    assert_eq!(rejected.reason, SendRejectReason::Full);

    // Второй отправитель в ту же очередь всё ещё проходит: под-квота
    // изолирует отправителей друг от друга, а не закрывает почтовый ящик.
    let mut quiet_conn = connect(&server, &quiet).await?;
    next_frame(&mut quiet_conn).await?;
    let accepted = send_and_read_ack(&mut quiet_conn, &target, b"hello", 0).await?;
    assert!(accepted.queued);
    assert_eq!(accepted.reason, SendRejectReason::Unspecified);

    Ok(())
}
