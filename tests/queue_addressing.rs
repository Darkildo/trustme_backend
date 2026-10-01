//! Адресация депозита по `queueId`.
//!
//! Проверяется и включённый режим, и выключенный: флаг существует ради
//! порядка выкатки, поэтому нода со снятым флагом обязана игнорировать
//! `queueId` так же строго, как нода с поднятым — маршрутизировать по
//! очереди.

mod common;

use anyhow::{Result, bail};
use common::{
    connect, decode, expect_auth_ok, next_frame, send_raw_and_read_ack, spawn_server,
    spawn_server_with_queue_addressing,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::net::TcpStream;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::net::noise::NoiseFramed;
use trust_message_tcp::wire::{self, Frame, frame};

const PROTO_VERSION: u32 = 1;

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

/// Депозит, адресованный только очередью: `recipientId` пуст — так будет
/// выглядеть отправка в целевой модели, где отправитель личности
/// получателя не знает.
fn send_by_queue(queue_id: Vec<u8>, body: &str) -> Vec<u8> {
    wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: Vec::new(),
        body: body.as_bytes().to_vec(),
        recipient_device_id: None,
        priority: 0,
        wake_hint: 0,
        queue_id,
        ttl_seconds: 0,
    }))
}

fn send_by_recipient(recipient: [u8; 32], queue_id: Vec<u8>, body: &str) -> Vec<u8> {
    wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: recipient.to_vec(),
        body: body.as_bytes().to_vec(),
        recipient_device_id: None,
        priority: 0,
        wake_hint: 0,
        queue_id,
        ttl_seconds: 0,
    }))
}

async fn allocate_queue(conn: &mut NoiseFramed<TcpStream>) -> Result<Vec<u8>> {
    conn.send_frame(&wrap(frame::Payload::AllocateQueue(wire::AllocateQueue {})))
        .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueAck(ack) if ack.ok => Ok(ack.queue_id),
        other => bail!("expected a successful QueueAck, got {other:?}"),
    }
}

async fn expect_incoming(conn: &mut NoiseFramed<TcpStream>) -> Result<wire::IncomingMessage> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::Incoming(msg) => Ok(msg),
        other => bail!("expected IncomingMessage, got {other:?}"),
    }
}

/// Основной сценарий: получатель заводит очередь, отправитель кладёт в неё
/// депозит вообще без `recipientId`, конверт приходит владельцу очереди.
#[tokio::test]
async fn a_queue_addressed_deposit_reaches_the_queue_owner() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qa_basic", LimitsConfig::default()).await?;
    let owner = SigningKey::from_bytes(&[41u8; 32]);
    let sender = SigningKey::from_bytes(&[42u8; 32]);

    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(
        &next_frame(&mut owner_conn).await?,
        &owner.verifying_key().to_bytes(),
    )?;
    let queue_id = allocate_queue(&mut owner_conn).await?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    let ack =
        send_raw_and_read_ack(&mut sender_conn, &send_by_queue(queue_id, "via-queue")).await?;
    assert!(ack.ok || ack.queued, "unexpected ack: {ack:?}");

    let incoming = expect_incoming(&mut owner_conn).await?;
    assert_eq!(incoming.body, b"via-queue");
    assert_eq!(incoming.from_user_id, sender.verifying_key().to_bytes());
    Ok(())
}

/// Депозит в неизвестную очередь отвергается, а не уходит по `recipientId`.
/// Иначе отзыв очереди ничего не значил бы: заблокированный контакт просто
/// вернулся бы к прямой адресации.
#[tokio::test]
async fn an_unknown_queue_is_rejected_and_does_not_fall_back() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qa_unknown", LimitsConfig::default()).await?;
    let owner = SigningKey::from_bytes(&[43u8; 32]);
    let sender = SigningKey::from_bytes(&[44u8; 32]);

    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(
        &next_frame(&mut owner_conn).await?,
        &owner.verifying_key().to_bytes(),
    )?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    // `recipientId` заполнен и указывает на живого получателя — и всё
    // равно решает очередь.
    let frame = send_by_recipient(
        owner.verifying_key().to_bytes(),
        vec![9u8; 32],
        "should-not-arrive",
    );
    let ack = send_raw_and_read_ack(&mut sender_conn, &frame).await?;
    assert!(!ack.ok && !ack.queued, "deposit must be refused: {ack:?}");
    assert_eq!(ack.reason, SendRejectReason::NoPermit);
    Ok(())
}

/// Отозванная очередь перестаёт принимать депозиты — это и есть блокировка
/// контакта: спам умирает на ноде, не доезжая до клиента.
#[tokio::test]
async fn revoking_a_queue_stops_deposits_into_it() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qa_revoked", LimitsConfig::default()).await?;
    let owner = SigningKey::from_bytes(&[45u8; 32]);
    let sender = SigningKey::from_bytes(&[46u8; 32]);

    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(
        &next_frame(&mut owner_conn).await?,
        &owner.verifying_key().to_bytes(),
    )?;
    let queue_id = allocate_queue(&mut owner_conn).await?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    // До отзыва — доходит.
    let ack =
        send_raw_and_read_ack(&mut sender_conn, &send_by_queue(queue_id.clone(), "before")).await?;
    assert!(ack.ok || ack.queued, "unexpected ack: {ack:?}");
    assert_eq!(expect_incoming(&mut owner_conn).await?.body, b"before");

    owner_conn
        .send_frame(&wrap(frame::Payload::RevokeQueue(wire::RevokeQueue {
            queue_id: queue_id.clone(),
        })))
        .await?;
    match decode(&next_frame(&mut owner_conn).await?)? {
        frame::Payload::QueueAck(ack) if ack.ok => {}
        other => bail!("revocation failed: {other:?}"),
    }

    // После — нет.
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_queue(queue_id, "after")).await?;
    assert!(
        !ack.ok && !ack.queued,
        "deposit into a revoked queue must be refused: {ack:?}"
    );
    assert_eq!(ack.reason, SendRejectReason::NoPermit);
    Ok(())
}

/// Со снятым флагом `queueId` принимается и игнорируется, доставка идёт
/// по `recipientId`.
#[tokio::test]
async fn with_the_flag_down_the_queue_id_is_still_ignored() -> Result<()> {
    let server = spawn_server("qa_flag_down", LimitsConfig::default()).await?;
    let owner = SigningKey::from_bytes(&[47u8; 32]);
    let sender = SigningKey::from_bytes(&[48u8; 32]);

    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(
        &next_frame(&mut owner_conn).await?,
        &owner.verifying_key().to_bytes(),
    )?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    // Выдуманная очередь и настоящий получатель: со снятым флагом это
    // обычная доставка, а не отказ.
    let frame = send_by_recipient(owner.verifying_key().to_bytes(), vec![9u8; 32], "direct");
    let ack = send_raw_and_read_ack(&mut sender_conn, &frame).await?;
    assert!(ack.ok || ack.queued, "unexpected ack: {ack:?}");
    assert_eq!(expect_incoming(&mut owner_conn).await?.body, b"direct");
    Ok(())
}

/// Очередь адресует аккаунт целиком, поэтому `recipientDeviceId` рядом с
/// ней не сужает доставку: конверт приходит в сессию без device_id так же,
/// как и в любую другую.
#[tokio::test]
async fn a_queue_addressed_deposit_is_account_scoped() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qa_scope", LimitsConfig::default()).await?;
    let owner = SigningKey::from_bytes(&[49u8; 32]);
    let sender = SigningKey::from_bytes(&[50u8; 32]);

    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(
        &next_frame(&mut owner_conn).await?,
        &owner.verifying_key().to_bytes(),
    )?;
    let queue_id = allocate_queue(&mut owner_conn).await?;

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(
        &next_frame(&mut sender_conn).await?,
        &sender.verifying_key().to_bytes(),
    )?;

    let framed = wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: Vec::new(),
        body: b"account-scope".to_vec(),
        // Устройство указано, но очередь принадлежит аккаунту — сужения
        // не происходит.
        recipient_device_id: Some(7),
        priority: 0,
        wake_hint: 0,
        queue_id,
        ttl_seconds: 0,
    }));
    let ack = send_raw_and_read_ack(&mut sender_conn, &framed).await?;
    assert!(ack.ok || ack.queued, "unexpected ack: {ack:?}");
    assert_eq!(
        expect_incoming(&mut owner_conn).await?.body,
        b"account-scope"
    );
    Ok(())
}
