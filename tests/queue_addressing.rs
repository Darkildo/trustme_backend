//! Адресация депозита по `queueId`.
//!
//! Проверяется и включённый режим, и выключенный: флаг существует ради
//! порядка выкатки, поэтому нода со снятым флагом обязана игнорировать
//! `queueId` так же строго, как нода с поднятым — маршрутизировать по
//! очереди.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, NodeOptions, connect, connect_as, decode, expect_auth_ok, next_frame,
    next_incoming_within, random_identity, send_raw_and_read_ack, spawn_node_with, spawn_server,
    spawn_server_with_queue_addressing, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::push::{MockTransport, PushKind};
use trust_message_tcp::wire::{self, Frame, frame};

/// Сколько ждать конверт, которого быть не должно.
const SILENCE: Duration = Duration::from_millis(400);

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

async fn allocate_queue(conn: &mut Conn) -> Result<Vec<u8>> {
    conn.send_frame(&wrap(frame::Payload::AllocateQueue(
        wire::AllocateQueue::default(),
    )))
    .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueAck(ack) if ack.ok => Ok(ack.queue_id),
        other => bail!("expected a successful QueueAck, got {other:?}"),
    }
}

async fn expect_incoming(conn: &mut Conn) -> Result<wire::IncomingMessage> {
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

/// A mailbox statement cannot redirect a named recipient into another
/// account's live queue. The rejection is indistinguishable from an unknown
/// queue, and the sender can still send a correctly bound deposit.
#[tokio::test]
async fn a_queue_owner_must_match_a_named_recipient() -> Result<()> {
    let server =
        spawn_server_with_queue_addressing("qa_owner_binding", LimitsConfig::default()).await?;
    let owner = random_identity();
    let other = random_identity();
    let sender = random_identity();
    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(&next_frame(&mut owner_conn).await?, &user_id_of(&owner))?;
    let queue = allocate_queue(&mut owner_conn).await?;
    let mut other_conn = connect(&server, &other).await?;
    expect_auth_ok(&next_frame(&mut other_conn).await?, &user_id_of(&other))?;
    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(&next_frame(&mut sender_conn).await?, &user_id_of(&sender))?;
    let bad = send_by_recipient(user_id_of(&other), queue.clone(), "wrong owner");
    let ack = send_raw_and_read_ack(&mut sender_conn, &bad).await?;
    assert!(!ack.ok && !ack.queued);
    assert_eq!(ack.reason, SendRejectReason::NoPermit);
    assert!(
        next_incoming_within(&mut owner_conn, SILENCE)
            .await?
            .is_none()
    );
    assert!(
        next_incoming_within(&mut other_conn, SILENCE)
            .await?
            .is_none()
    );
    let good = send_by_recipient(user_id_of(&owner), queue, "bound owner");
    let ack = send_raw_and_read_ack(&mut sender_conn, &good).await?;
    assert!(ack.ok || ack.queued);
    assert_eq!(expect_incoming(&mut owner_conn).await?.body, b"bound owner");
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

/// Депозит по очереди с указанием устройства (ответы sync).
fn send_to_device(queue_id: &[u8], device_id: Option<u32>, body: &str) -> Vec<u8> {
    wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: Vec::new(),
        body: body.as_bytes().to_vec(),
        recipient_device_id: device_id,
        priority: wire::MessagePriority::High as i32,
        wake_hint: 0,
        queue_id: queue_id.to_vec(),
        ttl_seconds: 0,
    }))
}

async fn device_session(
    server: &common::ServerHandle,
    identity: &SigningKey,
    device_id: u16,
) -> Result<Conn> {
    let mut conn = connect_as(server, identity, Some(device_id), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

/// Очередь плюс `recipientDeviceId` — доставка только этому устройству
/// владельца очереди, как у `recipientId` с устройством. Другое устройство
/// того же аккаунта конверта не видит.
#[tokio::test]
async fn a_queue_deposit_with_a_device_reaches_only_that_device() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qa_device", LimitsConfig::default()).await?;
    let owner = random_identity();
    let sender = random_identity();

    let mut phone = device_session(&server, &owner, 1).await?;
    let mut tablet = device_session(&server, &owner, 7).await?;
    let queue_id = allocate_queue(&mut phone).await?;
    let mut sender_conn = device_session(&server, &sender, 1).await?;

    let ack = send_raw_and_read_ack(
        &mut sender_conn,
        &send_to_device(&queue_id, Some(7), "to-tablet"),
    )
    .await?;
    assert!(ack.ok, "online device must receive it: {ack:?}");
    assert_eq!(expect_incoming(&mut tablet).await?.body, b"to-tablet");
    assert_eq!(next_incoming_within(&mut phone, SILENCE).await?, None);
    Ok(())
}

/// Устройство офлайн — конверт ждёт в его device-очереди и при
/// подключении приходит ему, а не другому устройству, которое было онлайн.
#[tokio::test]
async fn a_queue_deposit_for_an_offline_device_waits_for_it() -> Result<()> {
    let server =
        spawn_server_with_queue_addressing("qa_device_offline", LimitsConfig::default()).await?;
    let owner = random_identity();
    let sender = random_identity();

    let mut phone = device_session(&server, &owner, 1).await?;
    let queue_id = allocate_queue(&mut phone).await?;
    let mut sender_conn = device_session(&server, &sender, 1).await?;

    let ack = send_raw_and_read_ack(
        &mut sender_conn,
        &send_to_device(&queue_id, Some(7), "for-tablet"),
    )
    .await?;
    assert!(
        !ack.ok && ack.queued,
        "must wait in the device inbox: {ack:?}"
    );
    assert_eq!(next_incoming_within(&mut phone, SILENCE).await?, None);

    let mut tablet = device_session(&server, &owner, 7).await?;
    let replayed = next_incoming_within(&mut tablet, SILENCE)
        .await?
        .expect("the device inbox must be replayed to that device");
    assert_eq!(replayed.body, b"for-tablet");
    assert_eq!(next_incoming_within(&mut phone, SILENCE).await?, None);
    Ok(())
}

/// Очередь без устройства — как раньше: во все устройства владельца.
#[tokio::test]
async fn a_queue_deposit_without_a_device_reaches_every_device() -> Result<()> {
    let server =
        spawn_server_with_queue_addressing("qa_account_scope", LimitsConfig::default()).await?;
    let owner = random_identity();
    let sender = random_identity();

    let mut phone = device_session(&server, &owner, 1).await?;
    let mut tablet = device_session(&server, &owner, 7).await?;
    let queue_id = allocate_queue(&mut phone).await?;
    let mut sender_conn = device_session(&server, &sender, 1).await?;

    let ack =
        send_raw_and_read_ack(&mut sender_conn, &send_to_device(&queue_id, None, "to-all")).await?;
    assert!(ack.ok, "unexpected ack: {ack:?}");
    assert_eq!(expect_incoming(&mut phone).await?.body, b"to-all");
    assert_eq!(expect_incoming(&mut tablet).await?.body, b"to-all");
    Ok(())
}

/// Пуш по депозиту с устройством будит только это устройство.
#[tokio::test]
async fn a_queue_deposit_with_a_device_wakes_only_that_device() -> Result<()> {
    let transport = Arc::new(MockTransport::always_ok());
    let (server, _internals) = spawn_node_with(
        "qa_device_push",
        LimitsConfig::default(),
        NodeOptions {
            queue_addressing: true,
            push: Some(transport.clone()),
            ..NodeOptions::default()
        },
    )
    .await?;
    let owner = random_identity();
    let sender = random_identity();

    let mut queue_id = Vec::new();
    for device in [1u16, 7] {
        let mut conn = device_session(&server, &owner, device).await?;
        conn.send_frame(&wrap(frame::Payload::RegisterPushToken(
            wire::RegisterPushToken {
                token: format!("token-{device}"),
                platform: wire::PushPlatform::AndroidFcm as i32,
            },
        )))
        .await?;
        match decode(&next_frame(&mut conn).await?)? {
            frame::Payload::PushTokenAck(ack) if ack.ok => {}
            other => bail!("push token registration failed: {other:?}"),
        }
        if queue_id.is_empty() {
            queue_id = allocate_queue(&mut conn).await?;
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut sender_conn = device_session(&server, &sender, 1).await?;
    let ack = send_raw_and_read_ack(
        &mut sender_conn,
        &send_to_device(&queue_id, Some(7), "wake"),
    )
    .await?;
    assert!(ack.queued, "unexpected ack: {ack:?}");

    let mut woken = Vec::new();
    for _ in 0..50 {
        woken = transport
            .sent_payloads()
            .iter()
            .filter(|payload| payload.kind == PushKind::Wake)
            .map(|payload| payload.device_id)
            .collect();
        if !woken.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(SILENCE).await;
    let woken_after: Vec<u16> = transport
        .sent_payloads()
        .iter()
        .filter(|payload| payload.kind == PushKind::Wake)
        .map(|payload| payload.device_id)
        .collect();
    assert_eq!(woken, vec![7]);
    assert_eq!(woken_after, vec![7], "no other device may be woken");
    Ok(())
}
