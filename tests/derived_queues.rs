//! Очереди по тегу, надгробия и срок (server-contract.md, §6.7).
//!
//! Устройства одного аккаунта не связаны между собой и сходятся в
//! состоянии очередей только через ноду: одинаковый тег — одна и та же
//! очередь, отозванная — надгробие, которое не воскресить повторным
//! выделением.

mod common;

use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, NodeOptions, connect, decode, encode_ping, expect_auth_ok, next_frame, random_identity,
    send_raw_and_read_ack, spawn_node_with, spawn_server, spawn_server_with_queue_addressing,
    unix_now_secs, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use sha2::{Digest, Sha256};
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::wire::{self, Frame, QueueRejectReason, frame};

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: common::PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

/// Формула вывода, записанная независимо от кода ноды — так, как её
/// повторяет клиент.
fn expected_id(owner: &[u8; 32], tag: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"tm-queue-id-v1\0");
    hasher.update(owner);
    hasher.update(tag);
    hasher.finalize().to_vec()
}

async fn session(server: &common::ServerHandle, identity: &SigningKey) -> Result<Conn> {
    let mut conn = connect(server, identity).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn queue_ack(conn: &mut Conn, request: frame::Payload) -> Result<wire::QueueAck> {
    conn.send_frame(&wrap(request)).await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueAck(ack) => Ok(ack),
        other => bail!("expected QueueAck, got {other:?}"),
    }
}

async fn allocate(
    conn: &mut Conn,
    tag: &[u8],
    expires_at: u64,
    revoked: bool,
) -> Result<wire::QueueAck> {
    queue_ack(
        conn,
        frame::Payload::AllocateQueue(wire::AllocateQueue {
            tag: tag.to_vec(),
            expires_at,
            revoked,
        }),
    )
    .await
}

async fn revoke(conn: &mut Conn, queue_id: &[u8]) -> Result<wire::QueueAck> {
    queue_ack(
        conn,
        frame::Payload::RevokeQueue(wire::RevokeQueue {
            queue_id: queue_id.to_vec(),
        }),
    )
    .await
}

async fn list(conn: &mut Conn) -> Result<wire::QueueList> {
    conn.send_frame(&wrap(frame::Payload::ListQueues(wire::ListQueues {})))
        .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueList(list) => Ok(list),
        other => bail!("expected QueueList, got {other:?}"),
    }
}

fn send_by_queue(queue_id: &[u8], body: &[u8]) -> Vec<u8> {
    wrap(frame::Payload::ClientSend(wire::ClientSend {
        body: body.to_vec(),
        queue_id: queue_id.to_vec(),
        ..wire::ClientSend::default()
    }))
}

async fn expect_incoming(conn: &mut Conn) -> Result<wire::IncomingMessage> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::Incoming(message) => Ok(message),
        other => bail!("expected IncomingMessage, got {other:?}"),
    }
}

fn record<'a>(list: &'a wire::QueueList, queue_id: &[u8]) -> Option<&'a wire::QueueRecord> {
    list.queues
        .iter()
        .find(|record| record.queue_id == queue_id)
}

/// Тег даёт одну и ту же очередь из любой сессии аккаунта — в том числе из
/// двух одновременных, — и id совпадает с формулой, которую считает
/// клиент.
#[tokio::test]
async fn the_same_tag_yields_the_same_queue_from_any_session() -> Result<()> {
    let server = spawn_server("dq_same_tag", LimitsConfig::default()).await?;
    let owner = random_identity();
    let owner_id = user_id_of(&owner);
    let tag = [0x5Au8; 32];

    let mut first = session(&server, &owner).await?;
    let mut second = session(&server, &owner).await?;
    let (a, b) = tokio::join!(
        allocate(&mut first, &tag, 0, false),
        allocate(&mut second, &tag, 0, false)
    );
    let (a, b) = (a?, b?);
    assert!(a.ok && b.ok, "allocation refused: {a:?} / {b:?}");
    assert_eq!(a.queue_id, b.queue_id);
    assert_eq!(a.queue_id, expected_id(&owner_id, &tag));

    // И повтор — тот же id, а очередь одна.
    let again = allocate(&mut first, &tag, 0, false).await?;
    assert_eq!(again.queue_id, a.queue_id);
    let listed = list(&mut second).await?;
    assert_eq!(listed.queues.len(), 1);
    assert_eq!(listed.queues[0].revoked_at, 0);

    // Тот же тег у другого аккаунта — другая очередь.
    let stranger = random_identity();
    let mut stranger_conn = session(&server, &stranger).await?;
    let foreign = allocate(&mut stranger_conn, &tag, 0, false).await?;
    assert!(foreign.ok);
    assert_ne!(foreign.queue_id, a.queue_id);
    Ok(())
}

/// Негодные параметры — `INVALID`, и ничего не создано.
#[tokio::test]
async fn invalid_parameters_are_refused_without_side_effects() -> Result<()> {
    let server = spawn_server("dq_invalid", LimitsConfig::default()).await?;
    let owner = random_identity();
    let mut conn = session(&server, &owner).await?;
    let now = unix_now_secs();

    for (tag, expires_at, revoked) in [
        (vec![1u8; 31], 0, false),
        (vec![1u8; 33], 0, false),
        (vec![1u8; 32], now.saturating_sub(10), false),
        (Vec::new(), now.saturating_sub(10), false),
        (Vec::new(), 0, true),
    ] {
        let ack = allocate(&mut conn, &tag, expires_at, revoked).await?;
        assert!(!ack.ok, "must be refused: tag {} bytes", tag.len());
        assert_eq!(ack.reason, QueueRejectReason::Invalid as i32);
        assert!(ack.queue_id.is_empty());
    }
    assert!(list(&mut conn).await?.queues.is_empty());
    Ok(())
}

/// Отзыв оставляет надгробие: депозит по id — `NO_PERMIT`, тот же тег —
/// `REVOKED`, повторный отзыв — `ok`, а в списке видно, когда отозвана.
#[tokio::test]
async fn revocation_leaves_a_tombstone_that_cannot_be_reallocated() -> Result<()> {
    let server =
        spawn_server_with_queue_addressing("dq_tombstone", LimitsConfig::default()).await?;
    let owner = random_identity();
    let sender = random_identity();
    let tag = [0x11u8; 32];

    let mut owner_conn = session(&server, &owner).await?;
    let queue_id = allocate(&mut owner_conn, &tag, 0, false).await?.queue_id;
    let mut sender_conn = session(&server, &sender).await?;
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&queue_id, b"before")).await?;
    assert!(ack.ok || ack.queued, "deposit must pass: {ack:?}");
    assert_eq!(expect_incoming(&mut owner_conn).await?.body, b"before");

    assert!(revoke(&mut owner_conn, &queue_id).await?.ok);
    // Повторный отзыв своего надгробия — успех, а не NOT_FOUND.
    assert!(revoke(&mut owner_conn, &queue_id).await?.ok);

    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&queue_id, b"after")).await?;
    assert!(!ack.ok && !ack.queued);
    assert_eq!(ack.reason, SendRejectReason::NoPermit);

    let refused = allocate(&mut owner_conn, &tag, 0, false).await?;
    assert!(!refused.ok);
    assert_eq!(refused.reason, QueueRejectReason::Revoked as i32);
    assert!(refused.queue_id.is_empty());

    let listed = list(&mut owner_conn).await?;
    let tombstone = record(&listed, &queue_id).expect("tombstone must be listed");
    assert_eq!(tombstone.created_at, 0);
    assert!(tombstone.revoked_at > 0);
    Ok(())
}

/// `revoked = true` на новой ноде пула — надгробие сразу: заблокированный
/// контакт не получит по старому id доступа и там, где очередь ещё не
/// заводилась.
#[tokio::test]
async fn seeding_a_tombstone_blocks_the_id_from_the_start() -> Result<()> {
    let server = spawn_server_with_queue_addressing("dq_seed", LimitsConfig::default()).await?;
    let owner = random_identity();
    let owner_id = user_id_of(&owner);
    let sender = random_identity();
    let tag = [0x22u8; 32];

    let mut owner_conn = session(&server, &owner).await?;
    let ack = allocate(&mut owner_conn, &tag, 0, true).await?;
    assert!(ack.ok, "tombstone seeding refused: {:?}", ack.reason);
    assert_eq!(ack.queue_id, expected_id(&owner_id, &tag));
    // Идемпотентно.
    assert!(allocate(&mut owner_conn, &tag, 0, true).await?.ok);

    let mut sender_conn = session(&server, &sender).await?;
    let deposit =
        send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&ack.queue_id, b"x")).await?;
    assert_eq!(deposit.reason, SendRejectReason::NoPermit);
    assert_eq!(
        allocate(&mut owner_conn, &tag, 0, false).await?.reason,
        QueueRejectReason::Revoked as i32
    );
    let listed = list(&mut owner_conn).await?;
    assert!(record(&listed, &ack.queue_id).unwrap().revoked_at > 0);
    Ok(())
}

/// Очередь со сроком: до срока депозит проходит, после — `NO_PERMIT`, а в
/// списке она надгробие с `revoked_at = expires_at`.
#[tokio::test]
async fn an_expiring_queue_closes_at_its_deadline() -> Result<()> {
    let server = spawn_server_with_queue_addressing("dq_expiry", LimitsConfig::default()).await?;
    let owner = random_identity();
    let sender = random_identity();
    let tag = [0x33u8; 32];
    let expires_at = unix_now_secs() + 2;

    let mut owner_conn = session(&server, &owner).await?;
    let queue_id = allocate(&mut owner_conn, &tag, expires_at, false)
        .await?
        .queue_id;
    let listed = list(&mut owner_conn).await?;
    assert_eq!(record(&listed, &queue_id).unwrap().expires_at, expires_at);

    let mut sender_conn = session(&server, &sender).await?;
    let ack =
        send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&queue_id, b"in time")).await?;
    assert!(
        ack.ok || ack.queued,
        "deposit before the deadline must pass: {ack:?}"
    );
    assert_eq!(expect_incoming(&mut owner_conn).await?.body, b"in time");

    while unix_now_secs() < expires_at {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&queue_id, b"late")).await?;
    assert_eq!(ack.reason, SendRejectReason::NoPermit);

    let listed = list(&mut owner_conn).await?;
    let tombstone = record(&listed, &queue_id).expect("expired queue must be listed");
    assert_eq!(tombstone.revoked_at, expires_at);
    assert_eq!(tombstone.created_at, 0);
    assert_eq!(
        allocate(&mut owner_conn, &tag, 0, false).await?.reason,
        QueueRejectReason::Revoked as i32
    );
    Ok(())
}

/// Операции очередей не зависят от флага адресации: выделение по тегу,
/// надгробия и сроки работают и при `QUEUE_ADDRESSING_ENABLED=false`.
#[tokio::test]
async fn derived_queues_work_without_queue_addressing() -> Result<()> {
    let server = spawn_server("dq_flag_down", LimitsConfig::default()).await?;
    let owner = random_identity();
    let mut conn = session(&server, &owner).await?;
    let tag = [0x44u8; 32];

    let live = allocate(&mut conn, &tag, unix_now_secs() + 3600, false).await?;
    assert!(live.ok);
    assert!(revoke(&mut conn, &live.queue_id).await?.ok);
    assert_eq!(
        allocate(&mut conn, &tag, 0, false).await?.reason,
        QueueRejectReason::Revoked as i32
    );
    assert!(allocate(&mut conn, &[0x45u8; 32], 0, true).await?.ok);

    let listed = list(&mut conn).await?;
    assert_eq!(listed.queues.len(), 2);
    assert!(listed.queues.iter().all(|record| record.revoked_at > 0));
    Ok(())
}

/// Список, не влезающий в `MAX_FRAME_LEN` ноды, — отказ `INTERNAL`, а не
/// разрыв сессии: клиент принял бы разрыв за сбой сети и повторял запрос
/// по кругу.
#[tokio::test]
async fn a_list_over_the_frame_ceiling_is_refused_not_dropped() -> Result<()> {
    let (server, _internals) = spawn_node_with(
        "dq_small_frame",
        LimitsConfig::default(),
        NodeOptions {
            max_frame_len: Some(2048),
            ..NodeOptions::default()
        },
    )
    .await?;
    let owner = random_identity();
    let mut conn = session(&server, &owner).await?;
    // ~42 байта на надгробие: 64 штуки заведомо длиннее 2 КиБ.
    for i in 0..64u8 {
        assert!(allocate(&mut conn, &[i; 32], 0, true).await?.ok);
    }

    conn.send_frame(&wrap(frame::Payload::ListQueues(wire::ListQueues {})))
        .await?;
    match decode(&next_frame(&mut conn).await?)? {
        frame::Payload::QueueAck(ack) => {
            assert!(!ack.ok);
            assert_eq!(ack.reason, QueueRejectReason::Internal as i32);
        }
        other => bail!("expected QueueAck, got {other:?}"),
    }
    // Сессия жива.
    conn.send_frame(&encode_ping()).await?;
    match decode(&next_frame(&mut conn).await?)? {
        frame::Payload::Pong(_) => Ok(()),
        other => bail!("expected Pong, got {other:?}"),
    }
}
