//! Control-канал: жизненный цикл mailbox-очередей через живую сессию.
//!
//! Очередь — адрес, по которому контакт кладёт депозит, а знание её
//! идентификатора и есть право писать. Отсюда два свойства, которые
//! проверяются здесь и которые дороже остальных: идентификатор выдаёт
//! нода (клиент не может назвать чужой), и чужую очередь нельзя ни
//! отозвать, ни даже подтвердить её существование.

mod common;

use anyhow::{Result, bail};
use common::{connect, decode, expect_auth_ok, next_frame, spawn_server};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::wire::{self, Frame, QueueRejectReason, frame};

const PROTO_VERSION: u32 = 1;

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn allocate() -> Vec<u8> {
    wrap(frame::Payload::AllocateQueue(wire::AllocateQueue {}))
}

fn revoke(queue_id: Vec<u8>) -> Vec<u8> {
    wrap(frame::Payload::RevokeQueue(wire::RevokeQueue { queue_id }))
}

fn list() -> Vec<u8> {
    wrap(frame::Payload::ListQueues(wire::ListQueues {}))
}

fn expect_ack(bytes: &[u8]) -> Result<wire::QueueAck> {
    match decode(bytes)? {
        frame::Payload::QueueAck(ack) => Ok(ack),
        other => bail!("expected QueueAck, got {other:?}"),
    }
}

fn expect_list(bytes: &[u8]) -> Result<wire::QueueList> {
    match decode(bytes)? {
        frame::Payload::QueueList(list) => Ok(list),
        other => bail!("expected QueueList, got {other:?}"),
    }
}

fn limits(max_queues_per_user: usize) -> LimitsConfig {
    LimitsConfig {
        max_queues_per_user,
        ..LimitsConfig::default()
    }
}

/// Базовый цикл: завести, увидеть в списке, отозвать, увидеть пустой список.
#[tokio::test]
async fn allocate_list_revoke_roundtrip() -> Result<()> {
    let server = spawn_server("queue_roundtrip", limits(0)).await?;
    let identity = SigningKey::from_bytes(&[31u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    conn.send_frame(&allocate()).await?;
    let ack = expect_ack(&next_frame(&mut conn).await?)?;
    assert!(ack.ok, "allocation rejected: {:?}", ack.reason);
    // Идентификатор выдала нода, и он полноразмерный: 32 байта из CSPRNG.
    assert_eq!(ack.queue_id.len(), 32);
    assert_ne!(ack.queue_id, vec![0u8; 32], "queue id must not be all-zero");
    let queue_id = ack.queue_id.clone();

    conn.send_frame(&list()).await?;
    let listed = expect_list(&next_frame(&mut conn).await?)?;
    assert_eq!(listed.queues.len(), 1);
    assert_eq!(listed.queues[0].queue_id, queue_id);
    assert!(listed.queues[0].created_at > 0);

    conn.send_frame(&revoke(queue_id)).await?;
    let ack = expect_ack(&next_frame(&mut conn).await?)?;
    assert!(ack.ok, "revocation rejected: {:?}", ack.reason);

    conn.send_frame(&list()).await?;
    let listed = expect_list(&next_frame(&mut conn).await?)?;
    assert!(listed.queues.is_empty());
    Ok(())
}

/// Два вызова подряд дают разные идентификаторы. Совпадение означало бы,
/// что нода выдала один адрес двум контактам, — то есть депозиты одного
/// видны другому.
#[tokio::test]
async fn every_allocation_yields_a_fresh_id() -> Result<()> {
    let server = spawn_server("queue_fresh_ids", limits(0)).await?;
    let identity = SigningKey::from_bytes(&[32u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    let mut seen = Vec::new();
    for _ in 0..8 {
        conn.send_frame(&allocate()).await?;
        let ack = expect_ack(&next_frame(&mut conn).await?)?;
        assert!(ack.ok);
        assert!(!seen.contains(&ack.queue_id), "queue id repeated");
        seen.push(ack.queue_id);
    }
    Ok(())
}

/// Чужую очередь нельзя отозвать, и ответ обязан быть неотличим от «такой
/// очереди нет». Иначе `RevokeQueue` становится оракулом: подтверждает,
/// что идентификатор существует, — а идентификатор и есть право писать.
#[tokio::test]
async fn a_stranger_gets_not_found_not_forbidden() -> Result<()> {
    let server = spawn_server("queue_stranger", limits(0)).await?;
    let owner = SigningKey::from_bytes(&[33u8; 32]);
    let stranger = SigningKey::from_bytes(&[34u8; 32]);

    let mut owner_conn = connect(&server, &owner).await?;
    expect_auth_ok(
        &next_frame(&mut owner_conn).await?,
        &owner.verifying_key().to_bytes(),
    )?;
    owner_conn.send_frame(&allocate()).await?;
    let ack = expect_ack(&next_frame(&mut owner_conn).await?)?;
    let queue_id = ack.queue_id.clone();

    let mut stranger_conn = connect(&server, &stranger).await?;
    expect_auth_ok(
        &next_frame(&mut stranger_conn).await?,
        &stranger.verifying_key().to_bytes(),
    )?;

    stranger_conn.send_frame(&revoke(queue_id.clone())).await?;
    let ack = expect_ack(&next_frame(&mut stranger_conn).await?)?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::NotFound as i32);

    // И ответ на выдуманный идентификатор — ровно такой же.
    stranger_conn.send_frame(&revoke(vec![7u8; 32])).await?;
    let ack = expect_ack(&next_frame(&mut stranger_conn).await?)?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::NotFound as i32);

    // Очередь владельца при этом на месте.
    owner_conn.send_frame(&list()).await?;
    let listed = expect_list(&next_frame(&mut owner_conn).await?)?;
    assert_eq!(listed.queues.len(), 1);
    assert_eq!(listed.queues[0].queue_id, queue_id);
    Ok(())
}

/// Потолок очередей упирается отказом, а не молчаливым успехом: аллокация
/// дёшева для клиента и вечна для ноды.
#[tokio::test]
async fn the_per_user_ceiling_is_enforced() -> Result<()> {
    let server = spawn_server("queue_ceiling", limits(2)).await?;
    let identity = SigningKey::from_bytes(&[35u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    for _ in 0..2 {
        conn.send_frame(&allocate()).await?;
        assert!(expect_ack(&next_frame(&mut conn).await?)?.ok);
    }

    conn.send_frame(&allocate()).await?;
    let ack = expect_ack(&next_frame(&mut conn).await?)?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::Limit as i32);
    assert!(
        ack.queue_id.is_empty(),
        "rejected allocation must not carry an id"
    );
    Ok(())
}

/// Мусор в `queue_id` не рвёт сессию: неверная длина — это не
/// рассинхронизация потока, а ошибка запроса, и клиент обязан получить на
/// неё ответ и продолжить работать.
#[tokio::test]
async fn a_malformed_queue_id_is_rejected_without_dropping_the_session() -> Result<()> {
    let server = spawn_server("queue_malformed", limits(0)).await?;
    let identity = SigningKey::from_bytes(&[36u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    conn.send_frame(&revoke(vec![1u8; 7])).await?;
    let ack = expect_ack(&next_frame(&mut conn).await?)?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::NotFound as i32);

    // Сессия жива: следующая операция проходит.
    conn.send_frame(&allocate()).await?;
    assert!(expect_ack(&next_frame(&mut conn).await?)?.ok);
    Ok(())
}

/// Очереди принадлежат аккаунту, а не устройству: заведённая одной сессией
/// видна другой сессии того же пользователя. Иначе переустановка клиента
/// на втором устройстве потеряла бы контакты первого.
#[tokio::test]
async fn queues_belong_to_the_account_not_the_session() -> Result<()> {
    let server = spawn_server("queue_account_scope", limits(0)).await?;
    let identity = SigningKey::from_bytes(&[37u8; 32]);

    let mut first = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut first).await?,
        &identity.verifying_key().to_bytes(),
    )?;
    first.send_frame(&allocate()).await?;
    let queue_id = expect_ack(&next_frame(&mut first).await?)?.queue_id;

    let mut second = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut second).await?,
        &identity.verifying_key().to_bytes(),
    )?;
    second.send_frame(&list()).await?;
    let listed = expect_list(&next_frame(&mut second).await?)?;
    assert_eq!(listed.queues.len(), 1);
    assert_eq!(listed.queues[0].queue_id, queue_id);
    Ok(())
}
