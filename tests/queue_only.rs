//! Режим «только по очередям» (server-contract.md, §6.9).
//!
//! Аккаунт с поднятым флагом достижим только через свои очереди: кадр,
//! адресованный по `recipientId`, нода отвергает с `NO_PERMIT`. На этом
//! держится блокировка контакта — отзыв его очереди ничего не значил бы,
//! если бы контакт мог вернуться к прямой адресации по `user_id`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, NodeOptions, connect, connect_as, connect_delegated, decode, device_key,
    expect_auth_ok, expect_signed_config, issue_device_cert, next_frame, next_incoming_within,
    random_identity, send_raw_and_read_ack, spawn_node_with, spawn_server,
    spawn_server_with_queue_addressing, stop_node, temp_storage_path, unix_now_secs, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::push::{MockTransport, PushKind};
use trust_message_tcp::wire::{self, Frame, QueueRejectReason, frame};

/// Сколько ждать конверт, которого быть не должно.
const SILENCE: Duration = Duration::from_millis(400);

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: common::PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn send_by_recipient(recipient: [u8; 32], body: &[u8]) -> Vec<u8> {
    wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: recipient.to_vec(),
        body: body.to_vec(),
        priority: wire::MessagePriority::High as i32,
        ..wire::ClientSend::default()
    }))
}

fn send_by_queue(queue_id: &[u8], body: &[u8]) -> Vec<u8> {
    wrap(frame::Payload::ClientSend(wire::ClientSend {
        body: body.to_vec(),
        queue_id: queue_id.to_vec(),
        priority: wire::MessagePriority::High as i32,
        ..wire::ClientSend::default()
    }))
}

async fn session(server: &common::ServerHandle, identity: &SigningKey) -> Result<Conn> {
    let mut conn = connect(server, identity).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn session_as(
    server: &common::ServerHandle,
    identity: &SigningKey,
    device_id: u16,
) -> Result<Conn> {
    let mut conn = connect_as(server, identity, Some(device_id), FRAME_MAX).await?;
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

async fn set_queue_only(conn: &mut Conn, enabled: bool) -> Result<wire::QueueAck> {
    queue_ack(
        conn,
        frame::Payload::SetQueueOnly(wire::SetQueueOnly { enabled }),
    )
    .await
}

async fn allocate(conn: &mut Conn) -> Result<Vec<u8>> {
    let ack = queue_ack(
        conn,
        frame::Payload::AllocateQueue(wire::AllocateQueue::default()),
    )
    .await?;
    if !ack.ok {
        bail!("allocation refused: {:?}", ack.reason);
    }
    Ok(ack.queue_id)
}

async fn list(conn: &mut Conn) -> Result<wire::QueueList> {
    conn.send_frame(&wrap(frame::Payload::ListQueues(wire::ListQueues {})))
        .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueList(list) => Ok(list),
        other => bail!("expected QueueList, got {other:?}"),
    }
}

async fn server_config(
    conn: &mut Conn,
    server: &common::ServerHandle,
) -> Result<wire::ServerConfig> {
    conn.send_frame(&common::encode_get_server_config()?)
        .await?;
    expect_signed_config(&next_frame(conn).await?, &server.node_public)
}

fn wakes(transport: &MockTransport) -> usize {
    transport
        .sent_payloads()
        .iter()
        .filter(|payload| payload.kind == PushKind::Wake)
        .count()
}

async fn wait_for_wakes(transport: &MockTransport, want: usize) -> usize {
    for _ in 0..100 {
        if wakes(transport) >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    wakes(transport)
}

/// Главный сценарий: получатель включил режим. Кадр по `recipientId`
/// отвергается `NO_PERMIT` и не оставляет следа — ни конверта в
/// офлайн-очереди, ни пуша; депозит в его очередь проходит и будит его.
#[tokio::test]
async fn recipient_id_deposit_is_refused_and_leaves_no_trace() -> Result<()> {
    let transport = Arc::new(MockTransport::always_ok());
    let (server, _internals) = spawn_node_with(
        "qo_refused",
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
    let owner_id = user_id_of(&owner);

    // Владелец регистрирует push-токен, заводит очередь, включает режим и
    // уходит офлайн.
    let mut owner_conn = session(&server, &owner).await?;
    owner_conn
        .send_frame(&wrap(frame::Payload::RegisterPushToken(
            wire::RegisterPushToken {
                token: "owner-token".to_string(),
                platform: wire::PushPlatform::AndroidFcm as i32,
            },
        )))
        .await?;
    match decode(&next_frame(&mut owner_conn).await?)? {
        frame::Payload::PushTokenAck(ack) if ack.ok => {}
        other => bail!("push token registration failed: {other:?}"),
    }
    let queue_id = allocate(&mut owner_conn).await?;
    let ack = set_queue_only(&mut owner_conn, true).await?;
    assert!(ack.ok, "SetQueueOnly refused: {:?}", ack.reason);
    assert!(ack.queue_id.is_empty());
    drop(owner_conn);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut sender_conn = session(&server, &sender).await?;
    let ack =
        send_raw_and_read_ack(&mut sender_conn, &send_by_recipient(owner_id, b"direct")).await?;
    assert!(!ack.ok && !ack.queued, "deposit must be refused: {ack:?}");
    assert_eq!(ack.reason, SendRejectReason::NoPermit);
    assert_eq!(ack.queue_id, 0);
    tokio::time::sleep(SILENCE).await;
    assert_eq!(
        wakes(&transport),
        0,
        "a refused deposit must not wake anyone"
    );

    // По очереди — проходит и будит: пуш-тракт рабочий, и его молчание
    // выше что-то доказывает.
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&queue_id, b"queued")).await?;
    assert!(
        !ack.ok && ack.queued,
        "queue deposit must be stored: {ack:?}"
    );
    assert_eq!(wait_for_wakes(&transport, 1).await, 1);

    // Владелец, вернувшись, получает только депозит по очереди.
    let mut owner_conn = session(&server, &owner).await?;
    let incoming = next_incoming_within(&mut owner_conn, SILENCE)
        .await?
        .expect("the queue deposit must be replayed");
    assert_eq!(incoming.body, b"queued");
    assert_eq!(next_incoming_within(&mut owner_conn, SILENCE).await?, None);
    Ok(())
}

/// Свои устройства пишут себе свободно: отправитель и есть получатель.
#[tokio::test]
async fn own_devices_reach_each_other_by_recipient_id() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qo_self", LimitsConfig::default()).await?;
    let owner = random_identity();
    let owner_id = user_id_of(&owner);

    let mut first = session_as(&server, &owner, 1).await?;
    let mut second = session_as(&server, &owner, 2).await?;
    assert!(set_queue_only(&mut first, true).await?.ok);

    let ack = send_raw_and_read_ack(&mut first, &send_by_recipient(owner_id, b"to-self")).await?;
    assert!(ack.ok || ack.queued, "self deposit must pass: {ack:?}");
    let incoming = next_incoming_within(&mut second, SILENCE)
        .await?
        .expect("the other device must receive the envelope");
    assert_eq!(incoming.body, b"to-self");
    Ok(())
}

/// Снятие режима возвращает адресацию по `recipientId`.
#[tokio::test]
async fn clearing_the_mode_restores_recipient_id_addressing() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qo_clear", LimitsConfig::default()).await?;
    let owner = random_identity();
    let sender = random_identity();
    let owner_id = user_id_of(&owner);

    let mut owner_conn = session(&server, &owner).await?;
    let mut sender_conn = session(&server, &sender).await?;

    assert!(set_queue_only(&mut owner_conn, true).await?.ok);
    // Идемпотентно.
    assert!(set_queue_only(&mut owner_conn, true).await?.ok);
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_recipient(owner_id, b"no")).await?;
    assert_eq!(ack.reason, SendRejectReason::NoPermit);

    assert!(set_queue_only(&mut owner_conn, false).await?.ok);
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_recipient(owner_id, b"yes")).await?;
    assert!(
        ack.ok,
        "deposit must pass once the mode is cleared: {ack:?}"
    );
    let incoming = next_incoming_within(&mut owner_conn, SILENCE)
        .await?
        .expect("the owner must receive the envelope");
    assert_eq!(incoming.body, b"yes");
    Ok(())
}

/// `ListQueues` отражает флаг.
#[tokio::test]
async fn list_queues_reports_the_mode() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qo_list", LimitsConfig::default()).await?;
    let owner = random_identity();
    let mut conn = session(&server, &owner).await?;

    assert!(!list(&mut conn).await?.queue_only);
    assert!(set_queue_only(&mut conn, true).await?.ok);
    assert!(list(&mut conn).await?.queue_only);
    assert!(set_queue_only(&mut conn, false).await?.ok);
    assert!(!list(&mut conn).await?.queue_only);
    Ok(())
}

/// Отказ по режиму стоит до лимитов и бюджет rate-limit не расходует: иначе
/// любой, кто знает `user_id`, выжигал бы чужой бюджет заведомо
/// отвергаемыми кадрами — в том числе бюджет на честные депозиты.
#[tokio::test]
async fn refusal_does_not_consume_the_rate_limit_budget() -> Result<()> {
    let limits = LimitsConfig {
        send_msgs_per_sec: 1,
        send_bytes_per_day: 0,
        ..LimitsConfig::default()
    };
    let server = spawn_server_with_queue_addressing("qo_rate", limits).await?;
    let owner = random_identity();
    let sender = random_identity();
    let owner_id = user_id_of(&owner);

    let mut owner_conn = session(&server, &owner).await?;
    let queue_id = allocate(&mut owner_conn).await?;
    assert!(set_queue_only(&mut owner_conn, true).await?.ok);

    let mut sender_conn = session(&server, &sender).await?;
    for _ in 0..5 {
        let ack =
            send_raw_and_read_ack(&mut sender_conn, &send_by_recipient(owner_id, b"no")).await?;
        assert_eq!(ack.reason, SendRejectReason::NoPermit);
    }
    // Единственный слот секунды всё ещё свободен.
    let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_queue(&queue_id, b"yes")).await?;
    assert!(ack.ok, "budget must be intact: {ack:?}");
    Ok(())
}

/// Со снятой адресацией по очередям режим не объявляется и не ставится.
#[tokio::test]
async fn without_queue_addressing_the_mode_is_unsupported() -> Result<()> {
    let server = spawn_server("qo_unsupported", LimitsConfig::default()).await?;
    let owner = random_identity();
    let mut conn = session(&server, &owner).await?;

    let config = server_config(&mut conn, &server).await?;
    assert!(!config.supports_queue_addressing);
    assert!(!config.supports_queue_only);

    let ack = set_queue_only(&mut conn, true).await?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::Unsupported as i32);
    assert!(!list(&mut conn).await?.queue_only, "flag must stay unset");
    Ok(())
}

/// Флаг живёт в хранилище: переживает рестарт ноды, а на ноде, поднятой со
/// снятой адресацией по очередям, не действует — иначе аккаунт был бы
/// недостижим вовсе. Когда адресацию включают снова, флаг снова в силе.
#[tokio::test]
async fn the_flag_survives_a_restart_and_sleeps_without_queue_addressing() -> Result<()> {
    let storage_path = temp_storage_path("qo_restart");
    let owner = random_identity();
    let sender = random_identity();
    let owner_id = user_id_of(&owner);
    let options = |queue_addressing| NodeOptions {
        queue_addressing,
        storage_path: Some(storage_path.clone()),
        ..NodeOptions::default()
    };

    // 1. Адресация включена: режим ставится.
    let (server, internals) =
        spawn_node_with("qo_restart", LimitsConfig::default(), options(true)).await?;
    {
        let mut owner_conn = session(&server, &owner).await?;
        assert!(
            server_config(&mut owner_conn, &server)
                .await?
                .supports_queue_only
        );
        assert!(set_queue_only(&mut owner_conn, true).await?.ok);
    }
    stop_node(internals);

    // 2. Рестарт со снятой адресацией: флаг сохранён, но не мешает.
    let (server, internals) =
        spawn_node_with("qo_restart", LimitsConfig::default(), options(false)).await?;
    {
        let mut owner_conn = session(&server, &owner).await?;
        assert!(list(&mut owner_conn).await?.queue_only, "flag must persist");
        let mut sender_conn = session(&server, &sender).await?;
        let ack =
            send_raw_and_read_ack(&mut sender_conn, &send_by_recipient(owner_id, b"open")).await?;
        assert!(
            ack.ok,
            "without queue addressing the flag must not apply: {ack:?}"
        );
        let incoming = next_incoming_within(&mut owner_conn, SILENCE)
            .await?
            .expect("the owner must receive the envelope");
        assert_eq!(incoming.body, b"open");
    }
    stop_node(internals);

    // 3. Адресацию включили снова — флаг снова действует.
    let (server, internals) =
        spawn_node_with("qo_restart", LimitsConfig::default(), options(true)).await?;
    {
        let mut sender_conn = session(&server, &sender).await?;
        let ack = send_raw_and_read_ack(&mut sender_conn, &send_by_recipient(owner_id, b"closed"))
            .await?;
        assert_eq!(ack.reason, SendRejectReason::NoPermit);
    }
    stop_node(internals);
    let _ = std::fs::remove_dir_all(&storage_path);
    Ok(())
}

/// Делегированная сессия без права `QUEUES` режим не трогает; с ним —
/// ставит.
#[tokio::test]
async fn delegated_session_needs_the_queues_scope() -> Result<()> {
    let server = spawn_server_with_queue_addressing("qo_scope", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let now = unix_now_secs();
    let send_only = wire::DeviceCertScope::Send as u32;
    let with_queues = send_only | wire::DeviceCertScope::Queues as u32;

    let device = device_key();
    let cert = issue_device_cert(&account, 3, &device.public, send_only, now, now + 3600);
    let mut conn = connect_delegated(&server, &account_id, &device, 3, cert).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &account_id)?;
    let ack = set_queue_only(&mut conn, true).await?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::Forbidden as i32);

    let device = device_key();
    let cert = issue_device_cert(&account, 4, &device.public, with_queues, now, now + 3600);
    let mut conn = connect_delegated(&server, &account_id, &device, 4, cert).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &account_id)?;
    assert!(set_queue_only(&mut conn, true).await?.ok);
    assert!(list(&mut conn).await?.queue_only);
    Ok(())
}
