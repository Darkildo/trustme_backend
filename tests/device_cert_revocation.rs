//! Отзыв сертификатов устройства (server-contract.md, §6.10).
//!
//! Телефон украден запертым: ключа аккаунта у вора нет, но сертификат из
//! фонового хранилища открывал бы ему делегированную сессию «как это
//! устройство» до `not_after`. Владелец с другого устройства отзывает
//! сертификаты, и нода перестаёт пускать по ним — до `AuthOk`, при
//! подтверждении и в уже живой сессии, — не трогая сессий ключом аккаунта.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, NodeOptions, ServerHandle, connect_as, connect_delegated,
    connect_delegated_unconfirmed, decode, device_key, encode_client_send, encode_ping,
    expect_auth_ok, expect_connection_gone, expect_signed_config, issue_device_cert, next_frame,
    next_incoming_within, random_identity, send_raw_and_read_ack, spawn_node_with, spawn_server,
    spawn_server_with_queue_addressing, unix_now_secs, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::push::{MockTransport, PushKind};
use trust_message_tcp::wire::{self, Frame, QueueRejectReason, frame};

const DEVICE: u16 = 5;
const OTHER_DEVICE: u16 = 6;
const DAY: u64 = 24 * 3600;
const MAX_TTL: u64 = 30 * DAY;
const SILENCE: Duration = Duration::from_millis(400);
const ALL_BITS: u32 = wire::DeviceCertScope::Send as u32
    | wire::DeviceCertScope::PushTokens as u32
    | wire::DeviceCertScope::Queues as u32
    | wire::DeviceCertScope::CallSignals as u32;

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: common::PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

/// Сессия ключом аккаунта с данным `device_id`.
async fn full_session(server: &ServerHandle, account: &SigningKey, device: u16) -> Result<Conn> {
    let mut conn = connect_as(server, account, Some(device), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(account))?;
    Ok(conn)
}

/// Делегированный вход: сырое соединение после подтверждения (первым
/// кадром лежит ответ ноды — `AuthOk` или `AuthError`).
async fn delegated(
    server: &ServerHandle,
    account: &SigningKey,
    device: u16,
    scope: u32,
    not_before: u64,
) -> Result<Conn> {
    let key = device_key();
    let cert = issue_device_cert(
        account,
        device,
        &key.public,
        scope,
        not_before,
        not_before + DAY,
    );
    connect_delegated(server, &user_id_of(account), &key, device, cert).await
}

/// Делегированный вход, который обязан пройти.
async fn delegated_ok(
    server: &ServerHandle,
    account: &SigningKey,
    device: u16,
    scope: u32,
    not_before: u64,
) -> Result<Conn> {
    let mut conn = delegated(server, account, device, scope, not_before).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(account))?;
    Ok(conn)
}

/// Следующий кадр — `AuthError(403)`, после него соединение закрыто.
async fn expect_revoked(conn: &mut Conn) -> Result<()> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::AuthError(err) if err.code == 403 => {}
        other => bail!("expected AuthError 403, got {other:?}"),
    }
    assert!(
        expect_connection_gone(conn).await,
        "the node must close the session after 403"
    );
    Ok(())
}

async fn queue_ack(conn: &mut Conn, request: frame::Payload) -> Result<wire::QueueAck> {
    conn.send_frame(&wrap(request)).await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueAck(ack) => Ok(ack),
        other => bail!("expected QueueAck, got {other:?}"),
    }
}

async fn revoke(conn: &mut Conn, device_id: u32, issued_before: u64) -> Result<wire::QueueAck> {
    queue_ack(
        conn,
        frame::Payload::RevokeDeviceCerts(wire::RevokeDeviceCerts {
            device_id,
            issued_before,
            all: false,
        }),
    )
    .await
}

async fn revoke_all(conn: &mut Conn, device_id: u32) -> Result<wire::QueueAck> {
    queue_ack(
        conn,
        frame::Payload::RevokeDeviceCerts(wire::RevokeDeviceCerts {
            device_id,
            issued_before: 0,
            all: true,
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

/// Отзыв закрывает новый делегированный вход по старому сертификату:
/// `AuthError(403)` вместо `AuthOk`, офлайн-очередь устройства не выдана и
/// не потеряна, пушей вход не порождает.
#[tokio::test]
async fn a_revoked_certificate_is_refused_before_auth_ok() -> Result<()> {
    let transport = Arc::new(MockTransport::always_ok());
    let (server, _internals) = spawn_node_with(
        "rev_login",
        LimitsConfig::default(),
        NodeOptions {
            push: Some(transport.clone()),
            ..NodeOptions::default()
        },
    )
    .await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let sender = random_identity();
    let now = unix_now_secs();

    // Конверт ждёт устройство в его офлайн-очереди.
    let mut sender_conn = full_session(&server, &sender, 1).await?;
    let ack = send_raw_and_read_ack(
        &mut sender_conn,
        &encode_client_send(&account_id, Some(DEVICE), b"for the device", 0)?,
    )
    .await?;
    assert!(ack.queued, "must wait in the device inbox: {ack:?}");

    let mut owner = full_session(&server, &account, 1).await?;
    let ack = revoke(&mut owner, u32::from(DEVICE), now).await?;
    assert!(ack.ok, "revocation refused: {:?}", ack.reason);
    assert!(ack.queue_id.is_empty());

    let mut thief = delegated(&server, &account, DEVICE, ALL_BITS, now - 60).await?;
    expect_revoked(&mut thief).await?;
    tokio::time::sleep(SILENCE).await;
    assert!(
        transport
            .sent_payloads()
            .iter()
            .all(|payload| payload.kind != PushKind::Wake),
        "a refused login must not wake anyone"
    );

    // Конверт на месте: сессия ключом аккаунта того же устройства его
    // получает.
    let mut device = full_session(&server, &account, DEVICE).await?;
    let incoming = next_incoming_within(&mut device, SILENCE)
        .await?
        .expect("the device inbox must be intact");
    assert_eq!(incoming.body, b"for the device");
    Ok(())
}

/// Сертификат, выписанный не раньше момента отзыва, проходит.
#[tokio::test]
async fn a_certificate_issued_after_the_revocation_is_accepted() -> Result<()> {
    let server = spawn_server("rev_reissue", LimitsConfig::default()).await?;
    let account = random_identity();
    let issued_before = unix_now_secs() - 5;

    let mut owner = full_session(&server, &account, 1).await?;
    assert!(
        revoke(&mut owner, u32::from(DEVICE), issued_before)
            .await?
            .ok
    );

    let mut stale = delegated(&server, &account, DEVICE, ALL_BITS, issued_before - 1).await?;
    expect_revoked(&mut stale).await?;
    // `not_before == issued_before` — уже новый выпуск.
    delegated_ok(&server, &account, DEVICE, ALL_BITS, issued_before).await?;
    delegated_ok(&server, &account, DEVICE, ALL_BITS, issued_before + 3).await?;
    Ok(())
}

/// Живая делегированная сессия закрывается сразу после отзыва; то, что
/// приходит устройству дальше, ждёт в его очереди, а не теряется.
/// Сессии ключом аккаунта того же устройства и делегированные сессии
/// других устройств живут дальше.
#[tokio::test]
async fn live_sessions_of_the_revoked_device_are_closed_at_once() -> Result<()> {
    let server = spawn_server("rev_live", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let sender = random_identity();
    let now = unix_now_secs();

    let mut victim = delegated_ok(&server, &account, DEVICE, ALL_BITS, now - 60).await?;
    let mut sibling = delegated_ok(&server, &account, OTHER_DEVICE, ALL_BITS, now - 60).await?;
    let mut same_device_full = full_session(&server, &account, DEVICE).await?;
    let mut owner = full_session(&server, &account, 1).await?;

    assert!(revoke(&mut owner, u32::from(DEVICE), now).await?.ok);
    expect_revoked(&mut victim).await?;

    // Сессия ключом аккаунта того же устройства и чужое устройство живы.
    for conn in [&mut same_device_full, &mut sibling] {
        conn.send_frame(&encode_ping()).await?;
        match decode(&next_frame(conn).await?)? {
            frame::Payload::Pong(_) => {}
            other => bail!("expected Pong, got {other:?}"),
        }
    }

    // Конверт устройству теперь уходит его сессии ключом аккаунта, а когда
    // её нет — в очередь устройства.
    drop(same_device_full);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut sender_conn = full_session(&server, &sender, 1).await?;
    let ack = send_raw_and_read_ack(
        &mut sender_conn,
        &encode_client_send(&account_id, Some(DEVICE), b"after revocation", 0)?,
    )
    .await?;
    assert!(ack.queued, "must wait in the device inbox: {ack:?}");
    let mut device = full_session(&server, &account, DEVICE).await?;
    let incoming = next_incoming_within(&mut device, SILENCE)
        .await?
        .expect("the envelope must wait for the device");
    assert_eq!(incoming.body, b"after revocation");
    Ok(())
}

/// Отзывать вправе только сессия ключом аккаунта: делегированная получает
/// `FORBIDDEN` при любых битах, и отзыва не появляется.
#[tokio::test]
async fn a_delegated_session_cannot_revoke() -> Result<()> {
    let server = spawn_server("rev_forbidden", LimitsConfig::default()).await?;
    let account = random_identity();
    let now = unix_now_secs();

    let mut delegated_conn = delegated_ok(&server, &account, DEVICE, ALL_BITS, now - 60).await?;
    let ack = revoke(&mut delegated_conn, u32::from(OTHER_DEVICE), now).await?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, QueueRejectReason::Forbidden as i32);

    let mut owner = full_session(&server, &account, 1).await?;
    assert!(list(&mut owner).await?.device_cert_revocations.is_empty());
    delegated_ok(&server, &account, OTHER_DEVICE, ALL_BITS, now - 60).await?;
    Ok(())
}

/// Негодные параметры — `INVALID`, отзыва нет.
#[tokio::test]
async fn invalid_revocations_are_refused() -> Result<()> {
    let server = spawn_server("rev_invalid", LimitsConfig::default()).await?;
    let account = random_identity();
    let mut owner = full_session(&server, &account, 1).await?;
    let now = unix_now_secs();

    for (device_id, issued_before) in [(65_536u32, now), (7, 0), (7, now + 301 + 5)] {
        let ack = revoke(&mut owner, device_id, issued_before).await?;
        assert!(!ack.ok, "must be refused: {device_id} / {issued_before}");
        assert_eq!(ack.reason, QueueRejectReason::Invalid as i32);
    }
    assert!(list(&mut owner).await?.device_cert_revocations.is_empty());
    Ok(())
}

/// Отзыв, пришедший между `AuthOk` и подтверждающим кадром, ловится при
/// подтверждении.
#[tokio::test]
async fn a_revocation_before_confirmation_is_caught_on_confirmation() -> Result<()> {
    let server = spawn_server("rev_confirm", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let now = unix_now_secs();

    let key = device_key();
    let cert = issue_device_cert(&account, DEVICE, &key.public, ALL_BITS, now - 60, now + DAY);
    let mut pending =
        connect_delegated_unconfirmed(&server, &account_id, &key, DEVICE, cert).await?;
    expect_auth_ok(&next_frame(&mut pending).await?, &account_id)?;

    let mut owner = full_session(&server, &account, 1).await?;
    assert!(revoke(&mut owner, u32::from(DEVICE), now).await?.ok);

    pending.send_frame(&encode_ping()).await?;
    expect_revoked(&mut pending).await
}

/// `ListQueues` отдаёт действующие отзывы (максимум на устройство) и не
/// отдаёт устаревшие.
#[tokio::test]
async fn list_queues_reports_active_revocations_only() -> Result<()> {
    let server = spawn_server("rev_list", LimitsConfig::default()).await?;
    let account = random_identity();
    let mut owner = full_session(&server, &account, 1).await?;
    let now = unix_now_secs();

    assert!(revoke(&mut owner, u32::from(DEVICE), now - 100).await?.ok);
    // Более ранний не уменьшает, более поздний поднимает.
    assert!(revoke(&mut owner, u32::from(DEVICE), now - 500).await?.ok);
    assert!(revoke(&mut owner, u32::from(DEVICE), now).await?.ok);
    // Устаревший с рождения: всё, что он закрывал бы, уже истекло.
    let stale = now - MAX_TTL - 301;
    assert!(revoke(&mut owner, u32::from(OTHER_DEVICE), stale).await?.ok);

    let listed = list(&mut owner).await?;
    assert_eq!(
        listed.device_cert_revocations,
        vec![wire::DeviceCertRevocation {
            device_id: u32::from(DEVICE),
            issued_before: now,
        }]
    );
    Ok(())
}

/// Возможность объявлена всегда: при любом флаге адресации и даже при
/// выключенном делегированном входе, где отзыв принимается впрок.
#[tokio::test]
async fn revocation_is_always_advertised_and_accepted() -> Result<()> {
    let nodes = [
        spawn_server("rev_caps_plain", LimitsConfig::default()).await?,
        spawn_server_with_queue_addressing("rev_caps_queues", LimitsConfig::default()).await?,
        spawn_node_with(
            "rev_caps_no_certs",
            LimitsConfig::default(),
            NodeOptions {
                device_cert_max_ttl: Some(Duration::ZERO),
                ..NodeOptions::default()
            },
        )
        .await?
        .0,
    ];
    for server in &nodes {
        let account = random_identity();
        let mut owner = full_session(server, &account, 1).await?;
        owner
            .send_frame(&common::encode_get_server_config()?)
            .await?;
        let config = expect_signed_config(&next_frame(&mut owner).await?, &server.node_public)?;
        assert!(config.supports_device_cert_revocation);
        assert!(
            revoke(&mut owner, u32::from(DEVICE), unix_now_secs())
                .await?
                .ok
        );
    }
    Ok(())
}

/// Сертификат, выписанный до отзыва, но с `not_before` в будущем (часы
/// выписывающего устройства спешат): обычный отзыв «по сейчас» его не
/// закрывает, отзыв `all` — закрывает, и вход по нему получает 403.
#[tokio::test]
async fn revoking_all_closes_certificates_dated_ahead() -> Result<()> {
    let server = spawn_server("rev_all", LimitsConfig::default()).await?;
    let account = random_identity();
    let now = unix_now_secs();
    // В пределах допуска нода такой сертификат принимает уже сейчас.
    let ahead = now + 200;

    let mut owner = full_session(&server, &account, 1).await?;
    assert!(revoke(&mut owner, u32::from(DEVICE), now).await?.ok);
    delegated_ok(&server, &account, DEVICE, ALL_BITS, ahead).await?;

    let ack = revoke_all(&mut owner, u32::from(DEVICE)).await?;
    assert!(ack.ok, "revocation refused: {:?}", ack.reason);
    let mut thief = delegated(&server, &account, DEVICE, ALL_BITS, ahead).await?;
    expect_revoked(&mut thief).await?;

    // Нода поставила issued_before по своим часам на горизонт вперёд.
    let listed = list(&mut owner).await?;
    assert_eq!(listed.device_cert_revocations.len(), 1);
    assert!(listed.device_cert_revocations[0].issued_before >= now + MAX_TTL);
    // `all` игнорирует issued_before и не требует его.
    assert!(revoke_all(&mut owner, u32::from(OTHER_DEVICE)).await?.ok);
    assert_eq!(
        revoke_all(&mut owner, 70_000).await?.reason,
        QueueRejectReason::Invalid as i32
    );
    Ok(())
}
