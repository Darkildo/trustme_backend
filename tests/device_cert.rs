//! Делегированный вход: сессия по сертификату устройства.
//!
//! Проверяется то, ради чего сертификат существует: устройство без ключа
//! аккаунта получает сессию от его имени, но только в пределах выписанных
//! прав и срока, — и что ни одно звено цепочки «аккаунт → сертификат →
//! статик соединения» нельзя подменить.

mod common;

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use common::{
    Conn, HANDSHAKE_TIMEOUT, ServerHandle, confirm, connect, decode, encode_delivery_ack,
    expect_auth_ok, expect_connection_gone, next_frame, next_incoming_within, random_identity,
    send_and_read_ack, spawn_server, unix_now_secs, user_id_of,
};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use tokio::net::TcpStream;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::net::device_cert::signed_bytes;
use trust_message_tcp::net::noise::{NOISE_PARAMS_IK, NoiseFramed};
use trust_message_tcp::wire::{self, Frame, QueueRejectReason, frame};

const FRAME_MAX: usize = 8 * 1024 * 1024;
const DEVICE: u16 = 3;
const SCOPE_SEND: u32 = wire::DeviceCertScope::Send as u32;
const DAY: u64 = 24 * 3600;

/// X25519-пара устройства. Тем же генератором, каким snow делает
/// эфемералы: от ключа аккаунта она не зависит ничем.
struct DeviceKey {
    secret: [u8; 32],
    public: [u8; 32],
}

fn device_key() -> DeviceKey {
    let pair = snow::Builder::new(NOISE_PARAMS_IK.parse().expect("noise params"))
        .generate_keypair()
        .expect("device keypair");
    DeviceKey {
        secret: pair.private.as_slice().try_into().expect("32-byte secret"),
        public: pair.public.as_slice().try_into().expect("32-byte public"),
    }
}

fn issue(
    account: &SigningKey,
    device_id: u16,
    transport_key: &[u8; 32],
    scope: u32,
    not_before: u64,
    not_after: u64,
) -> wire::DeviceCertificate {
    let signing_key = [0x5a; 32];
    let message = signed_bytes(
        &user_id_of(account),
        device_id,
        transport_key,
        &signing_key,
        scope,
        not_before,
        not_after,
    );
    wire::DeviceCertificate {
        transport_key: transport_key.to_vec(),
        signing_key: signing_key.to_vec(),
        scope,
        not_before,
        not_after,
        signature: account.sign(&message).to_bytes().to_vec(),
        device_id: u32::from(device_id),
    }
}

/// Делегированный вход с подтверждением сессии — так, как это делает
/// клиент (см. `common::confirm`).
async fn connect_delegated(
    server: &ServerHandle,
    account_id: &[u8; 32],
    device: &DeviceKey,
    device_id: u16,
    cert: wire::DeviceCertificate,
) -> Result<Conn> {
    let stream = TcpStream::connect(server.addr).await?;
    let raw = NoiseFramed::connect_delegated(
        stream,
        &server.node_public,
        &device.secret,
        account_id,
        device_id,
        cert,
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await?;
    confirm(raw).await
}

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: 1,
        payload: Some(payload),
    }
    .encode_to_vec()
}

#[tokio::test]
async fn delegated_session_receives_and_sends_as_the_account() -> Result<()> {
    let server = spawn_server("device_cert_ok", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let device = device_key();
    let now = unix_now_secs();
    let cert = issue(
        &account,
        DEVICE,
        &device.public,
        SCOPE_SEND,
        now,
        now + 14 * DAY,
    );

    // Ключ аккаунта дальше не участвует: сессию держит ключ устройства.
    let mut delegated = connect_delegated(&server, &account_id, &device, DEVICE, cert).await?;
    expect_auth_ok(&next_frame(&mut delegated).await?, &account_id)?;

    let peer = random_identity();
    let mut peer_conn = connect(&server, &peer).await?;
    expect_auth_ok(&next_frame(&mut peer_conn).await?, &user_id_of(&peer))?;

    // Приём: конверт, адресованный аккаунту, приходит в делегированную сессию.
    let ack = send_and_read_ack(&mut peer_conn, &account_id, b"to-account", 0).await?;
    assert!(ack.ok, "peer send rejected: {ack:?}");
    let incoming = next_incoming_within(&mut delegated, Duration::from_secs(5))
        .await?
        .expect("delegated session must receive the envelope");
    assert_eq!(incoming.body, b"to-account");
    assert_eq!(incoming.from_user_id, user_id_of(&peer));
    if incoming.message_id != 0 {
        delegated
            .send_frame(&encode_delivery_ack(incoming.message_id))
            .await?;
    }

    // Отправка: собеседник видит отправителем аккаунт, а не устройство.
    let ack = send_and_read_ack(&mut delegated, &user_id_of(&peer), b"from-device", 0).await?;
    assert!(ack.ok, "delegated send rejected: {ack:?}");
    let incoming = next_incoming_within(&mut peer_conn, Duration::from_secs(5))
        .await?
        .expect("peer must receive the envelope");
    assert_eq!(incoming.body, b"from-device");
    assert_eq!(incoming.from_user_id, account_id);
    Ok(())
}

#[tokio::test]
async fn delegated_session_cannot_touch_push_tokens_or_queues() -> Result<()> {
    let server = spawn_server("device_cert_scope", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let device = device_key();
    let now = unix_now_secs();
    let cert = issue(&account, DEVICE, &device.public, SCOPE_SEND, now, now + DAY);
    let mut conn = connect_delegated(&server, &account_id, &device, DEVICE, cert).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &account_id)?;

    for request in [
        wrap(frame::Payload::AllocateQueue(wire::AllocateQueue {})),
        wrap(frame::Payload::ListQueues(wire::ListQueues {})),
        wrap(frame::Payload::RevokeQueue(wire::RevokeQueue {
            queue_id: vec![1u8; 32],
        })),
    ] {
        conn.send_frame(&request).await?;
        match decode(&next_frame(&mut conn).await?)? {
            frame::Payload::QueueAck(ack) => {
                assert!(!ack.ok);
                assert_eq!(ack.reason, QueueRejectReason::Forbidden as i32);
            }
            other => bail!("expected QueueAck, got {other:?}"),
        }
    }

    for request in [
        wrap(frame::Payload::RegisterPushToken(wire::RegisterPushToken {
            token: "stolen-device-token".to_string(),
            platform: wire::PushPlatform::AndroidFcm as i32,
        })),
        wrap(frame::Payload::UnregisterPushToken(
            wire::UnregisterPushToken {},
        )),
    ] {
        conn.send_frame(&request).await?;
        match decode(&next_frame(&mut conn).await?)? {
            frame::Payload::PushTokenAck(ack) => assert!(!ack.ok),
            other => bail!("expected PushTokenAck, got {other:?}"),
        }
    }

    // Сессия после отказов жива: отказ — ответ, а не разрыв. Получатель
    // офлайн, поэтому принятая отправка — это постановка в очередь.
    let ack = send_and_read_ack(&mut conn, &user_id_of(&random_identity()), b"x", 0).await?;
    assert!(ack.ok || ack.queued, "send within scope rejected: {ack:?}");
    Ok(())
}

#[tokio::test]
async fn receive_only_certificate_cannot_send() -> Result<()> {
    let server = spawn_server("device_cert_recv_only", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let device = device_key();
    let now = unix_now_secs();
    let cert = issue(&account, DEVICE, &device.public, 0, now, now + DAY);
    let mut conn = connect_delegated(&server, &account_id, &device, DEVICE, cert).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &account_id)?;

    let ack = send_and_read_ack(&mut conn, &user_id_of(&random_identity()), b"x", 0).await?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, SendRejectReason::Forbidden);
    Ok(())
}

/// Сессия не переживает сертификат, даже если клиент молчит: закрывает её
/// срок, а не очередной входящий кадр.
#[tokio::test]
async fn silent_delegated_session_closes_when_the_certificate_expires() -> Result<()> {
    let server = spawn_server("device_cert_expiry", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let device = device_key();
    let now = unix_now_secs();
    let cert = issue(&account, DEVICE, &device.public, SCOPE_SEND, now, now + 2);
    let mut conn = connect_delegated(&server, &account_id, &device, DEVICE, cert).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &account_id)?;
    let confirmed_at = Instant::now();

    // С этого момента клиент не шлёт ничего; `expect_connection_gone`
    // ждёт до 5 с, сертификату осталось не больше 2 с.
    assert!(
        expect_connection_gone(&mut conn).await,
        "the node kept a silent session past its certificate"
    );
    assert!(
        confirmed_at.elapsed() < Duration::from_secs(4),
        "a certificate with at most 2 s left kept the session for {:?}",
        confirmed_at.elapsed()
    );
    Ok(())
}

/// Каждое звено цепочки по отдельности: ни одно нельзя подменить и
/// получить сессию.
#[tokio::test]
async fn broken_chain_never_reaches_a_session() -> Result<()> {
    let server = spawn_server("device_cert_broken", LimitsConfig::default()).await?;
    let account = random_identity();
    let account_id = user_id_of(&account);
    let device = device_key();
    let now = unix_now_secs();

    // Сертификат выписан на другой ключ: украденный сертификат без
    // секрета устройства бесполезен.
    let other_device = device_key();
    let foreign_key = issue(
        &account,
        DEVICE,
        &other_device.public,
        SCOPE_SEND,
        now,
        now + DAY,
    );
    // Подписал не тот аккаунт, от чьего имени входят.
    let stranger = random_identity();
    let foreign_account = issue(
        &stranger,
        DEVICE,
        &device.public,
        SCOPE_SEND,
        now,
        now + DAY,
    );
    // Истёк.
    let expired = issue(
        &account,
        DEVICE,
        &device.public,
        SCOPE_SEND,
        now - 2 * DAY,
        now - DAY,
    );
    // Срок длиннее потолка ноды (30 суток).
    let too_long = issue(
        &account,
        DEVICE,
        &device.public,
        SCOPE_SEND,
        now,
        now + 31 * DAY,
    );
    // Права расширены после подписи.
    let mut widened = issue(&account, DEVICE, &device.public, SCOPE_SEND, now, now + DAY);
    widened.scope |= wire::DeviceCertScope::Queues as u32;

    for (label, cert, device_id) in [
        ("foreign transport key", foreign_key, DEVICE),
        ("foreign account", foreign_account, DEVICE),
        ("expired", expired, DEVICE),
        ("lifetime above ceiling", too_long, DEVICE),
        ("scope widened after signing", widened, DEVICE),
        (
            "presented from another device",
            issue(&account, DEVICE, &device.public, SCOPE_SEND, now, now + DAY),
            DEVICE + 1,
        ),
    ] {
        // IK: нода отвечает на msg1 до проверки identity, поэтому хендшейк
        // у клиента может сойтись — но сессии за ним нет.
        match connect_delegated(&server, &account_id, &device, device_id, cert).await {
            Err(_) => {}
            Ok(mut conn) => assert!(
                expect_connection_gone(&mut conn).await,
                "{label}: node kept the session"
            ),
        }
    }
    Ok(())
}
