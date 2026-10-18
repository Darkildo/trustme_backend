//! Роль сессии `BLOB` (server-contract.md §6.11): сессия передачи файлов
//! не участвует в доставке и не делает пользователя «в сети», а сессия
//! сообщений не принимает кадры хранилища, кроме `BlobStat`.

mod common;

use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, NodeOptions, connect_as, connect_blob, connect_delegated_blob, decode,
    device_key, encode_client_send, expect_auth_ok, expect_signed_config, issue_device_cert,
    next_frame, next_incoming_within, random_identity, send_and_read_ack, spawn_node_with,
    spawn_server, spawn_server_with_push, unix_now_secs, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::push::PushKind;
use trust_message_tcp::wire::{self, BlobRejectReason, Frame, QueueRejectReason, frame};

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: common::PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

async fn messages_session(
    server: &common::ServerHandle,
    identity: &SigningKey,
    device: u16,
) -> Result<Conn> {
    let mut conn = connect_as(server, identity, Some(device), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn blob_session(
    server: &common::ServerHandle,
    identity: &SigningKey,
    device: u16,
) -> Result<Conn> {
    let mut conn = connect_blob(server, identity, Some(device)).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn expect_blob_ack(conn: &mut Conn) -> Result<wire::BlobAck> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::BlobAck(ack) => Ok(ack),
        other => bail!("expected BlobAck, got {other:?}"),
    }
}

async fn expect_auth_error(conn: &mut Conn) -> Result<u32> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::AuthError(err) => Ok(err.code),
        other => bail!("expected AuthError, got {other:?}"),
    }
}

async fn ping_pong(conn: &mut Conn) -> Result<()> {
    conn.send_frame(&wrap(frame::Payload::Ping(wire::Ping {})))
        .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::Pong(_) => Ok(()),
        other => bail!("expected Pong, got {other:?}"),
    }
}

fn init_frame(request_id: u64) -> Vec<u8> {
    wrap(frame::Payload::BlobUploadInit(wire::BlobUploadInit {
        size: 10,
        sha256: vec![1u8; 32],
        blob_id: vec![2u8; 32],
        delete_token_hash: vec![3u8; 32],
        request_id,
        ..wire::BlobUploadInit::default()
    }))
}

/// Сессия `BLOB` не получает входящих и не принимает `ClientSend`, но
/// живёт дальше; отправитель видит получателя офлайн.
#[tokio::test]
async fn blob_session_is_not_a_delivery_target() -> Result<()> {
    let server = spawn_server("blob_role_delivery", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let mut alice_blob = blob_session(&server, &alice, 1).await?;
    let mut bob_conn = messages_session(&server, &bob, 1).await?;

    let ack = send_and_read_ack(&mut bob_conn, &user_id_of(&alice), b"hello", 0).await?;
    assert!(
        !ack.ok && ack.queued,
        "получатель обязан выглядеть офлайн: {ack:?}"
    );
    assert!(
        next_incoming_within(&mut alice_blob, Duration::from_millis(300))
            .await?
            .is_none(),
        "сессия BLOB не получает входящих"
    );

    alice_blob
        .send_frame(&encode_client_send(&user_id_of(&bob), None, b"x", 0)?)
        .await?;
    match decode(&next_frame(&mut alice_blob).await?)? {
        frame::Payload::SendAck(ack) => {
            assert!(!ack.ok && !ack.queued);
            assert_eq!(
                SendRejectReason::from_wire(ack.reason),
                SendRejectReason::Forbidden
            );
        }
        other => bail!("expected SendAck, got {other:?}"),
    }

    // Очереди и push-токены — дело сессии сообщений.
    alice_blob
        .send_frame(&wrap(frame::Payload::AllocateQueue(
            wire::AllocateQueue::default(),
        )))
        .await?;
    match decode(&next_frame(&mut alice_blob).await?)? {
        frame::Payload::QueueAck(ack) => {
            assert!(!ack.ok);
            assert_eq!(ack.reason, QueueRejectReason::Unsupported as i32);
        }
        other => bail!("expected QueueAck, got {other:?}"),
    }
    alice_blob
        .send_frame(&wrap(frame::Payload::RegisterPushToken(
            wire::RegisterPushToken {
                token: "t".into(),
                platform: wire::PushPlatform::AndroidFcm as i32,
            },
        )))
        .await?;
    match decode(&next_frame(&mut alice_blob).await?)? {
        frame::Payload::PushTokenAck(ack) => assert!(!ack.ok),
        other => bail!("expected PushTokenAck, got {other:?}"),
    }
    // Подтверждать в этой сессии нечего — кадр молча игнорируется.
    alice_blob
        .send_frame(&wrap(frame::Payload::DeliveryAck(wire::DeliveryAck {
            message_id: 1,
        })))
        .await?;
    ping_pong(&mut alice_blob).await?;

    // Конфиг доступен и в сессии BLOB и объявляет хранилище.
    alice_blob
        .send_frame(&wrap(frame::Payload::GetServerConfig(
            wire::GetServerConfig {},
        )))
        .await?;
    let config = expect_signed_config(&next_frame(&mut alice_blob).await?, &server.node_public)?;
    assert!(config.supports_blobs);
    assert_eq!(config.blob_chunk_max, 64 * 1024);
    Ok(())
}

/// Сессия `BLOB` не делает устройство «в сети»: офлайн-депозит будит его
/// пушем, хотя сессия передачи открыта.
#[tokio::test]
async fn blob_session_does_not_suppress_push() -> Result<()> {
    let (server, transport) =
        spawn_server_with_push("blob_role_push", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    {
        let mut alice_messages = messages_session(&server, &alice, 1).await?;
        alice_messages
            .send_frame(&wrap(frame::Payload::RegisterPushToken(
                wire::RegisterPushToken {
                    token: "alice-device-1".into(),
                    platform: wire::PushPlatform::AndroidFcm as i32,
                },
            )))
            .await?;
        match decode(&next_frame(&mut alice_messages).await?)? {
            frame::Payload::PushTokenAck(ack) => assert!(ack.ok, "{}", ack.message),
            other => bail!("expected PushTokenAck, got {other:?}"),
        }
    }
    let _alice_blob = blob_session(&server, &alice, 1).await?;
    let mut bob_conn = messages_session(&server, &bob, 1).await?;
    let ack = send_and_read_ack(&mut bob_conn, &user_id_of(&alice), b"wake up", 0).await?;
    assert!(ack.queued);

    let wakes = || {
        transport
            .sent_payloads()
            .iter()
            .filter(|payload| payload.kind == PushKind::Wake && payload.device_id == 1)
            .count()
    };
    for _ in 0..100 {
        if wakes() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        wakes() > 0,
        "устройство с одной лишь сессией BLOB обязано получить пуш"
    );
    Ok(())
}

/// Потолок сессий `BLOB` свой и не съедает `max_sessions_per_user`.
#[tokio::test]
async fn blob_sessions_have_their_own_ceiling() -> Result<()> {
    let limits = LimitsConfig {
        max_sessions_per_user: 1,
        ..LimitsConfig::default()
    };
    let (server, _internals) = spawn_node_with(
        "blob_role_ceiling",
        limits,
        NodeOptions {
            blob_config: Some(Box::new(|blobs| blobs.max_sessions_per_user = 2)),
            ..NodeOptions::default()
        },
    )
    .await?;
    let alice = random_identity();
    let _messages = messages_session(&server, &alice, 1).await?;
    let mut first = blob_session(&server, &alice, 1).await?;
    let _second = blob_session(&server, &alice, 2).await?;

    let mut third = connect_blob(&server, &alice, Some(3)).await?;
    assert_eq!(expect_auth_error(&mut third).await?, 401);
    let mut extra_messages = connect_as(&server, &alice, Some(4), FRAME_MAX).await?;
    assert_eq!(expect_auth_error(&mut extra_messages).await?, 401);

    // Ушедшая сессия освобождает место.
    ping_pong(&mut first).await?;
    drop(first);
    let mut reopened = None;
    for _ in 0..50 {
        let mut conn = connect_blob(&server, &alice, Some(3)).await?;
        match decode(&next_frame(&mut conn).await?)? {
            frame::Payload::AuthOk(_) => {
                reopened = Some(conn);
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    assert!(
        reopened.is_some(),
        "место ушедшей сессии BLOB не освободилось"
    );
    Ok(())
}

/// Отзыв сертификата закрывает и делегированную сессию `BLOB`.
#[tokio::test]
async fn certificate_revocation_closes_a_blob_session() -> Result<()> {
    let server = spawn_server("blob_role_revocation", LimitsConfig::default()).await?;
    let account = random_identity();
    let now = unix_now_secs();
    let key = device_key();
    let cert = issue_device_cert(&account, 7, &key.public, 0, now - 60, now + 86_400);
    let mut delegated =
        connect_delegated_blob(&server, &user_id_of(&account), &key, 7, cert).await?;
    expect_auth_ok(&next_frame(&mut delegated).await?, &user_id_of(&account))?;

    let mut owner = messages_session(&server, &account, 1).await?;
    owner
        .send_frame(&wrap(frame::Payload::RevokeDeviceCerts(
            wire::RevokeDeviceCerts {
                device_id: 7,
                issued_before: now,
                all: false,
            },
        )))
        .await?;
    match decode(&next_frame(&mut owner).await?)? {
        frame::Payload::QueueAck(ack) => assert!(ack.ok, "{:?}", ack.reason),
        other => bail!("expected QueueAck, got {other:?}"),
    }
    assert_eq!(expect_auth_error(&mut delegated).await?, 403);
    Ok(())
}

/// Сессия сообщений кадры хранилища не принимает: отказ `UNSUPPORTED` с
/// эхом `request_id` (у куска — `blob_id`), сессия живёт.
#[tokio::test]
async fn messages_session_refuses_blob_transfer_frames() -> Result<()> {
    let server = spawn_server("blob_role_messages", LimitsConfig::default()).await?;
    let alice = random_identity();
    let mut conn = messages_session(&server, &alice, 1).await?;

    conn.send_frame(&init_frame(41)).await?;
    let ack = expect_blob_ack(&mut conn).await?;
    assert!(!ack.ok);
    assert_eq!(ack.reason, BlobRejectReason::Unsupported as i32);
    assert_eq!(ack.request_id, 41);

    conn.send_frame(&wrap(frame::Payload::BlobUploadChunk(
        wire::BlobUploadChunk {
            blob_id: vec![9u8; 32],
            offset: 0,
            data: vec![1, 2, 3],
        },
    )))
    .await?;
    let ack = expect_blob_ack(&mut conn).await?;
    assert_eq!(ack.reason, BlobRejectReason::Unsupported as i32);
    assert_eq!(
        (ack.request_id, ack.blob_id.as_slice()),
        (0, &[9u8; 32][..])
    );

    for payload in [
        frame::Payload::BlobGet(wire::BlobGet {
            request_id: 42,
            ..Default::default()
        }),
        frame::Payload::BlobRelease(wire::BlobRelease {
            request_id: 43,
            ..Default::default()
        }),
        frame::Payload::BlobDelete(wire::BlobDelete {
            request_id: 44,
            ..Default::default()
        }),
        frame::Payload::BlobExtend(wire::BlobExtend {
            request_id: 45,
            ..Default::default()
        }),
        frame::Payload::BlobUploadCommit(wire::BlobUploadCommit {
            request_id: 46,
            ..Default::default()
        }),
        frame::Payload::BlobUploadStatus(wire::BlobUploadStatus {
            request_id: 47,
            ..Default::default()
        }),
    ] {
        conn.send_frame(&wrap(payload)).await?;
        let ack = expect_blob_ack(&mut conn).await?;
        assert_eq!(ack.reason, BlobRejectReason::Unsupported as i32);
        assert!((42..=47).contains(&ack.request_id));
    }
    ping_pong(&mut conn).await?;
    Ok(())
}

/// Выключенное хранилище: не объявлено, кадры получают `UNSUPPORTED` в
/// сессиях обеих ролей.
#[tokio::test]
async fn disabled_store_refuses_everything() -> Result<()> {
    let (server, internals) = spawn_node_with(
        "blob_role_disabled",
        LimitsConfig::default(),
        NodeOptions {
            blob_config: Some(Box::new(|blobs| blobs.enabled = false)),
            ..NodeOptions::default()
        },
    )
    .await?;
    assert!(internals.blobs.is_none());
    let alice = random_identity();
    let mut blob = blob_session(&server, &alice, 1).await?;
    blob.send_frame(&init_frame(7)).await?;
    let ack = expect_blob_ack(&mut blob).await?;
    assert_eq!(ack.reason, BlobRejectReason::Unsupported as i32);
    assert_eq!(ack.request_id, 7);

    let mut messages = messages_session(&server, &alice, 2).await?;
    messages
        .send_frame(&wrap(frame::Payload::BlobStat(wire::BlobStat {
            items: Vec::new(),
            request_id: 8,
        })))
        .await?;
    let ack = expect_blob_ack(&mut messages).await?;
    assert_eq!(ack.reason, BlobRejectReason::Unsupported as i32);
    messages
        .send_frame(&wrap(frame::Payload::GetServerConfig(
            wire::GetServerConfig {},
        )))
        .await?;
    let config = expect_signed_config(&next_frame(&mut messages).await?, &server.node_public)?;
    assert!(!config.supports_blobs);
    assert_eq!(config.blob_max_size, 0);
    Ok(())
}
