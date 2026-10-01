//! Регистрация push-токенов через живую сессию: приветствие одно на
//! аккаунт, число устройств с токенами ограничено, VoIP-токен — только hex.

mod common;

use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, connect_as, decode, expect_auth_ok, next_frame, random_identity,
    spawn_server_with_push, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::push::{MockTransport, PushKind};
use trust_message_tcp::wire::{self, Frame, frame};

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: common::PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

async fn session(
    server: &common::ServerHandle,
    identity: &SigningKey,
    device_id: u16,
) -> Result<Conn> {
    let mut conn = connect_as(server, identity, Some(device_id), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn register(
    conn: &mut Conn,
    platform: wire::PushPlatform,
    token: &str,
) -> Result<wire::PushTokenAck> {
    conn.send_frame(&wrap(frame::Payload::RegisterPushToken(
        wire::RegisterPushToken {
            token: token.to_string(),
            platform: platform as i32,
        },
    )))
    .await?;
    read_push_ack(conn).await
}

async fn unregister(conn: &mut Conn) -> Result<wire::PushTokenAck> {
    conn.send_frame(&wrap(frame::Payload::UnregisterPushToken(
        wire::UnregisterPushToken {},
    )))
    .await?;
    read_push_ack(conn).await
}

async fn read_push_ack(conn: &mut Conn) -> Result<wire::PushTokenAck> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::PushTokenAck(ack) => Ok(ack),
        other => bail!("expected PushTokenAck, got {other:?}"),
    }
}

fn welcomes(transport: &MockTransport) -> usize {
    transport
        .sent_payloads()
        .iter()
        .filter(|payload| payload.kind == PushKind::Welcome)
        .count()
}

async fn wait_for_welcomes(transport: &MockTransport, want: usize) -> usize {
    for _ in 0..100 {
        if welcomes(transport) >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    welcomes(transport)
}

/// Цикл Register → Unregister → Register второго приветствия не даёт.
#[tokio::test]
async fn welcome_push_is_not_repeated_by_reregistration() -> Result<()> {
    let (server, transport) =
        spawn_server_with_push("push_welcome_once", LimitsConfig::default()).await?;
    let alice = random_identity();
    let mut conn = session(&server, &alice, 1).await?;

    assert!(
        register(&mut conn, wire::PushPlatform::AndroidFcm, "fcm-1")
            .await?
            .ok
    );
    // Токен разрешается в момент отправки, поэтому снимать его можно только
    // после неё — иначе первое приветствие пропало бы само.
    assert_eq!(wait_for_welcomes(&transport, 1).await, 1);

    for round in 0..3 {
        assert!(unregister(&mut conn).await?.ok);
        let ack = register(
            &mut conn,
            wire::PushPlatform::AndroidFcm,
            &format!("fcm-{round}"),
        )
        .await?;
        assert!(ack.ok, "{}", ack.message);
    }
    // Другое устройство того же аккаунта — тоже без приветствия.
    let mut other = session(&server, &alice, 2).await?;
    assert!(
        register(&mut other, wire::PushPlatform::IosFcm, "fcm-2")
            .await?
            .ok
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(welcomes(&transport), 1, "the welcome push must be one-shot");
    Ok(())
}

/// Новое устройство сверх потолка получает отказ; смена токена известного
/// устройства и место, освобождённое снятием, работают как обычно.
#[tokio::test]
async fn push_devices_per_user_are_capped() -> Result<()> {
    let limits = LimitsConfig {
        max_push_devices_per_user: 2,
        ..LimitsConfig::default()
    };
    let (server, _transport) = spawn_server_with_push("push_device_cap", limits).await?;
    let alice = random_identity();
    let mut first = session(&server, &alice, 1).await?;
    let mut second = session(&server, &alice, 2).await?;
    let mut third = session(&server, &alice, 3).await?;

    assert!(
        register(&mut first, wire::PushPlatform::AndroidFcm, "a")
            .await?
            .ok
    );
    assert!(
        register(&mut second, wire::PushPlatform::IosVoip, "00ff")
            .await?
            .ok
    );

    let refused = register(&mut third, wire::PushPlatform::AndroidFcm, "c").await?;
    assert!(!refused.ok);
    assert_eq!(refused.message, "push device limit reached");

    // Уже известное устройство обновляет токен и заводит второй слот.
    assert!(
        register(&mut first, wire::PushPlatform::AndroidFcm, "a2")
            .await?
            .ok
    );
    assert!(
        register(&mut second, wire::PushPlatform::IosFcm, "b")
            .await?
            .ok
    );

    assert!(unregister(&mut second).await?.ok);
    assert!(
        register(&mut third, wire::PushPlatform::AndroidFcm, "c")
            .await?
            .ok
    );
    Ok(())
}

/// VoIP-токен APNs уходит в путь запроса: всё, что не hex, — отказ.
#[tokio::test]
async fn voip_token_must_be_hex() -> Result<()> {
    let (server, _transport) =
        spawn_server_with_push("push_voip_hex", LimitsConfig::default()).await?;
    let alice = random_identity();
    let mut conn = session(&server, &alice, 1).await?;

    for bad in ["../../3/device/other", "abc?x=1", "zz", "abc"] {
        let ack = register(&mut conn, wire::PushPlatform::IosVoip, bad).await?;
        assert!(!ack.ok, "{bad:?} was accepted");
        assert_eq!(ack.message, "invalid token");
    }
    assert!(
        register(&mut conn, wire::PushPlatform::IosVoip, "0123abcdEF")
            .await?
            .ok
    );
    Ok(())
}
