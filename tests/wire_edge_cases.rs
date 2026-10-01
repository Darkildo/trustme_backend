//! Негативные сценарии wire-слоя: что нода делает с кадрами, которые не
//! должна принимать.
//!
//! Разница между «игнорировать» и «разорвать соединение» здесь не
//! стилистическая. Кадр, который просто нечего обрабатывать, — не повод
//! рвать сессию; кадр, который нельзя разобрать, означает, что поток
//! рассинхронизирован, и продолжать в нём нечего.

mod common;

use anyhow::{Result, bail};
use common::{
    FRAME_MAX, connect, connect_as, decode, expect_auth_ok, expect_connection_gone, next_frame,
    spawn_server,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::wire::{self, Frame, frame};

const PROTO_VERSION: u32 = 1;

fn wrap(payload: Option<frame::Payload>) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload,
    }
    .encode_to_vec()
}

/// Кадр, который нельзя разобрать, рвёт соединение: после него неизвестно,
/// где в потоке границы следующего кадра, и продолжать нечего.
#[tokio::test]
async fn undecodable_frame_closes_the_connection() -> Result<()> {
    let server = spawn_server("bad_frame", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[21u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    // Нулевой тег невалиден в protobuf всегда.
    conn.send_frame(&[0x00, 0x01, 0x02, 0x03]).await?;

    assert!(
        expect_connection_gone(&mut conn).await,
        "нода обязана закрыть соединение после неразбираемого кадра"
    );
    Ok(())
}

/// Кадр без payload — не ошибка формата, а «нечего делать»: нода его
/// игнорирует и продолжает обслуживать сессию. На этом держится
/// возможность добавить keepalive-расширение, не ломая старую сторону.
#[tokio::test]
async fn frame_without_payload_is_ignored() -> Result<()> {
    let server = spawn_server("empty_frame", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[22u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    conn.send_frame(&wrap(None)).await?;

    // Сессия жива: следующий осмысленный кадр обслуживается.
    conn.send_frame(&wrap(Some(frame::Payload::Ping(wire::Ping {}))))
        .await?;
    match decode(&next_frame(&mut conn).await?)? {
        frame::Payload::Pong(_) => Ok(()),
        other => bail!("expected Pong after an empty frame, got {other:?}"),
    }
}

/// Кадр больше `maxFrameLen` ноды разрывает соединение. Клиент для этого
/// поднимает свой потолок выше серверного — иначе он не смог бы такой
/// кадр даже отправить.
#[tokio::test]
async fn oversized_frame_closes_the_connection() -> Result<()> {
    let server = spawn_server("oversized", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[23u8; 32]);

    let mut conn = connect_as(&server, &identity, Some(1), FRAME_MAX * 4).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    let oversized = wrap(Some(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: vec![9u8; 32],
        body: vec![0x5A; FRAME_MAX + 1024],
        ..wire::ClientSend::default()
    })));
    assert!(oversized.len() > FRAME_MAX);
    conn.send_frame(&oversized).await?;

    assert!(
        expect_connection_gone(&mut conn).await,
        "кадр сверх maxFrameLen обязан закрывать соединение"
    );
    Ok(())
}

/// `device_id` на проводе 32-битный, в домене 16-битный. Значение вне
/// диапазона — ошибка кадра, а не усечение до чужого устройства.
#[tokio::test]
async fn out_of_range_device_id_closes_the_connection() -> Result<()> {
    let server = spawn_server("device_range", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[24u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    conn.send_frame(&wrap(Some(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: vec![9u8; 32],
        body: b"payload".to_vec(),
        recipient_device_id: Some(70_000),
        ..wire::ClientSend::default()
    }))))
    .await?;

    assert!(
        expect_connection_gone(&mut conn).await,
        "device_id вне 16 бит обязан закрывать соединение"
    );
    Ok(())
}

/// Идентификатор получателя короче 32 байт разобрать нельзя — кадр
/// отвергается вместе с соединением.
#[tokio::test]
async fn short_recipient_id_closes_the_connection() -> Result<()> {
    let server = spawn_server("short_recipient", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[25u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    conn.send_frame(&wrap(Some(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: vec![9u8; 16],
        body: b"payload".to_vec(),
        ..wire::ClientSend::default()
    }))))
    .await?;

    assert!(
        expect_connection_gone(&mut conn).await,
        "короткий recipientId обязан закрывать соединение"
    );
    Ok(())
}

/// Незнакомое поле от более свежего клиента пропускается, и кадр
/// обрабатывается как обычно. Это то же правило, что проверяет
/// `tests/proto_schema.rs`, но уже на живой ноде.
#[tokio::test]
async fn unknown_field_does_not_break_the_session() -> Result<()> {
    use prost::encoding::{WireType, encode_key, encode_varint};

    let server = spawn_server("unknown_field", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[26u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut conn).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    let mut ping = wrap(Some(frame::Payload::Ping(wire::Ping {})));
    encode_key(4242, WireType::Varint, &mut ping);
    encode_varint(7, &mut ping);
    conn.send_frame(&ping).await?;

    match decode(&next_frame(&mut conn).await?)? {
        frame::Payload::Pong(_) => Ok(()),
        other => bail!("expected Pong despite an unknown field, got {other:?}"),
    }
}
