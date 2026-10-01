//! Интеграционные тесты Noise-сессии.
//!
//! Гоняют настоящий `accept_loop` через loopback-TCP: клиент проходит
//! Noise IK, получает `AuthOk` и работает по установленному каналу.
//! Проверяется:
//!   - сессия открывается без единого plaintext-кадра, identity доказана
//!     статиком клиента;
//!   - `GetServerConfig` обслуживается внутри сессии и отдаёт статик ноды
//!     для сверки пина;
//!   - клиент, запиннувший чужой статик ноды, до сессии не доходит;
//!   - лимит одновременных сессий приезжает как `AuthError` по уже
//!     установленному каналу, а не разрывом хендшейка.

mod common;

use anyhow::{Result, bail};
use common::{
    FRAME_MAX, HANDSHAKE_TIMEOUT, PROTO_VERSION, connect, decode, encode_get_server_config,
    expect_auth_ok, expect_signed_config, next_frame, spawn_server, temp_storage_path,
};
use ed25519_dalek::SigningKey;
use tokio::net::TcpStream;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::net::noise::{NodeIdentity, NoiseFramed};
use trust_message_tcp::wire::frame;

/// Сессия открывается одним лишь Noise-хендшейком, без единого
/// plaintext-кадра. `AuthOk` приходит сам, без запроса.
#[tokio::test]
async fn noise_handshake_opens_session_without_any_token() -> Result<()> {
    let server = spawn_server("open", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[11u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    let first = next_frame(&mut conn).await?;
    expect_auth_ok(&first, &identity.verifying_key().to_bytes())?;

    Ok(())
}

/// `GetServerConfig` внутри сессии отдаёт статик ноды — то, чем клиент
/// сверяет пин.
#[tokio::test]
async fn get_server_config_lives_inside_the_session() -> Result<()> {
    let server = spawn_server("config", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[12u8; 32]);

    let mut conn = connect(&server, &identity).await?;
    let first = next_frame(&mut conn).await?;
    expect_auth_ok(&first, &identity.verifying_key().to_bytes())?;

    conn.send_frame(&encode_get_server_config()?).await?;
    let response = next_frame(&mut conn).await?;

    // Клиент обязан именно проверять подпись, а не читать снапшот как
    // есть: тест ходит тем же путём.
    let cfg = expect_signed_config(&response, &server.node_public)?;
    assert_eq!(cfg.max_frame_len, FRAME_MAX as u64);
    assert_eq!(cfg.node_static_key, server.node_public.as_slice());
    assert_eq!(
        cfg.proto_version, PROTO_VERSION,
        "снапшот обязан называть ту же версию, что и хендшейк"
    );
    assert!(
        cfg.expires_at > cfg.issued_at,
        "подписанный снапшот обязан иметь срок"
    );

    Ok(())
}

/// IK с неверным статиком ноды не сходится: клиент, запиннувший чужой
/// ключ, сессию не получает. Первый контакт без пина (XX) проверяется
/// юнит-тестами `net::noise`.
#[tokio::test]
async fn client_with_wrong_node_key_never_reaches_a_session() -> Result<()> {
    let server = spawn_server("wrongkey", LimitsConfig::default()).await?;
    let identity = SigningKey::from_bytes(&[13u8; 32]);
    let wrong_node = NodeIdentity::load_or_generate(&temp_storage_path("wrongnode"), None)?;

    let stream = TcpStream::connect(server.addr).await?;
    let result = NoiseFramed::connect(
        stream,
        &wrong_node.public(),
        &identity,
        None,
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await;

    assert!(result.map(|_| ()).is_err(), "handshake must not complete");
    Ok(())
}

/// Лимит сессий — уже прикладной отказ, а не отказ канала: он приезжает
/// кадром `AuthError` по установленному Noise-соединению.
#[tokio::test]
async fn session_limit_is_reported_over_the_established_channel() -> Result<()> {
    let limits = LimitsConfig {
        max_sessions_per_user: 1,
        ..LimitsConfig::default()
    };
    let server = spawn_server("sesslimit", limits).await?;
    let identity = SigningKey::from_bytes(&[14u8; 32]);

    let mut first = connect(&server, &identity).await?;
    expect_auth_ok(
        &next_frame(&mut first).await?,
        &identity.verifying_key().to_bytes(),
    )?;

    let mut second = connect(&server, &identity).await?;
    let frame_bytes = next_frame(&mut second).await?;
    match decode(&frame_bytes)? {
        frame::Payload::AuthError(err) => {
            assert_eq!(err.code, 401);
            assert!(err.message.contains("session limit"));
        }
        _ => bail!("expected AuthError for the over-limit session"),
    }

    Ok(())
}
