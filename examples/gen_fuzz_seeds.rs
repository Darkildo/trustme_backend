//! Генератор сидового корпуса для фазз-таргетов.
//!
//! Корпус из валидных кадров даёт фаззеру готовые формы protobuf, от
//! которых отталкиваются мутации, и делает короткий CI-прогон
//! детерминированным: регрессия, ломающая разбор валидного кадра,
//! ловится сразу (см. `.github/workflows/ci.yml`).
//!
//! Перегенерировать после изменения схемы:
//!     cargo run --example gen_fuzz_seeds -- fuzz/seeds

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use prost::Message;
use trust_message_tcp::config::{RetentionPolicy, ServerConfigSnapshot};
use trust_message_tcp::net::framing::{
    encode_auth_error, encode_incoming, encode_pong, encode_push_token_ack, encode_send_ack,
    encode_signed_server_config,
};
use trust_message_tcp::net::noise::{NodeIdentity, NodeKeySource};
use trust_message_tcp::wire::{self, Frame, frame};

const PROTO_VERSION: u32 = 1;

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(name);
    std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    println!("  {} ({} байт)", path.display(), bytes.len());
    Ok(())
}

fn main() -> Result<()> {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/seeds".to_string());
    let root = Path::new(&root);

    // --- frame_decode: по кадру на каждый вариант oneof ---
    let dir = root.join("frame_decode");
    println!("frame_decode:");
    write(
        &dir,
        "auth_ok.bin",
        &wrap(frame::Payload::AuthOk(wire::AuthOk {
            user_id: vec![1u8; 32],
            server_time: 1_700_000_000,
        })),
    )?;
    write(
        &dir,
        "auth_error.bin",
        &encode_auth_error(401, "session limit exceeded"),
    )?;
    write(
        &dir,
        "client_send.bin",
        &wrap(frame::Payload::ClientSend(wire::ClientSend {
            recipient_id: vec![2u8; 32],
            body: b"ciphertext".to_vec(),
            recipient_device_id: Some(7),
            priority: wire::MessagePriority::High as i32,
            wake_hint: wire::WakeHint::IncomingCall as i32,
            queue_id: vec![3u8; 32],
            ttl_seconds: 86_400,
        })),
    )?;
    write(
        &dir,
        "client_send_minimal.bin",
        &wrap(frame::Payload::ClientSend(wire::ClientSend {
            recipient_id: vec![2u8; 32],
            body: b"x".to_vec(),
            ..wire::ClientSend::default()
        })),
    )?;
    write(
        &dir,
        "send_ack.bin",
        &encode_send_ack(
            false,
            false,
            0,
            trust_message_tcp::domain::reject::SendRejectReason::RateLimited,
        ),
    )?;
    write(
        &dir,
        "incoming.bin",
        &encode_incoming(
            [4u8; 32],
            Some(3),
            42,
            b"ciphertext",
            Some(trust_message_tcp::domain::priority::MessagePriority::Low),
        ),
    )?;
    write(&dir, "pong.bin", &encode_pong())?;
    write(&dir, "ping.bin", &wrap(frame::Payload::Ping(wire::Ping {})))?;
    write(
        &dir,
        "delivery_ack.bin",
        &wrap(frame::Payload::DeliveryAck(wire::DeliveryAck {
            message_id: 99,
        })),
    )?;
    write(
        &dir,
        "get_server_config.bin",
        &wrap(frame::Payload::GetServerConfig(wire::GetServerConfig {})),
    )?;
    write(
        &dir,
        "register_push_token.bin",
        &wrap(frame::Payload::RegisterPushToken(wire::RegisterPushToken {
            token: "fcm-token".to_string(),
            platform: wire::PushPlatform::IosVoip as i32,
        })),
    )?;
    write(&dir, "push_token_ack.bin", &encode_push_token_ack(true, ""))?;
    write(
        &dir,
        "empty_frame.bin",
        &Frame {
            proto_version: PROTO_VERSION,
            payload: None,
        }
        .encode_to_vec(),
    )?;

    // --- signed_server_config ---
    println!("signed_server_config:");
    let node = NodeIdentity::from_seed([7u8; 32], NodeKeySource::Configured);
    let snapshot = ServerConfigSnapshot {
        supports_queue_addressing: false,
        max_frame_len: 8 * 1024 * 1024,
        supports_device_addressing: true,
        deleted_messages_retention: RetentionPolicy::Disabled,
        offline_messages_retention: RetentionPolicy::KeepFor(std::time::Duration::from_secs(
            2_592_000,
        )),
        supports_delivery_ack: true,
        config_ttl: std::time::Duration::from_secs(86_400),
        advertised_address: Some("node.example:5000".to_string()),
    };
    let signed_frame = encode_signed_server_config(&snapshot, &node, 1_700_000_000);
    // Таргет ждёт голый SignedServerConfig, а не кадр — достаём payload.
    let payload = Frame::decode(signed_frame.as_slice())?
        .payload
        .context("frame carries no payload")?;
    let frame::Payload::SignedServerConfig(signed) = payload else {
        anyhow::bail!("expected SignedServerConfig");
    };
    write(
        &root.join("signed_server_config"),
        "valid.bin",
        &signed.encode_to_vec(),
    )?;
    // Тот же снапшот с испорченной подписью: путь «разобралось, но не
    // проверилось» интереснее, чем мусор.
    let mut tampered = signed.clone();
    tampered.signature[0] ^= 0xFF;
    write(
        &root.join("signed_server_config"),
        "bad_signature.bin",
        &tampered.encode_to_vec(),
    )?;

    // --- client_hello ---
    println!("client_hello:");
    let client = SigningKey::from_bytes(&[11u8; 32]);
    for (name, device_id) in [("with_device.bin", Some(7u32)), ("no_device.bin", None)] {
        write(
            &root.join("client_hello"),
            name,
            &wire::NoiseClientHello {
                identity_key: client.verifying_key().to_bytes().to_vec(),
                device_id,
            }
            .encode_to_vec(),
        )?;
    }

    // --- chunk_framing: поток логических кадров, нарезанный по-разному ---
    //
    // Первый байт таргет трактует как размер чанка, поэтому сиды несут
    // его явно: так фаззеру достаются и «заголовок приехал целиком», и
    // «заголовок разорван по байту».
    println!("chunk_framing:");
    let dir = root.join("chunk_framing");
    let body = wrap(frame::Payload::Ping(wire::Ping {}));
    let mut stream = Vec::new();
    for _ in 0..3 {
        stream.extend_from_slice(&(body.len() as u32).to_le_bytes());
        stream.extend_from_slice(&body);
    }
    for (name, chunk_hint) in [
        ("whole.bin", 255u8),
        ("byte_by_byte.bin", 0u8),
        ("split_header.bin", 2u8),
    ] {
        let mut seed = vec![chunk_hint];
        seed.extend_from_slice(&stream);
        write(&dir, name, &seed)?;
    }
    // Кадр с заявленной длиной сверх потолка: путь раннего отказа.
    let mut oversized = vec![255u8];
    oversized.extend_from_slice(&u32::MAX.to_le_bytes());
    write(&dir, "oversized_header.bin", &oversized)?;

    println!("\nготово: {}", root.display());
    Ok(())
}
