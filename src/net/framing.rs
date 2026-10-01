use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;

use crate::config::{RetentionPolicy, ServerConfigSnapshot};
use crate::domain::priority::MessagePriority;
use crate::domain::reject::SendRejectReason;
use crate::net::noise::{NodeIdentity, SERVER_CONFIG_SIGNING_DOMAIN};
use crate::state::registry::DeviceId;
use crate::wire::{self, Frame, frame};

/// Версия wire-протокола. Едет открытым текстом в начале соединения и
/// входит в prologue Noise, поэтому нода, не умеющая заявленную версию,
/// рвёт соединение до крипты, а не разбирает кадры, которых не понимает
/// (см. `net::noise`).
pub const PROTO_VERSION: u16 = 1;

/// Запас кадра под служебные поля, байт.
///
/// Тело едет в двух кадрах: отправитель присылает его в `ClientSend`,
/// получателю оно уходит в `IncomingMessage`. Тело одно, а служебные поля
/// разные: к кадру доставки нода добавляет `proto_version`, `message_id` и
/// `from_device_id`, за которые отправитель не платил. Без запаса
/// `ClientSend` ровно в размер потолка превращается в `IncomingMessage`
/// длиннее потолка: записать такой кадр получателю нельзя, а на брокерном
/// бэкенде конверт ещё и возвращается при каждом подключении.
///
/// Тело не длиннее `max_frame_len - SEND_BODY_RESERVE` помещается в оба
/// кадра при любых значениях остальных полей: худший `IncomingMessage`
/// занимает 65 байт сверх тела, худший `ClientSend` — 121.
pub const SEND_BODY_RESERVE: usize = 128;

/// Наибольшее тело `ClientSend`, которое нода принимает при потолке кадра
/// `max_frame_len`. Более длинное отклоняется `SendAck` с `TOO_LARGE`.
pub fn max_send_body_len(max_frame_len: usize) -> usize {
    max_frame_len.saturating_sub(SEND_BODY_RESERVE)
}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame> {
    Frame::decode(bytes).context("decode frame")
}

pub fn encode_auth_ok(user: [u8; 32]) -> Result<Vec<u8>> {
    let server_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs();
    Ok(encode_frame(frame::Payload::AuthOk(wire::AuthOk {
        user_id: user.to_vec(),
        server_time,
    })))
}

pub fn encode_auth_error(code: u16, message: &str) -> Vec<u8> {
    encode_frame(frame::Payload::AuthError(wire::AuthError {
        code: code as u32,
        message: message.to_string(),
    }))
}

/// Снапшот конфигурации, подписанный ключом ноды.
///
/// Неподписанного варианта нет намеренно: он был бы путём для downgrade.
pub fn encode_signed_server_config(
    config: &ServerConfigSnapshot,
    node: &NodeIdentity,
    now_secs: u64,
) -> Vec<u8> {
    let snapshot = wire::ServerConfig {
        proto_version: PROTO_VERSION as u32,
        max_frame_len: config.max_frame_len as u64,
        supports_device_addressing: config.supports_device_addressing,
        supports_offline_messages: config.supports_offline_messages(),
        supports_deleted_message_archive: config.supports_deleted_message_archive(),
        offline_messages_retention: Some(retention_config(config.offline_messages_retention)),
        deleted_messages_retention: Some(retention_config(config.deleted_messages_retention)),
        supports_delivery_ack: config.supports_delivery_ack,
        supports_queue_addressing: config.supports_queue_addressing,
        device_cert_max_ttl_secs: config.device_cert_max_ttl.as_secs(),
        // Статик ноды попадает под подпись: клиент сверяет его с тем,
        // которым прошёл хендшейк, и снапшот нельзя пересадить на другую
        // ноду.
        node_static_key: node.public().to_vec(),
        node_identity_key: node.identity_public().to_vec(),
        issued_at: now_secs,
        expires_at: now_secs.saturating_add(config.config_ttl.as_secs()),
        advertised_address: config.advertised_address.clone().unwrap_or_default(),
    };

    // Подписываются именно эти байты, и они же уезжают клиенту: protobuf
    // не канонизирован, и пересборка сообщения на другой стороне могла бы
    // дать другие байты при том же смысле.
    let config_bytes = snapshot.encode_to_vec();
    let signature = node.sign_server_config(&config_bytes);

    encode_frame(frame::Payload::SignedServerConfig(
        wire::SignedServerConfig {
            config: config_bytes,
            node_identity_key: node.identity_public().to_vec(),
            signature: signature.to_vec(),
        },
    ))
}

/// Клиентская проверка подписанного снапшота — эталонная реализация того,
/// что обязан делать каждый клиент. Используется тестами и `examples/`:
/// одна экспортируемая проверка подписи надёжнее нескольких копий.
///
/// `pinned_static` — X25519-статик, с которым клиент прошёл хендшейк.
/// Сверка с ним конверсии identity-ключа и делает подпись доказательством
/// «подписала та нода, с которой я говорю», а не просто «кто-то подписал».
pub fn verify_signed_server_config(
    signed: &wire::SignedServerConfig,
    pinned_static: &[u8; 32],
    now_secs: u64,
) -> Result<wire::ServerConfig> {
    let identity_key = as_fixed_32(&signed.node_identity_key)
        .context("signed config carries no valid node identity key")?;
    let verifying = VerifyingKey::from_bytes(&identity_key)
        .context("node identity key is not a valid ed25519 public key")?;

    if &verifying.to_montgomery().to_bytes() != pinned_static {
        bail!("signed config is signed by a key unrelated to the handshake static");
    }

    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);

    let mut message = Vec::with_capacity(SERVER_CONFIG_SIGNING_DOMAIN.len() + signed.config.len());
    message.extend_from_slice(SERVER_CONFIG_SIGNING_DOMAIN);
    message.extend_from_slice(&signed.config);
    verifying
        .verify_strict(&message, &signature)
        .context("server config signature does not verify")?;

    let config = wire::ServerConfig::decode(signed.config.as_slice())
        .context("signed config payload is not a ServerConfig")?;

    if config.expires_at == 0 {
        bail!("signed config carries no expiry");
    }
    if config.expires_at <= now_secs {
        bail!(
            "signed config expired at {} (now {now_secs})",
            config.expires_at
        );
    }
    if config.node_static_key != pinned_static.as_slice() {
        bail!("signed config names a different node static key");
    }

    Ok(config)
}

pub fn encode_incoming(
    from: [u8; 32],
    from_device_id: Option<DeviceId>,
    message_id: u64,
    body: &[u8],
    priority: Option<MessagePriority>,
) -> Vec<u8> {
    encode_frame(frame::Payload::Incoming(wire::IncomingMessage {
        from_user_id: from.to_vec(),
        body: body.to_vec(),
        from_device_id: encode_device_id(from_device_id),
        message_id,
        priority: MessagePriority::to_wire(priority),
    }))
}

pub fn encode_send_ack(ok: bool, queued: bool, queue_id: u64, reason: SendRejectReason) -> Vec<u8> {
    encode_frame(frame::Payload::SendAck(wire::SendAck {
        ok,
        queued,
        queue_id,
        reason: reason.to_wire(),
    }))
}

pub fn encode_pong() -> Vec<u8> {
    encode_frame(frame::Payload::Pong(wire::Pong {}))
}

pub fn encode_push_token_ack(ok: bool, message: &str) -> Vec<u8> {
    encode_frame(frame::Payload::PushTokenAck(wire::PushTokenAck {
        ok,
        message: message.to_string(),
    }))
}

/// Ответ на операцию с очередью. `queue_id` заполняется только успешным
/// `AllocateQueue` — это и есть выданный идентификатор.
pub fn encode_queue_ack(
    ok: bool,
    queue_id: Option<[u8; 32]>,
    reason: wire::QueueRejectReason,
) -> Vec<u8> {
    encode_frame(frame::Payload::QueueAck(wire::QueueAck {
        ok,
        queue_id: queue_id.map(|id| id.to_vec()).unwrap_or_default(),
        reason: reason as i32,
    }))
}

pub fn encode_queue_list(records: &[crate::state::queues::QueueRecord]) -> Vec<u8> {
    encode_frame(frame::Payload::QueueList(wire::QueueList {
        queues: records
            .iter()
            .map(|record| wire::QueueRecord {
                queue_id: record.queue_id.to_vec(),
                created_at: record.created_at_secs,
            })
            .collect(),
    }))
}

/// Идентификатор устройства на проводе — `uint32` (16-битных типов в
/// protobuf нет), в домене — `u16`. Значение вне диапазона может прислать
/// только сломанный или враждебный клиент, поэтому это ошибка кадра, а не
/// молчаливое усечение до чужого устройства.
pub fn decode_device_id(raw: Option<u32>) -> Result<Option<DeviceId>> {
    match raw {
        None => Ok(None),
        Some(value) => match DeviceId::try_from(value) {
            Ok(device_id) => Ok(Some(device_id)),
            Err(_) => bail!("device id {value} does not fit into 16 bits"),
        },
    }
}

pub fn encode_device_id(value: Option<DeviceId>) -> Option<u32> {
    value.map(u32::from)
}

/// 32-байтовый идентификатор из wire-поля `bytes`. Длина — ровно 32 байта:
/// более длинное поле не усекается, а отвергается, иначе разные значения
/// на проводе адресовали бы одного и того же получателя по первым 32
/// байтам.
pub fn as_fixed_32(data: &[u8]) -> Result<[u8; 32]> {
    data.try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", data.len()))
}

fn encode_frame(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION as u32,
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn retention_config(policy: RetentionPolicy) -> wire::RetentionConfig {
    let (mode, retention_seconds) = match policy {
        RetentionPolicy::Disabled => (wire::RetentionMode::Disabled, 0),
        RetentionPolicy::Immediate => (wire::RetentionMode::Immediate, 0),
        RetentionPolicy::KeepFor(duration) => (wire::RetentionMode::KeepFor, duration.as_secs()),
    };
    wire::RetentionConfig {
        mode: mode as i32,
        retention_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PROTO_VERSION, SEND_BODY_RESERVE, as_fixed_32, decode_device_id, decode_frame,
        encode_device_id, encode_incoming, encode_send_ack, encode_signed_server_config,
        max_send_body_len, verify_signed_server_config,
    };
    use crate::config::{RetentionPolicy, ServerConfigSnapshot};
    use crate::domain::priority::MessagePriority;
    use crate::domain::reject::SendRejectReason;
    use crate::net::noise::{NodeIdentity, NodeKeySource};
    use crate::wire::{RetentionMode, frame};
    use std::time::Duration;

    const NOW: u64 = 1_700_000_000;

    fn user(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn node(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32], NodeKeySource::Configured)
    }

    fn snapshot() -> ServerConfigSnapshot {
        ServerConfigSnapshot {
            max_frame_len: 1024,
            supports_device_addressing: true,
            deleted_messages_retention: RetentionPolicy::Disabled,
            offline_messages_retention: RetentionPolicy::KeepFor(Duration::from_secs(3600)),
            supports_delivery_ack: true,
            supports_queue_addressing: false,
            device_cert_max_ttl: Duration::from_secs(30 * 24 * 3600),
            config_ttl: Duration::from_secs(3600),
            advertised_address: Some("node.example:5000".to_string()),
        }
    }

    fn signed(bytes: &[u8]) -> crate::wire::SignedServerConfig {
        match payload(bytes) {
            frame::Payload::SignedServerConfig(signed) => signed,
            _ => panic!("unexpected frame variant"),
        }
    }

    fn payload(bytes: &[u8]) -> frame::Payload {
        decode_frame(bytes)
            .unwrap()
            .payload
            .expect("frame carries a payload")
    }

    #[test]
    fn incoming_frame_roundtrips_optional_device_id() {
        let encoded = encode_incoming(user(1), Some(42), 77, b"hello", Some(MessagePriority::High));
        let frame::Payload::Incoming(incoming) = payload(&encoded) else {
            panic!("unexpected frame variant");
        };

        assert_eq!(incoming.from_user_id, user(1));
        assert_eq!(incoming.body, b"hello");
        assert_eq!(decode_device_id(incoming.from_device_id).unwrap(), Some(42));
        assert_eq!(incoming.message_id, 77);
        assert_eq!(
            MessagePriority::from_wire(incoming.priority),
            Some(MessagePriority::High)
        );
    }

    #[test]
    fn incoming_frame_defaults_to_unset_priority_when_none() {
        let encoded = encode_incoming(user(1), None, 1, b"hi", None);
        let frame::Payload::Incoming(incoming) = payload(&encoded) else {
            panic!("unexpected frame variant");
        };
        assert_eq!(MessagePriority::from_wire(incoming.priority), None);
        assert_eq!(incoming.from_device_id, None);
    }

    /// `device_id = 0` — валидное устройство, и оно обязано отличаться от
    /// «устройство не указано»: на этом стоит выбор account- или
    /// device-scope доставки.
    #[test]
    fn device_id_zero_is_not_absence() {
        assert_eq!(encode_device_id(None), None);
        assert_eq!(encode_device_id(Some(0)), Some(0));
        assert_eq!(decode_device_id(None).unwrap(), None);
        assert_eq!(decode_device_id(Some(0)).unwrap(), Some(0));
    }

    /// Значение вне 16 бит — ошибка кадра, а не усечение до чужого
    /// устройства.
    #[test]
    fn device_id_out_of_range_is_rejected() {
        assert_eq!(decode_device_id(Some(65_535)).unwrap(), Some(65_535));
        assert!(decode_device_id(Some(65_536)).is_err());
    }

    #[test]
    fn signed_server_config_verifies_and_carries_the_snapshot() {
        let node = node(9);
        let encoded = encode_signed_server_config(&snapshot(), &node, NOW);
        let config = verify_signed_server_config(&signed(&encoded), &node.public(), NOW).unwrap();

        assert_eq!(config.proto_version, PROTO_VERSION as u32);
        assert_eq!(config.max_frame_len, 1024);
        assert!(config.supports_device_addressing);
        assert!(config.supports_offline_messages);
        assert!(config.supports_deleted_message_archive);
        assert!(config.supports_delivery_ack);
        assert_eq!(config.node_static_key, node.public());
        assert_eq!(config.node_identity_key, node.identity_public());
        assert_eq!(config.issued_at, NOW);
        assert_eq!(config.expires_at, NOW + 3600);
        assert_eq!(config.advertised_address, "node.example:5000");

        let offline = config.offline_messages_retention.unwrap();
        assert_eq!(offline.mode, RetentionMode::KeepFor as i32);
        assert_eq!(offline.retention_seconds, 3600);
        let deleted = config.deleted_messages_retention.unwrap();
        assert_eq!(deleted.mode, RetentionMode::Disabled as i32);
        assert_eq!(deleted.retention_seconds, 0);
    }

    /// Ключевое свойство схемы: identity-ключ ноды birational-конвертируется
    /// ровно в тот статик, которым клиент прошёл хендшейк. Без этой связи
    /// подпись доказывала бы только «кто-то подписал».
    #[test]
    fn identity_key_converts_to_the_handshake_static() {
        let node = node(11);
        let encoded = encode_signed_server_config(&snapshot(), &node, NOW);
        let signed = signed(&encoded);

        let identity = ed25519_dalek::VerifyingKey::from_bytes(
            &as_fixed_32(&signed.node_identity_key).unwrap(),
        )
        .unwrap();
        assert_eq!(identity.to_montgomery().to_bytes(), node.public());
    }

    /// Идентификатор — ровно 32 байта: короткий отвергается, а длинный не
    /// усекается до первых 32, иначе 33-байтовый `recipient_id` молча
    /// адресовал бы чужой ключ.
    #[test]
    fn fixed_32_requires_exact_length() {
        let id: Vec<u8> = (0..32).collect();
        assert_eq!(as_fixed_32(&id).unwrap().as_slice(), id.as_slice());

        for len in [0usize, 1, 31, 33, 64] {
            let data = vec![7u8; len];
            let err = as_fixed_32(&data).expect_err("wrong length must be rejected");
            assert!(
                err.to_string().contains(&format!("got {len}")),
                "unexpected error: {err}"
            );
        }
    }

    /// Правка любого байта снапшота ломает подпись — включая поля, которые
    /// нода могла бы счесть безобидными.
    #[test]
    fn tampered_snapshot_fails_verification() {
        let node = node(12);
        let encoded = encode_signed_server_config(&snapshot(), &node, NOW);
        let mut signed = signed(&encoded);

        for index in 0..signed.config.len() {
            let mut tampered = signed.clone();
            tampered.config[index] ^= 0x01;
            assert!(
                verify_signed_server_config(&tampered, &node.public(), NOW).is_err(),
                "byte {index} of the snapshot is not covered by the signature"
            );
        }

        signed.signature[0] ^= 0x01;
        assert!(verify_signed_server_config(&signed, &node.public(), NOW).is_err());
    }

    /// Снапшот, подписанный другой нодой, не проходит: подпись валидна, но
    /// ключ не тот, с которым клиент говорит. Это и есть защита от
    /// пересадки чужого конфига.
    #[test]
    fn snapshot_signed_by_another_node_is_rejected() {
        let mine = node(13);
        let other = node(14);
        let encoded = encode_signed_server_config(&snapshot(), &other, NOW);

        let err = verify_signed_server_config(&signed(&encoded), &mine.public(), NOW)
            .expect_err("foreign signer must be rejected");
        assert!(
            err.to_string()
                .contains("unrelated to the handshake static"),
            "unexpected error: {err}"
        );
    }

    /// Просроченный снапшот отвергается: иначе однажды подписанный конфиг
    /// предъявлялся бы вечно и отозвать его было бы нечем.
    #[test]
    fn expired_snapshot_is_rejected() {
        let node = node(15);
        let encoded = encode_signed_server_config(&snapshot(), &node, NOW);
        let signed = signed(&encoded);

        assert!(verify_signed_server_config(&signed, &node.public(), NOW + 3599).is_ok());
        let err = verify_signed_server_config(&signed, &node.public(), NOW + 3600)
            .expect_err("expired snapshot must be rejected");
        assert!(
            err.to_string().contains("expired"),
            "unexpected error: {err}"
        );
    }

    /// Незаданный адрес приезжает пустой строкой, а не отсутствующим
    /// полем: клиент обязан читать пустоту как «нода адрес не объявляет».
    #[test]
    fn signed_config_leaves_advertised_address_empty_when_unset() {
        let node = node(16);
        let encoded = encode_signed_server_config(
            &ServerConfigSnapshot {
                advertised_address: None,
                offline_messages_retention: RetentionPolicy::Disabled,
                supports_delivery_ack: false,
                supports_queue_addressing: false,
                ..snapshot()
            },
            &node,
            NOW,
        );
        let config = verify_signed_server_config(&signed(&encoded), &node.public(), NOW).unwrap();

        assert_eq!(config.advertised_address, "");
        assert!(!config.supports_delivery_ack);
    }

    /// SendAck.reason ходит по проводу и читается обратно во всех вариантах.
    /// Отсутствие поля у старого клиента неотличимо от `unspecified` —
    /// на этом держится совместимость (см. server-contract.md §6).
    #[test]
    fn send_ack_reason_roundtrips_all_variants() {
        for reason in [
            SendRejectReason::Unspecified,
            SendRejectReason::Full,
            SendRejectReason::NoPermit,
            SendRejectReason::Expired,
            SendRejectReason::RateLimited,
            SendRejectReason::InvalidTtl,
        ] {
            let encoded = encode_send_ack(false, false, 0, reason);
            let frame::Payload::SendAck(ack) = payload(&encoded) else {
                panic!("unexpected frame variant");
            };

            assert_eq!(SendRejectReason::from_wire(ack.reason), reason);
            assert!(!ack.ok);
            assert!(!ack.queued);
            assert_eq!(ack.queue_id, 0);
        }
    }

    /// Успешный ack несёт zero-значение reason: клиент, читающий его как
    /// «поле не заполнено», ведёт себя корректно.
    #[test]
    fn successful_send_ack_carries_unspecified_reason() {
        let encoded = encode_send_ack(true, true, 42, SendRejectReason::Unspecified);
        let frame::Payload::SendAck(ack) = payload(&encoded) else {
            panic!("unexpected frame variant");
        };

        assert!(ack.ok);
        assert!(ack.queued);
        assert_eq!(ack.queue_id, 42);
        assert_eq!(
            SendRejectReason::from_wire(ack.reason),
            SendRejectReason::Unspecified
        );
    }

    /// Тело на границе потолка помещается в кадр доставки при худших
    /// служебных полях: наибольший `message_id`, наибольший `deviceId`,
    /// приоритет задан. Без запаса такой `IncomingMessage` выходил длиннее
    /// `max_frame_len`, и запись его в сокет рвала сессию получателя.
    #[test]
    fn body_at_the_ceiling_fits_the_delivery_frame() {
        for max_frame_len in [1024usize, 1024 * 1024, 8 * 1024 * 1024] {
            let body = vec![0xABu8; max_send_body_len(max_frame_len)];
            let frame = encode_incoming(
                user(1),
                Some(u16::MAX),
                u64::MAX,
                &body,
                Some(MessagePriority::High),
            );
            assert!(
                frame.len() <= max_frame_len,
                "delivery frame of {} bytes exceeds max_frame_len {max_frame_len}",
                frame.len()
            );
        }
    }

    /// Тот же потолок оставляет место и входящему кадру: `ClientSend` с
    /// таким телом проходит по размеру, даже когда заполнены все поля и
    /// каждое занимает на проводе максимум.
    #[test]
    fn body_at_the_ceiling_fits_the_client_send_frame() {
        use crate::wire::{ClientSend, Frame};
        use prost::Message;

        for max_frame_len in [1024usize, 1024 * 1024, 8 * 1024 * 1024] {
            let frame = Frame {
                proto_version: u32::from(PROTO_VERSION),
                payload: Some(frame::Payload::ClientSend(ClientSend {
                    recipient_id: vec![0xFF; 32],
                    body: vec![0xABu8; max_send_body_len(max_frame_len)],
                    recipient_device_id: Some(u32::MAX),
                    // Отрицательное значение enum — худший случай: int32
                    // кодируется десятью байтами.
                    priority: -1,
                    wake_hint: -1,
                    queue_id: vec![0xFF; 32],
                    ttl_seconds: u64::MAX,
                })),
            }
            .encode_to_vec();
            assert!(
                frame.len() <= max_frame_len,
                "client frame of {} bytes exceeds max_frame_len {max_frame_len}",
                frame.len()
            );
        }
    }

    /// Запас не взят с потолка: тело ровно в размер старого предела
    /// (кадр `ClientSend` в точности `max_frame_len`) в кадр доставки не
    /// помещается — именно этот случай запас и закрывает.
    #[test]
    fn body_filling_the_client_frame_overflows_the_delivery_frame() {
        use crate::wire::{ClientSend, Frame};
        use prost::Message;

        let max_frame_len = 1024 * 1024;
        // Наибольшее тело, с которым минимальный `ClientSend` (без
        // `proto_version`, только получатель и тело) ещё укладывается в кадр.
        let mut body_len = max_frame_len;
        let client_frame_len = |body_len: usize| {
            Frame {
                proto_version: 0,
                payload: Some(frame::Payload::ClientSend(ClientSend {
                    recipient_id: vec![0xFF; 32],
                    body: vec![0u8; body_len],
                    ..ClientSend::default()
                })),
            }
            .encoded_len()
        };
        while client_frame_len(body_len) > max_frame_len {
            body_len -= 1;
        }
        assert_eq!(client_frame_len(body_len), max_frame_len);
        assert!(body_len > max_send_body_len(max_frame_len));
        assert!(body_len + SEND_BODY_RESERVE > max_frame_len);

        let delivery = encode_incoming(user(1), None, 1, &vec![0u8; body_len], None);
        assert!(delivery.len() > max_frame_len);
    }
}
