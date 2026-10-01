//! Контракт схемы, а не кода: правила совместимости protobuf
//! проверяются на сгенерированных типах.
//!
//! Эти проверки переживают любую реализацию кодека — они про то, что
//! обязана уметь любая сторона протокола, включая клиентские репозитории
//! на других языках.

use prost::Message;
use prost::encoding::{WireType, encode_key, encode_varint};
use trust_message_tcp::wire::{
    AllocateQueue, AuthError, AuthOk, ClientSend, DeliveryAck, Frame, GetServerConfig,
    IncomingMessage, ListQueues, MessagePriority, Ping, Pong, PushPlatform, PushTokenAck, QueueAck,
    QueueList, QueueRecord, QueueRejectReason, RegisterPushToken, RetentionConfig, RetentionMode,
    RevokeQueue, SendAck, SendRejectReason, ServerConfig, SignedServerConfig, UnregisterPushToken,
    WakeHint, frame,
};

const PROTO_VERSION: u32 = 1;

fn wrap(payload: frame::Payload) -> Frame {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(payload),
    }
}

fn roundtrip(frame: &Frame) -> Frame {
    let encoded = frame.encode_to_vec();
    Frame::decode(encoded.as_slice()).expect("frame decodes")
}

/// Число вариантов `Frame.payload`. Обновляется вместе с `variant_index`.
const PAYLOAD_VARIANTS: usize = 18;

/// Порядковый номер варианта. `match` без `_`: новый вариант oneof в схеме
/// ломает компиляцию теста, а не проходит мимо него.
fn variant_index(payload: &frame::Payload) -> usize {
    use frame::Payload as P;
    match payload {
        P::AuthOk(_) => 0,
        P::AuthError(_) => 1,
        P::ClientSend(_) => 2,
        P::SendAck(_) => 3,
        P::Incoming(_) => 4,
        P::Ping(_) => 5,
        P::Pong(_) => 6,
        P::DeliveryAck(_) => 7,
        P::GetServerConfig(_) => 8,
        P::SignedServerConfig(_) => 9,
        P::RegisterPushToken(_) => 10,
        P::UnregisterPushToken(_) => 11,
        P::PushTokenAck(_) => 12,
        P::AllocateQueue(_) => 13,
        P::RevokeQueue(_) => 14,
        P::ListQueues(_) => 15,
        P::QueueAck(_) => 16,
        P::QueueList(_) => 17,
    }
}

/// Каждый вариант oneof доходит до другой стороны тем же вариантом.
/// Список намеренно полный: новый кадр в схеме без строки здесь означает
/// вариант, который никто ни разу не гонял по проводу.
#[test]
fn every_payload_variant_roundtrips() {
    let variants = vec![
        frame::Payload::AuthOk(AuthOk {
            user_id: vec![1u8; 32],
            server_time: 1_700_000_000,
        }),
        frame::Payload::AuthError(AuthError {
            code: 401,
            message: "session limit exceeded".to_string(),
        }),
        frame::Payload::ClientSend(ClientSend {
            recipient_id: vec![2u8; 32],
            body: b"ciphertext".to_vec(),
            recipient_device_id: Some(7),
            priority: MessagePriority::High as i32,
            wake_hint: WakeHint::IncomingCall as i32,
            queue_id: vec![3u8; 32],
            ttl_seconds: 86_400,
        }),
        frame::Payload::SendAck(SendAck {
            ok: false,
            queued: false,
            queue_id: 0,
            reason: SendRejectReason::RateLimited as i32,
        }),
        frame::Payload::Incoming(IncomingMessage {
            from_user_id: vec![4u8; 32],
            body: b"ciphertext".to_vec(),
            from_device_id: None,
            message_id: 42,
            priority: MessagePriority::Low as i32,
        }),
        frame::Payload::Ping(Ping {}),
        frame::Payload::Pong(Pong {}),
        frame::Payload::DeliveryAck(DeliveryAck { message_id: 99 }),
        frame::Payload::GetServerConfig(GetServerConfig {}),
        frame::Payload::SignedServerConfig(SignedServerConfig {
            config: ServerConfig {
                supports_queue_addressing: false,
                proto_version: PROTO_VERSION,
                max_frame_len: 8 * 1024 * 1024,
                supports_device_addressing: true,
                supports_offline_messages: true,
                supports_deleted_message_archive: false,
                offline_messages_retention: Some(RetentionConfig {
                    mode: RetentionMode::KeepFor as i32,
                    retention_seconds: 2_592_000,
                }),
                deleted_messages_retention: Some(RetentionConfig {
                    mode: RetentionMode::Disabled as i32,
                    retention_seconds: 0,
                }),
                supports_delivery_ack: true,
                node_static_key: vec![5u8; 32],
                node_identity_key: vec![6u8; 32],
                issued_at: 1_700_000_000,
                expires_at: 1_700_086_400,
                advertised_address: "node.example:5000".to_string(),
            }
            .encode_to_vec(),
            node_identity_key: vec![6u8; 32],
            signature: vec![7u8; 64],
        }),
        frame::Payload::RegisterPushToken(RegisterPushToken {
            token: "fcm-token".to_string(),
            platform: PushPlatform::IosVoip as i32,
        }),
        frame::Payload::UnregisterPushToken(UnregisterPushToken {}),
        frame::Payload::PushTokenAck(PushTokenAck {
            ok: true,
            message: String::new(),
        }),
        frame::Payload::AllocateQueue(AllocateQueue {}),
        frame::Payload::RevokeQueue(RevokeQueue {
            queue_id: vec![8u8; 32],
        }),
        frame::Payload::ListQueues(ListQueues {}),
        frame::Payload::QueueAck(QueueAck {
            ok: false,
            queue_id: vec![9u8; 32],
            reason: QueueRejectReason::Limit as i32,
        }),
        frame::Payload::QueueList(QueueList {
            queues: vec![QueueRecord {
                queue_id: vec![10u8; 32],
                created_at: 1_700_000_000,
            }],
        }),
    ];

    let mut seen = [false; PAYLOAD_VARIANTS];
    for payload in &variants {
        seen[variant_index(payload)] = true;
    }
    let missing: Vec<usize> = (0..PAYLOAD_VARIANTS).filter(|&i| !seen[i]).collect();
    assert!(
        missing.is_empty(),
        "варианты Frame.payload без roundtrip-проверки: {missing:?}"
    );

    for payload in variants {
        let original = wrap(payload);
        assert_eq!(roundtrip(&original), original);
    }
}

/// Незнакомое значение enum от более свежей стороны — не ошибка кадра.
/// Кадр декодируется целиком, а нераспознанное значение остаётся сырым
/// i32; читатель сводит его к `_UNSPECIFIED` сам.
#[test]
fn unknown_enum_value_does_not_break_decoding() {
    let original = wrap(frame::Payload::ClientSend(ClientSend {
        recipient_id: vec![1u8; 32],
        body: b"body".to_vec(),
        // Значение, которого в схеме ещё нет.
        priority: 99,
        wake_hint: 77,
        ..ClientSend::default()
    }));

    let decoded = roundtrip(&original);
    let frame::Payload::ClientSend(send) = decoded.payload.expect("payload present") else {
        panic!("expected ClientSend");
    };
    assert_eq!(send.priority, 99);
    assert!(MessagePriority::try_from(send.priority).is_err());
    assert!(WakeHint::try_from(send.wake_hint).is_err());
}

/// Поле, которого читатель не знает, пропускается. На этом держится
/// правило «аддитивное поле не ломает старую сторону»: более новая нода
/// дописывает поле, старый клиент читает кадр, не замечая его.
#[test]
fn unknown_field_is_skipped() {
    let original = wrap(frame::Payload::Ping(Ping {}));
    let mut encoded = original.encode_to_vec();

    // Поле с номером из будущего, которого нет в схеме.
    encode_key(9999, WireType::Varint, &mut encoded);
    encode_varint(1234, &mut encoded);

    let decoded = Frame::decode(encoded.as_slice()).expect("unknown field must not break decoding");
    assert_eq!(decoded, original);
}

/// `device_id = 0` — валидный идентификатор устройства, поэтому presence
/// у него выражена явным `optional`, а не нулевым значением.
#[test]
fn absent_device_id_differs_from_zero() {
    let absent = wrap(frame::Payload::ClientSend(ClientSend {
        recipient_id: vec![1u8; 32],
        recipient_device_id: None,
        ..ClientSend::default()
    }));
    let zero = wrap(frame::Payload::ClientSend(ClientSend {
        recipient_id: vec![1u8; 32],
        recipient_device_id: Some(0),
        ..ClientSend::default()
    }));

    assert_ne!(absent.encode_to_vec(), zero.encode_to_vec());

    let frame::Payload::ClientSend(decoded_absent) = roundtrip(&absent).payload.unwrap() else {
        panic!("expected ClientSend");
    };
    let frame::Payload::ClientSend(decoded_zero) = roundtrip(&zero).payload.unwrap() else {
        panic!("expected ClientSend");
    };
    assert_eq!(decoded_absent.recipient_device_id, None);
    assert_eq!(decoded_zero.recipient_device_id, Some(0));
}

/// Кадр без payload — не ошибка формата: пустой конверт декодируется, а
/// как с ним обойтись, решает читатель (нода такой игнорирует).
#[test]
fn frame_without_payload_decodes() {
    let empty = Frame {
        proto_version: PROTO_VERSION,
        payload: None,
    };
    assert_eq!(roundtrip(&empty), empty);
}

/// Нулевые значения enum-ов зафиксированы: на них держится правило
/// «zero неотличим от отсутствия поля».
#[test]
fn zero_values_are_unspecified() {
    assert_eq!(MessagePriority::Unspecified as i32, 0);
    assert_eq!(WakeHint::Unspecified as i32, 0);
    assert_eq!(RetentionMode::Unspecified as i32, 0);
    assert_eq!(SendRejectReason::Unspecified as i32, 0);
    assert_eq!(PushPlatform::Unspecified as i32, 0);
}
