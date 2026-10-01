//! Сертификат устройства: делегированный вход на ноду.
//!
//! # Зачем
//!
//! Identity клиента — статик Noise, выведенный из ключа аккаунта. Фоновому
//! процессу клиента (приём пушей, звонок с заблокированного экрана) сессия
//! нужна тогда, когда ключ аккаунта закрыт PIN'ом, и без делегирования ему
//! пришлось бы хранить сам ключ аккаунта вне PIN-защиты. Сертификат
//! разрывает эту связь: ключ аккаунта один раз, при разблокировке,
//! подписывает отдельную X25519-пару устройства, и дальше сессию держит
//! она. Утечка фонового хранилища отдаёт ключ, который протухает сам, ничего
//! не может подписать от имени аккаунта и ограничен в правах на ноде.
//!
//! # Ограничение: нет отзыва
//!
//! Нода не хранит состояния о сертификатах, поэтому единственный предел
//! украденному сертификату — `not_after`. Отсюда потолок срока жизни на
//! стороне ноды: клиент с ошибкой (или под принуждением) не выпишет
//! сертификат на десять лет.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::net::noise::is_small_order_x25519;
use crate::state::registry::{DeviceId, UserId};
use crate::wire;

/// Домен подписи сертификата устройства. Отделяет эти подписи от всего
/// остального, что подписывает ключ аккаунта на прикладном уровне.
pub const DEVICE_CERT_SIGNING_DOMAIN: &[u8] = b"trustmessage/device-cert/v1";

/// Допуск на расхождение часов клиента и ноды для `not_before`. Сертификат
/// выписывается «с этой секунды», и телефон, спешащий на минуту, иначе не
/// смог бы войти сразу после разблокировки. На `not_after` допуска нет:
/// истёкший сертификат — истёкший.
pub const NOT_BEFORE_SKEW_SECS: u64 = 300;

/// Права сессии на ноде.
///
/// Приём, `DeliveryAck`, `Ping` и `GetServerConfig` доступны любой сессии:
/// без них делегированная сессия бессмысленна, а вреда от них не больше,
/// чем от самого факта входа. Всё остальное — по битам сертификата.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionScope(u32);

impl SessionScope {
    const SEND: u32 = wire::DeviceCertScope::Send as u32;
    const PUSH_TOKENS: u32 = wire::DeviceCertScope::PushTokens as u32;
    const QUEUES: u32 = wire::DeviceCertScope::Queues as u32;

    /// Сессия, вошедшая ключом аккаунта: ограничивать нечем и незачем.
    pub const FULL: Self = Self(u32::MAX);

    /// Права из сертификата. Неизвестные биты сохраняются, но ничего не
    /// значат: биты только добавляют права, и бит из будущей схемы не может
    /// расширить то, что эта нода умеет проверять.
    pub fn from_cert_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub fn can_send(self) -> bool {
        self.0 & Self::SEND != 0
    }

    pub fn can_manage_push_tokens(self) -> bool {
        self.0 & Self::PUSH_TOKENS != 0
    }

    pub fn can_manage_queues(self) -> bool {
        self.0 & Self::QUEUES != 0
    }

    pub fn is_delegated(self) -> bool {
        self != Self::FULL
    }
}

/// Проверенный сертификат: что нода из него берёт.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedDeviceCert {
    pub transport_key: [u8; 32],
    pub scope: SessionScope,
    pub not_after: u64,
}

/// Байты под подписью. Фиксированные длины и порядок — канонизация: у
/// protobuf её нет, поэтому подписывать сериализованное сообщение нельзя.
pub fn signed_bytes(
    identity_key: &UserId,
    device_id: DeviceId,
    transport_key: &[u8; 32],
    signing_key: &[u8; 32],
    scope: u32,
    not_before: u64,
    not_after: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEVICE_CERT_SIGNING_DOMAIN.len() + 32 * 3 + 4 + 4 + 8 + 8);
    out.extend_from_slice(DEVICE_CERT_SIGNING_DOMAIN);
    out.extend_from_slice(identity_key);
    out.extend_from_slice(&u32::from(device_id).to_le_bytes());
    out.extend_from_slice(transport_key);
    out.extend_from_slice(signing_key);
    out.extend_from_slice(&scope.to_le_bytes());
    out.extend_from_slice(&not_before.to_le_bytes());
    out.extend_from_slice(&not_after.to_le_bytes());
    out
}

/// Проверить сертификат из `ClientHello`.
///
/// `max_ttl_secs == 0` — делегированный вход на этой ноде выключен.
/// Сверка `transport_key` со статиком соединения — забота вызывающего: эта
/// функция отвечает на вопрос «выписал ли аккаунт такой сертификат и
/// действует ли он», а не «тот ли ключ прошёл хендшейк».
pub fn verify(
    identity_key: &UserId,
    device_id: Option<DeviceId>,
    cert: &wire::DeviceCertificate,
    now_secs: u64,
    max_ttl_secs: u64,
) -> Result<VerifiedDeviceCert> {
    if max_ttl_secs == 0 {
        bail!("device certificates are disabled on this node");
    }
    // Сертификат выписан устройству, и сессия обязана быть сессией этого
    // устройства: `device_id` в hello — открытая заявка, подпись её
    // закрепляет.
    let device_id = device_id.context("device certificate requires a device id")?;
    if u32::from(device_id) != cert.device_id {
        bail!("device certificate was issued to another device");
    }

    let transport_key = fixed_32(&cert.transport_key, "device transport key")?;
    // Статик малого порядка даёт DH-выход, не зависящий от секрета, — с
    // ним хендшейк проходит любой, у кого есть сам сертификат, и
    // сертификат превращается в предъявительский токен.
    if is_small_order_x25519(&transport_key) {
        bail!("device transport key has small order");
    }
    let signing_key = fixed_32(&cert.signing_key, "device signing key")?;
    let signature: [u8; 64] = cert
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("device certificate signature must contain 64 bytes"))?;

    if cert.not_after <= cert.not_before {
        bail!("device certificate has an empty validity window");
    }
    if cert.not_after - cert.not_before > max_ttl_secs {
        bail!("device certificate lifetime exceeds the node ceiling");
    }
    if now_secs.saturating_add(NOT_BEFORE_SKEW_SECS) < cert.not_before {
        bail!("device certificate is not valid yet");
    }
    if now_secs >= cert.not_after {
        bail!("device certificate has expired");
    }

    let verifying = VerifyingKey::from_bytes(identity_key)
        .context("client identity key is not a valid ed25519 public key")?;
    // Для ключа малого порядка подпись подделывается без секрета (`R = rB`,
    // `s = r` проходит нестрогую проверку). `verify_strict` такие ключи и
    // сейчас отвергает, но отказ здесь не должен зависеть от выбора режима
    // проверки ниже.
    if verifying.is_weak() {
        bail!("client identity key has small order");
    }
    let message = signed_bytes(
        identity_key,
        device_id,
        &transport_key,
        &signing_key,
        cert.scope,
        cert.not_before,
        cert.not_after,
    );
    // `verify_strict`: без малого порядка и неканонических S — у подписи,
    // которая открывает сессию от чужого имени, не должно быть двойников.
    verifying
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| anyhow::anyhow!("device certificate signature is invalid"))?;

    Ok(VerifiedDeviceCert {
        transport_key,
        scope: SessionScope::from_cert_bits(cert.scope),
        not_after: cert.not_after,
    })
}

fn fixed_32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must contain 32 bytes (got {})", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_800_000_000;
    const MAX_TTL: u64 = 30 * 24 * 3600;
    const DEVICE: DeviceId = 7;

    fn account() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn issue(
        account: &SigningKey,
        device_id: DeviceId,
        scope: u32,
        not_before: u64,
        not_after: u64,
    ) -> wire::DeviceCertificate {
        let transport_key = [0x22; 32];
        let signing_key = [0x33; 32];
        let message = signed_bytes(
            &account.verifying_key().to_bytes(),
            device_id,
            &transport_key,
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

    fn check(
        cert: &wire::DeviceCertificate,
        device_id: Option<DeviceId>,
    ) -> Result<VerifiedDeviceCert> {
        verify(
            &account().verifying_key().to_bytes(),
            device_id,
            cert,
            NOW,
            MAX_TTL,
        )
    }

    #[test]
    fn valid_certificate_yields_its_scope() {
        let cert = issue(&account(), DEVICE, 1, NOW - 10, NOW + 14 * 24 * 3600);
        let verified = check(&cert, Some(DEVICE)).expect("valid certificate");
        assert_eq!(verified.transport_key, [0x22; 32]);
        assert!(verified.scope.can_send());
        assert!(!verified.scope.can_manage_push_tokens());
        assert!(!verified.scope.can_manage_queues());
        assert!(verified.scope.is_delegated());
    }

    #[test]
    fn full_scope_allows_everything() {
        assert!(SessionScope::FULL.can_send());
        assert!(SessionScope::FULL.can_manage_push_tokens());
        assert!(SessionScope::FULL.can_manage_queues());
        assert!(!SessionScope::FULL.is_delegated());
    }

    #[test]
    fn unknown_scope_bits_grant_nothing() {
        let cert = issue(&account(), DEVICE, 1 << 20, NOW - 10, NOW + 3600);
        let verified = check(&cert, Some(DEVICE)).expect("valid certificate");
        assert!(!verified.scope.can_send());
        assert!(!verified.scope.can_manage_push_tokens());
        assert!(!verified.scope.can_manage_queues());
    }

    #[test]
    fn certificate_is_bound_to_the_device() {
        let cert = issue(&account(), DEVICE, 1, NOW - 10, NOW + 3600);
        assert!(check(&cert, Some(DEVICE + 1)).is_err());
        assert!(check(&cert, None).is_err());
    }

    #[test]
    fn certificate_is_bound_to_the_account() {
        let stranger = SigningKey::from_bytes(&[0x44; 32]);
        let cert = issue(&stranger, DEVICE, 1, NOW - 10, NOW + 3600);
        assert!(check(&cert, Some(DEVICE)).is_err());
    }

    #[test]
    fn every_signed_field_is_covered() {
        let base = issue(&account(), DEVICE, 1, NOW - 10, NOW + 3600);
        type Mutation = Box<dyn Fn(&mut wire::DeviceCertificate)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|c| c.transport_key[0] ^= 1),
            Box::new(|c| c.signing_key[0] ^= 1),
            Box::new(|c| c.scope |= 2),
            Box::new(|c| c.not_before -= 1),
            Box::new(|c| c.not_after += 1),
            Box::new(|c| c.device_id += 1),
        ];
        for mutate in mutations {
            let mut cert = base.clone();
            mutate(&mut cert);
            assert!(check(&cert, Some(DEVICE)).is_err());
        }
    }

    #[test]
    fn validity_window_is_enforced() {
        let expired = issue(&account(), DEVICE, 1, NOW - 7200, NOW);
        assert!(check(&expired, Some(DEVICE)).is_err());

        let future = issue(
            &account(),
            DEVICE,
            1,
            NOW + NOT_BEFORE_SKEW_SECS + 1,
            NOW + 7200,
        );
        assert!(check(&future, Some(DEVICE)).is_err());

        let skewed = issue(
            &account(),
            DEVICE,
            1,
            NOW + NOT_BEFORE_SKEW_SECS,
            NOW + 7200,
        );
        assert!(check(&skewed, Some(DEVICE)).is_ok());

        let empty = issue(&account(), DEVICE, 1, NOW, NOW);
        assert!(check(&empty, Some(DEVICE)).is_err());
    }

    #[test]
    fn lifetime_ceiling_is_enforced() {
        let long = issue(&account(), DEVICE, 1, NOW - 10, NOW - 10 + MAX_TTL + 1);
        assert!(check(&long, Some(DEVICE)).is_err());
        let exact = issue(&account(), DEVICE, 1, NOW - 10, NOW - 10 + MAX_TTL);
        assert!(check(&exact, Some(DEVICE)).is_ok());
    }

    #[test]
    fn disabled_node_rejects_any_certificate() {
        let cert = issue(&account(), DEVICE, 1, NOW - 10, NOW + 3600);
        let result = verify(
            &account().verifying_key().to_bytes(),
            Some(DEVICE),
            &cert,
            NOW,
            0,
        );
        assert!(result.is_err());
    }

    /// Сертификат на транспортный ключ малого порядка подписан честно, но
    /// ничего не аутентифицирует: DH с таким статиком не зависит от секрета,
    /// и войти по нему смог бы любой, кто видел сертификат.
    #[test]
    fn small_order_transport_key_is_rejected() {
        let account = account();
        for transport_key in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            let signing_key = [0x33; 32];
            let message = signed_bytes(
                &account.verifying_key().to_bytes(),
                DEVICE,
                &transport_key,
                &signing_key,
                1,
                NOW - 10,
                NOW + 3600,
            );
            let cert = wire::DeviceCertificate {
                transport_key: transport_key.to_vec(),
                signing_key: signing_key.to_vec(),
                scope: 1,
                not_before: NOW - 10,
                not_after: NOW + 3600,
                signature: account.sign(&message).to_bytes().to_vec(),
                device_id: u32::from(DEVICE),
            };
            let err = check(&cert, Some(DEVICE)).expect_err("small-order transport key");
            assert!(
                err.to_string().contains("small order"),
                "unexpected error: {err}"
            );
        }
    }

    /// Для ключа аккаунта малого порядка подпись подделывается без секрета:
    /// `R = rB, s = r` проходит нестрогую проверку. Такой «аккаунт» не
    /// должен выписывать сертификаты вне зависимости от режима проверки.
    #[test]
    fn weak_account_key_cannot_issue_certificates() {
        use curve25519_dalek::{EdwardsPoint, Scalar};
        use ed25519_dalek::Verifier;

        let mut weak_identity = [0u8; 32];
        weak_identity[0] = 1; // нейтральный элемент Ed25519
        let transport_key = [0x22; 32];
        let signing_key = [0x33; 32];
        let message = signed_bytes(
            &weak_identity,
            DEVICE,
            &transport_key,
            &signing_key,
            1,
            NOW - 10,
            NOW + 3600,
        );

        let r = Scalar::from(12_345u32);
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&EdwardsPoint::mul_base(&r).compress().to_bytes());
        forged[32..].copy_from_slice(r.as_bytes());

        // Подделка настоящая: нестрогая проверка её принимает.
        let verifying = VerifyingKey::from_bytes(&weak_identity).unwrap();
        assert!(
            verifying
                .verify(&message, &Signature::from_bytes(&forged))
                .is_ok()
        );

        let cert = wire::DeviceCertificate {
            transport_key: transport_key.to_vec(),
            signing_key: signing_key.to_vec(),
            scope: 1,
            not_before: NOW - 10,
            not_after: NOW + 3600,
            signature: forged.to_vec(),
            device_id: u32::from(DEVICE),
        };
        let err = verify(&weak_identity, Some(DEVICE), &cert, NOW, MAX_TTL)
            .expect_err("weak account key must not issue certificates");
        assert!(
            err.to_string().contains("small order"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_lengths_are_rejected() {
        let mut cert = issue(&account(), DEVICE, 1, NOW - 10, NOW + 3600);
        cert.signature.pop();
        assert!(check(&cert, Some(DEVICE)).is_err());
        let mut cert = issue(&account(), DEVICE, 1, NOW - 10, NOW + 3600);
        cert.transport_key.push(0);
        assert!(check(&cert, Some(DEVICE)).is_err());
    }

    /// Общий тестовый вектор ноды и клиентской реализации
    /// (`trust_utils::transport::device_cert`): одни и те же поля обязаны
    /// давать одну и ту же подпись. Разойдётся формат — клиент перестанет
    /// входить на ноду, и по симптомам это не отлаживается.
    #[test]
    fn cross_repo_signature_vector() {
        let account = SigningKey::from_bytes(&[0x11; 32]);
        let message = signed_bytes(
            &account.verifying_key().to_bytes(),
            7,
            &[0x22; 32],
            &[0x33; 32],
            9,
            1_800_000_000,
            1_801_209_600,
        );
        let expected: [u8; 64] = [
            131, 23, 78, 90, 46, 11, 147, 150, 148, 74, 30, 72, 238, 181, 237, 230, 10, 52, 165,
            101, 188, 255, 247, 185, 109, 125, 174, 190, 134, 233, 216, 64, 16, 64, 196, 71, 21,
            165, 121, 43, 159, 176, 186, 43, 82, 53, 11, 227, 125, 47, 74, 133, 168, 150, 140, 250,
            67, 75, 239, 226, 126, 230, 216, 5,
        ];
        assert_eq!(account.sign(&message).to_bytes(), expected);
    }
}
