//! Разбор payload'а первого сообщения хендшейка и проверка сертификата
//! устройства из него.
//!
//! Эти байты разбираются до того, как identity клиента доказана, — то есть
//! от кого угодно, кто дошёл до ноды по TCP и знает её статик. Сертификат
//! устройства проверяется на том же шаге, тоже до доказательства identity.
//! Единственная защита здесь — корректность самого разбора и проверки.

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use trust_message_tcp::net::device_cert::{self, NOT_BEFORE_SKEW_SECS, SessionScope};
use trust_message_tcp::net::noise::decode_client_hello;
use trust_message_tcp::wire::{DeviceCertificate, NoiseClientHello};

/// Момент «сейчас» внутри окна сертификата из сида `with_device_cert.bin`
/// (examples/gen_fuzz_seeds.rs): сид проходит проверку целиком, и мутации
/// стартуют от успешного пути, а не только от отказов.
const NOW: u64 = 1_700_000_000 + 3_600;
/// Потолок срока жизни сертификата — как у ноды по умолчанию, 30 суток.
const MAX_TTL: u64 = 30 * 24 * 3600;

fuzz_target!(|data: &[u8]| {
    let Ok(hello) = decode_client_hello(data) else {
        return;
    };

    // Разбор принял те же байты, что и protobuf, и не исказил их по
    // дороге: identity — ровно присланные 32 байта, device_id — то же
    // число. Молчаливое усечение device_id означало бы адресацию чужого
    // устройства.
    let raw = NoiseClientHello::decode(data).expect("decode_client_hello принял не-protobuf");
    assert_eq!(&hello.identity_key[..], &raw.identity_key[..]);
    assert_eq!(hello.device_id.map(u32::from), raw.device_id);

    let Some(cert) = &hello.device_cert else {
        return;
    };

    // Делегированный вход выключен — никакой сертификат не проходит.
    assert!(device_cert::verify(&hello.identity_key, hello.device_id, cert, NOW, 0).is_err());

    // Фиксированное «сейчас» — как у живой ноды. Второй вызов берёт
    // «сейчас» из самого сертификата: тогда проверки окна чаще проходят, и
    // мутированные ключи и подписи доходят до криптографии.
    for now in [NOW, cert.not_before] {
        if let Ok(verified) =
            device_cert::verify(&hello.identity_key, hello.device_id, cert, now, MAX_TTL)
        {
            assert_accepted_cert_is_sound(&hello.device_id, cert, &verified, now);
        }
    }
});

/// Принятый сертификат обязан удовлетворять всему, что нода из него
/// выводит: он выписан этому устройству, действует сейчас, не длиннее
/// потолка, и наружу отдаются ровно его поля.
fn assert_accepted_cert_is_sound(
    device_id: &Option<u16>,
    cert: &DeviceCertificate,
    verified: &device_cert::VerifiedDeviceCert,
    now: u64,
) {
    assert_eq!(device_id.map(u32::from), Some(cert.device_id));
    assert!(cert.not_before < cert.not_after);
    assert!(cert.not_after - cert.not_before <= MAX_TTL);
    assert!(now < cert.not_after);
    assert!(now.saturating_add(NOT_BEFORE_SKEW_SECS) >= cert.not_before);
    assert_eq!(&verified.transport_key[..], &cert.transport_key[..]);
    assert_eq!(cert.signing_key.len(), 32);
    assert_eq!(cert.signature.len(), 64);
    assert_eq!(verified.not_after, cert.not_after);
    assert_eq!(verified.scope, SessionScope::from_cert_bits(cert.scope));
}
