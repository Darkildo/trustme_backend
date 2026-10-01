//! Проверка подписанного снапшота конфигурации.
//!
//! Путь целиком состоит из разбора недоверенных байт: длина ключа, длина
//! подписи, вложенное protobuf-сообщение. Он же — эталон, который повторяют
//! клиентские реализации, поэтому паника здесь означала бы падение и у них.

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use trust_message_tcp::net::framing::verify_signed_server_config;
use trust_message_tcp::wire::SignedServerConfig;

fuzz_target!(|data: &[u8]| {
    let Ok(signed) = SignedServerConfig::decode(data) else {
        return;
    };

    // Пин фиксирован: интересен разбор, а не подбор подписи — её фаззер не
    // найдёт, и проверка обязана отказать, не паникуя.
    let pinned = [7u8; 32];
    let result = verify_signed_server_config(&signed, &pinned, 1_700_000_000);
    assert!(
        result.is_err(),
        "случайные байты не могут пройти проверку подписи"
    );
});
