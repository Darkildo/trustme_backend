//! Разбор payload'а первого сообщения хендшейка.
//!
//! Эти байты разбираются до того, как identity клиента доказана, — то есть
//! от кого угодно, кто дошёл до ноды по TCP и знает её статик. Единственная
//! защита здесь — корректность самого разборщика.

#![no_main]

use libfuzzer_sys::fuzz_target;
use trust_message_tcp::net::noise::decode_client_hello;

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = decode_client_hello(data) {
        // Разбор либо отказывает, либо выдаёт значения в домене: 32-байтовый
        // идентификатор и device_id, влезающий в 16 бит. Молчаливого
        // усечения быть не должно — оно означало бы адресацию чужого
        // устройства.
        assert_eq!(hello.identity_key.len(), 32);
        let _ = hello.device_id;
    }
});
