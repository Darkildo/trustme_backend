//! Кодогенерация схем.
//!
//! Схемы компилирует `protox` — это чистый Rust, поэтому системный
//! `protoc` не нужен ни в образе, ни в CI, ни на машине разработчика.
//! `buf` остаётся инструментом линта/breaking-проверки в CI и зависимостью
//! сборки не является.

const PROTO_FILES: [&str; 3] = [
    "schemas/trustmessage/wire/v1/wire.proto",
    "schemas/trustmessage/broker/v1/broker.proto",
    "schemas/trustmessage/push/v1/push.proto",
];

fn main() {
    for proto in PROTO_FILES {
        println!("cargo:rerun-if-changed={proto}");
    }
    let descriptors = protox::compile(PROTO_FILES, ["schemas"]).expect("proto schema compile");
    let mut config = prost_build::Config::new();
    // Один включаемый файл с деревом модулей: prost генерирует
    // кросс-пакетные пути (broker -> wire) в расчёте на вложенность
    // `trustmessage::wire::v1`, и собирать её вручную незачем.
    config.include_file("proto_mod.rs");
    // Через tonic, а не через голый prost: в push-схеме есть service, и его
    // клиент нужен ноде, когда пуши уходят во внешний шлюз. Сервер не
    // генерируем — его реализует сам шлюз, отдельный сервис вне этого
    // репозитория.
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_fds_with_config(descriptors, config)
        .expect("proto codegen failed");
}
