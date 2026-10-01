pub mod config;
pub mod delivery;
pub mod domain;
pub mod net;
pub mod observability;
pub mod push;
pub mod state;

/// Код, сгенерированный из `schemas/trustmessage/**.proto`. Дерево модулей
/// повторяет package схем, потому что на эту вложенность рассчитаны
/// кросс-пакетные пути в сгенерированном коде.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto_mod.rs"));
}

/// Короткие псевдонимы: wire-протокол клиент <-> нода и внутренний формат
/// конверта в брокере.
pub use proto::trustmessage::broker::v1 as broker;
pub use proto::trustmessage::push::v1 as push_gateway;
pub use proto::trustmessage::wire::v1 as wire;
