//! Протокол агента `tmnode` и админки, версия 1 (docs/agent-protocol.md).
//!
//! Агент всегда звонит сам — исходящими HTTPS-запросами: на сервере ноды
//! не открывается ни одного входящего порта ради управления. Типы общие
//! для обеих сторон: админка берёт их из этого крейта.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::node_config::Backend;

/// Префикс пути API агента на стороне админки.
pub const API_PREFIX: &str = "/api/v1/agent";

/// `POST /api/v1/agent/enroll` — одноразовый токен меняется на постоянный
/// токен агента и задание на установку.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrollRequest {
    /// Одноразовый токен из панели (`tme_…`).
    pub token: String,
    pub hostname: String,
    /// `x86_64` / `aarch64`.
    pub arch: String,
    pub tmnode_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrollResponse {
    pub agent_id: String,
    /// Постоянный токен агента (`tma_…`). Хранится только в
    /// `/etc/tmnode/agent.toml` с правами 0600.
    pub agent_token: String,
    pub node_id: String,
    pub node_name: String,
    pub install: InstallSpec,
    /// Желаемые настройки без перезапуска на момент подключения.
    pub runtime: Option<RuntimeDoc>,
}

/// Что поставить на сервер. Его же собирает `tmnode install` без админки.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstallSpec {
    /// Образ ноды, например `ghcr.io/darkildo/trustme_backend:v0.6.0`.
    pub image: String,
    /// Публичный адрес сервера (IP или имя), по которому к ноде ходят
    /// клиенты.
    pub public_host: String,
    /// Порт ноды на хосте и в контейнере.
    pub port: u16,
    pub backend: Backend,
    /// coturn рядом с нодой; `None` — TURN не ставится.
    pub coturn: Option<CoturnSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoturnSpec {
    pub image: String,
    /// `realm` coturn — обычно публичное имя сервера.
    pub realm: String,
    /// Общий секрет `static-auth-secret`. Тот же секрет админка кладёт в
    /// секцию `[ice]` `runtime.toml` ноды.
    pub secret: String,
    pub port: u16,
    pub relay_min_port: u16,
    pub relay_max_port: u16,
}

/// Содержимое `runtime.toml` и его метка версии.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeDoc {
    pub version: String,
    pub content: String,
}

/// `POST /api/v1/agent/heartbeat` (Bearer `tma_…`) раз в `interval_secs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Heartbeat {
    pub tmnode_version: String,
    /// Публичный ключ ноды (пин), если он уже известен.
    pub node_key: Option<String>,
    /// Отчёт `tmnode doctor` (`tmnode.report/1`).
    pub report: Option<Value>,
    /// Содержимое `runtime.status.json` ноды.
    pub runtime_status: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatResponse {
    /// Через сколько секунд следующий heartbeat.
    pub interval_secs: u64,
    /// Желаемый `runtime.toml`. Агент пишет его, если версия отличается от
    /// той, что лежит на диске.
    pub runtime: Option<RuntimeDoc>,
}

/// Пределы интервала heartbeat, которые агент принимает от админки.
pub const MIN_INTERVAL_SECS: u64 = 5;
pub const MAX_INTERVAL_SECS: u64 = 3600;
pub const DEFAULT_INTERVAL_SECS: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shape_is_stable() {
        let spec = InstallSpec {
            image: "ghcr.io/darkildo/trustme_backend:v0.6.0".into(),
            public_host: "203.0.113.10".into(),
            port: 18081,
            backend: Backend::Sled,
            coturn: Some(CoturnSpec {
                image: "coturn/coturn:4.6.3".into(),
                realm: "node.example.org".into(),
                secret: "s".repeat(32),
                port: 3478,
                relay_min_port: 49160,
                relay_max_port: 49200,
            }),
        };
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["backend"], "sled");
        assert_eq!(json["coturn"]["relay_min_port"], 49160);
        let back: InstallSpec = serde_json::from_value(json).unwrap();
        assert_eq!(back, spec);

        let hb: HeartbeatResponse =
            serde_json::from_str(r#"{"interval_secs":30,"runtime":null}"#).unwrap();
        assert!(hb.runtime.is_none());
    }
}
