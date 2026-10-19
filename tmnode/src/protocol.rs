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
    /// Образ, на котором сейчас запущен контейнер ноды
    /// (`ghcr.io/darkildo/trustme_backend:v0.7.0`). Нет у агентов до 0.3.0.
    #[serde(default)]
    pub node_image: Option<String>,
    /// Ход последнего задания на обновление. Агент присылает его, пока
    /// админка не перестанет присылать это задание. Нет у агентов до 0.3.0.
    #[serde(default)]
    pub update: Option<UpdateStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatResponse {
    /// Через сколько секунд следующий heartbeat.
    pub interval_secs: u64,
    /// Желаемый `runtime.toml`. Агент пишет его, если версия отличается от
    /// той, что лежит на диске.
    pub runtime: Option<RuntimeDoc>,
    /// Задание на обновление. Админка присылает его в каждом ответе, пока
    /// агент не сообщит итог (`UpdateStatus::state` — не `running`).
    #[serde(default)]
    pub update: Option<UpdateOrder>,
}

/// Обновить ноду и/или сам `tmnode` до версий из релиза бэкенда.
///
/// Админка называет только версии. Откуда качать, агент решает сам: образ —
/// из своего репозитория образов, бинарь — из GitHub Releases своего
/// репозитория (docs/agent-protocol.md, «Обновление»). Поэтому даже
/// захваченная админка не подсунет ни чужой образ, ни чужой бинарь —
/// только другой выпущенный релиз.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateOrder {
    /// ULID задания. По нему агент узнаёт задание, которое уже выполнил.
    pub id: String,
    /// Версия ноды `X.Y.Z`: образ `<репозиторий>:vX.Y.Z`. `None` — контейнер
    /// ноды не трогать.
    pub node_version: Option<String>,
    /// Новый `tmnode`. `None` — не трогать.
    pub tmnode: Option<TmnodeRelease>,
    /// Разрешить версию ниже текущей. Откат данных не гарантирован: новая
    /// версия могла уже изменить их формат.
    #[serde(default)]
    pub allow_downgrade: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TmnodeRelease {
    /// `X.Y.Z` — версия, которую печатает `tmnode version` нового бинаря.
    pub version: String,
    /// SHA-256 бинаря `tmnode-<arch>-linux` для архитектуры агента (hex,
    /// строчные). Должна совпасть и с файлом, и с `SHA256SUMS` релиза.
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateStatus {
    /// `UpdateOrder::id`.
    pub id: String,
    pub state: UpdateState,
    /// Шаг, на котором агент сейчас или на котором остановился.
    pub step: Option<UpdateStep>,
    /// Причина для человека, если `failed`, `rolled_back` или `refused`.
    pub error: Option<String>,
    /// Unix-время, секунды.
    pub started_at: u64,
    pub finished_at: Option<u64>,
    /// Что стояло до обновления и что стоит после (или вернулось после
    /// отката): образ ноды и версия `tmnode`.
    pub from_node_image: Option<String>,
    pub node_image: Option<String>,
    pub from_tmnode: Option<String>,
    pub tmnode: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    /// Выполняется. Агент присылает этот статус до долгих шагов.
    Running,
    /// Всё, что просили, стоит и проверено.
    Succeeded,
    /// Не удалось, но работает прежняя версия: откатываться было не нужно
    /// (упало до замены) или не получилось — см. `error`.
    Failed,
    /// Новая версия не прошла проверку, агент вернул прежнюю.
    RolledBack,
    /// Агент отказался: нода не под управлением админки, версия не
    /// совпадает с закреплённой в `node.toml`, понижение без
    /// `allow_downgrade`, неверная версия или контрольная сумма.
    Refused,
}

impl UpdateState {
    /// Итог: админка перестаёт присылать задание.
    pub fn is_final(self) -> bool {
        self != Self::Running
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStep {
    /// Проверка задания по `node.toml` и текущим версиям.
    Check,
    /// Скачивание и проверка нового `tmnode`.
    DownloadTmnode,
    /// Замена бинаря и перезапуск службы агента.
    RestartAgent,
    /// `docker pull` нового образа ноды.
    PullImage,
    /// Остановка прежнего контейнера и запуск нового с теми же томами,
    /// портами и окружением.
    Recreate,
    /// Проверка новой ноды: работает, ключ прежний, рукопожатие и
    /// подписанный конфиг проходят.
    Verify,
    /// Возврат прежнего контейнера.
    Rollback,
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
        assert!(hb.update.is_none());
    }

    /// Старый агент и старая админка понимают новые сообщения: новые поля
    /// необязательны, лишние — пропускаются.
    #[test]
    fn update_fields_are_additive() {
        let old_beat: Heartbeat = serde_json::from_str(
            r#"{"tmnode_version":"0.2.0","node_key":null,"report":null,"runtime_status":null}"#,
        )
        .unwrap();
        assert!(old_beat.update.is_none() && old_beat.node_image.is_none());

        let order = UpdateOrder {
            id: "01jb0000000000000000000000".into(),
            node_version: Some("0.7.0".into()),
            tmnode: Some(TmnodeRelease {
                version: "0.3.0".into(),
                sha256: "ab".repeat(32),
            }),
            allow_downgrade: false,
        };
        let json = serde_json::to_value(HeartbeatResponse {
            interval_secs: 30,
            runtime: None,
            update: Some(order.clone()),
        })
        .unwrap();
        assert_eq!(json["update"]["node_version"], "0.7.0");
        assert_eq!(json["update"]["tmnode"]["sha256"], "ab".repeat(32));
        let back: HeartbeatResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.update, Some(order));

        let status = UpdateStatus {
            id: "01jb0000000000000000000000".into(),
            state: UpdateState::RolledBack,
            step: Some(UpdateStep::Verify),
            error: Some("рукопожатие не прошло".into()),
            started_at: 1,
            finished_at: Some(2),
            from_node_image: Some("ghcr.io/darkildo/trustme_backend:v0.6.0".into()),
            node_image: Some("ghcr.io/darkildo/trustme_backend:v0.6.0".into()),
            from_tmnode: Some("0.3.0".into()),
            tmnode: Some("0.3.0".into()),
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["state"], "rolled_back");
        assert_eq!(json["step"], "verify");
        assert!(UpdateState::RolledBack.is_final() && !UpdateState::Running.is_final());
    }
}
