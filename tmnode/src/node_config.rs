//! `node.toml` — описание ноды для `tmnode` (схема 1, docs/tmnode.md).
//!
//! Файл описывает, какой должна быть нода: где она отвечает, под каким
//! ключом, на каком бэкенде, кто ею управляет и как обновляется. Один и тот
//! же файл пишет мастер установки у новичка и присылает admin-сервис для
//! парка нод, поэтому схема строгая: опечатка в ключе — ошибка, а не молча
//! проигнорированная настройка.
//!
//! Секретов в файле нет: ключ ноды здесь только публичный (пин), секрет
//! остаётся в `STORAGE_PATH/node_identity_key` или `NODE_IDENTITY_KEY`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Версия схемы, которую понимает этот `tmnode`.
pub const SCHEMA_VERSION: u32 = 1;

/// Путь по умолчанию: его `tmnode doctor` читает без `--config`.
pub const DEFAULT_PATH: &str = "/etc/tmnode/node.toml";

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Версия схемы файла. Файл новее `tmnode` не читается: поля, которых
    /// он не знает, могли бы менять смысл известных.
    pub schema: u32,
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub management: Management,
    /// Где нода отвечает клиентам. Без него проверка снаружи берёт
    /// опубликованный порт контейнера и ключ, выведенный из секрета.
    pub endpoint: Option<Endpoint>,
    #[serde(default)]
    pub runtime: Runtime,
    /// Ожидаемый бэкенд доставки; расхождение с тем, на чём нода реально
    /// запущена, — предупреждение.
    pub delivery: Option<Delivery>,
    #[serde(default)]
    pub updates: Updates,
}

/// Метаданные ноды. `id`, `org` и метки заполняет admin-сервис при
/// подключении ноды к парку; локальной установке они не нужны.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Человекочитаемое имя, до 64 символов.
    pub name: Option<String>,
    /// Устойчивый идентификатор ноды в парке: `[a-z0-9-]`, до 64 символов.
    pub id: Option<String>,
    /// Организация в admin-сервисе, тот же формат, что у `id`.
    pub org: Option<String>,
    /// Метки для группировки нод: ключ `[a-z0-9_.-]`, до 63 символов.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Management {
    #[serde(default)]
    pub mode: ManagementMode,
}

/// Кто источник правды для этой ноды. Пока нода `managed`, локальный
/// `tmnode` не меняет её настройки, а только сообщает о расхождениях —
/// иначе два источника правды затирали бы друг друга.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ManagementMode {
    #[default]
    Local,
    Managed,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// `host:port`, по которому к ноде подключаются клиенты.
    pub addr: String,
    /// Публичный X25519-статик ноды (`node_key=` в логе), 64 hex.
    pub node_key: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    #[serde(default)]
    pub kind: RuntimeKind,
    /// Имя контейнера ноды.
    #[serde(default = "default_container")]
    pub container: String,
    /// Каталог данных ноды на хосте. По умолчанию выводится из точек
    /// монтирования контейнера.
    pub data_dir: Option<PathBuf>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            kind: RuntimeKind::default(),
            container: default_container(),
            data_dir: None,
        }
    }
}

fn default_container() -> String {
    "message-service".to_owned()
}

/// Как запущена нода. В схеме 1 — только Docker; `systemd` и Kubernetes
/// займут здесь свои значения, не меняя остальных полей.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeKind {
    #[default]
    Docker,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub backend: Backend,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Sled,
    Jetstream,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sled => "sled",
            Self::Jetstream => "jetstream",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    #[serde(default)]
    pub channel: Channel,
    /// Закреплённая версия `X.Y.Z`; обязательна при `channel = "pinned"`.
    pub version: Option<String>,
}

/// Откуда брать обновления: `stable` следует за одноимённым тегом,
/// `pinned` держит версию, пока её не сменят явно (так компании выкатывают
/// обновления по частям парка).
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    #[default]
    Stable,
    Pinned,
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("не удалось прочитать {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("{} не прошёл проверку", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        // Версию схемы смотрим раньше строгого разбора: файл из будущей
        // схемы иначе упал бы на незнакомом поле, и человек не понял бы,
        // что обновить нужно сам tmnode.
        let probe: toml::Table = toml::from_str(text).context("файл — не TOML")?;
        match probe.get("schema") {
            None => bail!("нет поля `schema`"),
            Some(toml::Value::Integer(v)) if *v > i64::from(SCHEMA_VERSION) => bail!(
                "схема {v} новее, чем понимает этот tmnode ({SCHEMA_VERSION}); обновите tmnode"
            ),
            Some(_) => {}
        }
        let config: Self = toml::from_str(text).context("неверная структура")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA_VERSION {
            bail!(
                "schema = {}: поддерживается только {SCHEMA_VERSION}",
                self.schema
            );
        }
        if let Some(name) = &self.node.name
            && (name.trim().is_empty() || name.chars().count() > 64)
        {
            bail!("node.name: от 1 до 64 символов");
        }
        for (field, value) in [("node.id", &self.node.id), ("node.org", &self.node.org)] {
            if let Some(value) = value
                && !is_slug(value, 64, |c| c == '-')
            {
                bail!("{field}: только a-z, 0-9 и `-`, до 64 символов");
            }
        }
        for (key, value) in &self.node.labels {
            if !is_slug(key, 63, |c| matches!(c, '-' | '_' | '.')) {
                bail!("node.labels: ключ `{key}` — только a-z, 0-9, `-`, `_`, `.`, до 63 символов");
            }
            if value.chars().count() > 256 {
                bail!("node.labels.{key}: значение длиннее 256 символов");
            }
        }
        if let Some(endpoint) = &self.endpoint {
            check_addr(&endpoint.addr).context("endpoint.addr")?;
            parse_node_key(&endpoint.node_key).context("endpoint.node_key")?;
        }
        if self.runtime.container.trim().is_empty() {
            bail!("runtime.container пуст");
        }
        match (self.updates.channel, &self.updates.version) {
            (Channel::Pinned, None) => bail!("updates.version обязателен при channel = \"pinned\""),
            (Channel::Stable, Some(_)) => {
                bail!("updates.version задаётся только при channel = \"pinned\"")
            }
            (Channel::Pinned, Some(version)) if !is_version(version) => {
                bail!("updates.version: ожидается X.Y.Z, получено `{version}`")
            }
            _ => {}
        }
        Ok(())
    }

    /// Пин из `endpoint`, если он задан. Валидность проверена при разборе.
    pub fn endpoint_key(&self) -> Option<[u8; 32]> {
        self.endpoint
            .as_ref()
            .and_then(|e| parse_node_key(&e.node_key).ok())
    }
}

/// Пин ноды: 32 байта в hex.
pub fn parse_node_key(raw: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).context("ожидается 64 hex-символа")?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("ожидается 32 байта, получено {}", b.len()))
}

/// `host:port` с непустым хостом и ненулевым портом. Имя не резолвится:
/// проверка формы, а не доступности.
pub fn check_addr(addr: &str) -> Result<()> {
    let (host, port) = addr.rsplit_once(':').context("ожидается host:port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        bail!("пустой хост в `{addr}`");
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => bail!("порт в `{addr}` — не число от 1 до 65535"),
        Ok(_) => Ok(()),
    }
}

fn is_slug(value: &str, max: usize, extra: impl Fn(char) -> bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra(c))
}

fn is_version(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "005bdc6b8a958d7f7d8504dac2e7ff5ab506b491d9259432b303a0ca9ae9ed79";

    #[test]
    fn minimal_file_takes_defaults() {
        let cfg = NodeConfig::parse("schema = 1\n").unwrap();
        assert_eq!(cfg.management.mode, ManagementMode::Local);
        assert_eq!(cfg.runtime.kind, RuntimeKind::Docker);
        assert_eq!(cfg.runtime.container, "message-service");
        assert_eq!(cfg.updates.channel, Channel::Stable);
        assert!(cfg.endpoint.is_none());
        assert!(cfg.endpoint_key().is_none());
    }

    #[test]
    fn full_file_parses() {
        let cfg = NodeConfig::parse(&format!(
            r#"
schema = 1

[node]
name = "Семейная нода"
id = "node-01"
org = "acme"
labels = {{ team = "sales", "region.eu" = "1" }}

[management]
mode = "managed"

[endpoint]
addr = "203.0.113.10:18081"
node_key = "{KEY}"

[runtime]
kind = "docker"
container = "tm-node"
data_dir = "/srv/tm"

[delivery]
backend = "jetstream"

[updates]
channel = "pinned"
version = "0.5.0"
"#
        ))
        .unwrap();
        assert_eq!(cfg.management.mode, ManagementMode::Managed);
        assert_eq!(cfg.node.labels["team"], "sales");
        assert_eq!(cfg.runtime.data_dir.as_deref(), Some(Path::new("/srv/tm")));
        assert_eq!(cfg.delivery.as_ref().unwrap().backend, Backend::Jetstream);
        assert_eq!(cfg.endpoint_key().unwrap()[0], 0x00);
        assert_eq!(cfg.endpoint_key().unwrap()[1], 0x5b);
    }

    fn rejects(text: &str, needle: &str) {
        let err = NodeConfig::parse(text).expect_err(text);
        let msg = format!("{err:#}");
        assert!(msg.contains(needle), "`{msg}` не содержит `{needle}`");
    }

    #[test]
    fn invalid_files_are_rejected_with_a_reason() {
        rejects("", "schema");
        rejects("schema = 2\n", "обновите tmnode");
        rejects("schema = 0\n", "поддерживается только 1");
        rejects("schema = 1\nfoo = 1\n", "неверная структура");
        rejects(
            "schema = 1\n[runtime]\nimage = \"x\"\n",
            "неверная структура",
        );
        rejects("schema = 1\n[node]\nname = \"  \"\n", "node.name");
        rejects("schema = 1\n[node]\nid = \"Node_1\"\n", "node.id");
        rejects("schema = 1\n[node]\norg = \"\"\n", "node.org");
        rejects(
            "schema = 1\n[node.labels]\n\"Team\" = \"x\"\n",
            "node.labels",
        );
        rejects(
            &format!(
                "schema = 1\n[node.labels]\nteam = \"{}\"\n",
                "x".repeat(257)
            ),
            "длиннее 256",
        );
        rejects(
            "schema = 1\n[endpoint]\naddr = \"host\"\nnode_key = \"00\"\n",
            "endpoint.addr",
        );
        rejects(
            "schema = 1\n[endpoint]\naddr = \"host:1\"\nnode_key = \"00\"\n",
            "endpoint.node_key",
        );
        rejects(
            "schema = 1\n[runtime]\ncontainer = \" \"\n",
            "runtime.container",
        );
        rejects(
            "schema = 1\n[runtime]\nkind = \"podman\"\n",
            "неверная структура",
        );
        rejects(
            "schema = 1\n[updates]\nchannel = \"pinned\"\n",
            "обязателен",
        );
        rejects(
            "schema = 1\n[updates]\nversion = \"0.5.0\"\n",
            "только при channel",
        );
        rejects(
            "schema = 1\n[updates]\nchannel = \"pinned\"\nversion = \"0.5\"\n",
            "X.Y.Z",
        );
        rejects("schema = [", "не TOML");
    }

    #[test]
    fn addresses_are_checked_by_form() {
        assert!(check_addr("203.0.113.10:18081").is_ok());
        assert!(check_addr("node.example.org:1").is_ok());
        assert!(check_addr("[2001:db8::1]:18081").is_ok());
        assert!(check_addr(":18081").is_err());
        assert!(check_addr("host:0").is_err());
        assert!(check_addr("host:99999").is_err());
    }

    #[test]
    fn load_reports_the_path() {
        let err = NodeConfig::load(Path::new("/nonexistent/tmnode/node.toml")).unwrap_err();
        assert!(format!("{err:#}").contains("/nonexistent/tmnode/node.toml"));
    }
}
