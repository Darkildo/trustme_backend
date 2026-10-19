//! Каталог настраиваемых лимитов ноды — общий контракт ноды, `tmnode` и
//! админки (docs/runtime-config.md).
//!
//! Каждая настройка — число. Её имя — имя переменной окружения в нижнем
//! регистре: одно и то же имя в `.env`, в файле `runtime.toml` и в панели.
//! Здесь же её единица, пределы, значение по умолчанию и то, когда она
//! вступает в силу без перезапуска.

use std::time::Duration;

use serde::Serialize;

use crate::config::{BlobConfig, Config, LimitsConfig};

/// Когда изменение настройки начинает действовать.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Сразу: следующая операция видит новое значение.
    Hot,
    /// Для новых соединений и сессий; живые работают со старым до
    /// переподключения.
    NewSessions,
    /// После перезапуска ноды: значение входит в постоянные индексы или в
    /// протокол, который клиенты кэшируют.
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Отправка и квоты очередей.
    Messages,
    /// Сессии и управляющие кадры.
    Sessions,
    /// Вход и TCP.
    Network,
    /// Хранилище файлов.
    Blobs,
    /// Сертификаты и подписанный конфиг.
    Security,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Count,
    PerSecond,
    Bytes,
    BytesPerDay,
    Seconds,
}

/// Значения, которые настраиваются каталогом. Отдельно от [`Config`]: у
/// конфига нет значения по умолчанию целиком (адрес, путь, бэкенд), а у
/// лимитов есть.
#[derive(Clone, Debug)]
pub struct Tunables {
    pub limits: LimitsConfig,
    pub blobs: BlobConfig,
    pub device_cert_max_ttl_secs: u64,
    pub server_config_ttl_secs: u64,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            limits: LimitsConfig::default(),
            blobs: BlobConfig::default(),
            device_cert_max_ttl_secs: 30 * 24 * 3600,
            server_config_ttl_secs: 24 * 3600,
        }
    }
}

impl Tunables {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            limits: cfg.limits,
            blobs: cfg.blobs.clone(),
            device_cert_max_ttl_secs: cfg.device_cert_max_ttl.as_secs(),
            server_config_ttl_secs: cfg.server_config_ttl.as_secs(),
        }
    }

    pub fn apply_to(&self, cfg: &mut Config) {
        cfg.limits = self.limits;
        cfg.blobs = self.blobs.clone();
        cfg.device_cert_max_ttl = Duration::from_secs(self.device_cert_max_ttl_secs);
        cfg.server_config_ttl = Duration::from_secs(self.server_config_ttl_secs);
    }
}

pub struct Setting {
    /// Имя: переменная окружения в нижнем регистре.
    pub key: &'static str,
    pub group: Group,
    pub unit: Unit,
    pub scope: Scope,
    pub min: u64,
    pub max: u64,
    /// `0` значит «без ограничения».
    pub zero_unlimited: bool,
    /// Одна строка для панели.
    pub summary: &'static str,
    pub get: fn(&Tunables) -> u64,
    pub set: fn(&mut Tunables, u64),
}

impl Setting {
    pub fn env(&self) -> String {
        self.key.to_ascii_uppercase()
    }

    pub fn default_value(&self) -> u64 {
        (self.get)(&Tunables::default())
    }

    /// Проверить значение по пределам каталога.
    pub fn check(&self, value: u64) -> Result<(), String> {
        if value == 0 && self.zero_unlimited {
            return Ok(());
        }
        if value < self.min || value > self.max {
            let zero = if self.zero_unlimited {
                " (или 0 — без ограничения)"
            } else {
                ""
            };
            return Err(format!(
                "{}: от {} до {}{zero}, получено {value}",
                self.key, self.min, self.max
            ));
        }
        Ok(())
    }
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;
const TIB: u64 = 1024 * GIB;
const DAY: u64 = 86_400;
/// Потолок счётчиков — с запасом, но так, чтобы значение влезало в
/// `usize` и `u32` там, где поле такого типа.
const COUNT_MAX: u64 = 1_000_000_000;
const RATE_MAX: u64 = 1_000_000;

macro_rules! setting {
    (
        $key:literal, $group:ident, $unit:ident, $scope:ident,
        $min:expr, $max:expr, $zero:expr, $summary:literal,
        |$t:ident| $field:expr, $ty:ty
    ) => {
        Setting {
            key: $key,
            group: Group::$group,
            unit: Unit::$unit,
            scope: Scope::$scope,
            min: $min,
            max: $max,
            zero_unlimited: $zero,
            summary: $summary,
            get: |$t: &Tunables| $field as u64,
            set: |$t: &mut Tunables, value: u64| $field = value as $ty,
        }
    };
}

/// Все настройки, в порядке групп.
pub static CATALOG: &[Setting] = &[
    // Отправка и квоты очередей.
    setting!(
        "ttl_min_seconds",
        Messages,
        Seconds,
        Hot,
        1,
        365 * DAY,
        true,
        "Минимальный срок жизни сообщения: депозит с меньшим ttl отклоняется",
        |t| t.limits.ttl_min_seconds,
        u64
    ),
    setting!(
        "quota_max_messages_per_queue",
        Messages,
        Count,
        Hot,
        1,
        COUNT_MAX,
        true,
        "Потолок сообщений в одной очереди (прямой бэкенд)",
        |t| t.limits.max_messages_per_queue,
        usize
    ),
    setting!(
        "quota_max_bytes_per_queue",
        Messages,
        Bytes,
        Hot,
        KIB,
        TIB,
        true,
        "Потолок объёма одной очереди (прямой бэкенд)",
        |t| t.limits.max_bytes_per_queue,
        u64
    ),
    setting!(
        "quota_max_messages_sender_pair",
        Messages,
        Count,
        Hot,
        1,
        COUNT_MAX,
        true,
        "Сколько сообщений один отправитель держит в очередях одного получателя",
        |t| t.limits.max_messages_sender_pair,
        usize
    ),
    setting!(
        "rate_limit_send_msgs_per_sec",
        Messages,
        PerSecond,
        Hot,
        1,
        RATE_MAX,
        true,
        "Отправка: сообщений в секунду на пользователя",
        |t| t.limits.send_msgs_per_sec,
        u32
    ),
    setting!(
        "rate_limit_send_bytes_per_day",
        Messages,
        BytesPerDay,
        Hot,
        MIB,
        100 * TIB,
        true,
        "Отправка: байт в сутки на пользователя",
        |t| t.limits.send_bytes_per_day,
        u64
    ),
    // Сессии и управляющие кадры.
    setting!(
        "limit_max_sessions_per_user",
        Sessions,
        Count,
        Hot,
        1,
        100_000,
        true,
        "Одновременных сессий одного пользователя",
        |t| t.limits.max_sessions_per_user,
        usize
    ),
    setting!(
        "session_confirm_timeout_secs",
        Sessions,
        Seconds,
        NewSessions,
        1,
        600,
        false,
        "Сколько нода ждёт первый кадр клиента после входа",
        |t| t.limits.session_confirm_timeout_secs,
        u64
    ),
    setting!(
        "limit_ping_per_sec",
        Sessions,
        PerSecond,
        NewSessions,
        1,
        RATE_MAX,
        true,
        "Ping в секунду на соединение",
        |t| t.limits.ping_per_sec,
        u32
    ),
    setting!(
        "limit_control_per_sec",
        Sessions,
        PerSecond,
        NewSessions,
        1,
        RATE_MAX,
        true,
        "Управляющих кадров очередей в секунду на соединение",
        |t| t.limits.control_per_sec,
        u32
    ),
    setting!(
        "max_queues_per_user",
        Sessions,
        Count,
        Hot,
        1,
        COUNT_MAX,
        true,
        "Очередей на пользователя — по сути потолок контактов",
        |t| t.limits.max_queues_per_user,
        usize
    ),
    setting!(
        "max_push_devices_per_user",
        Sessions,
        Count,
        Hot,
        1,
        100_000,
        true,
        "Устройств с push-токенами на пользователя",
        |t| t.limits.max_push_devices_per_user,
        usize
    ),
    // Вход и TCP.
    setting!(
        "limit_max_connections",
        Network,
        Count,
        Hot,
        1,
        COUNT_MAX,
        true,
        "Открытых TCP-соединений на ноду",
        |t| t.limits.max_connections,
        usize
    ),
    setting!(
        "limit_handshake_inflight",
        Network,
        Count,
        Hot,
        1,
        COUNT_MAX,
        true,
        "Одновременных хендшейков на ноду",
        |t| t.limits.handshake_max_inflight,
        usize
    ),
    setting!(
        "limit_handshake_inflight_per_ip",
        Network,
        Count,
        Hot,
        1,
        COUNT_MAX,
        true,
        "Одновременных хендшейков с одного IP (за общим NAT — выше)",
        |t| t.limits.handshake_max_inflight_per_ip,
        usize
    ),
    setting!(
        "tcp_keepalive_secs",
        Network,
        Seconds,
        NewSessions,
        1,
        32_767,
        true,
        "Простой до первой keepalive-пробы (0 — без keepalive)",
        |t| t.limits.tcp_keepalive_secs,
        u64
    ),
    setting!(
        "tcp_keepalive_interval_secs",
        Network,
        Seconds,
        NewSessions,
        1,
        32_767,
        false,
        "Интервал между keepalive-пробами",
        |t| t.limits.tcp_keepalive_interval_secs,
        u64
    ),
    setting!(
        "tcp_keepalive_retries",
        Network,
        Count,
        NewSessions,
        1,
        127,
        false,
        "Неотвеченных keepalive-проб до разрыва",
        |t| t.limits.tcp_keepalive_retries,
        u32
    ),
    setting!(
        "tcp_user_timeout_secs",
        Network,
        Seconds,
        NewSessions,
        1,
        3600,
        true,
        "Сколько записанное нодой может ждать TCP-подтверждения (0 — системное)",
        |t| t.limits.tcp_user_timeout_secs,
        u64
    ),
    // Хранилище файлов.
    setting!(
        "blob_max_size_bytes",
        Blobs,
        Bytes,
        Hot,
        KIB,
        TIB,
        false,
        "Потолок одного файла",
        |t| t.blobs.max_size,
        u64
    ),
    setting!(
        "blob_max_ttl_secs",
        Blobs,
        Seconds,
        Hot,
        60,
        3650 * DAY,
        false,
        "Потолок срока жизни файла",
        |t| t.blobs.max_ttl_secs,
        u64
    ),
    setting!(
        "blob_quota_per_owner_bytes",
        Blobs,
        Bytes,
        Hot,
        MIB,
        100 * TIB,
        true,
        "Квота файлов на владельца",
        |t| t.blobs.quota_per_owner,
        u64
    ),
    setting!(
        "blob_quota_per_pair_bytes",
        Blobs,
        Bytes,
        Hot,
        MIB,
        100 * TIB,
        true,
        "Квота загрузившего в ящик одного получателя",
        |t| t.blobs.quota_per_pair,
        u64
    ),
    setting!(
        "blob_upload_bytes_per_day",
        Blobs,
        BytesPerDay,
        Hot,
        MIB,
        100 * TIB,
        true,
        "Загрузка файлов: байт в сутки на пользователя",
        |t| t.blobs.upload_bytes_per_day,
        u64
    ),
    setting!(
        "blob_disk_reserve_bytes",
        Blobs,
        Bytes,
        Hot,
        MIB,
        100 * TIB,
        true,
        "Свободное место, ниже которого загрузки получают QUOTA",
        |t| t.blobs.disk_reserve,
        u64
    ),
    setting!(
        "blob_tombstone_secs",
        Blobs,
        Seconds,
        Hot,
        60,
        3650 * DAY,
        true,
        "Сколько помнить удалённый или истёкший файл",
        |t| t.blobs.tombstone_secs,
        u64
    ),
    setting!(
        "max_blob_sessions_per_user",
        Blobs,
        Count,
        NewSessions,
        1,
        10_000,
        true,
        "Одновременных сессий передачи файлов одного пользователя",
        |t| t.blobs.max_sessions_per_user,
        usize
    ),
    setting!(
        "blob_get_window_bytes",
        Blobs,
        Bytes,
        Hot,
        64 * KIB,
        GIB,
        false,
        "Окно скачивания: сколько нода шлёт без подтверждения",
        |t| t.blobs.get_window,
        u64
    ),
    setting!(
        "blob_sync_every_bytes",
        Blobs,
        Bytes,
        Hot,
        64 * KIB,
        GIB,
        false,
        "Шаг fsync при загрузке",
        |t| t.blobs.sync_every,
        u64
    ),
    setting!(
        "blob_ops_per_sec",
        Blobs,
        PerSecond,
        Hot,
        1,
        RATE_MAX,
        true,
        "Операций хранилища в секунду на пользователя",
        |t| t.blobs.ops_per_sec,
        u32
    ),
    setting!(
        "blob_stat_per_sec",
        Blobs,
        PerSecond,
        Hot,
        1,
        RATE_MAX,
        true,
        "BlobStat в секунду на пользователя",
        |t| t.blobs.stat_per_sec,
        u32
    ),
    setting!(
        "blob_upload_stale_secs",
        Blobs,
        Seconds,
        Restart,
        60,
        365 * DAY,
        false,
        "Через сколько брошенная загрузка удаляется (входит в индекс сроков)",
        |t| t.blobs.upload_stale_secs,
        u64
    ),
    setting!(
        "blob_min_charge_bytes",
        Blobs,
        Bytes,
        Restart,
        1,
        GIB,
        true,
        "Минимальный учётный размер файла в квотах (входит в счётчики квот)",
        |t| t.blobs.min_charge,
        u64
    ),
    setting!(
        "blob_chunk_max_bytes",
        Blobs,
        Bytes,
        Restart,
        4 * KIB,
        64 * MIB,
        false,
        "Потолок куска загрузки и скачивания (объявляется клиентам)",
        |t| t.blobs.chunk_max,
        usize
    ),
    // Сертификаты и подписанный конфиг.
    setting!(
        "device_cert_max_ttl_seconds",
        Security,
        Seconds,
        Restart,
        60,
        3650 * DAY,
        true,
        "Потолок срока сертификата устройства (0 — делегированный вход выключен)",
        |t| t.device_cert_max_ttl_secs,
        u64
    ),
    setting!(
        "server_config_ttl_seconds",
        Security,
        Seconds,
        Restart,
        60,
        30 * DAY,
        false,
        "Срок жизни подписанного конфига у клиента",
        |t| t.server_config_ttl_secs,
        u64
    ),
];

pub fn find(key: &str) -> Option<&'static Setting> {
    CATALOG.iter().find(|s| s.key == key)
}

/// Каталог для панели и `tmnode`: всё, кроме функций доступа.
#[derive(Debug, Serialize)]
pub struct SettingInfo {
    pub key: &'static str,
    pub env: String,
    pub group: Group,
    pub unit: Unit,
    pub scope: Scope,
    pub min: u64,
    pub max: u64,
    pub zero_unlimited: bool,
    pub default: u64,
    pub summary: &'static str,
}

pub fn describe() -> Vec<SettingInfo> {
    CATALOG
        .iter()
        .map(|s| SettingInfo {
            key: s.key,
            env: s.env(),
            group: s.group,
            unit: s.unit,
            scope: s.scope,
            min: s.min,
            max: s.max,
            zero_unlimited: s.zero_unlimited,
            default: s.default_value(),
            summary: s.summary,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_defaults_fit() {
        let mut keys: Vec<&str> = CATALOG.iter().map(|s| s.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), CATALOG.len());
        for setting in CATALOG {
            assert!(setting.min <= setting.max, "{}", setting.key);
            setting
                .check(setting.default_value())
                .unwrap_or_else(|e| panic!("default of {}: {e}", setting.key));
            assert_eq!(setting.env(), setting.key.to_ascii_uppercase());
        }
    }

    #[test]
    fn setters_round_trip() {
        for setting in CATALOG {
            let mut t = Tunables::default();
            let value = setting.min.max(1) + 1;
            (setting.set)(&mut t, value);
            assert_eq!((setting.get)(&t), value, "{}", setting.key);
        }
    }

    #[test]
    fn bounds_and_unlimited() {
        let s = find("rate_limit_send_msgs_per_sec").unwrap();
        assert!(s.check(0).is_ok());
        assert!(
            s.check(RATE_MAX + 1)
                .unwrap_err()
                .contains("без ограничения")
        );
        let s = find("session_confirm_timeout_secs").unwrap();
        assert!(s.check(0).is_err());
        assert!(find("nope").is_none());
        assert_eq!(describe().len(), CATALOG.len());
    }
}
