//! Настройки без перезапуска: файл `runtime.toml` (docs/runtime-config.md).
//!
//! Порядок источников: умолчания → `.env` и окружение → `runtime.toml`.
//! Файл пишет оператор или агент `tmnode` по заданию админки. Нода читает
//! его при старте и перечитывает на лету: при изменении файла (проверка раз
//! в [`POLL_INTERVAL`]) и по SIGHUP.
//!
//! Неверный файл не применяется целиком — нода остаётся на прежних
//! настройках, а причина пишется в лог и в файл статуса. Нода с неверным
//! файлом стартует на настройках окружения: ошибка в лимитах не должна
//! класть ноду.
//!
//! Итог каждой попытки — в `runtime.status.json` рядом с файлом: по нему
//! агент сообщает админке, какая версия применена и что ждёт перезапуска.

pub mod catalog;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::{Config, IceServerConfig};
use crate::net::listener::Live;
use crate::net::rate_limit::unix_now_secs;
use crate::observability;
use catalog::{CATALOG, Scope, Tunables};

/// Как часто нода смотрит, не изменился ли файл.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Потолок размера файла: настроек несколько десятков.
pub const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Содержимое `runtime.toml`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFile {
    /// Метка версии от того, кто пишет файл (админка). Нода её не
    /// толкует — только возвращает в статусе.
    pub version: Option<String>,
    /// Настройки каталога: имя → значение.
    #[serde(default)]
    pub settings: BTreeMap<String, u64>,
    /// ICE-серверы для звонков (server-contract.md §6.12). Нет секции —
    /// серверы из окружения (то есть никаких).
    pub ice: Option<IceSection>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IceSection {
    #[serde(default)]
    pub servers: Vec<IceServerSection>,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IceServerSection {
    pub urls: Vec<String>,
    /// Общий секрет coturn (`static-auth-secret`). Обязателен у `turn:` и
    /// `turns:`, запрещён у STUN.
    pub secret: Option<String>,
}

/// Секрет TURN в отладочный вывод не попадает.
impl std::fmt::Debug for IceServerSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceServerSection")
            .field("urls", &self.urls)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Сколько ICE-серверов и URL у одного сервера принимает нода.
const MAX_ICE_SERVERS: usize = 8;
const MAX_ICE_URLS: usize = 8;
/// Короче — секрет TURN перебирается.
const MIN_ICE_SECRET: usize = 16;

impl IceServerSection {
    fn validate(&self, index: usize) -> Result<IceServerConfig> {
        let at = |what: String| anyhow!("ice.servers[{index}]: {what}");
        if self.urls.is_empty() || self.urls.len() > MAX_ICE_URLS {
            return Err(at(format!("от 1 до {MAX_ICE_URLS} urls")));
        }
        let mut turn = false;
        for url in &self.urls {
            let (scheme, rest) = url.split_once(':').unwrap_or(("", ""));
            match scheme {
                "turn" | "turns" => turn = true,
                "stun" | "stuns" => {}
                _ => {
                    return Err(at(format!(
                        "`{url}`: ожидается stun:, stuns:, turn: или turns:"
                    )));
                }
            }
            if rest.is_empty() || url.len() > 256 || url.chars().any(char::is_whitespace) {
                return Err(at(format!("`{url}`: неверный адрес")));
            }
        }
        let secret = self
            .secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (turn, secret) {
            (true, None) => {
                return Err(at("у TURN нужен secret (static-auth-secret coturn)".into()));
            }
            (false, Some(_)) => return Err(at("у STUN secret не нужен".into())),
            (true, Some(secret)) if secret.len() < MIN_ICE_SECRET => {
                return Err(at(format!("secret короче {MIN_ICE_SECRET} символов")));
            }
            _ => {}
        }
        Ok(IceServerConfig {
            urls: self.urls.clone(),
            secret: secret.map(str::to_owned),
        })
    }
}

impl RuntimeFile {
    pub fn parse(text: &str) -> Result<Self> {
        let file: Self = toml::from_str(text).context("runtime.toml: неверная структура")?;
        if let Some(version) = &file.version
            && version.chars().count() > 128
        {
            bail!("version: не длиннее 128 символов");
        }
        Ok(file)
    }

    /// Наложить настройки файла на `base`. Ошибка — если имя не из каталога,
    /// значение вне пределов или вместе они несовместимы.
    pub fn overlay(&self, base: &Tunables, max_frame_len: usize) -> Result<Tunables> {
        let mut out = base.clone();
        if let Some(ice) = &self.ice {
            if ice.servers.len() > MAX_ICE_SERVERS {
                bail!("ice.servers: не больше {MAX_ICE_SERVERS}");
            }
            out.ice.servers = ice
                .servers
                .iter()
                .enumerate()
                .map(|(i, server)| server.validate(i))
                .collect::<Result<_>>()?;
        }
        for (key, value) in &self.settings {
            let setting =
                catalog::find(key).ok_or_else(|| anyhow!("неизвестная настройка `{key}`"))?;
            setting.check(*value).map_err(|e| anyhow!(e))?;
            (setting.set)(&mut out, *value);
        }
        validate(&out, max_frame_len)?;
        Ok(out)
    }
}

/// Проверки, которые связывают несколько настроек.
pub fn validate(t: &Tunables, max_frame_len: usize) -> Result<()> {
    crate::config::check_tcp_keepalive(&t.limits)?;
    let reserve = crate::blob::BLOB_FRAME_RESERVE;
    if t.blobs.chunk_max.saturating_add(reserve) > max_frame_len {
        bail!(
            "blob_chunk_max_bytes ({}) плюс {reserve} байт заголовка не влезают в MAX_FRAME_LEN ({max_frame_len})",
            t.blobs.chunk_max
        );
    }
    Ok(())
}

/// Итог попытки применить файл — `runtime.status.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Status {
    /// `applied` — применён, `invalid` — отвергнут, `absent` — файла нет.
    pub result: String,
    /// `version` применённого файла.
    pub version: Option<String>,
    /// SHA-256 содержимого, по которому шла попытка.
    pub sha256: Option<String>,
    pub at: u64,
    pub error: Option<String>,
    /// Настройки, новые значения которых ждут перезапуска.
    pub pending_restart: Vec<String>,
}

pub fn default_path(storage_path: &str) -> PathBuf {
    Path::new(storage_path).join("runtime.toml")
}

pub fn status_path(path: &Path) -> PathBuf {
    path.with_file_name("runtime.status.json")
}

fn read_file(path: &Path) -> Result<Option<(String, String)>> {
    match std::fs::metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
        Ok(meta) if meta.len() > MAX_FILE_BYTES => {
            bail!("{} больше {MAX_FILE_BYTES} байт", path.display())
        }
        Ok(_) => {}
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let hash = hex::encode(Sha256::digest(text.as_bytes()));
    Ok(Some((text, hash)))
}

/// При старте: наложить файл на конфиг из окружения. Значения «только после
/// перезапуска» применяются именно здесь.
pub fn apply_at_startup(cfg: &mut Config, path: &Path) -> Status {
    let base = Tunables::from_config(cfg);
    let status = match read_file(path) {
        Ok(None) => Status {
            result: "absent".into(),
            at: unix_now_secs(),
            ..Status::default()
        },
        Ok(Some((text, hash))) => match RuntimeFile::parse(&text)
            .and_then(|file| Ok((file.overlay(&base, cfg.max_frame_len)?, file)))
        {
            Ok((tunables, file)) => {
                tunables.apply_to(cfg);
                info!(
                    path = %path.display(),
                    version = file.version.as_deref().unwrap_or("-"),
                    settings = file.settings.len(),
                    "runtime settings applied at startup"
                );
                Status {
                    result: "applied".into(),
                    version: file.version,
                    sha256: Some(hash),
                    at: unix_now_secs(),
                    ..Status::default()
                }
            }
            Err(err) => invalid(path, Some(hash), &err),
        },
        Err(err) => invalid(path, None, &err),
    };
    write_status(path, &status);
    status
}

fn invalid(path: &Path, hash: Option<String>, err: &anyhow::Error) -> Status {
    warn!(path = %path.display(), error = format!("{err:#}"), "runtime settings rejected; keeping the previous ones");
    observability::observe_runtime_reload("invalid");
    Status {
        result: "invalid".into(),
        sha256: hash,
        at: unix_now_secs(),
        error: Some(format!("{err:#}")),
        ..Status::default()
    }
}

/// Записать статус атомарно: агент не должен прочитать половину файла.
fn write_status(path: &Path, status: &Status) {
    let target = status_path(path);
    let tmp = target.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(status).expect("status serializes");
    let written = std::fs::write(&tmp, body).and_then(|()| std::fs::rename(&tmp, &target));
    if let Err(err) = written {
        warn!(path = %target.display(), error = %err, "failed to write runtime status");
    }
}

/// Перечитывание на лету.
pub struct Reloader {
    path: PathBuf,
    /// Конфиг из окружения, без файла: от него считается каждое наложение,
    /// чтобы удалённая из файла настройка вернулась к значению окружения.
    base: Config,
    /// Настройки, с которыми нода стартовала: значения «только после
    /// перезапуска» берутся отсюда.
    running: Tunables,
    live: Arc<Live>,
    last_hash: Option<String>,
}

impl Reloader {
    /// `base` — конфиг из окружения, `running` — он же с файлом, наложенным
    /// при старте.
    pub fn new(
        path: PathBuf,
        base: Config,
        running: &Config,
        live: Arc<Live>,
        startup: &Status,
    ) -> Self {
        Self {
            path,
            base,
            running: Tunables::from_config(running),
            live,
            last_hash: startup.sha256.clone(),
        }
    }

    /// Проверить файл и, если он изменился, применить. `None` — менять
    /// нечего.
    pub fn reload(&mut self, force: bool) -> Option<Status> {
        let read = read_file(&self.path);
        let hash = match &read {
            Ok(Some((_, hash))) => Some(hash.clone()),
            _ => None,
        };
        if !force && hash == self.last_hash {
            return None;
        }
        self.last_hash = hash.clone();
        let status = match read {
            // Файл удалён — настройки возвращаются к окружению.
            Ok(None) => self.apply(&RuntimeFile::default(), None, "absent"),
            Ok(Some((text, hash))) => match RuntimeFile::parse(&text) {
                Ok(file) => self.apply(&file, Some(hash), "applied"),
                Err(err) => invalid(&self.path, Some(hash), &err),
            },
            Err(err) => invalid(&self.path, None, &err),
        };
        write_status(&self.path, &status);
        Some(status)
    }

    fn apply(&mut self, file: &RuntimeFile, hash: Option<String>, result: &str) -> Status {
        let base = Tunables::from_config(&self.base);
        let wanted = match file.overlay(&base, self.base.max_frame_len) {
            Ok(wanted) => wanted,
            Err(err) => return invalid(&self.path, hash, &err),
        };
        // Значения «только после перезапуска» остаются текущими, но
        // запоминаются как ожидающие.
        let mut effective = wanted.clone();
        let mut pending = Vec::new();
        for setting in CATALOG.iter().filter(|s| s.scope == Scope::Restart) {
            let next = (setting.get)(&wanted);
            let now = (setting.get)(&self.running);
            if next != now {
                pending.push(setting.key.to_owned());
                (setting.set)(&mut effective, now);
            }
        }
        let mut cfg = self.base.clone();
        effective.apply_to(&mut cfg);
        self.live.apply(&cfg);
        observability::observe_runtime_reload("applied");
        info!(
            version = file.version.as_deref().unwrap_or("-"),
            settings = file.settings.len(),
            pending_restart = pending.len(),
            "runtime settings applied"
        );
        Status {
            result: result.into(),
            version: file.version.clone(),
            sha256: hash,
            at: unix_now_secs(),
            error: None,
            pending_restart: pending,
        }
    }

    /// Следить за файлом: опрос раз в [`POLL_INTERVAL`] и SIGHUP.
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            #[cfg(unix)]
            let mut hup =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
            let mut tick = tokio::time::interval(POLL_INTERVAL);
            loop {
                #[cfg(unix)]
                let forced = match hup.as_mut() {
                    Some(hup) => tokio::select! {
                        _ = tick.tick() => false,
                        _ = hup.recv() => true,
                    },
                    None => {
                        tick.tick().await;
                        false
                    }
                };
                #[cfg(not(unix))]
                let forced = {
                    tick.tick().await;
                    false
                };
                // Чтение файла — блокирующее, но крошечное; отдельный поток
                // ради него не нужен.
                self.reload(forced);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::from_env_vars;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tm_runtime_{label}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env_config(dir: &Path) -> Config {
        from_env_vars([
            ("STORAGE_PATH".to_owned(), dir.display().to_string()),
            ("RATE_LIMIT_SEND_MSGS_PER_SEC".to_owned(), "70".to_owned()),
        ])
        .unwrap()
    }

    fn read_status(path: &Path) -> Status {
        serde_json::from_slice(&std::fs::read(status_path(path)).unwrap()).unwrap()
    }

    #[test]
    fn file_is_parsed_strictly() {
        let file =
            RuntimeFile::parse("version = \"v7\"\n[settings]\nrate_limit_send_msgs_per_sec = 10\n")
                .unwrap();
        assert_eq!(file.version.as_deref(), Some("v7"));
        assert_eq!(file.settings["rate_limit_send_msgs_per_sec"], 10);
        assert!(RuntimeFile::parse("limits = 1").is_err());
        assert!(RuntimeFile::parse("[settings]\nx = \"a\"").is_err());
        assert!(RuntimeFile::parse(&format!("version = \"{}\"", "v".repeat(129))).is_err());
        assert_eq!(RuntimeFile::parse("").unwrap(), RuntimeFile::default());
    }

    #[test]
    fn overlay_checks_names_bounds_and_combinations() {
        let base = Tunables::default();
        let frame = 8 * 1024 * 1024;
        let file = |text: &str| RuntimeFile::parse(text).unwrap();

        let t =
            file("[settings]\nblob_quota_per_owner_bytes = 1048576\nlimit_max_connections = 0\n")
                .overlay(&base, frame)
                .unwrap();
        assert_eq!(t.blobs.quota_per_owner, 1_048_576);
        assert_eq!(t.limits.max_connections, 0);

        let err = file("[settings]\nnope = 1\n")
            .overlay(&base, frame)
            .unwrap_err();
        assert!(format!("{err:#}").contains("nope"));
        let err = file("[settings]\nsession_confirm_timeout_secs = 0\n")
            .overlay(&base, frame)
            .unwrap_err();
        assert!(format!("{err:#}").contains("session_confirm_timeout_secs"));
        let err = file("[settings]\nblob_chunk_max_bytes = 8388608\n")
            .overlay(&base, frame)
            .unwrap_err();
        assert!(format!("{err:#}").contains("MAX_FRAME_LEN"));
    }

    #[test]
    fn ice_section_is_validated() {
        let base = Tunables::default();
        let frame = 8 * 1024 * 1024;
        let ok = RuntimeFile::parse(
            r#"
[settings]
ice_credential_ttl_secs = 600

[[ice.servers]]
urls = ["stun:stun.example.org:3478"]

[[ice.servers]]
urls = ["turn:turn.example.org:3478?transport=udp", "turns:turn.example.org:5349"]
secret = "0123456789abcdef0123"
"#,
        )
        .unwrap()
        .overlay(&base, frame)
        .unwrap();
        assert_eq!(ok.ice.servers.len(), 2);
        assert_eq!(ok.ice.credential_ttl_secs, 600);
        assert!(ok.ice.servers[0].secret.is_none());
        // Секрет не попадает в отладочный вывод.
        assert!(!format!("{:?}", ok.ice).contains("0123456789abcdef0123"));

        for (text, needle) in [
            ("[[ice.servers]]\nurls = []\n", "urls"),
            ("[[ice.servers]]\nurls = [\"http://x\"]\n", "stun:"),
            ("[[ice.servers]]\nurls = [\"turn:\"]\n", "неверный адрес"),
            (
                "[[ice.servers]]\nurls = [\"turn:x:3478\"]\n",
                "нужен secret",
            ),
            (
                "[[ice.servers]]\nurls = [\"turn:x:3478\"]\nsecret = \"short\"\n",
                "короче",
            ),
            (
                "[[ice.servers]]\nurls = [\"stun:x:3478\"]\nsecret = \"0123456789abcdef0123\"\n",
                "не нужен",
            ),
            ("[ice]\nfoo = 1\n", "неверная структура"),
        ] {
            let err = RuntimeFile::parse(text)
                .and_then(|f| f.overlay(&base, frame))
                .expect_err(text);
            assert!(format!("{err:#}").contains(needle), "{text}: {err:#}");
        }
        let many = "[[ice.servers]]\nurls = [\"stun:x:1\"]\n".repeat(9);
        let err = RuntimeFile::parse(&many)
            .unwrap()
            .overlay(&base, frame)
            .unwrap_err();
        assert!(format!("{err:#}").contains("не больше"));
    }

    #[test]
    fn startup_applies_valid_files_and_survives_broken_ones() {
        let dir = temp_dir("startup");
        let path = default_path(&dir.display().to_string());

        let mut cfg = env_config(&dir);
        assert_eq!(apply_at_startup(&mut cfg, &path).result, "absent");
        assert_eq!(cfg.limits.send_msgs_per_sec, 70);

        std::fs::write(
            &path,
            "version = \"a1\"\n[settings]\nrate_limit_send_msgs_per_sec = 5\nblob_min_charge_bytes = 4096\n",
        )
        .unwrap();
        let status = apply_at_startup(&mut cfg, &path);
        assert_eq!(status.result, "applied");
        assert_eq!(cfg.limits.send_msgs_per_sec, 5);
        // При старте применяются и настройки «после перезапуска».
        assert_eq!(cfg.blobs.min_charge, 4096);
        assert_eq!(read_status(&path).version.as_deref(), Some("a1"));

        std::fs::write(&path, "[settings]\nrate_limit_send_msgs_per_sec = -1\n").unwrap();
        let mut cfg = env_config(&dir);
        let status = apply_at_startup(&mut cfg, &path);
        assert_eq!(status.result, "invalid");
        assert!(status.error.is_some());
        assert_eq!(cfg.limits.send_msgs_per_sec, 70);
        assert_eq!(read_status(&path).result, "invalid");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_swaps_live_limits_and_holds_restart_ones() {
        let dir = temp_dir("reload");
        let path = default_path(&dir.display().to_string());
        let base = env_config(&dir);
        let mut running = base.clone();
        let startup = apply_at_startup(&mut running, &path);
        let live = Live::new(&running, None);
        let mut reloader = Reloader::new(path.clone(), base, &running, live.clone(), &startup);

        assert!(reloader.reload(false).is_none(), "nothing changed");

        std::fs::write(
            &path,
            "version = \"v2\"\n[settings]\nrate_limit_send_msgs_per_sec = 3\nlimit_max_connections = 1\nblob_max_size_bytes = 2048\nblob_min_charge_bytes = 1\n",
        )
        .unwrap();
        let status = reloader.reload(false).unwrap();
        assert_eq!(status.result, "applied");
        assert_eq!(status.version.as_deref(), Some("v2"));
        assert_eq!(
            status.pending_restart,
            vec!["blob_min_charge_bytes".to_owned()]
        );
        assert_eq!(live.limits.cfg().send_msgs_per_sec, 3);
        let snapshot = live.server_config.current();
        assert_eq!(snapshot.blobs.map(|b| b.max_size), Some(2048));
        let first = live.connections.try_acquire().unwrap();
        assert!(live.connections.try_acquire().is_none());
        drop(first);
        let user = [1u8; 32];
        for _ in 0..3 {
            assert!(live.limits.send.check_at(&user, 1, 100));
        }
        assert!(!live.limits.send.check_at(&user, 1, 100));

        // Испорченный файл не трогает живые лимиты.
        std::fs::write(&path, "[settings]\nrate_limit_send_msgs_per_sec = \"x\"\n").unwrap();
        assert_eq!(reloader.reload(false).unwrap().result, "invalid");
        assert_eq!(live.limits.cfg().send_msgs_per_sec, 3);
        assert_eq!(read_status(&path).result, "invalid");

        // Без файла — снова окружение.
        std::fs::remove_file(&path).unwrap();
        let status = reloader.reload(false).unwrap();
        assert_eq!(status.result, "absent");
        assert_eq!(live.limits.cfg().send_msgs_per_sec, 70);
        assert!(live.connections.try_acquire().is_some());
        assert!(
            reloader.reload(true).is_some(),
            "SIGHUP rereads even unchanged files"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Адресация по очередям объявляется в подписанном конфиге: правка файла
    /// ждёт перезапуска, при старте применяется.
    #[tokio::test]
    async fn queue_addressing_waits_for_restart() {
        let dir = temp_dir("queue_addressing");
        let path = default_path(&dir.display().to_string());
        let base = env_config(&dir);
        assert!(base.queue_addressing_enabled, "включена по умолчанию");
        let mut running = base.clone();
        let startup = apply_at_startup(&mut running, &path);
        let live = Live::new(&running, None);
        let mut reloader =
            Reloader::new(path.clone(), base.clone(), &running, live.clone(), &startup);

        std::fs::write(&path, "[settings]\nqueue_addressing_enabled = 0\n").unwrap();
        let status = reloader.reload(false).unwrap();
        assert_eq!(status.result, "applied");
        assert_eq!(
            status.pending_restart,
            vec!["queue_addressing_enabled".to_owned()]
        );
        assert!(live.server_config.current().supports_queue_addressing);

        let mut restarted = base;
        assert_eq!(apply_at_startup(&mut restarted, &path).result, "applied");
        assert!(!restarted.queue_addressing_enabled);
        assert!(!restarted.server_config_snapshot().supports_queue_addressing);

        std::fs::write(&path, "[settings]\nqueue_addressing_enabled = 2\n").unwrap();
        assert_eq!(reloader.reload(false).unwrap().result, "invalid");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_files_are_refused() {
        let dir = temp_dir("big");
        let path = default_path(&dir.display().to_string());
        std::fs::write(&path, "#".repeat(MAX_FILE_BYTES as usize + 1)).unwrap();
        let mut cfg = env_config(&dir);
        let status = apply_at_startup(&mut cfg, &path);
        assert!(status.error.unwrap().contains("больше"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
