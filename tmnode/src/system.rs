//! Всё, что `tmnode doctor` узнаёт о машине: контейнер ноды, диск, память,
//! часы, файлы. За интерфейсом `System` — чтобы проверки тестировались на
//! подставных ответах, а не на настоящем сервере.
//!
//! Только чтение: ни один метод ничего не меняет на машине.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;
use trust_message_tcp::net::probe::{ProbeError, ProbeOutcome};
use zeroize::Zeroizing;

/// Контейнер ноды по `docker inspect`.
#[derive(Clone, Default)]
pub struct Container {
    pub status: String,
    /// `healthy` / `unhealthy` / `starting`; `None` — healthcheck не задан.
    pub health: Option<String>,
    pub image: String,
    pub restart_count: u64,
    /// Окружение контейнера. Тут лежат секреты (ключ ноды, креды пушей),
    /// поэтому `Debug` его не печатает.
    pub env: Vec<(String, Zeroizing<String>)>,
    pub mounts: Vec<Mount>,
    pub ports: Vec<PortBinding>,
}

impl fmt::Debug for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Container")
            .field("status", &self.status)
            .field("health", &self.health)
            .field("image", &self.image)
            .field("env", &format_args!("<{} vars>", self.env.len()))
            .field("mounts", &self.mounts)
            .field("ports", &self.ports)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub source: PathBuf,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortBinding {
    pub container_port: u16,
    pub host_ip: String,
    pub host_port: u16,
}

impl Container {
    pub fn env_var(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.trim().is_empty())
    }

    /// Путь на хосте для пути внутри контейнера — через самую длинную
    /// подходящую точку монтирования. `None` — путь живёт в слое
    /// контейнера и пропадёт при его пересоздании.
    pub fn host_path(&self, inside: &Path) -> Option<PathBuf> {
        self.mounts
            .iter()
            .filter(|m| inside.starts_with(&m.destination))
            .max_by_key(|m| m.destination.components().count())
            .map(|m| {
                let rest = inside
                    .strip_prefix(&m.destination)
                    .expect("filtered by starts_with");
                if rest.as_os_str().is_empty() {
                    m.source.clone()
                } else {
                    m.source.join(rest)
                }
            })
    }

    /// Порт хоста, на который опубликован порт контейнера.
    pub fn published_port(&self, container_port: u16) -> Option<&PortBinding> {
        self.ports
            .iter()
            .find(|p| p.container_port == container_port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemInfo {
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    pub total: u64,
    pub available: u64,
}

/// Почему не удалось спросить Docker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerError {
    /// Утилиты `docker` нет.
    Missing,
    /// Docker ответил ошибкой (демон не запущен, нет прав на сокет).
    Failed(String),
}

#[allow(async_fn_in_trait)]
pub trait System {
    /// `Ok(None)` — контейнера с таким именем нет.
    fn container(&self, name: &str) -> Result<Option<Container>, DockerError>;
    fn read_secret(&self, path: &Path) -> io::Result<Zeroizing<String>>;
    /// Права файла (`mode & 0o777`).
    fn file_mode(&self, path: &Path) -> io::Result<u32>;
    fn disk_space(&self, path: &Path) -> io::Result<DiskSpace>;
    fn memory(&self) -> io::Result<MemInfo>;
    /// Синхронизированы ли часы (NTP); `None` — узнать не удалось.
    fn clock_synced(&self) -> Option<bool>;
    async fn probe(
        &self,
        addr: &str,
        node_key: &[u8; 32],
        step_timeout: Duration,
    ) -> Result<ProbeOutcome, ProbeError>;
}

/// Настоящая машина.
pub struct HostSystem {
    /// Исполняемый файл Docker CLI. По умолчанию `docker` из `PATH`.
    pub docker: PathBuf,
    pub meminfo: PathBuf,
    pub timedatectl: PathBuf,
}

impl Default for HostSystem {
    fn default() -> Self {
        Self {
            docker: PathBuf::from("docker"),
            meminfo: PathBuf::from("/proc/meminfo"),
            timedatectl: PathBuf::from("timedatectl"),
        }
    }
}

impl System for HostSystem {
    fn container(&self, name: &str) -> Result<Option<Container>, DockerError> {
        let output = Command::new(&self.docker)
            .args(["inspect", "--type", "container", "--", name])
            .output()
            .map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => DockerError::Missing,
                _ => DockerError::Failed(err.to_string()),
            })?;
        if output.status.success() {
            return parse_inspect(&output.stdout)
                .map(Some)
                .map_err(DockerError::Failed);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such container") || stderr.contains("No such object") {
            return Ok(None);
        }
        Err(DockerError::Failed(stderr.trim().to_owned()))
    }

    fn read_secret(&self, path: &Path) -> io::Result<Zeroizing<String>> {
        std::fs::read_to_string(path).map(Zeroizing::new)
    }

    fn file_mode(&self, path: &Path) -> io::Result<u32> {
        use std::os::unix::fs::PermissionsExt;
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
    }

    fn disk_space(&self, path: &Path) -> io::Result<DiskSpace> {
        Ok(DiskSpace {
            total: fs2::total_space(path)?,
            available: fs2::available_space(path)?,
        })
    }

    fn memory(&self) -> io::Result<MemInfo> {
        parse_meminfo(&std::fs::read_to_string(&self.meminfo)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no MemTotal/MemAvailable"))
    }

    fn clock_synced(&self) -> Option<bool> {
        let output = Command::new(&self.timedatectl)
            .args(["show", "--property=NTPSynchronized", "--value"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        }
    }

    async fn probe(
        &self,
        addr: &str,
        node_key: &[u8; 32],
        step_timeout: Duration,
    ) -> Result<ProbeOutcome, ProbeError> {
        trust_message_tcp::net::probe::probe(addr, node_key, step_timeout).await
    }
}

/// Разобрать вывод `docker inspect` (массив из одного объекта).
pub fn parse_inspect(json: &[u8]) -> Result<Container, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Inspect {
        state: State,
        #[serde(default)]
        restart_count: u64,
        config: Config,
        #[serde(default)]
        mounts: Vec<RawMount>,
        network_settings: Option<NetworkSettings>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct State {
        status: String,
        health: Option<Health>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Health {
        status: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Config {
        image: String,
        #[serde(default)]
        env: Option<Vec<String>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawMount {
        source: PathBuf,
        destination: PathBuf,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct NetworkSettings {
        #[serde(default)]
        ports: Option<std::collections::BTreeMap<String, Option<Vec<HostBinding>>>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct HostBinding {
        host_ip: String,
        host_port: String,
    }

    let mut items: Vec<Inspect> =
        serde_json::from_slice(json).map_err(|err| format!("docker inspect: {err}"))?;
    if items.len() != 1 {
        return Err(format!(
            "docker inspect: ожидался 1 объект, получено {}",
            items.len()
        ));
    }
    let item = items.remove(0);

    let env = item
        .config
        .env
        .unwrap_or_default()
        .into_iter()
        .filter_map(|pair| {
            let pair = Zeroizing::new(pair);
            pair.split_once('=')
                .map(|(k, v)| (k.to_owned(), Zeroizing::new(v.to_owned())))
        })
        .collect();

    let mut ports = Vec::new();
    for (spec, bindings) in item
        .network_settings
        .and_then(|n| n.ports)
        .unwrap_or_default()
    {
        let Some((port, "tcp")) = spec.split_once('/') else {
            continue;
        };
        let Ok(container_port) = port.parse() else {
            continue;
        };
        for binding in bindings.unwrap_or_default() {
            if let Ok(host_port) = binding.host_port.parse() {
                ports.push(PortBinding {
                    container_port,
                    host_ip: binding.host_ip,
                    host_port,
                });
            }
        }
    }

    Ok(Container {
        status: item.state.status,
        health: item.state.health.map(|h| h.status),
        image: item.config.image,
        restart_count: item.restart_count,
        env,
        mounts: item
            .mounts
            .into_iter()
            .map(|m| Mount {
                source: m.source,
                destination: m.destination,
            })
            .collect(),
        ports,
    })
}

/// `MemTotal` и `MemAvailable` из `/proc/meminfo`, в байтах.
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|rest| rest.trim().strip_suffix("kB"))
            .and_then(|kb| kb.trim().parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };
    Some(MemInfo {
        total: field("MemTotal")?,
        available: field("MemAvailable")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const INSPECT: &str = r#"[{
        "RestartCount": 2,
        "State": {"Status": "running", "Health": {"Status": "healthy"}},
        "Config": {
            "Image": "trust-message-service:jetstream",
            "Env": ["STORAGE_PATH=/srv/trust-message/data", "NODE_IDENTITY_KEY=abc", "BROKEN"]
        },
        "Mounts": [
            {"Source": "/root/deploy/data", "Destination": "/srv/trust-message/data"},
            {"Source": "/root/deploy/blobs", "Destination": "/srv/trust-message/data/blobs"}
        ],
        "NetworkSettings": {"Ports": {
            "18081/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18081"}, {"HostIp": "::", "HostPort": "18081"}],
            "9000/tcp": null,
            "5353/udp": [{"HostIp": "0.0.0.0", "HostPort": "5353"}]
        }}
    }]"#;

    #[test]
    fn inspect_output_is_parsed() {
        let c = parse_inspect(INSPECT.as_bytes()).unwrap();
        assert_eq!(c.status, "running");
        assert_eq!(c.health.as_deref(), Some("healthy"));
        assert_eq!(c.image, "trust-message-service:jetstream");
        assert_eq!(c.restart_count, 2);
        assert_eq!(c.env_var("STORAGE_PATH"), Some("/srv/trust-message/data"));
        assert_eq!(c.env_var("NODE_IDENTITY_KEY"), Some("abc"));
        assert_eq!(c.env_var("BROKEN"), None);
        assert_eq!(c.ports.len(), 2);
        assert_eq!(c.published_port(18081).unwrap().host_port, 18081);
        assert!(c.published_port(9000).is_none());
        assert!(c.published_port(5353).is_none());

        // Debug не печатает окружение — там секреты.
        let debug = format!("{c:?}");
        assert!(!debug.contains("abc"));
        assert!(debug.contains("<2 vars>"));
    }

    #[test]
    fn host_path_uses_the_deepest_mount() {
        let c = parse_inspect(INSPECT.as_bytes()).unwrap();
        assert_eq!(
            c.host_path(Path::new("/srv/trust-message/data/node_identity_key")),
            Some(PathBuf::from("/root/deploy/data/node_identity_key"))
        );
        assert_eq!(
            c.host_path(Path::new("/srv/trust-message/data/blobs")),
            Some(PathBuf::from("/root/deploy/blobs"))
        );
        assert_eq!(
            c.host_path(Path::new("/srv/trust-message/data")),
            Some(PathBuf::from("/root/deploy/data"))
        );
        assert_eq!(c.host_path(Path::new("/app/data")), None);
    }

    #[test]
    fn malformed_inspect_is_an_error() {
        assert!(parse_inspect(b"not json").is_err());
        assert!(parse_inspect(b"[]").unwrap_err().contains("получено 0"));
        let minimal = r#"[{"State":{"Status":"exited"},"Config":{"Image":"x"}}]"#;
        let c = parse_inspect(minimal.as_bytes()).unwrap();
        assert_eq!(c.status, "exited");
        assert!(c.health.is_none() && c.env.is_empty() && c.ports.is_empty());
    }

    #[test]
    fn meminfo_is_parsed() {
        let text = "MemTotal:        2009756 kB\nMemFree:  1 kB\nMemAvailable:     812345 kB\n";
        assert_eq!(
            parse_meminfo(text),
            Some(MemInfo {
                total: 2_009_756 * 1024,
                available: 812_345 * 1024
            })
        );
        assert_eq!(parse_meminfo("MemTotal: 1 kB\n"), None);
    }

    /// Подставной `docker`: скрипт, который отвечает заготовкой. Так
    /// проверяется настоящий вызов процесса и разбор его вывода.
    fn fake_tool(dir: &Path, name: &str, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tmnode_{label}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn host_system_talks_to_docker_and_timedatectl() {
        let dir = temp_dir("host");
        let fixture = dir.join("inspect.json");
        std::fs::write(&fixture, INSPECT).unwrap();

        let host = HostSystem {
            docker: fake_tool(
                &dir,
                "docker",
                &format!(
                    r#"case "$5" in
  message-service) cat {} ;;
  gone) echo "Error: No such container: gone" >&2; exit 1 ;;
  *) echo "permission denied while trying to connect" >&2; exit 1 ;;
esac"#,
                    fixture.display()
                ),
            ),
            meminfo: dir.join("meminfo"),
            timedatectl: fake_tool(&dir, "timedatectl", "echo yes"),
        };

        let c = host.container("message-service").unwrap().unwrap();
        assert_eq!(c.status, "running");
        assert!(host.container("gone").unwrap().is_none());
        assert!(matches!(
            host.container("other"),
            Err(DockerError::Failed(msg)) if msg.contains("permission denied")
        ));
        assert_eq!(host.clock_synced(), Some(true));

        let host = HostSystem {
            docker: dir.join("no-such-docker"),
            timedatectl: fake_tool(&dir, "timedatectl2", "echo maybe"),
            ..HostSystem::default()
        };
        assert_eq!(host.container("x").unwrap_err(), DockerError::Missing);
        assert_eq!(host.clock_synced(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_system_reads_files_disk_and_memory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("files");
        let secret = dir.join("node_identity_key");
        std::fs::write(&secret, "00ff\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::write(dir.join("meminfo"), "MemTotal: 4 kB\nMemAvailable: 2 kB\n").unwrap();

        let host = HostSystem {
            meminfo: dir.join("meminfo"),
            ..HostSystem::default()
        };
        assert_eq!(host.read_secret(&secret).unwrap().as_str(), "00ff\n");
        assert_eq!(host.file_mode(&secret).unwrap(), 0o640);
        let disk = host.disk_space(&dir).unwrap();
        assert!(disk.total >= disk.available && disk.total > 0);
        assert_eq!(host.memory().unwrap().total, 4096);

        let broken = HostSystem {
            meminfo: dir.join("missing"),
            ..HostSystem::default()
        };
        assert!(broken.memory().is_err());
        std::fs::write(dir.join("bad"), "nothing").unwrap();
        let bad = HostSystem {
            meminfo: dir.join("bad"),
            ..HostSystem::default()
        };
        assert_eq!(bad.memory().unwrap_err().kind(), io::ErrorKind::InvalidData);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
