//! Проверки `tmnode doctor`. Только чтение: ни одна проверка ничего не
//! меняет ни на машине, ни на ноде.
//!
//! Набор и порядок проверок фиксированы (`CHECK_IDS`): в отчёте есть каждая,
//! даже неприменимая — со статусом `skip` и причиной. Так admin-сервис
//! сравнивает отчёты разных нод построчно, а не гадает, почему строки нет.

use std::path::{Path, PathBuf};
use std::time::Duration;

use trust_message_tcp::config::{self as node_config, DeliveryBackendKind};
use trust_message_tcp::net::noise::{NODE_KEY_FILE, NodeIdentity, NodeKeySource, fingerprint};
use trust_message_tcp::net::probe::ProbeStage;

use crate::node_config::NodeConfig;
use crate::report::{Check, Report, Status, Target};
use crate::system::{Container, DockerError, System};

/// Все проверки в порядке выполнения. Идентификаторы — часть контракта
/// `tmnode.report/1`.
pub const CHECK_IDS: &[&str] = &[
    "config.file",
    "runtime.docker",
    "runtime.container",
    "runtime.config",
    "config.drift",
    "host.data_dir",
    "identity.secret",
    "identity.pin",
    "host.disk",
    "host.blob_reserve",
    "host.memory",
    "host.clock",
    "endpoint.tcp",
    "endpoint.handshake",
    "endpoint.config",
];

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Свободного места меньше — нода вот-вот упрётся в диск (sled, JetStream).
const DISK_FAIL_BELOW: u64 = 512 * MIB;
const DISK_WARN_BELOW: u64 = 2 * GIB;
/// Рекомендуемый минимум памяти по бэкенду: JetStream держит NATS рядом.
const MEMORY_SLED: u64 = 512 * MIB;
const MEMORY_JETSTREAM: u64 = GIB;
const MEMORY_AVAILABLE_WARN_BELOW: u64 = 64 * MIB;

/// Откуда взят `node.toml`.
pub enum ConfigSource {
    /// Файла нет и он не задан — проверка по умолчаниям.
    Absent,
    Loaded(PathBuf, Box<NodeConfig>),
    Invalid(PathBuf, String),
}

pub struct Input {
    pub config: ConfigSource,
    /// `--container`: перекрывает `runtime.container`.
    pub container: Option<String>,
    /// `--addr` / `--node-key`: перекрывают `endpoint`.
    pub addr: Option<String>,
    pub node_key: Option<[u8; 32]>,
    /// `--remote`: машина — не хост ноды, проверяется только сеть.
    pub remote: bool,
    pub step_timeout: Duration,
}

/// Что проверки хоста узнали для проверки снаружи: если адрес и пин не
/// заданы, нода проверяется по опубликованному порту и своему же ключу.
#[derive(Default)]
struct HostFacts {
    node_key: Option<[u8; 32]>,
    local_addr: Option<String>,
}

pub async fn run<S: System>(sys: &S, input: &Input, now: u64) -> Report {
    let mut checks = Vec::with_capacity(CHECK_IDS.len());

    let config = match &input.config {
        ConfigSource::Absent => {
            checks.push(Check::skip(
                "config.file",
                "node.toml не задан — проверка по умолчаниям",
            ));
            None
        }
        ConfigSource::Loaded(path, config) => {
            checks.push(
                Check::ok("config.file", "node.toml в порядке")
                    .data("path", path.display().to_string()),
            );
            Some(config.as_ref())
        }
        ConfigSource::Invalid(path, error) => {
            checks.push(
                Check::new("config.file", Status::Fail, error.clone())
                    .hint("исправьте файл: схема — docs/tmnode.md")
                    .data("path", path.display().to_string()),
            );
            None
        }
    };

    let container = input
        .container
        .clone()
        .or_else(|| config.map(|c| c.runtime.container.clone()))
        .unwrap_or_else(|| crate::node_config::Runtime::default().container);

    let facts = if input.remote {
        for id in &CHECK_IDS[1..12] {
            checks.push(Check::skip(id, "проверка снаружи (--remote)"));
        }
        HostFacts::default()
    } else {
        host_checks(sys, config, &container, &mut checks)
    };

    let addr = input
        .addr
        .clone()
        .or_else(|| config.and_then(|c| c.endpoint.as_ref().map(|e| e.addr.clone())))
        .or_else(|| facts.local_addr.clone());
    let node_key = input
        .node_key
        .or_else(|| config.and_then(NodeConfig::endpoint_key))
        .or(facts.node_key);
    endpoint_checks(
        sys,
        addr.as_deref(),
        node_key,
        input.step_timeout,
        &mut checks,
    )
    .await;

    let target = Target {
        config: match &input.config {
            ConfigSource::Absent => None,
            ConfigSource::Loaded(path, _) | ConfigSource::Invalid(path, _) => {
                Some(path.display().to_string())
            }
        },
        container: (!input.remote).then_some(container),
        addr,
        node_key: node_key.map(hex::encode),
    };
    Report::new(target, checks, now)
}

fn host_checks<S: System>(
    sys: &S,
    config: Option<&NodeConfig>,
    name: &str,
    checks: &mut Vec<Check>,
) -> HostFacts {
    let mut facts = HostFacts::default();

    // runtime.docker / runtime.container
    let container = match sys.container(name) {
        Err(err) => {
            let (summary, hint) = match err {
                DockerError::Missing => (
                    "Docker на этой машине не найден".to_owned(),
                    "если нода на другом сервере, запустите с --remote",
                ),
                DockerError::Failed(msg) => (
                    format!("Docker не ответил: {msg}"),
                    "нужны права на Docker: запустите от root или из группы docker",
                ),
            };
            checks.push(Check::new("runtime.docker", Status::Error, summary).hint(hint));
            checks.push(Check::skip("runtime.container", "Docker недоступен"));
            None
        }
        Ok(found) => {
            checks.push(Check::ok("runtime.docker", "Docker отвечает"));
            match found {
                None => {
                    checks.push(
                        Check::new(
                            "runtime.container",
                            Status::Fail,
                            format!("контейнер {name} не найден"),
                        )
                        .hint("проверьте runtime.container в node.toml или --container"),
                    );
                    None
                }
                Some(c) => {
                    checks.push(container_check(name, &c));
                    Some(c)
                }
            }
        }
    };

    // runtime.config — окружение контейнера тем же кодом, что у ноды.
    let effective = match &container {
        None => {
            checks.push(Check::skip("runtime.config", "нет контейнера"));
            None
        }
        Some(c) => {
            let vars = c
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().to_owned()));
            match node_config::from_env_vars(vars) {
                Ok(cfg) => {
                    checks.push(effective_check(&cfg));
                    Some(cfg)
                }
                Err(err) => {
                    checks.push(
                        Check::new(
                            "runtime.config",
                            Status::Fail,
                            format!("нода не примет такое окружение: {err:#}"),
                        )
                        .hint("исправьте переменные в .env / compose и пересоздайте контейнер"),
                    );
                    None
                }
            }
        }
    };

    checks.push(drift_check(config, effective.as_ref(), container.as_ref()));

    // host.data_dir
    let data_dir = match (&effective, &container) {
        (Some(cfg), Some(c)) => {
            let inside = Path::new(&cfg.storage_path);
            let host = config
                .and_then(|n| n.runtime.data_dir.clone())
                .or_else(|| c.host_path(inside));
            match &host {
                Some(path) => checks.push(
                    Check::ok("host.data_dir", format!("данные ноды в {}", path.display()))
                        .data("host_path", path.display().to_string())
                        .data("storage_path", cfg.storage_path.clone()),
                ),
                None => checks.push(
                    Check::new(
                        "host.data_dir",
                        Status::Fail,
                        format!(
                            "{} не вынесен на хост: очереди и ключ ноды пропадут при пересоздании контейнера",
                            cfg.storage_path
                        ),
                    )
                    .hint(format!("смонтируйте том в {}", cfg.storage_path)),
                ),
            }
            host
        }
        _ => {
            checks.push(Check::skip("host.data_dir", "конфиг ноды не разобран"));
            None
        }
    };

    // identity.secret / identity.pin
    let identity = identity_secret_check(sys, effective.as_ref(), data_dir.as_deref(), checks);
    checks.push(pin_check(config, identity.as_ref()));
    facts.node_key = identity.map(|i| i.public());

    // host.disk / host.blob_reserve
    match &data_dir {
        Some(dir) => checks.push(disk_check(sys, dir)),
        None => checks.push(Check::skip("host.disk", "каталог данных не известен")),
    }
    checks.push(blob_reserve_check(
        sys,
        effective.as_ref(),
        container.as_ref(),
        config,
    ));

    // host.memory / host.clock — от контейнера не зависят.
    let backend = effective.as_ref().map(|c| c.delivery.backend);
    checks.push(memory_check(sys, backend));
    checks.push(match sys.clock_synced() {
        Some(true) => Check::ok("host.clock", "часы синхронизированы (NTP)"),
        Some(false) => Check::new("host.clock", Status::Warn, "часы не синхронизированы")
            .hint("включите NTP: timedatectl set-ntp true — от часов зависят сроки сертификатов и конфигурации"),
        None => Check::skip("host.clock", "не удалось узнать (нет timedatectl)"),
    });

    if let (Some(cfg), Some(c)) = (&effective, &container) {
        facts.local_addr = bind_port(&cfg.bind_addr)
            .and_then(|port| c.published_port(port))
            .map(|binding| {
                let host = match binding.host_ip.as_str() {
                    "" | "0.0.0.0" | "::" => "127.0.0.1",
                    ip => ip,
                };
                if host.contains(':') {
                    format!("[{host}]:{}", binding.host_port)
                } else {
                    format!("{host}:{}", binding.host_port)
                }
            });
    }
    facts
}

fn container_check(name: &str, c: &Container) -> Check {
    let check = match (c.status.as_str(), c.health.as_deref()) {
        ("running", Some("unhealthy")) => Check::new(
            "runtime.container",
            Status::Fail,
            format!("{name} работает, но healthcheck не проходит"),
        )
        .hint(format!("docker logs {name}")),
        ("running", Some("starting")) => Check::new(
            "runtime.container",
            Status::Warn,
            format!("{name} запускается"),
        )
        .hint("повторите проверку через минуту"),
        ("running", health) => Check::ok(
            "runtime.container",
            match health {
                Some(h) => format!("{name} работает ({h})"),
                None => format!("{name} работает"),
            },
        ),
        (status, _) => Check::new(
            "runtime.container",
            Status::Fail,
            format!("{name} не работает: {status}"),
        )
        .hint(format!("docker logs {name}; docker start {name}")),
    };
    check
        .data("image", c.image.clone())
        .data("status", c.status.clone())
        .data("health", c.health.clone())
        .data("restart_count", c.restart_count)
}

fn effective_check(cfg: &node_config::Config) -> Check {
    let backend = backend_name(cfg.delivery.backend);
    Check::ok(
        "runtime.config",
        format!(
            "окружение разобрано: бэкенд {backend}, хранилище файлов {}",
            if cfg.blobs.enabled {
                "включено"
            } else {
                "выключено"
            }
        ),
    )
    .data("backend", backend)
    .data("storage_path", cfg.storage_path.clone())
    .data("bind_addr", cfg.bind_addr.clone())
    .data("blobs_enabled", cfg.blobs.enabled)
    .data("queue_addressing", cfg.queue_addressing_enabled)
}

/// Расхождение между тем, какой нода должна быть (`node.toml`), и тем, как
/// она запущена.
fn drift_check(
    config: Option<&NodeConfig>,
    effective: Option<&node_config::Config>,
    container: Option<&Container>,
) -> Check {
    let (Some(config), Some(effective)) = (config, effective) else {
        return Check::skip(
            "config.drift",
            "нужны и node.toml, и разобранный конфиг ноды",
        );
    };
    let mut diffs = Vec::new();
    if let Some(expected) = &config.delivery {
        let actual = backend_name(effective.delivery.backend);
        if expected.backend.as_str() != actual {
            diffs.push(format!(
                "бэкенд: в node.toml {}, нода запущена на {actual}",
                expected.backend.as_str()
            ));
        }
    }
    if let (Some(endpoint), Some(c)) = (&config.endpoint, container)
        && let Some(port) = endpoint
            .addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
    {
        let published: Vec<u16> = bind_port(&effective.bind_addr)
            .map(|bind| {
                c.ports
                    .iter()
                    .filter(|p| p.container_port == bind)
                    .map(|p| p.host_port)
                    .collect()
            })
            .unwrap_or_default();
        if !published.is_empty() && !published.contains(&port) {
            diffs.push(format!(
                "порт: endpoint.addr указывает {port}, контейнер опубликован на {}",
                published[0]
            ));
        }
    }
    if diffs.is_empty() {
        Check::ok("config.drift", "нода запущена так, как описано в node.toml")
    } else {
        Check::new("config.drift", Status::Warn, diffs.join("; "))
            .hint("приведите node.toml или окружение контейнера к одному виду")
    }
}

fn identity_secret_check<S: System>(
    sys: &S,
    effective: Option<&node_config::Config>,
    data_dir: Option<&Path>,
    checks: &mut Vec<Check>,
) -> Option<NodeIdentity> {
    let Some(effective) = effective else {
        checks.push(Check::skip("identity.secret", "конфиг ноды не разобран"));
        return None;
    };
    if let Some(raw) = effective.node_identity_key.as_deref() {
        return match NodeIdentity::from_secret_hex(raw, NodeKeySource::Configured) {
            Ok(identity) => {
                checks.push(
                    Check::ok("identity.secret", "ключ ноды задан через NODE_IDENTITY_KEY")
                        .data("source", "env"),
                );
                Some(identity)
            }
            Err(_) => {
                checks.push(
                    Check::new(
                        "identity.secret",
                        Status::Fail,
                        "NODE_IDENTITY_KEY — не 64 hex-символа: нода не стартует",
                    )
                    .hint("восстановите ключ из бэкапа (docs/runbook-node-key.md)"),
                );
                None
            }
        };
    }
    let Some(dir) = data_dir else {
        checks.push(Check::skip("identity.secret", "каталог данных не известен"));
        return None;
    };
    let path = dir.join(NODE_KEY_FILE);
    let shown = path.display().to_string();
    match sys.read_secret(&path) {
        Ok(raw) => match NodeIdentity::from_secret_hex(&raw, NodeKeySource::File) {
            Ok(identity) => {
                let check = match sys.file_mode(&path) {
                    Ok(mode) if mode & 0o077 != 0 => Check::new(
                        "identity.secret",
                        Status::Warn,
                        format!("ключ ноды доступен не только владельцу (права {mode:o})"),
                    )
                    .hint(format!("chmod 600 {shown}")),
                    _ => Check::ok("identity.secret", "ключ ноды на месте"),
                };
                checks.push(check.data("source", "file").data("path", shown));
                Some(identity)
            }
            Err(_) => {
                checks.push(
                    Check::new(
                        "identity.secret",
                        Status::Fail,
                        "файл ключа ноды повреждён: нода не стартует",
                    )
                    .hint("восстановите node_identity_key из бэкапа (docs/runbook-node-key.md)")
                    .data("path", shown),
                );
                None
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            checks.push(
                Check::new(
                    "identity.secret",
                    Status::Fail,
                    "файла ключа нет: при следующем старте нода создаст новый ключ, и клиенты перестанут подключаться",
                )
                .hint("восстановите node_identity_key из бэкапа (docs/runbook-node-key.md)")
                .data("path", shown),
            );
            None
        }
        Err(err) => {
            checks.push(
                Check::new(
                    "identity.secret",
                    Status::Error,
                    format!("не удалось прочитать ключ ноды: {err}"),
                )
                .hint("запустите от root")
                .data("path", shown),
            );
            None
        }
    }
}

fn pin_check(config: Option<&NodeConfig>, identity: Option<&NodeIdentity>) -> Check {
    let Some(identity) = identity else {
        return Check::skip("identity.pin", "ключ ноды не прочитан");
    };
    let public = identity.public();
    let check = match config.and_then(NodeConfig::endpoint_key) {
        Some(pinned) if pinned != public => Check::new(
            "identity.pin",
            Status::Fail,
            "ключ ноды не совпадает с endpoint.node_key: клиенты с этим пином не подключатся",
        )
        .hint(
            "верните прежний ключ из бэкапа или обновите пин у клиентов (docs/runbook-node-key.md)",
        )
        .data("expected", hex::encode(pinned)),
        Some(_) => Check::ok("identity.pin", "ключ ноды совпадает с пином в node.toml"),
        None => Check::ok("identity.pin", "пин в node.toml не задан"),
    };
    check
        .data("node_key", hex::encode(public))
        .data("fingerprint", fingerprint(&public))
}

fn disk_check<S: System>(sys: &S, dir: &Path) -> Check {
    match sys.disk_space(dir) {
        Err(err) => Check::new(
            "host.disk",
            Status::Error,
            format!("не удалось узнать место на диске: {err}"),
        ),
        Ok(space) => {
            let summary = format!(
                "свободно {} из {}",
                human_bytes(space.available),
                human_bytes(space.total)
            );
            let check = if space.available < DISK_FAIL_BELOW {
                Check::new("host.disk", Status::Fail, summary)
                    .hint("нода вот-вот упрётся в диск: освободите место или расширьте диск")
            } else if space.available < DISK_WARN_BELOW {
                Check::new("host.disk", Status::Warn, summary)
                    .hint("места мало: освободите или расширьте диск")
            } else {
                Check::ok("host.disk", summary)
            };
            check
                .data("total_bytes", space.total)
                .data("available_bytes", space.available)
        }
    }
}

fn blob_reserve_check<S: System>(
    sys: &S,
    effective: Option<&node_config::Config>,
    container: Option<&Container>,
    config: Option<&NodeConfig>,
) -> Check {
    let (Some(effective), Some(container)) = (effective, container) else {
        return Check::skip("host.blob_reserve", "конфиг ноды не разобран");
    };
    if !effective.blobs.enabled {
        return Check::skip("host.blob_reserve", "хранилище файлов выключено");
    }
    let inside = Path::new(&effective.blobs.dir);
    let host = container.host_path(inside).or_else(|| {
        // Каталог данных переопределён в node.toml: блобы по умолчанию
        // лежат внутри него.
        let data = config.and_then(|c| c.runtime.data_dir.as_ref())?;
        let rest = inside.strip_prefix(&effective.storage_path).ok()?;
        Some(data.join(rest))
    });
    let Some(host) = host else {
        return Check::new(
            "host.blob_reserve",
            Status::Fail,
            format!(
                "{} не вынесен на хост: файлы пропадут при пересоздании контейнера",
                effective.blobs.dir
            ),
        )
        .hint(format!("смонтируйте том в {}", effective.blobs.dir));
    };
    // Каталог блобов создаёт нода; пока его нет, место считается по
    // ближайшему существующему родителю — та же файловая система.
    let measured = host
        .ancestors()
        .find(|p| sys.disk_space(p).is_ok())
        .unwrap_or(&host)
        .to_path_buf();
    match sys.disk_space(&measured) {
        Err(err) => Check::new(
            "host.blob_reserve",
            Status::Error,
            format!("не удалось узнать место под файлы: {err}"),
        ),
        Ok(space) => {
            let reserve = effective.blobs.disk_reserve;
            let check = if space.available <= reserve {
                Check::new(
                    "host.blob_reserve",
                    Status::Warn,
                    format!(
                        "свободно {} при резерве {}: загрузка файлов получает QUOTA",
                        human_bytes(space.available),
                        human_bytes(reserve)
                    ),
                )
                .hint("расширьте диск или уменьшите BLOB_DISK_RESERVE_BYTES")
            } else {
                Check::ok(
                    "host.blob_reserve",
                    format!(
                        "под файлы доступно {} сверх резерва {}",
                        human_bytes(space.available - reserve),
                        human_bytes(reserve)
                    ),
                )
            };
            check
                .data("available_bytes", space.available)
                .data("reserve_bytes", reserve)
                .data("host_path", host.display().to_string())
        }
    }
}

fn memory_check<S: System>(sys: &S, backend: Option<DeliveryBackendKind>) -> Check {
    let memory = match sys.memory() {
        Ok(memory) => memory,
        Err(err) => {
            return Check::new(
                "host.memory",
                Status::Error,
                format!("не удалось узнать память: {err}"),
            );
        }
    };
    let recommended = match backend {
        Some(DeliveryBackendKind::JetStream) => MEMORY_JETSTREAM,
        _ => MEMORY_SLED,
    };
    let summary = format!(
        "всего {}, доступно {}",
        human_bytes(memory.total),
        human_bytes(memory.available)
    );
    // Ядро забирает часть памяти себе: на машине «1 ГиБ» MemTotal — около
    // 960 МиБ. Предупреждать её владельца за это незачем.
    let check = if memory.total < recommended / 10 * 9 {
        Check::new("host.memory", Status::Warn, summary).hint(format!(
            "для этого бэкенда рекомендуется от {}",
            human_bytes(recommended)
        ))
    } else if memory.available < MEMORY_AVAILABLE_WARN_BELOW {
        Check::new("host.memory", Status::Warn, summary)
            .hint("свободной памяти почти нет: проверьте, что ещё работает на машине")
    } else {
        Check::ok("host.memory", summary)
    };
    check
        .data("total_bytes", memory.total)
        .data("available_bytes", memory.available)
}

async fn endpoint_checks<S: System>(
    sys: &S,
    addr: Option<&str>,
    node_key: Option<[u8; 32]>,
    step_timeout: Duration,
    checks: &mut Vec<Check>,
) {
    let (Some(addr), Some(node_key)) = (addr, node_key) else {
        let why = if addr.is_none() {
            "адрес ноды не известен: задайте endpoint.addr в node.toml или --addr"
        } else {
            "ключ ноды не известен: задайте endpoint.node_key в node.toml или --node-key"
        };
        for id in ["endpoint.tcp", "endpoint.handshake", "endpoint.config"] {
            checks.push(Check::skip(id, why));
        }
        return;
    };

    match sys.probe(addr, &node_key, step_timeout).await {
        Ok(outcome) => {
            let cfg = &outcome.config;
            checks.push(
                Check::ok(
                    "endpoint.tcp",
                    format!("порт открыт ({} мс)", outcome.connect_time.as_millis()),
                )
                .data("connect_ms", outcome.connect_time.as_millis() as u64),
            );
            checks.push(
                Check::ok(
                    "endpoint.handshake",
                    format!(
                        "нода узнала пин и пустила ({} мс)",
                        outcome.handshake_time.as_millis()
                    ),
                )
                .data("handshake_ms", outcome.handshake_time.as_millis() as u64),
            );
            checks.push(
                Check::ok(
                    "endpoint.config",
                    format!(
                        "конфигурация подписана ключом ноды; протокол {}, файлы {}",
                        cfg.proto_version,
                        if cfg.supports_blobs {
                            "есть"
                        } else {
                            "нет"
                        }
                    ),
                )
                .data("proto_version", cfg.proto_version)
                .data("expires_at", cfg.expires_at)
                .data("supports_delivery_ack", cfg.supports_delivery_ack)
                .data("supports_queue_addressing", cfg.supports_queue_addressing)
                .data("supports_blobs", cfg.supports_blobs)
                .data("blob_max_size", cfg.blob_max_size),
            );
        }
        Err(err) => {
            let reason = format!("{:#}", err.error);
            let reached = |stage: ProbeStage| err.stage as u8 > stage as u8;
            checks.push(if reached(ProbeStage::Connect) {
                Check::ok("endpoint.tcp", "порт открыт")
            } else {
                Check::new(
                    "endpoint.tcp",
                    Status::Fail,
                    format!("нет соединения с {addr}: {reason}"),
                )
                .hint("проверьте адрес, публикацию порта контейнера и файрвол")
            });
            checks.push(match err.stage {
                ProbeStage::Connect => Check::skip("endpoint.handshake", "нет соединения"),
                ProbeStage::Handshake => Check::new(
                    "endpoint.handshake",
                    Status::Fail,
                    format!("рукопожатие не прошло: {reason}"),
                )
                .hint("ключ ноды не совпадает с пином, или по этому адресу отвечает не нода"),
                ProbeStage::Auth => Check::new(
                    "endpoint.handshake",
                    Status::Fail,
                    format!("нода отказала во входе: {reason}"),
                )
                .hint("docker logs ноды покажет причину"),
                ProbeStage::Config => Check::ok("endpoint.handshake", "нода узнала пин и пустила"),
            });
            checks.push(if err.stage == ProbeStage::Config {
                Check::new(
                    "endpoint.config",
                    Status::Fail,
                    format!("конфигурация ноды не прошла проверку: {reason}"),
                )
                .hint("проверьте часы на ноде и на этой машине: подпись имеет срок")
            } else {
                Check::skip("endpoint.config", "сессии нет")
            });
        }
    }
}

fn backend_name(kind: DeliveryBackendKind) -> &'static str {
    match kind {
        DeliveryBackendKind::Sled => "sled",
        DeliveryBackendKind::JetStream => "jetstream",
    }
}

fn bind_port(bind_addr: &str) -> Option<u16> {
    bind_addr.rsplit_once(':')?.1.parse().ok()
}

/// Байты по-человечески: `1.7 ГиБ`, `512 МиБ`.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value >= 10.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
