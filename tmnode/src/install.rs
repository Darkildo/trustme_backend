//! `tmnode install` — нода на чистом сервере одной командой: Docker-
//! контейнеры ноды, по желанию NATS (JetStream) и coturn, файл настроек и
//! `node.toml`, служба агента.
//!
//! Без docker compose: только `docker` — меньше зависимостей у новичка.
//! Все действия идут через [`Runner`], и тесты сверяют точный список
//! команд, не трогая машину.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use trust_message_tcp::net::noise::{NODE_KEY_FILE, NodeIdentity, NodeKeySource, fingerprint};

use crate::node_config::Backend;
use crate::protocol::{CoturnSpec, InstallSpec, RuntimeDoc};

/// Где что лежит на хосте.
#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    /// Каталог данных ноды (sled, ключ, `runtime.toml`).
    pub data_dir: PathBuf,
    /// Каталог настроек `tmnode`: `node.toml`, `agent.toml`, конфиг coturn.
    pub etc_dir: PathBuf,
    /// Юнит systemd агента.
    pub unit_path: PathBuf,
}

impl Layout {
    /// Пути по умолчанию с переопределением из окружения:
    /// `TMNODE_ETC_DIR`, `TMNODE_DATA_DIR`, `TMNODE_UNIT_PATH`. Нужны, когда
    /// `tmnode` работает не в стандартных каталогах — например, агент рядом
    /// с нодой, запущенной без Docker.
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> Self {
        let default = Self::default();
        Self {
            data_dir: env("TMNODE_DATA_DIR").map_or(default.data_dir, PathBuf::from),
            etc_dir: env("TMNODE_ETC_DIR").map_or(default.etc_dir, PathBuf::from),
            unit_path: env("TMNODE_UNIT_PATH").map_or(default.unit_path, PathBuf::from),
        }
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/trustme/node"),
            etc_dir: PathBuf::from("/etc/tmnode"),
            unit_path: PathBuf::from("/etc/systemd/system/tmnode-agent.service"),
        }
    }
}

/// Имена контейнеров и сети.
pub const NODE_CONTAINER: &str = "message-service";
pub const NATS_CONTAINER: &str = "trustme-nats";
pub const COTURN_CONTAINER: &str = "trustme-coturn";
pub const NETWORK: &str = "trustme";
pub const NATS_IMAGE: &str = "nats:2.12.6-alpine";
/// Каталог данных внутри контейнера ноды и её пользователь (Dockerfile).
const NODE_DATA_INSIDE: &str = "/srv/trust-message/data";
const NODE_UID: u32 = 10001;
/// Пользователь coturn в официальном образе (`nobody`).
const COTURN_UID: u32 = 65534;

/// Действия над машиной.
pub trait Runner {
    /// Выполнить команду; ошибка — ненулевой код выхода с его stderr.
    fn run(&self, program: &str, args: &[String]) -> Result<String>;
    /// Долгая команда (`docker pull`): не занимает поток, пока идёт, — агент
    /// тем временем шлёт heartbeat, — и обрывается, если `idle` ничего не
    /// выводит: зависшее соединение иначе держит её часами. Обрыв — ошибка
    /// [`Stalled`]. По умолчанию — обычный [`Runner::run`].
    fn run_long<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        idle: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
        let _ = idle;
        Box::pin(std::future::ready(self.run(program, args)))
    }
    /// Записать файл атомарно с правами `mode` и владельцем `uid`.
    fn write_file(&self, path: &Path, contents: &[u8], mode: u32, uid: Option<u32>) -> Result<()>;
    fn create_dir(&self, path: &Path, uid: Option<u32>) -> Result<()>;
    fn read_file(&self, path: &Path) -> Result<Option<String>>;
    /// Переименовать файл. В пределах одного каталога — атомарно: так
    /// подменяется бинарь `tmnode`.
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
    /// Скопировать файл с правами; копия появляется целиком или никак.
    fn copy_file(&self, from: &Path, to: &Path) -> Result<()>;
    /// Удалить файл; файла нет — не ошибка.
    fn remove_file(&self, path: &Path) -> Result<()>;
    fn sleep(&self, duration: Duration);
}

/// Команда ничего не выводила дольше допустимого и оборвана.
#[derive(Debug)]
pub struct Stalled {
    pub command: String,
    pub idle: Duration,
}

impl std::fmt::Display for Stalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: нет вывода {} с — оборвано",
            self.command,
            self.idle.as_secs()
        )
    }
}

impl std::error::Error for Stalled {}

/// Настоящая машина.
pub struct HostRunner;

impl HostRunner {
    async fn run_watched(&self, program: &str, args: &[String], idle: Duration) -> Result<String> {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

        let command = format!(
            "{program} {}",
            args.first().map(String::as_str).unwrap_or("")
        );
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("запуск {program}"))?;
        let mut stderr = child.stderr.take().expect("stderr piped");
        let errors = tokio::spawn(async move {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text).await;
            text
        });
        let mut lines = BufReader::new(child.stdout.take().expect("stdout piped")).lines();
        let mut out = String::new();
        let read = loop {
            match tokio::time::timeout(idle, lines.next_line()).await {
                Err(_) => {
                    break Err(anyhow!(Stalled {
                        command: command.clone(),
                        idle,
                    }));
                }
                Ok(Ok(Some(line))) => {
                    out.push_str(&line);
                    out.push('\n');
                }
                Ok(Ok(None)) => break Ok(()),
                Ok(Err(err)) => break Err(anyhow!(err).context(format!("вывод {command}"))),
            }
        };
        if let Err(err) = read {
            // stderr не дочитывается: его может держать потомок команды.
            errors.abort();
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(err);
        }
        let status = child
            .wait()
            .await
            .with_context(|| format!("ожидание {command}"))?;
        let errors = errors.await.unwrap_or_default();
        if !status.success() {
            bail!("{command}: {}", errors.trim());
        }
        Ok(out)
    }
}

/// Сменить владельца может только root. Без root (агент рядом с нодой,
/// запущенной тем же пользователем, разработка) владелец остаётся текущим —
/// он и так может читать свои файлы.
fn chown_if_root(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let euid = std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0);
    if euid != 0 {
        return Ok(());
    }
    std::os::unix::fs::chown(path, Some(uid), Some(uid))
        .with_context(|| format!("владелец {}", path.display()))
}

impl Runner for HostRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<String> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("запуск {program}"))?;
        if !output.status.success() {
            bail!(
                "{program} {}: {}",
                args.first().map(String::as_str).unwrap_or(""),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn run_long<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        idle: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + 'a>> {
        Box::pin(self.run_watched(program, args, idle))
    }

    fn write_file(&self, path: &Path, contents: &[u8], mode: u32, uid: Option<u32>) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let tmp = path.with_extension("tmnode-tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("запись {}", tmp.display()))?;
        file.write_all(contents)?;
        file.sync_all()?;
        // `mode` при создании режет umask: выставляем явно.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        if let Some(uid) = uid {
            chown_if_root(&tmp, uid)?;
        }
        std::fs::rename(&tmp, path).with_context(|| format!("запись {}", path.display()))?;
        Ok(())
    }

    fn create_dir(&self, path: &Path, uid: Option<u32>) -> Result<()> {
        std::fs::create_dir_all(path).with_context(|| format!("каталог {}", path.display()))?;
        if let Some(uid) = uid {
            chown_if_root(path, uid)?;
        }
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("чтение {}", path.display())),
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        std::fs::rename(from, to)
            .with_context(|| format!("переименование {} в {}", from.display(), to.display()))
    }

    fn copy_file(&self, from: &Path, to: &Path) -> Result<()> {
        let mut tmp = to.as_os_str().to_owned();
        tmp.push(".tmnode-copy");
        let tmp = PathBuf::from(tmp);
        std::fs::copy(from, &tmp)
            .with_context(|| format!("копирование {} в {}", from.display(), tmp.display()))?;
        std::fs::rename(&tmp, to).with_context(|| format!("запись {}", to.display()))
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                Err(err).with_context(|| format!("удаление {}", path.display()))
            }
            _ => Ok(()),
        }
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Итог установки.
#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub node_key: String,
    pub fingerprint: String,
    pub addr: String,
}

/// Что ещё нужно `node.toml` от установщика.
pub struct NodeMeta<'a> {
    pub id: Option<&'a str>,
    pub name: Option<&'a str>,
    /// Нода подключена к админке — тогда `management.mode = "managed"`.
    pub managed: bool,
}

pub fn install(
    runner: &dyn Runner,
    layout: &Layout,
    spec: &InstallSpec,
    runtime: Option<&RuntimeDoc>,
    meta: &NodeMeta<'_>,
) -> Result<Installed> {
    check_spec(spec)?;
    // node.toml пишется последним, но проверяется до первого шага: с
    // файлом, который не примет сам tmnode, агент не работает, а ставить
    // ради этого ноду незачем. Ключ ещё не известен — на его месте нули.
    let addr = format!("{}:{}", spec.public_host, spec.port);
    check_node_toml(&node_toml(
        meta,
        &addr,
        &"0".repeat(64),
        layout,
        spec.backend,
    ))?;
    let docker = |args: &[&str]| -> Result<String> {
        runner.run(
            "docker",
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    };
    docker(&["version", "--format", "{{.Server.Version}}"])
        .context("Docker не отвечает: установите docker.io и запустите службу")?;

    // Не затираем живую ноду: её ключ и данные дороже повторной установки.
    if docker(&["inspect", "--type", "container", NODE_CONTAINER]).is_ok() {
        bail!(
            "контейнер {NODE_CONTAINER} уже есть: нода установлена. Для обновления — tmnode update, \
             для переустановки удалите контейнер сами"
        );
    }

    if docker(&["network", "inspect", NETWORK]).is_err() {
        docker(&["network", "create", NETWORK])?;
    }
    runner.create_dir(&layout.data_dir, Some(NODE_UID))?;
    runner.create_dir(&layout.etc_dir, None)?;
    if let Some(runtime) = runtime {
        // Файл читает нода в контейнере — владелец её пользователь.
        runner.write_file(
            &layout.data_dir.join("runtime.toml"),
            runtime.content.as_bytes(),
            0o600,
            Some(NODE_UID),
        )?;
    }

    let mut env = vec![
        format!("BIND_PORT={}", spec.port),
        format!("STORAGE_PATH={NODE_DATA_INSIDE}"),
    ];
    if spec.backend == Backend::Jetstream {
        let nats_dir = layout.data_dir.join("nats");
        runner.create_dir(&nats_dir, None)?;
        docker(&["pull", NATS_IMAGE])?;
        run_container(
            runner,
            NATS_CONTAINER,
            &["--network", NETWORK],
            &[format!("{}:/data", nats_dir.display())],
            &[],
            NATS_IMAGE,
            &["-js", "-sd", "/data"],
        )?;
        env.push("DELIVERY_BACKEND=jetstream".into());
        env.push(format!("NATS_URL=nats://{NATS_CONTAINER}:4222"));
    }

    docker(&["pull", &spec.image])?;
    run_container(
        runner,
        NODE_CONTAINER,
        &["--network", NETWORK, "-p", &format!("{0}:{0}", spec.port)],
        &[format!("{}:{NODE_DATA_INSIDE}", layout.data_dir.display())],
        &env,
        &spec.image,
        &[],
    )?;

    if let Some(coturn) = &spec.coturn {
        install_coturn(runner, layout, coturn)?;
    }

    let key = wait_for_key(runner, &layout.data_dir)?;
    let text = node_toml(meta, &addr, &key, layout, spec.backend);
    check_node_toml(&text)?;
    runner.write_file(
        &layout.etc_dir.join("node.toml"),
        text.as_bytes(),
        0o644,
        None,
    )?;
    Ok(Installed {
        fingerprint: fingerprint(&decode_key(&key)?),
        node_key: key,
        addr,
    })
}

fn check_spec(spec: &InstallSpec) -> Result<()> {
    let safe = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-:/@".contains(c))
    };
    if !safe(&spec.image) {
        bail!("image: недопустимое имя образа `{}`", spec.image);
    }
    if !safe(&spec.public_host) || spec.public_host.contains('/') {
        bail!("public_host: недопустимый адрес `{}`", spec.public_host);
    }
    if spec.port == 0 {
        bail!("port: 0");
    }
    if let Some(c) = &spec.coturn {
        if !safe(&c.image) || !safe(&c.realm) {
            bail!("coturn: недопустимый образ или realm");
        }
        if c.secret.len() < 16 || c.secret.chars().any(|ch| ch.is_whitespace() || ch == '"') {
            bail!("coturn.secret: от 16 символов, без пробелов и кавычек");
        }
        if c.relay_min_port == 0 || c.relay_min_port > c.relay_max_port {
            bail!("coturn: неверный диапазон relay-портов");
        }
    }
    Ok(())
}

fn run_container(
    runner: &dyn Runner,
    name: &str,
    extra: &[&str],
    volumes: &[String],
    env: &[String],
    image: &str,
    args: &[&str],
) -> Result<String> {
    let mut cmd: Vec<String> = ["run", "-d", "--name", name, "--restart", "unless-stopped"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    cmd.extend(extra.iter().map(|s| s.to_string()));
    for volume in volumes {
        cmd.push("-v".into());
        cmd.push(volume.clone());
    }
    for var in env {
        cmd.push("-e".into());
        cmd.push(var.clone());
    }
    cmd.push(image.into());
    cmd.extend(args.iter().map(|s| s.to_string()));
    runner.run("docker", &cmd)
}

/// coturn в сети хоста: ему нужен диапазон UDP-портов relay, а проброс
/// тысяч портов через docker медленный и капризный. Секрет — в файле
/// конфигурации, не в командной строке: её видят `ps` и `docker inspect`.
fn install_coturn(runner: &dyn Runner, layout: &Layout, coturn: &CoturnSpec) -> Result<()> {
    let dir = layout.etc_dir.join("coturn");
    runner.create_dir(&dir, None)?;
    let conf = dir.join("turnserver.conf");
    runner.write_file(
        &conf,
        turnserver_conf(coturn).as_bytes(),
        0o400,
        Some(COTURN_UID),
    )?;
    runner.run("docker", &["pull".into(), coturn.image.clone()])?;
    run_container(
        runner,
        COTURN_CONTAINER,
        &["--network", "host"],
        &[format!("{}:/etc/coturn/turnserver.conf:ro", conf.display())],
        &[],
        &coturn.image,
        &["-c", "/etc/coturn/turnserver.conf"],
    )?;
    Ok(())
}

/// Конфигурация coturn. Временные учётки по общему секрету — те же, что
/// подписывает нода (server-contract.md §6.12). Ретрансляция во
/// внутренние сети запрещена: иначе TURN стал бы входом в сеть сервера.
pub fn turnserver_conf(c: &CoturnSpec) -> String {
    format!(
        "# Создано tmnode install. Секрет — тот же, что в [ice] runtime.toml ноды.\n\
         listening-port={port}\n\
         min-port={min}\n\
         max-port={max}\n\
         realm={realm}\n\
         use-auth-secret\n\
         static-auth-secret={secret}\n\
         fingerprint\n\
         no-cli\n\
         no-multicast-peers\n\
         no-tlsv1\n\
         no-tlsv1_1\n\
         log-file=stdout\n\
         denied-peer-ip=0.0.0.0-0.255.255.255\n\
         denied-peer-ip=10.0.0.0-10.255.255.255\n\
         denied-peer-ip=100.64.0.0-100.127.255.255\n\
         denied-peer-ip=127.0.0.0-127.255.255.255\n\
         denied-peer-ip=169.254.0.0-169.254.255.255\n\
         denied-peer-ip=172.16.0.0-172.31.255.255\n\
         denied-peer-ip=192.168.0.0-192.168.255.255\n\
         denied-peer-ip=::1\n\
         denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n\
         denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
        port = c.port,
        min = c.relay_min_port,
        max = c.relay_max_port,
        realm = c.realm,
        secret = c.secret,
    )
}

/// Ключ создаёт нода при первом старте; ждём его до минуты.
fn wait_for_key(runner: &dyn Runner, data_dir: &Path) -> Result<String> {
    let path = data_dir.join(NODE_KEY_FILE);
    for _ in 0..60 {
        if let Some(secret) = runner.read_file(&path)? {
            let identity = NodeIdentity::from_secret_hex(secret.trim(), NodeKeySource::File)
                .context("ключ ноды повреждён")?;
            return Ok(identity.public_hex());
        }
        runner.sleep(Duration::from_secs(1));
    }
    bail!("нода не создала ключ за минуту: docker logs {NODE_CONTAINER} покажет причину")
}

fn decode_key(hex_key: &str) -> Result<[u8; 32]> {
    crate::node_config::parse_node_key(hex_key)
}

fn node_toml(
    meta: &NodeMeta<'_>,
    addr: &str,
    key: &str,
    layout: &Layout,
    backend: Backend,
) -> String {
    let mut out = String::from("# Создано tmnode install. Схема — docs/tmnode.md.\nschema = 1\n");
    if meta.id.is_some() || meta.name.is_some() {
        out.push_str("\n[node]\n");
        if let Some(name) = meta.name {
            out.push_str(&format!("name = {}\n", toml_string(name)));
        }
        if let Some(id) = meta.id {
            out.push_str(&format!("id = {}\n", toml_string(id)));
        }
    }
    out.push_str(&format!(
        "\n[management]\nmode = \"{}\"\n",
        if meta.managed { "managed" } else { "local" }
    ));
    out.push_str(&format!(
        "\n[endpoint]\naddr = {}\nnode_key = \"{key}\"\n",
        toml_string(addr)
    ));
    out.push_str(&format!(
        "\n[runtime]\nkind = \"docker\"\ncontainer = \"{NODE_CONTAINER}\"\ndata_dir = {}\n",
        toml_string(&layout.data_dir.display().to_string())
    ));
    out.push_str(&format!(
        "\n[delivery]\nbackend = \"{}\"\n",
        backend.as_str()
    ));
    out
}

/// Тот же разбор, что у `tmnode doctor` и агента.
fn check_node_toml(text: &str) -> Result<()> {
    crate::node_config::NodeConfig::parse(text)
        .map(drop)
        .context("node.toml для этой ноды не прошёл бы проверку")
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

/// Юнит systemd агента.
pub fn agent_unit(tmnode_path: &str) -> String {
    format!(
        "[Unit]\n\
         Description=TrustMe node agent (tmnode)\n\
         After=network-online.target docker.service\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         ExecStart={tmnode_path} agent\n\
         Restart=always\n\
         RestartSec=10\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Поставить и запустить службу агента.
pub fn install_agent_service(
    runner: &dyn Runner,
    layout: &Layout,
    tmnode_path: &str,
) -> Result<()> {
    runner.write_file(
        &layout.unit_path,
        agent_unit(tmnode_path).as_bytes(),
        0o644,
        None,
    )?;
    runner.run("systemctl", &["daemon-reload".into()])?;
    runner.run(
        "systemctl",
        &[
            "enable".into(),
            "--now".into(),
            "tmnode-agent.service".into(),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn sh(script: &str) -> Vec<String> {
        vec!["-c".into(), script.into()]
    }

    #[tokio::test]
    async fn long_commands_are_cut_when_silent() {
        let idle = Duration::from_millis(300);
        let out = HostRunner
            .run_long("sh", &sh("echo one; sleep 0.1; echo two"), idle)
            .await
            .unwrap();
        assert_eq!(out, "one\ntwo\n");

        let started = std::time::Instant::now();
        let err = HostRunner
            .run_long("sh", &sh("echo one; sleep 30"), idle)
            .await
            .unwrap_err();
        assert!(err.is::<Stalled>(), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "команда не убита"
        );

        let err = HostRunner
            .run_long("sh", &sh("echo boom >&2; exit 3"), idle)
            .await
            .unwrap_err();
        assert!(!err.is::<Stalled>());
        assert!(format!("{err:#}").contains("boom"), "{err:#}");
    }

    /// Записанный файл: содержимое, права, владелец.
    type WrittenFile = (String, u32, Option<u32>);

    #[derive(Default)]
    struct FakeRunner {
        commands: RefCell<Vec<String>>,
        files: RefCell<HashMap<PathBuf, WrittenFile>>,
        dirs: RefCell<Vec<PathBuf>>,
        /// Команды (начало строки), которые завершаются ошибкой.
        failing: Vec<&'static str>,
        /// Через сколько чтений ключа он «появится».
        key_after: RefCell<usize>,
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> Result<String> {
            let line = format!("{program} {}", args.join(" "));
            self.commands.borrow_mut().push(line.clone());
            if self.failing.iter().any(|f| line.starts_with(f)) {
                bail!("simulated failure: {line}");
            }
            Ok(String::new())
        }

        fn write_file(
            &self,
            path: &Path,
            contents: &[u8],
            mode: u32,
            uid: Option<u32>,
        ) -> Result<()> {
            self.files.borrow_mut().insert(
                path.to_owned(),
                (String::from_utf8(contents.to_vec()).unwrap(), mode, uid),
            );
            Ok(())
        }

        fn create_dir(&self, path: &Path, _uid: Option<u32>) -> Result<()> {
            self.dirs.borrow_mut().push(path.to_owned());
            Ok(())
        }

        fn read_file(&self, path: &Path) -> Result<Option<String>> {
            if path.ends_with(NODE_KEY_FILE) {
                let mut left = self.key_after.borrow_mut();
                if *left > 0 {
                    *left -= 1;
                    return Ok(None);
                }
                return Ok(Some(hex::encode([0xab_u8; 32])));
            }
            Ok(self.files.borrow().get(path).map(|f| f.0.clone()))
        }

        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            let file = self.files.borrow_mut().remove(from);
            match file {
                Some(file) => {
                    self.files.borrow_mut().insert(to.to_owned(), file);
                    Ok(())
                }
                None => bail!("нет {}", from.display()),
            }
        }

        fn copy_file(&self, from: &Path, to: &Path) -> Result<()> {
            let file = self.files.borrow().get(from).cloned();
            match file {
                Some(file) => {
                    self.files.borrow_mut().insert(to.to_owned(), file);
                    Ok(())
                }
                None => bail!("нет {}", from.display()),
            }
        }

        fn remove_file(&self, path: &Path) -> Result<()> {
            self.files.borrow_mut().remove(path);
            Ok(())
        }

        fn sleep(&self, _duration: Duration) {}
    }

    fn spec(backend: Backend, coturn: bool) -> InstallSpec {
        InstallSpec {
            image: "ghcr.io/darkildo/trustme_backend:v0.6.0".into(),
            public_host: "203.0.113.10".into(),
            port: 18081,
            backend,
            coturn: coturn.then(|| CoturnSpec {
                image: "coturn/coturn:4.6.3".into(),
                realm: "node.example.org".into(),
                secret: "0123456789abcdef0123".into(),
                port: 3478,
                relay_min_port: 49160,
                relay_max_port: 49200,
            }),
        }
    }

    fn fresh() -> FakeRunner {
        FakeRunner {
            // Контейнера и сети ещё нет.
            failing: vec!["docker inspect", "docker network inspect"],
            key_after: RefCell::new(2),
            ..FakeRunner::default()
        }
    }

    fn layout() -> Layout {
        Layout {
            data_dir: "/data".into(),
            etc_dir: "/etc/tmnode".into(),
            unit_path: "/etc/systemd/system/tmnode-agent.service".into(),
        }
    }

    #[test]
    fn sled_node_with_turn_is_installed() {
        let runner = fresh();
        let runtime = RuntimeDoc {
            version: "v1".into(),
            content: "version = \"v1\"\n".into(),
        };
        let meta = NodeMeta {
            id: Some("node-01"),
            name: Some("Офис \"Берлин\""),
            managed: true,
        };
        let done = install(
            &runner,
            &layout(),
            &spec(Backend::Sled, true),
            Some(&runtime),
            &meta,
        )
        .unwrap();
        let public = NodeIdentity::from_seed([0xab; 32], NodeKeySource::File).public_hex();
        assert_eq!(done.node_key, public);
        assert_eq!(done.addr, "203.0.113.10:18081");
        assert_eq!(done.fingerprint.len(), 64 + 15);

        let commands = runner.commands.borrow();
        let docker_runs: Vec<&String> = commands
            .iter()
            .filter(|c| c.starts_with("docker run"))
            .collect();
        assert_eq!(docker_runs.len(), 2);
        assert_eq!(
            docker_runs[0].as_str(),
            "docker run -d --name message-service --restart unless-stopped --network trustme \
             -p 18081:18081 -v /data:/srv/trust-message/data -e BIND_PORT=18081 \
             -e STORAGE_PATH=/srv/trust-message/data ghcr.io/darkildo/trustme_backend:v0.6.0"
        );
        assert!(docker_runs[1].contains("--network host"));
        // Секрет coturn не попадает в командную строку.
        assert!(!commands.iter().any(|c| c.contains("0123456789abcdef0123")));
        assert!(commands.contains(&"docker network create trustme".to_string()));

        let files = runner.files.borrow();
        let (runtime_file, mode, uid) = &files[Path::new("/data/runtime.toml")];
        assert_eq!(
            (runtime_file.as_str(), *mode, *uid),
            ("version = \"v1\"\n", 0o600, Some(NODE_UID))
        );
        let (conf, mode, uid) = &files[Path::new("/etc/tmnode/coturn/turnserver.conf")];
        assert!(conf.contains("static-auth-secret=0123456789abcdef0123"));
        assert!(conf.contains("denied-peer-ip=10.0.0.0-10.255.255.255"));
        assert_eq!((*mode, *uid), (0o400, Some(COTURN_UID)));

        let (node_toml, _, _) = &files[Path::new("/etc/tmnode/node.toml")];
        let parsed = crate::node_config::NodeConfig::parse(node_toml).unwrap();
        assert_eq!(parsed.node.name.as_deref(), Some("Офис \"Берлин\""));
        assert_eq!(
            parsed.management.mode,
            crate::node_config::ManagementMode::Managed
        );
        assert_eq!(parsed.endpoint.unwrap().node_key, public);
        assert_eq!(parsed.runtime.data_dir.as_deref(), Some(Path::new("/data")));
        assert_eq!(parsed.delivery.unwrap().backend, Backend::Sled);
    }

    #[test]
    fn jetstream_adds_nats_and_env() {
        let runner = fresh();
        let meta = NodeMeta {
            id: None,
            name: None,
            managed: false,
        };
        install(
            &runner,
            &layout(),
            &spec(Backend::Jetstream, false),
            None,
            &meta,
        )
        .unwrap();
        let commands = runner.commands.borrow();
        assert!(
            commands
                .iter()
                .any(|c| c.starts_with("docker run -d --name trustme-nats"))
        );
        let node = commands
            .iter()
            .find(|c| c.contains("--name message-service"))
            .unwrap();
        assert!(
            node.contains("-e DELIVERY_BACKEND=jetstream -e NATS_URL=nats://trustme-nats:4222")
        );
        assert!(!commands.iter().any(|c| c.contains("coturn")));
        let files = runner.files.borrow();
        assert!(!files.contains_key(Path::new("/data/runtime.toml")));
        let parsed =
            crate::node_config::NodeConfig::parse(&files[Path::new("/etc/tmnode/node.toml")].0)
                .unwrap();
        assert_eq!(
            parsed.management.mode,
            crate::node_config::ManagementMode::Local
        );
    }

    #[test]
    fn existing_node_and_missing_docker_stop_the_install() {
        let meta = NodeMeta {
            id: None,
            name: None,
            managed: false,
        };
        let runner = FakeRunner {
            failing: vec!["docker network inspect"],
            ..FakeRunner::default()
        };
        let err =
            install(&runner, &layout(), &spec(Backend::Sled, false), None, &meta).unwrap_err();
        assert!(err.to_string().contains("уже есть"));
        assert!(
            !runner
                .commands
                .borrow()
                .iter()
                .any(|c| c.starts_with("docker run"))
        );

        let runner = FakeRunner {
            failing: vec!["docker version"],
            ..FakeRunner::default()
        };
        let err =
            install(&runner, &layout(), &spec(Backend::Sled, false), None, &meta).unwrap_err();
        assert!(format!("{err:#}").contains("Docker не отвечает"));
    }

    #[test]
    fn missing_key_times_out() {
        let runner = fresh();
        *runner.key_after.borrow_mut() = 1000;
        let meta = NodeMeta {
            id: None,
            name: None,
            managed: false,
        };
        let err =
            install(&runner, &layout(), &spec(Backend::Sled, false), None, &meta).unwrap_err();
        assert!(err.to_string().contains("не создала ключ"));
    }

    #[test]
    fn unsafe_specs_are_refused() {
        let meta = NodeMeta {
            id: None,
            name: None,
            managed: false,
        };
        let mut bad = spec(Backend::Sled, true);
        bad.image = "img; rm -rf /".into();
        assert!(install(&fresh(), &layout(), &bad, None, &meta).is_err());
        let mut bad = spec(Backend::Sled, true);
        bad.public_host = "a/b".into();
        assert!(install(&fresh(), &layout(), &bad, None, &meta).is_err());
        let mut bad = spec(Backend::Sled, true);
        bad.port = 0;
        assert!(install(&fresh(), &layout(), &bad, None, &meta).is_err());
        let mut bad = spec(Backend::Sled, true);
        bad.coturn.as_mut().unwrap().secret = "short".into();
        assert!(install(&fresh(), &layout(), &bad, None, &meta).is_err());
        let mut bad = spec(Backend::Sled, true);
        bad.coturn.as_mut().unwrap().relay_min_port = 50000;
        assert!(install(&fresh(), &layout(), &bad, None, &meta).is_err());
        let mut bad = spec(Backend::Sled, true);
        bad.coturn.as_mut().unwrap().realm = "a b".into();
        assert!(install(&fresh(), &layout(), &bad, None, &meta).is_err());
    }

    #[test]
    fn host_runner_runs_and_writes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "tmnode_runner_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let host = HostRunner;
        host.create_dir(&dir.join("a/b"), None).unwrap();
        let file = dir.join("a/b/x.toml");
        // Не root: владелец не меняется, запись проходит.
        host.write_file(&file, b"hello", 0o600, Some(10001))
            .unwrap();
        host.create_dir(&dir.join("c"), Some(10001)).unwrap();
        assert_eq!(host.read_file(&file).unwrap().as_deref(), Some("hello"));
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(host.read_file(&dir.join("nope")).unwrap().is_none());
        host.copy_file(&file, &dir.join("copy")).unwrap();
        let mode = std::fs::metadata(dir.join("copy"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        host.rename(&dir.join("copy"), &dir.join("moved")).unwrap();
        assert_eq!(
            host.read_file(&dir.join("moved")).unwrap().as_deref(),
            Some("hello")
        );
        host.remove_file(&dir.join("moved")).unwrap();
        host.remove_file(&dir.join("moved")).unwrap();
        assert!(host.read_file(&dir.join("moved")).unwrap().is_none());
        assert!(host.rename(&dir.join("nope"), &dir.join("x")).is_err());
        assert_eq!(host.run("echo", &["hi".into()]).unwrap().trim(), "hi");
        assert!(host.run("false", &[]).is_err());
        assert!(host.run("/nonexistent/program", &[]).is_err());
        host.sleep(Duration::from_millis(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn layout_follows_the_environment() {
        let layout = Layout::from_env(|key| match key {
            "TMNODE_ETC_DIR" => Some("/tmp/etc".into()),
            "TMNODE_DATA_DIR" => Some("/tmp/data".into()),
            _ => None,
        });
        assert_eq!(layout.etc_dir, PathBuf::from("/tmp/etc"));
        assert_eq!(layout.data_dir, PathBuf::from("/tmp/data"));
        assert_eq!(layout.unit_path, Layout::default().unit_path);
    }

    #[test]
    fn agent_service_is_enabled() {
        let runner = fresh();
        install_agent_service(&runner, &layout(), "/usr/local/bin/tmnode").unwrap();
        let unit = &runner.files.borrow()[Path::new("/etc/systemd/system/tmnode-agent.service")]
            .0
            .clone();
        assert!(unit.contains("ExecStart=/usr/local/bin/tmnode agent"));
        // Самообновление: агент завершается после замены бинаря, служба
        // поднимается уже новым — при любом коде выхода.
        assert!(unit.contains("Restart=always\n"));
        assert_eq!(
            runner.commands.borrow().last().unwrap(),
            "systemctl enable --now tmnode-agent.service"
        );
    }
}
