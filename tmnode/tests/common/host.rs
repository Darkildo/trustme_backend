//! Подставной сервер для обновления: Docker с состоянием (контейнеры,
//! образы), файлы в памяти, релизы без сети. Один объект — и `Runner`, и
//! `System`: `doctor` видит те же контейнеры, что создаёт движок.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use tmnode::install::{Layout, Runner};
use tmnode::protocol::UpdateStatus;
use tmnode::system::{Container, DiskSpace, DockerError, MemInfo, System, parse_inspect};
use tmnode::update::{Fetch, Origin, Progress, Sources, Updater};
use trust_message_tcp::net::probe::{ProbeError, ProbeOutcome, ProbeStage};
use zeroize::Zeroizing;

use super::{DATA, Fake, SEED, healthy, node_public};

pub const REPO: &str = "ghcr.io/darkildo/trustme_backend";
pub const NODE: &str = "message-service";
pub const PREV: &str = "message-service.prev";
pub const INSIDE: &str = "/srv/trust-message/data";
pub const PATH_ENV: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const RELEASES: &str = "https://releases.example.org";
pub const NOW: u64 = 1_800_000_000;

pub fn now() -> u64 {
    NOW
}

pub fn image(version: &str) -> String {
    format!("{REPO}:v{version}")
}

pub fn image_id(version: &str) -> String {
    format!("sha256:{}", version.replace('.', "").repeat(16))
}

/// Секрет ключа ноды в окружении контейнера: он не должен попасть ни в
/// статус, ни в `update.json`, ни в командную строку.
pub fn secret() -> String {
    hex::encode(SEED)
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Как ведёт себя нода на образе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    Healthy,
    /// Стартует с другим ключом.
    RotatesKey,
    /// Порт открыт, рукопожатие не проходит.
    NoHandshake,
    /// Сразу падает.
    Crashes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    pub source: String,
    pub destination: String,
    pub rw: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctr {
    pub image: String,
    pub image_id: String,
    pub running: bool,
    pub env: Vec<String>,
    /// `unless-stopped`, `on-failure:3`; пусто — без политики.
    pub restart: String,
    pub network: String,
    pub extra_networks: Vec<String>,
    /// (порт/протокол, IP хоста, порт хоста).
    pub ports: Vec<(String, String, String)>,
    pub mounts: Vec<VolumeMount>,
}

/// Нода как после `tmnode install`, но с ключом в окружении.
pub fn node_ctr(version: &str) -> Ctr {
    Ctr {
        image: image(version),
        image_id: image_id(version),
        running: true,
        env: vec![
            PATH_ENV.into(),
            "RUST_LOG=info".into(),
            "BIND_PORT=18081".into(),
            format!("STORAGE_PATH={INSIDE}"),
            format!("NODE_IDENTITY_KEY={}", secret()),
            "METRICS_ENABLED=true".into(),
        ],
        restart: "unless-stopped".into(),
        network: "trustme".into(),
        extra_networks: Vec::new(),
        ports: vec![("18081/tcp".into(), String::new(), "18081".into())],
        mounts: vec![VolumeMount {
            source: DATA.into(),
            destination: INSIDE.into(),
            rw: true,
        }],
    }
}

impl Ctr {
    fn inspect(&self) -> serde_json::Value {
        let (policy, retries) = match self.restart.split_once(':') {
            Some((name, n)) => (name.to_owned(), n.parse::<i64>().unwrap()),
            None => (self.restart.clone(), 0),
        };
        let mut bindings = serde_json::Map::new();
        for (spec, ip, port) in &self.ports {
            let list = bindings
                .entry(spec.clone())
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap();
            list.push(json!({"HostIp": ip, "HostPort": port}));
        }
        let mut networks = serde_json::Map::new();
        networks.insert(self.network.clone(), json!({}));
        for extra in &self.extra_networks {
            networks.insert(extra.clone(), json!({}));
        }
        let mounts: Vec<_> = self
            .mounts
            .iter()
            .map(|m| {
                if m.source.starts_with('/') {
                    json!({"Type": "bind", "Source": m.source, "Destination": m.destination, "RW": m.rw})
                } else {
                    json!({"Type": "volume", "Name": m.source,
                           "Source": format!("/var/lib/docker/volumes/{}/_data", m.source),
                           "Destination": m.destination, "RW": m.rw})
                }
            })
            .collect();
        json!([{
            "Image": self.image_id,
            "RestartCount": 0,
            "State": {"Status": if self.running { "running" } else { "exited" }},
            "Config": {"Image": self.image, "Env": self.env},
            "HostConfig": {
                "NetworkMode": self.network,
                "PortBindings": bindings,
                "RestartPolicy": {"Name": policy, "MaximumRetryCount": retries}
            },
            "Mounts": mounts,
            "NetworkSettings": {
                "Networks": networks,
                "Ports": if self.running { serde_json::Value::Object(bindings) } else { json!({}) }
            }
        }])
    }
}

#[derive(Debug, Clone)]
pub struct Img {
    pub id: String,
    pub env: Vec<String>,
}

pub struct Host {
    pub base: Fake,
    pub containers: RefCell<BTreeMap<String, Ctr>>,
    /// Образы в реестре: по имени.
    pub registry: RefCell<BTreeMap<String, Img>>,
    pub behaviour: RefCell<BTreeMap<String, Behaviour>>,
    pub files: RefCell<BTreeMap<PathBuf, (Vec<u8>, u32)>>,
    pub commands: RefCell<Vec<String>>,
    pub sleeps: RefCell<u32>,
    /// Начала команд, которые завершаются ошибкой.
    pub failing: RefCell<Vec<String>>,
    /// Что печатает `tmnode.new version`.
    pub new_binary_says: RefCell<String>,
    /// Содержимое `--env-file` при каждом `docker create`.
    pub created_env: RefCell<Vec<String>>,
}

impl Host {
    /// Сервер с нодой 0.6.0; в реестре — 0.5.0, 0.6.0, 0.7.0.
    pub fn new() -> Self {
        let mut registry = BTreeMap::new();
        for version in ["0.5.0", "0.6.0", "0.7.0"] {
            registry.insert(
                image(version),
                Img {
                    id: image_id(version),
                    env: vec![PATH_ENV.into(), "RUST_LOG=info".into()],
                },
            );
        }
        let mut containers = BTreeMap::new();
        containers.insert(NODE.to_owned(), node_ctr("0.6.0"));
        Self {
            base: healthy(),
            containers: RefCell::new(containers),
            registry: RefCell::new(registry),
            behaviour: RefCell::new(BTreeMap::new()),
            files: RefCell::new(BTreeMap::new()),
            commands: RefCell::new(Vec::new()),
            sleeps: RefCell::new(0),
            failing: RefCell::new(Vec::new()),
            new_binary_says: RefCell::new(String::new()),
            created_env: RefCell::new(Vec::new()),
        }
    }

    pub fn set_behaviour(&self, version: &str, behaviour: Behaviour) {
        self.behaviour
            .borrow_mut()
            .insert(image(version), behaviour);
    }

    fn behaviour_of(&self, image: &str) -> Behaviour {
        self.behaviour
            .borrow()
            .get(image)
            .copied()
            .unwrap_or(Behaviour::Healthy)
    }

    pub fn ctr(&self, name: &str) -> Option<Ctr> {
        self.containers.borrow().get(name).cloned()
    }

    pub fn commands(&self) -> Vec<String> {
        self.commands.borrow().clone()
    }

    pub fn file(&self, path: &Path) -> Option<Vec<u8>> {
        self.files.borrow().get(path).map(|f| f.0.clone())
    }

    fn docker(&self, args: &[String]) -> Result<String> {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut containers = self.containers.borrow_mut();
        let missing = |name: &str| anyhow!("docker {}: Error: No such object: {name}", a[0]);
        match a.as_slice() {
            ["inspect", "--type", "container", name] => containers
                .get(*name)
                .map(|c| c.inspect().to_string())
                .ok_or_else(|| missing(name)),
            ["image", "inspect", id] => self
                .registry
                .borrow()
                .values()
                .find(|img| img.id == *id)
                .map(|img| json!([{"Id": img.id, "Config": {"Env": img.env}}]).to_string())
                .ok_or_else(|| missing(id)),
            ["pull", image] => {
                if self.registry.borrow().contains_key(*image) {
                    Ok(String::new())
                } else {
                    bail!("docker pull: manifest unknown")
                }
            }
            ["stop", "-t", "30", name] => {
                containers
                    .get_mut(*name)
                    .ok_or_else(|| missing(name))?
                    .running = false;
                Ok(String::new())
            }
            ["rename", from, to] => {
                if containers.contains_key(*to) {
                    bail!("docker rename: name {to} is already in use");
                }
                let c = containers.remove(*from).ok_or_else(|| missing(from))?;
                containers.insert(to.to_string(), c);
                Ok(String::new())
            }
            ["update", "--restart", policy, name] => {
                let c = containers.get_mut(*name).ok_or_else(|| missing(name))?;
                c.restart = if *policy == "no" {
                    String::new()
                } else {
                    policy.to_string()
                };
                Ok(String::new())
            }
            ["create", rest @ ..] => {
                let created = self.create(rest)?;
                let (name, ctr) = created;
                if containers.contains_key(&name) {
                    bail!("docker create: name {name} is already in use");
                }
                containers.insert(name, ctr);
                Ok("new-id\n".into())
            }
            ["network", "connect", network, name] => {
                let c = containers.get_mut(*name).ok_or_else(|| missing(name))?;
                c.extra_networks.push(network.to_string());
                Ok(String::new())
            }
            ["start", name] => {
                let c = containers.get_mut(*name).ok_or_else(|| missing(name))?;
                c.running = self.behaviour_of(&c.image) != Behaviour::Crashes;
                Ok(String::new())
            }
            ["rm", "-f", name] => {
                containers.remove(*name).ok_or_else(|| missing(name))?;
                Ok(String::new())
            }
            ["rm", name] => {
                let c = containers.get(*name).ok_or_else(|| missing(name))?;
                if c.running {
                    bail!("docker rm: container is running");
                }
                containers.remove(*name);
                Ok(String::new())
            }
            ["logs", "--tail", "20", name] => {
                containers.get(*name).ok_or_else(|| missing(name))?;
                // Нода, которая печатает своё окружение, — худший случай.
                let mut out: String = (1..=30).map(|i| format!("строка {i}\n")).collect();
                out.push_str(&format!("env NODE_IDENTITY_KEY={}\nпаника\n", secret()));
                Ok(out)
            }
            other => bail!("неожиданная команда docker {other:?}"),
        }
    }

    /// `docker create`: контейнер из флагов; окружение — образа, поверх —
    /// из `--env-file`, как у Docker.
    fn create(&self, args: &[&str]) -> Result<(String, Ctr)> {
        let mut name = None;
        let mut ctr = Ctr {
            image: String::new(),
            image_id: String::new(),
            running: false,
            env: Vec::new(),
            restart: String::new(),
            network: "default".into(),
            extra_networks: Vec::new(),
            ports: Vec::new(),
            mounts: Vec::new(),
        };
        let mut file_env = String::new();
        let mut iter = args.iter();
        while let Some(&arg) = iter.next() {
            let mut value = || {
                iter.next()
                    .copied()
                    .ok_or_else(|| anyhow!("{arg}: нет значения"))
            };
            match arg {
                "--name" => name = Some(value()?.to_owned()),
                "--restart" => ctr.restart = value()?.to_owned(),
                "--network" => ctr.network = value()?.to_owned(),
                "-p" => {
                    let spec: Vec<&str> = value()?.split(':').collect();
                    ctr.ports.push(match spec.as_slice() {
                        [hp, cp] => (cp.to_string(), String::new(), hp.to_string()),
                        [ip, hp, cp] => (cp.to_string(), ip.to_string(), hp.to_string()),
                        _ => bail!("-p: не понял"),
                    });
                }
                "-v" => {
                    let spec: Vec<&str> = value()?.split(':').collect();
                    ctr.mounts.push(match spec.as_slice() {
                        [s, d] => VolumeMount {
                            source: s.to_string(),
                            destination: d.to_string(),
                            rw: true,
                        },
                        [s, d, "ro"] => VolumeMount {
                            source: s.to_string(),
                            destination: d.to_string(),
                            rw: false,
                        },
                        _ => bail!("-v: не понял"),
                    });
                }
                "--env-file" => {
                    let path = PathBuf::from(value()?);
                    let bytes = self.file(&path).ok_or_else(|| {
                        anyhow!("docker create: open {}: no such file", path.display())
                    })?;
                    file_env = String::from_utf8(bytes)?;
                }
                "-e" => bail!("окружение в командной строке: его видит ps"),
                image if !image.starts_with('-') => {
                    ctr.image = image.to_owned();
                    break;
                }
                other => bail!("неожиданный флаг {other}"),
            }
        }
        let img = self
            .registry
            .borrow()
            .get(&ctr.image)
            .cloned()
            .ok_or_else(|| anyhow!("docker create: no such image {}", ctr.image))?;
        ctr.image_id = img.id;
        ctr.env = img.env;
        for line in file_env.lines() {
            let key = line.split('=').next().unwrap();
            ctr.env.retain(|e| e.split('=').next() != Some(key));
            ctr.env.push(line.to_owned());
        }
        self.created_env.borrow_mut().push(file_env);
        Ok((name.ok_or_else(|| anyhow!("--name"))?, ctr))
    }

    fn running_node(&self) -> Option<Ctr> {
        self.ctr(NODE).filter(|c| c.running)
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for Host {
    fn run(&self, program: &str, args: &[String]) -> Result<String> {
        let line = format!("{program} {}", args.join(" "));
        self.commands.borrow_mut().push(line.clone());
        if self
            .failing
            .borrow()
            .iter()
            .any(|f| line.starts_with(f.as_str()))
        {
            bail!(
                "{program} {}: simulated failure",
                args.first().map(String::as_str).unwrap_or("")
            );
        }
        if program == "docker" {
            return self.docker(args);
        }
        if program.ends_with(".new") && args == ["version"] {
            if self.file(Path::new(program)).is_none() {
                bail!("запуск {program}: нет файла");
            }
            return Ok(self.new_binary_says.borrow().clone());
        }
        bail!("неожиданная программа {program}")
    }

    fn write_file(&self, path: &Path, contents: &[u8], mode: u32, _uid: Option<u32>) -> Result<()> {
        self.files
            .borrow_mut()
            .insert(path.to_owned(), (contents.to_vec(), mode));
        Ok(())
    }

    fn create_dir(&self, _path: &Path, _uid: Option<u32>) -> Result<()> {
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<Option<String>> {
        Ok(self
            .file(path)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let file = self.files.borrow_mut().remove(from);
        let file = file.ok_or_else(|| anyhow!("нет {}", from.display()))?;
        self.files.borrow_mut().insert(to.to_owned(), file);
        Ok(())
    }

    fn copy_file(&self, from: &Path, to: &Path) -> Result<()> {
        let file = self.files.borrow().get(from).cloned();
        let file = file.ok_or_else(|| anyhow!("нет {}", from.display()))?;
        self.files.borrow_mut().insert(to.to_owned(), file);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.files.borrow_mut().remove(path);
        Ok(())
    }

    fn sleep(&self, _duration: Duration) {
        *self.sleeps.borrow_mut() += 1;
    }
}

impl System for Host {
    fn container(&self, name: &str) -> Result<Option<Container>, DockerError> {
        let Some(ctr) = self.ctr(name) else {
            return Ok(None);
        };
        let mut container =
            parse_inspect(ctr.inspect().to_string().as_bytes()).map_err(DockerError::Failed)?;
        if self.behaviour_of(&ctr.image) == Behaviour::RotatesKey {
            container.env.retain(|(k, _)| k != "NODE_IDENTITY_KEY");
            container.env.push((
                "NODE_IDENTITY_KEY".into(),
                Zeroizing::new(sha256(b"another node key")),
            ));
        }
        Ok(Some(container))
    }

    fn read_secret(&self, path: &Path) -> io::Result<Zeroizing<String>> {
        self.base.read_secret(path)
    }

    fn file_mode(&self, path: &Path) -> io::Result<u32> {
        self.base.file_mode(path)
    }

    fn disk_space(&self, path: &Path) -> io::Result<DiskSpace> {
        self.base.disk_space(path)
    }

    fn memory(&self) -> io::Result<MemInfo> {
        self.base.memory()
    }

    fn clock_synced(&self) -> Option<bool> {
        self.base.clock_synced()
    }

    async fn probe(
        &self,
        addr: &str,
        node_key: &[u8; 32],
        step_timeout: Duration,
    ) -> Result<ProbeOutcome, ProbeError> {
        let fail = |stage| {
            Err(ProbeError {
                stage,
                error: anyhow!("simulated {}", ProbeStage::as_str(stage)),
            })
        };
        match self.running_node() {
            None => fail(ProbeStage::Connect),
            Some(ctr) => match self.behaviour_of(&ctr.image) {
                Behaviour::NoHandshake | Behaviour::RotatesKey => fail(ProbeStage::Handshake),
                _ => self.base.probe(addr, node_key, step_timeout).await,
            },
        }
    }
}

/// Релизы без сети: URL → тело.
#[derive(Default)]
pub struct Releases {
    pub files: RefCell<BTreeMap<String, Vec<u8>>>,
    pub fetched: RefCell<Vec<String>>,
}

impl Releases {
    /// Релиз `v<release>` с бинарём tmnode для x86_64 и его суммой.
    pub fn publish(&self, release: &str, binary: &[u8]) {
        self.publish_sums(release, &sha256(binary));
        self.files.borrow_mut().insert(
            format!("{RELEASES}/v{release}/tmnode-x86_64-linux"),
            binary.to_vec(),
        );
    }

    pub fn publish_sums(&self, release: &str, sha: &str) {
        self.files.borrow_mut().insert(
            format!("{RELEASES}/v{release}/SHA256SUMS"),
            format!(
                "{sha}  tmnode-x86_64-linux\n{}  tmnode-aarch64-linux\n",
                "0".repeat(64)
            )
            .into_bytes(),
        );
    }
}

impl Fetch for Releases {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>> {
        self.fetched.borrow_mut().push(url.to_owned());
        let body = self
            .files
            .borrow()
            .get(url)
            .cloned()
            .ok_or_else(|| anyhow!("{url}: 404 Not Found"))?;
        if body.len() > limit {
            bail!("{url}: больше {limit} байт");
        }
        Ok(body)
    }
}

/// Шаги, о которых движок сообщал до начала.
#[derive(Default)]
pub struct Steps(pub RefCell<Vec<UpdateStatus>>);

impl Progress for Steps {
    async fn running(&self, status: &UpdateStatus) {
        self.0.borrow_mut().push(status.clone());
    }
}

impl Steps {
    pub fn names(&self) -> Vec<String> {
        self.0
            .borrow()
            .iter()
            .map(|s| {
                serde_json::to_value(s.step)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }
}

/// Всё для одного сценария.
pub struct Setup {
    pub layout: Layout,
    pub node_toml: PathBuf,
    pub tmnode_path: PathBuf,
    pub sources: Sources,
    pub host: Host,
    pub releases: Releases,
}

/// `node.toml` с пином ноды; `extra` дописывается в конец.
pub fn setup(label: &str, mode: &str, extra: &str) -> Setup {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tmnode_update_{label}_{nanos}"));
    std::fs::create_dir_all(root.join("etc")).unwrap();
    let node_toml = root.join("etc/node.toml");
    std::fs::write(
        &node_toml,
        format!(
            "schema = 1\n[management]\nmode = \"{mode}\"\n[endpoint]\naddr = \"127.0.0.1:18081\"\nnode_key = \"{}\"\n[runtime]\ndata_dir = \"{DATA}\"\n{extra}",
            hex::encode(node_public())
        ),
    )
    .unwrap();
    let host = Host::new();
    let tmnode_path = root.join("bin/tmnode");
    host.write_file(&tmnode_path, b"old tmnode", 0o755, None)
        .unwrap();
    Setup {
        layout: Layout {
            data_dir: DATA.into(),
            etc_dir: root.join("etc"),
            unit_path: root.join("tmnode-agent.service"),
        },
        node_toml,
        tmnode_path,
        sources: Sources {
            image_repo: REPO.into(),
            releases_url: RELEASES.into(),
            arch: "x86_64".into(),
        },
        host,
        releases: Releases::default(),
    }
}

impl Setup {
    /// Движок с этой версией `tmnode`: так проверяется и прежний агент, и
    /// новый после перезапуска.
    pub fn updater<'a>(&'a self, version: &'a str, origin: Origin) -> Updater<'a, Host, Releases> {
        Updater {
            runner: &self.host,
            sys: &self.host,
            fetch: &self.releases,
            layout: &self.layout,
            sources: &self.sources,
            node_toml: &self.node_toml,
            tmnode_path: &self.tmnode_path,
            tmnode_version: version,
            origin,
            now: &now,
        }
    }

    pub fn state_file(&self) -> String {
        String::from_utf8(
            self.host
                .file(&self.layout.etc_dir.join("update.json"))
                .expect("update.json записан"),
        )
        .unwrap()
    }

    pub fn env_file(&self) -> PathBuf {
        self.layout.etc_dir.join("update.env")
    }
}
