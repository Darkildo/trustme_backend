//! Обновление ноды и самого `tmnode` до версий из релиза бэкенда
//! (docs/agent-protocol.md, «Обновление»).
//!
//! Задание приходит от админки (агент) или из `tmnode update`; движок у них
//! один. Задание называет только версии. Откуда качать, решает `tmnode`:
//! образ — из своего репозитория, бинарь — из своих GitHub Releases со
//! сверкой SHA-256 и с релизом, и с заданием.
//!
//! Ход задания пишется в `<etc>/update.json` перед каждым шагом. Агент,
//! перезапущенный после замены бинаря или упавший посреди шага, дочитывает
//! задание оттуда ([`Updater::resume`]).
//!
//! Всё, что меняет машину, идёт через [`Runner`]; скачивание — через
//! [`Fetch`]; проверка новой ноды — `doctor` через [`System`]. Тесты сверяют
//! точный список команд docker, не трогая ни машину, ни сеть.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::doctor::{self, ConfigSource, Input};
use crate::install::{Layout, Runner, Stalled};
use crate::node_config::{Channel, ManagementMode, NodeConfig};
use crate::protocol::{UpdateOrder, UpdateState, UpdateStatus, UpdateStep};
use crate::report::{Report, Status};
use crate::system::System;

/// Репозиторий образов ноды по умолчанию (`TMNODE_IMAGE_REPO`).
pub const DEFAULT_IMAGE_REPO: &str = "ghcr.io/darkildo/trustme_backend";
/// Адрес релизов по умолчанию (`TMNODE_RELEASES_URL`).
pub const DEFAULT_RELEASES_URL: &str =
    "https://github.com/Darkildo/trustme_backend/releases/download";

/// Сколько новая нода может приходить в себя.
const VERIFY_LIMIT: Duration = Duration::from_secs(120);
const VERIFY_PAUSE: Duration = Duration::from_secs(5);
/// `docker stop -t`: столько секунд нода получает на корректную остановку.
const STOP_TIMEOUT_SECS: &str = "30";
/// Хвост `docker logs` в причине отката.
const LOG_TAIL_LINES: usize = 20;
const LOG_TAIL_BYTES: usize = 2048;
/// Потолок причины в статусе: она уходит в админку с каждым heartbeat.
const ERROR_MAX_BYTES: usize = 4096;
const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SUMS_BYTES: usize = 64 * 1024;
/// Скачивание файла релиза: столько без единого байта — соединение
/// зависло, попытка обрывается.
const FETCH_STALL: Duration = Duration::from_secs(30);
const FETCH_ATTEMPTS: u32 = 3;
const FETCH_BACKOFF: Duration = Duration::from_secs(5);
/// `docker pull` без вывода. Строку он печатает на каждом этапе слоя, а не
/// на каждом мегабайте: большой слой на медленном канале молчит минутами.
const PULL_IDLE: Duration = Duration::from_secs(300);
const PULL_ATTEMPTS: u32 = 3;

/// Версия `X.Y.Z`: только цифры, без ведущих нулей. Сравнивается по
/// числам, а не как строка: `0.10.0` новее `0.9.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = [0u32; 3];
        let mut iter = text.split('.');
        for slot in &mut parts {
            let part = iter.next()?;
            let digits = !part.is_empty()
                && part.len() <= 9
                && part.bytes().all(|b| b.is_ascii_digit())
                && !(part.len() > 1 && part.starts_with('0'));
            if !digits {
                return None;
            }
            *slot = part.parse().ok()?;
        }
        if iter.next().is_some() {
            return None;
        }
        Some(Self {
            major: parts[0],
            minor: parts[1],
            patch: parts[2],
        })
    }

    /// Версия из тега образа `…:vX.Y.Z`. Другой тег (`stable`, хэш) —
    /// версия не известна.
    pub fn from_image(image: &str) -> Option<Self> {
        let tag = image.rsplit_once(':')?.1;
        Self::parse(tag.strip_prefix('v')?)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Откуда брать образ ноды и бинарь `tmnode`. Задаёт хост, не админка.
#[derive(Debug, Clone, PartialEq)]
pub struct Sources {
    /// Репозиторий образов без тега: образ — `<repo>:vX.Y.Z`.
    pub image_repo: String,
    /// Корень релизов: `<url>/vX.Y.Z/<файл>`.
    pub releases_url: String,
    /// Архитектура бинаря: `tmnode-<arch>-linux`.
    pub arch: String,
}

impl Sources {
    /// `TMNODE_IMAGE_REPO` и `TMNODE_RELEASES_URL` из окружения службы, по
    /// умолчанию — репозиторий проекта.
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let pick = |key: &str, default: &str| {
            env(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_owned())
        };
        let sources = Self {
            image_repo: pick("TMNODE_IMAGE_REPO", DEFAULT_IMAGE_REPO),
            releases_url: pick("TMNODE_RELEASES_URL", DEFAULT_RELEASES_URL)
                .trim_end_matches('/')
                .to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        };
        sources.check()?;
        Ok(sources)
    }

    pub fn check(&self) -> Result<()> {
        let repo = &self.image_repo;
        let repo_ok = !repo.is_empty()
            && repo.len() <= 255
            && repo
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-/:".contains(c))
            && repo.starts_with(|c: char| c.is_ascii_alphanumeric())
            && !repo.ends_with(['/', ':', '.', '-'])
            && !repo.rsplit('/').next().unwrap_or("").contains(':');
        if !repo_ok {
            bail!(
                "TMNODE_IMAGE_REPO: ожидается репозиторий образов без тега, например {DEFAULT_IMAGE_REPO}"
            );
        }
        let url = &self.releases_url;
        let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|prefix| url.starts_with(prefix));
        if !(url.starts_with("https://") || local) || url.chars().any(|c| c.is_whitespace()) {
            bail!("TMNODE_RELEASES_URL: только https:// (http — для localhost)");
        }
        if !self
            .arch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            bail!("архитектура `{}` не поддерживается", self.arch);
        }
        Ok(())
    }

    pub fn image(&self, version: Version) -> String {
        format!("{}:v{version}", self.image_repo)
    }

    /// Имя бинаря `tmnode` в релизе (release.yml).
    pub fn asset(&self) -> String {
        format!("tmnode-{}-linux", self.arch)
    }

    pub fn release_file(&self, release: Version, file: &str) -> String {
        format!("{}/v{release}/{file}", self.releases_url)
    }
}

/// Скачивание файлов релиза.
#[allow(async_fn_in_trait)]
pub trait Fetch {
    /// Тело ответа целиком, не больше `limit` байт.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>>;
}

/// Скачивание по HTTPS. Зависшее соединение (данные перестали идти)
/// обрывается через [`FETCH_STALL`], сбой сети и ответ 5xx повторяются до
/// [`FETCH_ATTEMPTS`] раз: CDN релизов бывает доступен через раз.
pub struct HttpFetch {
    client: reqwest::Client,
    stall: Duration,
    attempts: u32,
    backoff: Duration,
}

/// Исход одной попытки: повторять ли.
enum Attempt {
    Retry(anyhow::Error),
    Final(anyhow::Error),
}

impl HttpFetch {
    pub fn new(sources: &Sources) -> Result<Self> {
        Self::with_limits(sources, FETCH_STALL, FETCH_ATTEMPTS, FETCH_BACKOFF)
    }

    pub fn with_limits(
        sources: &Sources,
        stall: Duration,
        attempts: u32,
        backoff: Duration,
    ) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(600))
                // Релизы GitHub отдают файл через перенаправление: оно
                // тоже должно быть по HTTPS.
                .https_only(sources.releases_url.starts_with("https://"))
                .user_agent(concat!("tmnode/", env!("CARGO_PKG_VERSION")))
                .build()?,
            stall,
            attempts: attempts.max(1),
            backoff,
        })
    }

    async fn attempt(&self, url: &str, limit: usize) -> Result<Vec<u8>, Attempt> {
        let stall = self.stall.as_secs();
        let mut response = match tokio::time::timeout(self.stall, self.client.get(url).send()).await
        {
            Err(_) => return Err(Attempt::Retry(anyhow!("{url}: нет ответа {stall} с"))),
            Ok(Err(err)) => {
                return Err(Attempt::Retry(
                    anyhow!(err).context(format!("{url} недоступен")),
                ));
            }
            Ok(Ok(response)) => response,
        };
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(Attempt::Retry(anyhow!("{url}: {status}")));
        }
        if !status.is_success() {
            return Err(Attempt::Final(anyhow!("{url}: {status}")));
        }
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(Attempt::Final(anyhow!("{url}: больше {limit} байт")));
        }
        let mut body = Vec::new();
        loop {
            let chunk = match tokio::time::timeout(self.stall, response.chunk()).await {
                Err(_) => {
                    return Err(Attempt::Retry(anyhow!(
                        "{url}: данные не идут {stall} с (получено {} байт)",
                        body.len()
                    )));
                }
                Ok(Err(err)) => {
                    return Err(Attempt::Retry(
                        anyhow!(err).context(format!("{url}: обрыв")),
                    ));
                }
                Ok(Ok(None)) => return Ok(body),
                Ok(Ok(Some(chunk))) => chunk,
            };
            if body.len() + chunk.len() > limit {
                return Err(Attempt::Final(anyhow!("{url}: больше {limit} байт")));
            }
            body.extend_from_slice(&chunk);
        }
    }
}

impl Fetch for HttpFetch {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>> {
        let mut attempt = 1;
        loop {
            match self.attempt(url, limit).await {
                Ok(body) => return Ok(body),
                Err(Attempt::Final(err)) => return Err(err),
                Err(Attempt::Retry(err)) if attempt >= self.attempts => {
                    return Err(err.context(format!("{attempt} попытки")));
                }
                Err(Attempt::Retry(_)) => {
                    tokio::time::sleep(self.backoff * attempt).await;
                    attempt += 1;
                }
            }
        }
    }
}

/// Кому сообщать ход задания до долгих шагов: агент шлёт отдельный
/// heartbeat, `tmnode update` печатает шаг.
#[allow(async_fn_in_trait)]
pub trait Progress {
    /// Ошибки доставки — забота реализации: задание от них не зависит.
    async fn running(&self, status: &UpdateStatus);
}

/// Никому не сообщать.
impl Progress for () {
    async fn running(&self, _status: &UpdateStatus) {}
}

/// Кто прислал задание.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Админка: нужно `management.mode = "managed"` в `node.toml`.
    Admin,
    /// `tmnode update` на сервере: только для ноды без админки — у
    /// управляемой ноды один источник правды.
    Local,
}

/// `<etc>/update.json`: последнее задание и его ход. Секретов здесь нет.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Saved {
    pub order: UpdateOrder,
    pub status: UpdateStatus,
    /// Задание из `tmnode update`: в админку не уходит.
    #[serde(default)]
    pub local: bool,
    /// Админка перестала присылать задание: итог ей больше не нужен.
    #[serde(default)]
    pub acknowledged: bool,
    /// Политика перезапуска прежнего контейнера. Пока он лежит как
    /// `<имя>.prev`, она снята — иначе Docker поднял бы его рядом с новым.
    #[serde(default)]
    pub restart_policy: Option<String>,
}

/// Чем закончился вызов движка.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Итог задания или повтор итога по тому же `id`.
    Done(UpdateStatus),
    /// Бинарь `tmnode` заменён, задание записано как `restart_agent`.
    /// Процесс должен завершиться: служба поднимется уже новым бинарём и
    /// продолжит задание ([`Updater::resume`]).
    Restart(UpdateStatus),
}

impl Outcome {
    pub fn status(&self) -> &UpdateStatus {
        match self {
            Self::Done(status) | Self::Restart(status) => status,
        }
    }
}

/// Движок обновления на конкретной машине.
pub struct Updater<'a, S, F> {
    pub runner: &'a dyn Runner,
    pub sys: &'a S,
    pub fetch: &'a F,
    pub layout: &'a Layout,
    pub sources: &'a Sources,
    /// `node.toml`: контейнер ноды, пин, разрешение управлять, закреплённая
    /// версия.
    pub node_toml: &'a Path,
    /// Работающий бинарь `tmnode` (`std::env::current_exe`).
    pub tmnode_path: &'a Path,
    /// Версия работающего `tmnode`.
    pub tmnode_version: &'a str,
    pub origin: Origin,
    pub now: &'a dyn Fn() -> u64,
}

/// Выполняемое задание и секреты, которые нельзя выпустить в статус.
struct Run {
    saved: Saved,
    secrets: Vec<Zeroizing<String>>,
}

/// Что из задания на самом деле нужно сделать.
#[derive(Debug, Default)]
struct Plan {
    /// Новый `tmnode`: версия (она же — релиз, из которого он берётся) и
    /// SHA-256.
    tmnode: Option<(Version, String)>,
    node: Option<Version>,
}

/// Проверка новой ноды.
enum Verdict {
    Passed,
    /// Ждать бессмысленно: ключ ноды сменился.
    Fatal(String),
    Wait(String),
}

impl<S: System, F: Fetch> Updater<'_, S, F> {
    pub fn state_path(&self) -> PathBuf {
        self.layout.etc_dir.join("update.json")
    }

    fn env_file(&self) -> PathBuf {
        self.layout.etc_dir.join("update.env")
    }

    /// Последнее задание. Повреждённый файл — как отсутствующий: пишется он
    /// атомарно, и битым бывает разве что после ручной правки.
    pub fn load(&self) -> Option<Saved> {
        let text = self.runner.read_file(&self.state_path()).ok()??;
        serde_json::from_str(&text).ok()
    }

    fn save(&self, saved: &Saved) -> Result<()> {
        let text = serde_json::to_string_pretty(saved).expect("update state serializes");
        self.runner
            .write_file(&self.state_path(), text.as_bytes(), 0o600, None)
    }

    /// Статус для heartbeat: последнее задание от админки, пока она его
    /// присылает.
    pub fn report(&self) -> Option<UpdateStatus> {
        self.load()
            .filter(|saved| !saved.local && !saved.acknowledged)
            .map(|saved| saved.status)
    }

    /// Админка ответила без этого задания (или с другим): итог она получила,
    /// дальше его не присылать.
    pub fn acknowledge(&self, order_id: Option<&str>) {
        if let Some(mut saved) = self.load()
            && saved.status.state.is_final()
            && !saved.acknowledged
            && order_id != Some(saved.order.id.as_str())
        {
            saved.acknowledged = true;
            let _ = self.save(&saved);
        }
    }

    /// Выполнить задание. Повтор `id` с итогом ничего не делает и
    /// возвращает тот же итог.
    pub async fn execute(&self, order: &UpdateOrder, progress: &impl Progress) -> Outcome {
        if let Some(saved) = self.load() {
            if saved.order.id == order.id {
                if saved.status.state.is_final() {
                    return Outcome::Done(saved.status);
                }
                if let Some(outcome) = self.resume(progress).await {
                    return outcome;
                }
            } else if !saved.status.state.is_final() {
                // Одновременно — одно задание: прежнее сначала доводится.
                if let Some(Outcome::Restart(status)) = self.resume(progress).await {
                    return Outcome::Restart(status);
                }
            }
        }
        self.start(order, progress).await
    }

    async fn start(&self, order: &UpdateOrder, progress: &impl Progress) -> Outcome {
        let now = (self.now)();
        let mut run = Run {
            saved: Saved {
                order: order.clone(),
                status: UpdateStatus {
                    id: order.id.clone(),
                    state: UpdateState::Running,
                    step: Some(UpdateStep::Check),
                    error: None,
                    started_at: now,
                    finished_at: None,
                    from_node_image: None,
                    node_image: None,
                    from_tmnode: Some(self.tmnode_version.to_owned()),
                    tmnode: Some(self.tmnode_version.to_owned()),
                },
                local: self.origin == Origin::Local,
                acknowledged: self.origin == Origin::Local,
                restart_policy: None,
            },
            secrets: Vec::new(),
        };
        let config = match NodeConfig::load(self.node_toml) {
            Ok(config) => config,
            Err(err) => {
                return self.finish(&mut run, UpdateState::Failed, Some(format!("{err:#}")));
            }
        };
        let current = self.current_image(&config);
        run.saved.status.from_node_image = current.clone();
        run.saved.status.node_image = current.clone();
        if let Err(err) = self.save(&run.saved) {
            return self.finish(&mut run, UpdateState::Failed, Some(format!("{err:#}")));
        }
        let plan = match self.plan(order, &config, current.as_deref(), self.origin) {
            Ok(plan) => plan,
            Err(why) => return self.finish(&mut run, UpdateState::Refused, Some(why)),
        };
        if let Some((version, sha256)) = &plan.tmnode {
            return match self
                .replace_tmnode(&mut run, *version, sha256, progress)
                .await
            {
                Ok(()) => Outcome::Restart(run.saved.status),
                Err(err) => self.finish(&mut run, UpdateState::Failed, Some(format!("{err:#}"))),
            };
        }
        self.node_part(run, &config, plan.node, progress).await
    }

    /// Дочитать незавершённое задание: после перезапуска агента или после
    /// падения посреди шага. `None` — дочитывать нечего.
    pub async fn resume(&self, progress: &impl Progress) -> Option<Outcome> {
        let saved = self.load()?;
        if saved.status.state.is_final() {
            return None;
        }
        // Окружение для нового контейнера живёт только на время `docker
        // create`; упавший посреди него агент мог его оставить.
        let _ = self.runner.remove_file(&self.env_file());
        let mut run = Run {
            saved,
            secrets: Vec::new(),
        };
        let step = run.saved.status.step.unwrap_or(UpdateStep::Check);
        Some(match step {
            UpdateStep::RestartAgent => self.after_restart(run, progress).await,
            UpdateStep::Check | UpdateStep::DownloadTmnode | UpdateStep::PullImage => {
                // До пересоздания контейнера машина не менялась.
                let why = format!(
                    "агент перезапустился на шаге {}: задание прервано, нода не менялась",
                    step_name(step)
                );
                self.finish(&mut run, UpdateState::Failed, Some(why))
            }
            UpdateStep::Recreate | UpdateStep::Verify | UpdateStep::Rollback => {
                self.recover_node(&mut run, step, progress).await
            }
        })
    }

    /// Новый агент после самообновления: версия должна быть заданной.
    async fn after_restart(&self, mut run: Run, progress: &impl Progress) -> Outcome {
        let order = run.saved.order.clone();
        if let Some(wanted) = &order.tmnode
            && wanted.version != self.tmnode_version
        {
            let why = format!(
                "после перезапуска работает tmnode {}, а задание ставило {}: бинарь не заменён",
                self.tmnode_version, wanted.version
            );
            return self.finish(&mut run, UpdateState::Failed, Some(why));
        }
        run.saved.status.tmnode = Some(self.tmnode_version.to_owned());
        let config = match NodeConfig::load(self.node_toml) {
            Ok(config) => config,
            Err(err) => {
                return self.finish(&mut run, UpdateState::Failed, Some(format!("{err:#}")));
            }
        };
        let origin = if run.saved.local {
            Origin::Local
        } else {
            Origin::Admin
        };
        let current = self.current_image(&config);
        match self.plan(&order, &config, current.as_deref(), origin) {
            Ok(plan) => self.node_part(run, &config, plan.node, progress).await,
            Err(why) => self.finish(&mut run, UpdateState::Refused, Some(why)),
        }
    }

    /// Проверить задание по `node.toml` и текущим версиям. `Err` — отказ.
    fn plan(
        &self,
        order: &UpdateOrder,
        config: &NodeConfig,
        current_image: Option<&str>,
        origin: Origin,
    ) -> Result<Plan, String> {
        if !valid_id(&order.id) {
            return Err("id задания: от 1 до 64 символов a-z, A-Z, 0-9, `-`, `_`".into());
        }
        if order.node_version.is_none() && order.tmnode.is_none() {
            return Err("задание пустое: нет ни node_version, ни tmnode".into());
        }
        match (origin, config.management.mode) {
            (Origin::Admin, ManagementMode::Managed) | (Origin::Local, ManagementMode::Local) => {}
            (Origin::Admin, ManagementMode::Local) => {
                return Err(
                    "в node.toml нет management.mode = \"managed\": админке не разрешено управлять нодой"
                        .into(),
                );
            }
            (Origin::Local, ManagementMode::Managed) => {
                return Err(
                    "нода под управлением админки (management.mode = \"managed\"): обновляйте её из панели"
                        .into(),
                );
            }
        }
        let node = order
            .node_version
            .as_deref()
            .map(|v| {
                Version::parse(v).ok_or(format!("node_version: ожидается X.Y.Z, получено `{v}`"))
            })
            .transpose()?;
        let tmnode = match &order.tmnode {
            None => None,
            Some(release) => {
                let version = Version::parse(&release.version).ok_or(format!(
                    "tmnode.version: ожидается X.Y.Z, получено `{}`",
                    release.version
                ))?;
                let sha256 = release.sha256.to_ascii_lowercase();
                if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("tmnode.sha256: ожидается 64 hex-символа".into());
                }
                Some((version, sha256))
            }
        };

        if let (Some(wanted), Channel::Pinned) = (node, config.updates.channel) {
            let pinned = config.updates.version.as_deref().unwrap_or("");
            if Version::parse(pinned) != Some(wanted) {
                return Err(format!(
                    "в node.toml закреплена версия {pinned} (updates.channel = \"pinned\"), задание ставит {wanted}"
                ));
            }
        }

        let current_node = current_image.and_then(Version::from_image);
        let mut plan = Plan::default();
        if let Some(wanted) = node {
            if current_image == Some(self.sources.image(wanted).as_str()) {
                // Уже стоит: эта часть выполнена.
            } else if let Some(current) = current_node
                && wanted < current
                && !order.allow_downgrade
            {
                return Err(format!(
                    "нода {current} новее {wanted}: понижение — только с allow_downgrade"
                ));
            } else {
                plan.node = Some(wanted);
            }
        }
        if let Some((wanted, sha256)) = tmnode {
            let own = Version::parse(self.tmnode_version);
            if own == Some(wanted) {
                // Уже стоит.
            } else if let Some(own) = own
                && wanted < own
                && !order.allow_downgrade
            {
                return Err(format!(
                    "tmnode {own} новее {wanted}: понижение — только с allow_downgrade"
                ));
            } else {
                plan.tmnode = Some((wanted, sha256));
            }
        }
        Ok(plan)
    }

    /// Задание для `tmnode update` без админки. SHA-256 бинаря берётся из
    /// `SHA256SUMS` релиза; при выполнении файл сверяется с ним ещё раз.
    pub async fn local_order(
        &self,
        node_version: Option<Version>,
        tmnode_version: Option<Version>,
        allow_downgrade: bool,
    ) -> Result<UpdateOrder> {
        let tmnode_version =
            tmnode_version.filter(|v| Version::parse(self.tmnode_version) != Some(*v));
        let tmnode = match tmnode_version {
            None => None,
            Some(release) => {
                let asset = self.sources.asset();
                let sums = self
                    .fetch
                    .get(
                        &self.sources.release_file(release, "SHA256SUMS"),
                        MAX_SUMS_BYTES,
                    )
                    .await
                    .with_context(|| format!("SHA256SUMS релиза v{release}"))?;
                let sha256 = parse_sums(&String::from_utf8_lossy(&sums), &asset)
                    .ok_or_else(|| anyhow!("в SHA256SUMS релиза v{release} нет {asset}"))?;
                Some(crate::protocol::TmnodeRelease {
                    version: release.to_string(),
                    sha256,
                })
            }
        };
        Ok(UpdateOrder {
            id: format!("local-{}", (self.now)()),
            node_version: node_version.map(|v| v.to_string()),
            tmnode,
            allow_downgrade,
        })
    }

    fn current_image(&self, config: &NodeConfig) -> Option<String> {
        self.sys
            .container(&config.runtime.container)
            .ok()
            .flatten()
            .map(|c| c.image)
    }

    /// Скачать и проверить новый `tmnode`, сохранить прежний как
    /// `<имя>.prev` и атомарно подменить бинарь.
    async fn replace_tmnode(
        &self,
        run: &mut Run,
        version: Version,
        sha256: &str,
        progress: &impl Progress,
    ) -> Result<()> {
        self.step(run, UpdateStep::DownloadTmnode, progress).await?;
        // Версия tmnode — версия релиза бэкенда, в котором он вышел.
        let release = version;
        let asset = self.sources.asset();
        let sums = self
            .fetch
            .get(
                &self.sources.release_file(release, "SHA256SUMS"),
                MAX_SUMS_BYTES,
            )
            .await
            .with_context(|| format!("SHA256SUMS релиза v{release}"))?;
        let listed = parse_sums(&String::from_utf8_lossy(&sums), &asset)
            .ok_or_else(|| anyhow!("в SHA256SUMS релиза v{release} нет {asset}"))?;
        if listed != sha256 {
            bail!("SHA-256 {asset} в SHA256SUMS релиза v{release} не совпадает с заданием");
        }
        let binary = self
            .fetch
            .get(
                &self.sources.release_file(release, &asset),
                MAX_BINARY_BYTES,
            )
            .await
            .with_context(|| format!("{asset} релиза v{release}"))?;
        if hex::encode(Sha256::digest(&binary)) != sha256 {
            bail!("SHA-256 скачанного {asset} не совпадает ни с SHA256SUMS, ни с заданием");
        }

        let paths = BinaryPaths::of(self.tmnode_path)?;
        self.runner.write_file(&paths.new, &binary, 0o755, None)?;
        let printed = self.runner.run(&paths.new_str, &["version".into()]);
        let expected = format!("tmnode {version}");
        let checked = match &printed {
            Ok(out) if out.trim() == expected => Ok(()),
            Ok(out) => Err(anyhow!(
                "новый tmnode печатает «{}», а ждали «{expected}»",
                clip(out.trim(), 120)
            )),
            Err(err) => Err(anyhow!("новый tmnode не запускается: {err:#}")),
        };
        if let Err(err) = checked {
            let _ = self.runner.remove_file(&paths.new);
            return Err(err);
        }

        run.saved.status.tmnode = Some(version.to_string());
        self.step(run, UpdateStep::RestartAgent, progress).await?;
        self.runner
            .copy_file(self.tmnode_path, &paths.prev)
            .context("сохранить прежний tmnode")?;
        self.runner
            .rename(&paths.new, self.tmnode_path)
            .context("подменить tmnode")?;
        Ok(())
    }

    /// Обновить контейнер ноды, если это нужно, и подвести итог задания.
    async fn node_part(
        &self,
        mut run: Run,
        config: &NodeConfig,
        node: Option<Version>,
        progress: &impl Progress,
    ) -> Outcome {
        let Some(version) = node else {
            return self.finish(&mut run, UpdateState::Succeeded, None);
        };
        let (state, error) = match self.update_node(&mut run, config, version, progress).await {
            Ok(()) => (UpdateState::Succeeded, None),
            Err((state, why)) => (state, Some(why)),
        };
        self.finish(&mut run, state, error)
    }

    async fn update_node(
        &self,
        run: &mut Run,
        config: &NodeConfig,
        version: Version,
        progress: &impl Progress,
    ) -> Result<(), (UpdateState, String)> {
        let failed = |err: anyhow::Error| (UpdateState::Failed, format!("{err:#}"));
        let name = config.runtime.container.as_str();
        check_name(name).map_err(failed)?;
        let prev = format!("{name}.prev");
        let image = self.sources.image(version);

        self.step(run, UpdateStep::PullImage, progress)
            .await
            .map_err(failed)?;
        self.pull(&image)
            .await
            .with_context(|| format!("docker pull {image}"))
            .map_err(failed)?;
        let old = self
            .inspect(name)
            .map_err(failed)?
            .ok_or_else(|| (UpdateState::Failed, format!("контейнер {name} не найден")))?;
        run.secrets.extend(secret_values(&old.env));
        if self.inspect(&prev).map_err(failed)?.is_some() {
            return Err(failed(anyhow!(
                "контейнер {prev} уже есть — остался от прошлого обновления: разберитесь с ним вручную"
            )));
        }
        let image_env = self.image_env(&old.image_id).map_err(failed)?;
        let env = old.carried_env(&image_env).map_err(failed)?;
        let expected = self.expected_key(config).await.map_err(failed)?;

        run.saved.restart_policy = old.restart.clone();
        self.step(run, UpdateStep::Recreate, progress)
            .await
            .map_err(failed)?;
        self.docker(&["stop", "-t", STOP_TIMEOUT_SECS, name])
            .context("docker stop")
            .map_err(failed)?;
        if let Err(err) = self.docker(&["rename", name, &prev]) {
            let _ = self.docker(&["start", name]);
            return Err(failed(err.context("docker rename")));
        }
        if old.restart.is_some() {
            // Не критично: без этого прежний контейнер только поднимется
            // при перезапуске Docker и не займёт порт, пока работает новый.
            let _ = self.docker(&["update", "--restart", "no", &prev]);
        }
        if let Err(err) = self.start_new(&old, name, &image, &env) {
            return Err(match self.rollback(name, &prev, old.restart.as_deref()) {
                Ok(()) => failed(err.context("новый контейнер не запустился; работает прежний")),
                Err(back) => failed(anyhow!(
                    "новый контейнер не запустился: {err:#}; откат не удался: {back:#}"
                )),
            });
        }

        self.verify_or_rollback(run, config, name, &prev, &image, &expected, progress)
            .await
    }

    /// Проверка новой ноды; не прошла — откат на прежний контейнер.
    #[allow(clippy::too_many_arguments)]
    async fn verify_or_rollback(
        &self,
        run: &mut Run,
        config: &NodeConfig,
        name: &str,
        prev: &str,
        image: &str,
        expected: &str,
        progress: &impl Progress,
    ) -> Result<(), (UpdateState, String)> {
        let failed = |err: anyhow::Error| (UpdateState::Failed, format!("{err:#}"));
        self.step(run, UpdateStep::Verify, progress)
            .await
            .map_err(failed)?;
        match self.verify(config, expected).await {
            Ok(()) => {
                // Не удалился — не беда: новая нода уже проверена.
                let _ = self.docker(&["rm", prev]);
                run.saved.status.node_image = Some(image.to_owned());
                Ok(())
            }
            Err(why) => {
                let logs = self.log_tail(name);
                run.saved.status.error = Some(why.clone());
                self.step(run, UpdateStep::Rollback, progress)
                    .await
                    .map_err(failed)?;
                let restart = run.saved.restart_policy.clone();
                match self.rollback(name, prev, restart.as_deref()) {
                    Ok(()) => Err((UpdateState::RolledBack, format!("{why}\n{logs}"))),
                    Err(err) => Err((
                        UpdateState::Failed,
                        format!("{why}; откат не удался: {err:#}\n{logs}"),
                    )),
                }
            }
        }
    }

    /// Агент упал посреди пересоздания, проверки или отката: сначала
    /// вернуть рабочее состояние.
    async fn recover_node(
        &self,
        run: &mut Run,
        step: UpdateStep,
        progress: &impl Progress,
    ) -> Outcome {
        let config = match NodeConfig::load(self.node_toml) {
            Ok(config) => config,
            Err(err) => return self.finish(run, UpdateState::Failed, Some(format!("{err:#}"))),
        };
        let name = config.runtime.container.clone();
        let prev = format!("{name}.prev");
        let restart = run.saved.restart_policy.clone();
        let image = run
            .saved
            .order
            .node_version
            .as_deref()
            .and_then(Version::parse)
            .map(|v| self.sources.image(v));
        let (old, new) = match (self.inspect(&prev), self.inspect(&name)) {
            (Ok(old), Ok(new)) => (old, new),
            (Err(err), _) | (_, Err(err)) => {
                return self.finish(run, UpdateState::Failed, Some(format!("{err:#}")));
            }
        };
        for found in [&old, &new].into_iter().flatten() {
            run.secrets.extend(secret_values(&found.env));
        }
        let interrupted = format!("агент перезапустился на шаге {}", step_name(step));

        let Some(_old) = old else {
            // Прежний контейнер не переименован или уже убран.
            return match (step, new) {
                (UpdateStep::Verify, Some(new))
                    if new.running && Some(&new.image) == image.as_ref() =>
                {
                    // Проверка прошла, итог не успел записаться.
                    run.saved.status.node_image = Some(new.image);
                    self.finish(run, UpdateState::Succeeded, None)
                }
                (UpdateStep::Rollback, Some(_)) => {
                    let _ = self.docker(&["start", &name]);
                    let why = run.saved.status.error.clone().unwrap_or(interrupted);
                    self.finish(run, UpdateState::RolledBack, Some(why))
                }
                (_, Some(_)) => {
                    let started = self.docker(&["start", &name]);
                    let why = match started {
                        Ok(_) => {
                            format!("{interrupted}: прежний контейнер запущен, нода не обновлена")
                        }
                        Err(err) => {
                            format!("{interrupted}: контейнер {name} не запускается: {err:#}")
                        }
                    };
                    self.finish(run, UpdateState::Failed, Some(why))
                }
                (_, None) => self.finish(
                    run,
                    UpdateState::Failed,
                    Some(format!(
                        "{interrupted}: контейнеров {name} и {prev} нет — нода не работает"
                    )),
                ),
            };
        };

        let new_running = new.as_ref().is_some_and(|n| n.running);
        if step != UpdateStep::Rollback && new_running {
            // Новый контейнер работает: довести проверку.
            let expected = match self.expected_key(&config).await {
                Ok(expected) => expected,
                Err(err) => return self.finish(run, UpdateState::Failed, Some(format!("{err:#}"))),
            };
            let image = new.map(|n| n.image).unwrap_or_default();
            let (state, error) = match self
                .verify_or_rollback(run, &config, &name, &prev, &image, &expected, progress)
                .await
            {
                Ok(()) => (UpdateState::Succeeded, None),
                Err((state, why)) => (state, Some(why)),
            };
            return self.finish(run, state, error);
        }

        let why = run
            .saved
            .status
            .error
            .clone()
            .filter(|_| step == UpdateStep::Rollback)
            .unwrap_or_else(|| format!("{interrupted}: новый контейнер не работал"));
        run.saved.status.step = Some(UpdateStep::Rollback);
        match self.rollback(&name, &prev, restart.as_deref()) {
            Ok(()) => {
                run.saved.status.node_image = run.saved.status.from_node_image.clone();
                self.finish(run, UpdateState::RolledBack, Some(why))
            }
            Err(err) => self.finish(
                run,
                UpdateState::Failed,
                Some(format!("{why}; откат не удался: {err:#}")),
            ),
        }
    }

    /// Создать и запустить новый контейнер. Окружение — во временном файле
    /// с правами 0600: в командной строке его видел бы `ps`.
    fn start_new(
        &self,
        old: &Inspected,
        name: &str,
        image: &str,
        env: &Zeroizing<String>,
    ) -> Result<()> {
        let env_file = self.env_file();
        self.runner
            .write_file(&env_file, env.as_bytes(), 0o600, None)?;
        let created = self
            .runner
            .run("docker", &old.create_args(name, image, &env_file));
        let removed = self.runner.remove_file(&env_file);
        created.context("docker create")?;
        removed?;
        for network in &old.extra_networks {
            self.docker(&["network", "connect", network, name])
                .context("docker network connect")?;
        }
        self.docker(&["start", name]).context("docker start")?;
        Ok(())
    }

    /// Вернуть прежний контейнер: новый удалить, прежнему вернуть имя,
    /// политику перезапуска и запустить.
    fn rollback(&self, name: &str, prev: &str, restart: Option<&str>) -> Result<()> {
        if self.inspect(name)?.is_some() {
            self.docker(&["rm", "-f", name])?;
        }
        self.docker(&["rename", prev, name])?;
        if let Some(policy) = restart {
            self.docker(&["update", "--restart", policy, name])?;
        }
        self.docker(&["start", name])?;
        Ok(())
    }

    /// Новая нода работает, ключ прежний, рукопожатие и подписанный конфиг
    /// проходят — не дольше двух минут.
    async fn verify(&self, config: &NodeConfig, expected: &str) -> Result<(), String> {
        let started = Instant::now();
        let attempts = (VERIFY_LIMIT.as_secs() / VERIFY_PAUSE.as_secs()).max(1);
        let mut last = String::new();
        for attempt in 1..=attempts {
            let report = self.doctor(config).await;
            match judge(&report, expected) {
                Verdict::Passed => return Ok(()),
                Verdict::Fatal(why) => return Err(why),
                Verdict::Wait(why) => last = why,
            }
            if attempt == attempts || started.elapsed() >= VERIFY_LIMIT {
                break;
            }
            self.runner.sleep(VERIFY_PAUSE);
        }
        Err(format!(
            "новая нода не прошла проверку за {} с: {last}",
            VERIFY_LIMIT.as_secs()
        ))
    }

    async fn doctor(&self, config: &NodeConfig) -> Report {
        doctor::run(
            self.sys,
            &Input {
                config: ConfigSource::Loaded(self.node_toml.to_owned(), Box::new(config.clone())),
                container: None,
                addr: None,
                node_key: None,
                remote: false,
                step_timeout: Duration::from_secs(5),
            },
            (self.now)(),
        )
        .await
    }

    /// Ключ, который нода должна сохранить: пин из `node.toml`, а без него
    /// — ключ, который нода держит сейчас.
    async fn expected_key(&self, config: &NodeConfig) -> Result<String> {
        if let Some(endpoint) = &config.endpoint {
            return Ok(endpoint.node_key.to_ascii_lowercase());
        }
        let report = self.doctor(config).await;
        pin_key(&report).ok_or_else(|| {
            anyhow!("ключ ноды не прочитан: проверить новую ноду не с чем (tmnode doctor покажет причину)")
        })
    }

    /// `docker pull` с обрывом зависшей загрузки и повтором: прерванный
    /// pull Docker отменяет, а скачанные слои сохраняет, так что повтор
    /// докачивает остальное по новому соединению.
    async fn pull(&self, image: &str) -> Result<()> {
        let args = ["pull".to_owned(), image.to_owned()];
        let mut attempt = 1;
        loop {
            match self.runner.run_long("docker", &args, PULL_IDLE).await {
                Ok(_) => return Ok(()),
                Err(err) if attempt < PULL_ATTEMPTS && err.is::<Stalled>() => attempt += 1,
                Err(err) => return Err(err),
            }
        }
    }

    fn docker(&self, args: &[&str]) -> Result<String> {
        self.runner.run(
            "docker",
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }

    /// `docker inspect` контейнера; `None` — такого нет.
    fn inspect(&self, name: &str) -> Result<Option<Inspected>> {
        match self.docker(&["inspect", "--type", "container", name]) {
            Ok(out) => {
                let out = Zeroizing::new(out);
                parse_container(&out).map(Some)
            }
            Err(err) if format!("{err:#}").contains("No such") => Ok(None),
            Err(err) => Err(err.context("docker inspect")),
        }
    }

    /// Окружение, заданное самим образом (`Config.Env`).
    fn image_env(&self, image_id: &str) -> Result<Vec<Zeroizing<String>>> {
        let out = Zeroizing::new(
            self.docker(&["image", "inspect", image_id])
                .context("docker image inspect")?,
        );
        parse_image_env(&out)
    }

    /// Хвост журнала контейнера для причины отката: последние строки, не
    /// больше 2 КБ. Секреты вычищаются при записи статуса.
    fn log_tail(&self, name: &str) -> String {
        let tail = LOG_TAIL_LINES.to_string();
        match self.docker(&["logs", "--tail", &tail, name]) {
            Ok(out) => format!("docker logs {name}:\n{}", tail_text(&out)),
            Err(_) => format!("docker logs {name} недоступен"),
        }
    }

    /// Записать шаг и сообщить о нём до начала работы.
    async fn step(&self, run: &mut Run, step: UpdateStep, progress: &impl Progress) -> Result<()> {
        run.saved.status.step = Some(step);
        self.save(&run.saved)?;
        progress.running(&run.saved.status).await;
        Ok(())
    }

    fn finish(&self, run: &mut Run, state: UpdateState, error: Option<String>) -> Outcome {
        let status = &mut run.saved.status;
        status.state = state;
        status.finished_at = Some((self.now)());
        status.error = error.map(|text| clip(&redact(&text, &run.secrets), ERROR_MAX_BYTES));
        // Итог — то, что стоит сейчас: без успеха контейнер прежний (или
        // возвращён откатом), а tmnode — тот, что подводит итог.
        if state != UpdateState::Succeeded {
            status.node_image = status.from_node_image.clone();
        }
        status.tmnode = Some(self.tmnode_version.to_owned());
        // Итог не записался — повтор задания запустит его заново; сделать
        // тут больше нечего.
        let _ = self.save(&run.saved);
        Outcome::Done(run.saved.status.clone())
    }
}

/// Пути самообновления рядом с работающим бинарём: тот же каталог —
/// значит, rename атомарен.
struct BinaryPaths {
    new: PathBuf,
    new_str: String,
    prev: PathBuf,
}

impl BinaryPaths {
    fn of(current: &Path) -> Result<Self> {
        let file = current
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| anyhow!("путь к tmnode не распознан: {}", current.display()))?;
        let new = current.with_file_name(format!("{file}.new"));
        let new_str = new
            .to_str()
            .ok_or_else(|| anyhow!("путь к tmnode не UTF-8: {}", current.display()))?
            .to_owned();
        Ok(Self {
            prev: current.with_file_name(format!("{file}.prev")),
            new,
            new_str,
        })
    }
}

/// Строка `SHA256SUMS` для файла: `<hex>  <имя>` (или `<hex> *<имя>`).
pub fn parse_sums(text: &str, file: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (hash, name) = line.trim_end().split_once(char::is_whitespace)?;
        let name = name.trim_start().trim_start_matches('*');
        let hash = hash.to_ascii_lowercase();
        (name == file && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(hash)
    })
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Имя контейнера, сети или тома по правилам Docker. Имя, начатое с `-`,
/// docker принял бы за флаг.
fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if !ok {
        bail!("недопустимое имя `{name}`");
    }
    Ok(())
}

fn step_name(step: UpdateStep) -> &'static str {
    match step {
        UpdateStep::Check => "check",
        UpdateStep::DownloadTmnode => "download_tmnode",
        UpdateStep::RestartAgent => "restart_agent",
        UpdateStep::PullImage => "pull_image",
        UpdateStep::Recreate => "recreate",
        UpdateStep::Verify => "verify",
        UpdateStep::Rollback => "rollback",
    }
}

/// Итог как в протоколе: `succeeded`, `rolled_back`…
pub fn state_name(state: UpdateState) -> &'static str {
    match state {
        UpdateState::Running => "running",
        UpdateState::Succeeded => "succeeded",
        UpdateState::Failed => "failed",
        UpdateState::RolledBack => "rolled_back",
        UpdateState::Refused => "refused",
    }
}

/// Шаг по-человечески — для `tmnode update`.
pub fn step_text(step: UpdateStep) -> &'static str {
    match step {
        UpdateStep::Check => "проверка задания",
        UpdateStep::DownloadTmnode => "скачиваю tmnode и сверяю SHA-256",
        UpdateStep::RestartAgent => "заменяю tmnode",
        UpdateStep::PullImage => "скачиваю образ ноды",
        UpdateStep::Recreate => "пересоздаю контейнер ноды",
        UpdateStep::Verify => "проверяю новую ноду (до двух минут)",
        UpdateStep::Rollback => "возвращаю прежний контейнер",
    }
}

/// Прошла ли новая нода проверку.
fn judge(report: &Report, expected: &str) -> Verdict {
    let check = |id: &str| report.checks.iter().find(|c| c.id == id);
    // Ключа нет или он повреждён — нода создаст новый.
    if let Some(secret) = check("identity.secret")
        && secret.status == Status::Fail
    {
        return Verdict::Fatal(format!("ключ ноды сменится: {}", secret.summary));
    }
    if let Some(pin) = check("identity.pin") {
        if pin.status == Status::Fail {
            return Verdict::Fatal(format!("ключ ноды сменился: {}", pin.summary));
        }
        if let Some(key) = pin_key(report)
            && key != expected
        {
            return Verdict::Fatal(format!("ключ ноды сменился: был {expected}, стал {key}"));
        }
    }
    if let Some(c) = check("runtime.container")
        && matches!(c.status, Status::Fail | Status::Error | Status::Skip)
    {
        return Verdict::Wait(c.summary.clone());
    }
    if check("identity.pin").is_none_or(|c| c.status != Status::Ok) {
        return Verdict::Wait("ключ ноды не прочитан".into());
    }
    for id in ["endpoint.tcp", "endpoint.handshake", "endpoint.config"] {
        match check(id) {
            Some(c) if c.status == Status::Ok => {}
            Some(c) => return Verdict::Wait(format!("{id}: {}", c.summary)),
            None => return Verdict::Wait(format!("{id}: нет в отчёте")),
        }
    }
    if report.target.node_key.as_deref() != Some(expected) {
        return Verdict::Fatal(format!("нода проверена не с тем ключом: ждали {expected}"));
    }
    Verdict::Passed
}

/// Публичный ключ из файла или окружения ноды (проверка `identity.pin`).
fn pin_key(report: &Report) -> Option<String> {
    report
        .checks
        .iter()
        .find(|c| c.id == "identity.pin")?
        .data
        .get("node_key")?
        .as_str()
        .map(str::to_owned)
}

/// Значения окружения, которые нельзя выпускать в статус и журнал: всё,
/// что названо как секрет, и любое длинное значение — по имени всех
/// секретов не угадать.
fn secret_values(env: &[Zeroizing<String>]) -> Vec<Zeroizing<String>> {
    const MARKERS: [&str; 7] = [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASS",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE",
    ];
    env.iter()
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            let named = MARKERS.iter().any(|m| key.to_ascii_uppercase().contains(m));
            ((named && value.len() >= 4) || value.len() >= 12)
                .then(|| Zeroizing::new(value.to_owned()))
        })
        .collect()
}

fn redact(text: &str, secrets: &[Zeroizing<String>]) -> String {
    let mut sorted: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();
    // Длинные первыми: короткий секрет может быть частью длинного.
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = text.to_owned();
    for secret in sorted {
        if !secret.is_empty() {
            out = out.replace(secret, "***");
        }
    }
    out
}

/// Последние строки журнала, не больше 2 КБ.
fn tail_text(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    let tail = lines[start..].join("\n");
    if tail.len() <= LOG_TAIL_BYTES {
        return tail;
    }
    let mut cut = tail.len() - LOG_TAIL_BYTES;
    while !tail.is_char_boundary(cut) {
        cut += 1;
    }
    format!("…{}", &tail[cut..])
}

/// Обрезать по границе символа.
fn clip(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Контейнер ноды по `docker inspect` — всё, чтобы запустить такой же на
/// другом образе. Окружение — секрет: `Debug` его не печатает.
pub struct Inspected {
    /// Id образа (`sha256:…`): тег мог уже переехать на новый образ.
    pub image_id: String,
    /// Имя образа, на котором создан контейнер.
    pub image: String,
    pub running: bool,
    /// `KEY=VALUE`.
    pub env: Vec<Zeroizing<String>>,
    /// `--restart`: `unless-stopped`, `on-failure:3`; `None` — без политики.
    pub restart: Option<String>,
    /// `--network`; `None` — сеть Docker по умолчанию.
    pub network: Option<String>,
    /// Сети, подключённые к контейнеру помимо `network`.
    pub extra_networks: Vec<String>,
    /// Значения `-p`.
    pub ports: Vec<String>,
    /// Значения `-v`.
    pub volumes: Vec<String>,
}

impl fmt::Debug for Inspected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inspected")
            .field("image_id", &self.image_id)
            .field("image", &self.image)
            .field("running", &self.running)
            .field("env", &format_args!("<{} vars>", self.env.len()))
            .field("restart", &self.restart)
            .field("network", &self.network)
            .field("extra_networks", &self.extra_networks)
            .field("ports", &self.ports)
            .field("volumes", &self.volumes)
            .finish()
    }
}

impl Inspected {
    /// Окружение нового контейнера в формате `--env-file`: всё, кроме
    /// пар, заданных самим прежним образом, — новый образ даст свои
    /// умолчания (`PATH`, `RUST_LOG`). Значение, переопределённое при
    /// запуске, остаётся.
    pub fn carried_env(&self, image_env: &[Zeroizing<String>]) -> Result<Zeroizing<String>> {
        let mut out = Zeroizing::new(String::new());
        for pair in &self.env {
            if image_env.iter().any(|own| own.as_str() == pair.as_str()) {
                continue;
            }
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            if key.is_empty() || key.starts_with('#') || key.chars().any(char::is_whitespace) {
                bail!("переменная окружения `{key}`: такое имя не перенести в новый контейнер");
            }
            if value.contains(['\n', '\r', '\0']) {
                bail!("переменная {key}: перевод строки в значении не перенести в новый контейнер");
            }
            out.push_str(pair);
            out.push('\n');
        }
        Ok(out)
    }

    /// `docker create` нового контейнера с теми же сетью, портами, томами и
    /// политикой перезапуска.
    pub fn create_args(&self, name: &str, image: &str, env_file: &Path) -> Vec<String> {
        let mut args: Vec<String> = vec!["create".into(), "--name".into(), name.into()];
        if let Some(policy) = &self.restart {
            args.extend(["--restart".into(), policy.clone()]);
        }
        if let Some(network) = &self.network {
            args.extend(["--network".into(), network.clone()]);
        }
        for port in &self.ports {
            args.extend(["-p".into(), port.clone()]);
        }
        for volume in &self.volumes {
            args.extend(["-v".into(), volume.clone()]);
        }
        args.extend([
            "--env-file".into(),
            env_file.display().to_string(),
            image.into(),
        ]);
        args
    }
}

/// Разобрать `docker inspect` контейнера. Всё, что не перенести в новый
/// контейнер без потерь, — ошибка до остановки прежнего.
pub fn parse_container(json: &str) -> Result<Inspected> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Raw {
        image: String,
        state: RawState,
        config: RawConfig,
        host_config: RawHost,
        #[serde(default)]
        mounts: Option<Vec<RawMount>>,
        #[serde(default)]
        network_settings: Option<RawNetworks>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawState {
        status: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawConfig {
        image: String,
        #[serde(default)]
        env: Option<Vec<String>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawHost {
        #[serde(default)]
        network_mode: Option<String>,
        #[serde(default)]
        port_bindings: Option<BTreeMap<String, Option<Vec<RawBinding>>>>,
        #[serde(default)]
        restart_policy: Option<RawRestart>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawBinding {
        #[serde(default)]
        host_ip: String,
        #[serde(default)]
        host_port: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawRestart {
        #[serde(default)]
        name: String,
        #[serde(default)]
        maximum_retry_count: i64,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawMount {
        #[serde(rename = "Type")]
        kind: String,
        #[serde(default)]
        source: String,
        destination: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(rename = "RW", default = "yes")]
        rw: bool,
    }
    fn yes() -> bool {
        true
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawNetworks {
        #[serde(default)]
        networks: Option<BTreeMap<String, serde_json::Value>>,
    }

    let mut items: Vec<Raw> =
        serde_json::from_str(json).map_err(|err| anyhow!("docker inspect: {err}"))?;
    if items.len() != 1 {
        bail!(
            "docker inspect: ожидался 1 объект, получено {}",
            items.len()
        );
    }
    let raw = items.remove(0);

    if !raw
        .image
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':')
        || raw.image.is_empty()
    {
        bail!("docker inspect: неожиданный id образа");
    }

    let restart = match raw.host_config.restart_policy {
        None => None,
        Some(policy) => match policy.name.as_str() {
            "" | "no" => None,
            "always" | "unless-stopped" => Some(policy.name),
            "on-failure" if policy.maximum_retry_count > 0 => {
                Some(format!("on-failure:{}", policy.maximum_retry_count))
            }
            "on-failure" => Some(policy.name),
            other => bail!("политика перезапуска `{other}` не поддерживается"),
        },
    };

    let mode = raw.host_config.network_mode.unwrap_or_default();
    let attached: Vec<String> = raw
        .network_settings
        .and_then(|n| n.networks)
        .map(|n| n.into_keys().collect())
        .unwrap_or_default();
    let (network, extra_networks) = match mode.as_str() {
        "" | "default" => (
            None,
            attached.into_iter().filter(|n| n != "bridge").collect(),
        ),
        "host" | "none" => (Some(mode.clone()), Vec::new()),
        m if m.starts_with("container:") => {
            bail!("сеть другого контейнера ({m}) не поддерживается")
        }
        _ => {
            let extra = attached.into_iter().filter(|n| *n != mode).collect();
            (Some(mode.clone()), extra)
        }
    };
    for net in network.iter().chain(&extra_networks) {
        check_name(net).context("сеть")?;
    }

    let mut ports = Vec::new();
    if network.as_deref() != Some("host") {
        for (spec, bindings) in raw.host_config.port_bindings.unwrap_or_default() {
            let (port, proto) = spec
                .split_once('/')
                .ok_or_else(|| anyhow!("порт `{spec}`: ожидается порт/протокол"))?;
            let numeric = |p: &str| {
                !p.is_empty()
                    && p.split('-')
                        .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            };
            if !numeric(port) || !matches!(proto, "tcp" | "udp" | "sctp") {
                bail!("порт `{spec}` не поддерживается");
            }
            for binding in bindings.unwrap_or_default() {
                let ip = binding.host_ip;
                let host_port = binding.host_port;
                if !ip
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
                    || !(host_port.is_empty() || numeric(&host_port))
                {
                    bail!("публикация порта `{spec}` не поддерживается");
                }
                let ip = if ip.contains(':') {
                    format!("[{ip}]")
                } else {
                    ip
                };
                ports.push(match (ip.is_empty(), host_port.is_empty()) {
                    (true, true) => spec.clone(),
                    (true, false) => format!("{host_port}:{spec}"),
                    (false, true) => format!("{ip}::{spec}"),
                    (false, false) => format!("{ip}:{host_port}:{spec}"),
                });
            }
        }
    }

    let mut volumes = Vec::new();
    for mount in raw.mounts.unwrap_or_default() {
        let source = match mount.kind.as_str() {
            "bind" => mount.source,
            "volume" => {
                let name = mount.name.unwrap_or_default();
                check_name(&name).context("том")?;
                name
            }
            other => bail!(
                "том типа {other} ({}) не перенести в новый контейнер",
                mount.destination
            ),
        };
        for path in [&source, &mount.destination] {
            if path.is_empty() || path.contains([':', '\n', '\r', '\0']) {
                bail!("том `{path}`: такой путь не перенести в новый контейнер");
            }
        }
        let ro = if mount.rw { "" } else { ":ro" };
        volumes.push(format!("{source}:{}{ro}", mount.destination));
    }

    Ok(Inspected {
        image_id: raw.image,
        image: raw.config.image,
        running: raw.state.status == "running",
        env: raw
            .config
            .env
            .unwrap_or_default()
            .into_iter()
            .map(Zeroizing::new)
            .collect(),
        restart,
        network,
        extra_networks,
        ports,
        volumes,
    })
}

/// `Config.Env` из `docker image inspect`.
pub fn parse_image_env(json: &str) -> Result<Vec<Zeroizing<String>>> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Raw {
        #[serde(default)]
        config: Option<RawConfig>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawConfig {
        #[serde(default)]
        env: Option<Vec<String>>,
    }
    let items: Vec<Raw> =
        serde_json::from_str(json).map_err(|err| anyhow!("docker image inspect: {err}"))?;
    let [item] = <[Raw; 1]>::try_from(items).map_err(|items| {
        anyhow!(
            "docker image inspect: ожидался 1 объект, получено {}",
            items.len()
        )
    })?;
    Ok(item
        .config
        .and_then(|c| c.env)
        .unwrap_or_default()
        .into_iter()
        .map(Zeroizing::new)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP-сервер, который отвечает по сценарию: по ответу на соединение,
    /// `None` — принять запрос и молчать, как зависший CDN.
    async fn serve(
        script: Vec<Option<&'static str>>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let served = std::sync::Arc::new(AtomicUsize::new(0));
        let count = served.clone();
        tokio::spawn(async move {
            for answer in script {
                let (mut socket, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    match answer {
                        Some(text) => {
                            let _ = socket.write_all(text.as_bytes()).await;
                        }
                        None => {
                            let _ = socket
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                                .await;
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        }
                    }
                });
            }
        });
        (url, served)
    }

    fn fetcher(attempts: u32) -> HttpFetch {
        let sources = Sources {
            image_repo: DEFAULT_IMAGE_REPO.into(),
            releases_url: "http://127.0.0.1".into(),
            arch: "x86_64".into(),
        };
        HttpFetch::with_limits(
            &sources,
            Duration::from_millis(300),
            attempts,
            Duration::from_millis(10),
        )
        .unwrap()
    }

    const FULL: &str =
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabcdefghij";

    #[tokio::test]
    async fn stalled_and_failed_downloads_are_retried() {
        let (url, served) = serve(vec![
            None,
            Some("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Some(FULL),
        ])
        .await;
        let body = fetcher(3).get(&url, 1024).await.unwrap();
        assert_eq!(body, b"abcdefghij");
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn downloads_give_up_after_the_last_attempt_or_a_final_answer() {
        let (url, served) = serve(vec![None, None, Some(FULL)]).await;
        let err = format!("{:#}", fetcher(2).get(&url, 1024).await.unwrap_err());
        assert!(
            err.contains("данные не идут") && err.contains("2 попытки"),
            "{err}"
        );
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 2);

        let (url, served) = serve(vec![
            Some("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Some(FULL),
        ])
        .await;
        let err = format!("{:#}", fetcher(3).get(&url, 1024).await.unwrap_err());
        assert!(err.contains("404"), "{err}");
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);

        let (url, _) = serve(vec![Some(FULL)]).await;
        let err = format!("{:#}", fetcher(3).get(&url, 4).await.unwrap_err());
        assert!(err.contains("больше 4 байт"), "{err}");
    }

    #[test]
    fn versions_are_strict_and_compared_as_numbers() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("0.10.0") > v("0.9.0"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert_eq!(v("0.7.0").to_string(), "0.7.0");
        for bad in [
            "",
            "0.7",
            "0.7.0.1",
            "v0.7.0",
            "0.07.0",
            "0.7.x",
            "0.7.0-rc1",
            " 0.7.0",
            "0..1",
            "1234567890.0.0",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(
            Version::from_image("ghcr.io/darkildo/trustme_backend:v0.6.0"),
            Some(v("0.6.0"))
        );
        assert_eq!(
            Version::from_image("ghcr.io/darkildo/trustme_backend:stable"),
            None
        );
        assert_eq!(Version::from_image("localhost:5000/node"), None);
    }

    #[test]
    fn sources_come_from_the_environment() {
        let default = Sources::from_env(|_| None).unwrap();
        assert_eq!(default.image_repo, DEFAULT_IMAGE_REPO);
        assert_eq!(
            default.release_file(Version::parse("0.7.0").unwrap(), "SHA256SUMS"),
            "https://github.com/Darkildo/trustme_backend/releases/download/v0.7.0/SHA256SUMS"
        );
        assert_eq!(
            default.image(Version::parse("0.7.0").unwrap()),
            "ghcr.io/darkildo/trustme_backend:v0.7.0"
        );

        let own = Sources::from_env(|key| match key {
            "TMNODE_IMAGE_REPO" => Some("registry.example.org:5000/team/node".into()),
            "TMNODE_RELEASES_URL" => Some("https://mirror.example.org/releases/".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(own.releases_url, "https://mirror.example.org/releases");
        for (key, bad) in [
            ("TMNODE_IMAGE_REPO", "ghcr.io/x/y:latest"),
            ("TMNODE_IMAGE_REPO", "-x"),
            ("TMNODE_IMAGE_REPO", "img; rm -rf /"),
            ("TMNODE_IMAGE_REPO", "Upper/Case"),
            ("TMNODE_RELEASES_URL", "http://mirror.example.org"),
            ("TMNODE_RELEASES_URL", "ftp://x"),
        ] {
            assert!(
                Sources::from_env(|k| (k == key).then(|| bad.to_owned())).is_err(),
                "{key}={bad}"
            );
        }
    }

    #[test]
    fn sums_are_parsed() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let text = format!("{a}  tmnode-x86_64-linux\n{b} *tmnode-aarch64-linux\nbad line\n");
        assert_eq!(parse_sums(&text, "tmnode-x86_64-linux"), Some(a));
        assert_eq!(
            parse_sums(&text, "tmnode-aarch64-linux"),
            Some("b".repeat(64))
        );
        assert_eq!(parse_sums(&text, "tmnode-riscv64-linux"), None);
        assert_eq!(
            parse_sums("abc  tmnode-x86_64-linux\n", "tmnode-x86_64-linux"),
            None
        );
    }

    #[test]
    fn logs_are_trimmed_and_secrets_redacted() {
        let long: String = (0..100).map(|i| format!("строка {i}\n")).collect();
        let tail = tail_text(&long);
        assert_eq!(tail.lines().count(), LOG_TAIL_LINES);
        assert!(tail.starts_with("строка 80") && tail.ends_with("строка 99"));
        let wide = "я".repeat(5000);
        let tail = tail_text(&wide);
        assert!(tail.len() <= LOG_TAIL_BYTES + "…".len());

        let env = vec![
            Zeroizing::new(format!("NODE_IDENTITY_KEY={}", "ab".repeat(32))),
            Zeroizing::new("PUSH_TOKEN=abcd".to_owned()),
            Zeroizing::new("BIND_PORT=18081".to_owned()),
        ];
        let secrets = secret_values(&env);
        let text = format!("key {} token abcd port 18081", "ab".repeat(32));
        assert_eq!(redact(&text, &secrets), "key *** token *** port 18081");
        assert_eq!(clip("абв", 3), "а…");
    }

    const INSPECT: &str = r#"[{
        "Image": "sha256:0123abcd",
        "State": {"Status": "running"},
        "Config": {
            "Image": "ghcr.io/darkildo/trustme_backend:v0.6.0",
            "Env": ["PATH=/usr/bin", "RUST_LOG=info", "BIND_PORT=18081", "RUST_BACKTRACE=1"]
        },
        "HostConfig": {
            "NetworkMode": "trustme",
            "PortBindings": {
                "18081/tcp": [{"HostIp": "", "HostPort": "18081"}],
                "9000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "9000"}, {"HostIp": "::1", "HostPort": "9000"}]
            },
            "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3}
        },
        "Mounts": [
            {"Type": "bind", "Source": "/var/lib/trustme/node", "Destination": "/srv/trust-message/data", "RW": true},
            {"Type": "volume", "Name": "blobs", "Source": "/var/lib/docker/volumes/blobs/_data", "Destination": "/srv/blobs", "RW": false}
        ],
        "NetworkSettings": {"Networks": {"trustme": {}, "monitoring": {}}}
    }]"#;

    #[test]
    fn inspect_becomes_the_same_container_on_a_new_image() {
        let c = parse_container(INSPECT).unwrap();
        assert!(c.running);
        assert_eq!(c.extra_networks, vec!["monitoring".to_owned()]);
        assert_eq!(
            c.create_args(
                "message-service",
                "ghcr.io/darkildo/trustme_backend:v0.7.0",
                Path::new("/etc/tmnode/update.env")
            )
            .join(" "),
            "create --name message-service --restart on-failure:3 --network trustme \
             -p 18081:18081/tcp -p 127.0.0.1:9000:9000/tcp -p [::1]:9000:9000/tcp \
             -v /var/lib/trustme/node:/srv/trust-message/data -v blobs:/srv/blobs:ro \
             --env-file /etc/tmnode/update.env ghcr.io/darkildo/trustme_backend:v0.7.0"
        );
        let image_env = vec![
            Zeroizing::new("PATH=/usr/bin".to_owned()),
            Zeroizing::new("RUST_LOG=debug".to_owned()),
        ];
        // PATH — от образа; RUST_LOG=info задан при запуске поверх debug
        // образа — остаётся.
        assert_eq!(
            c.carried_env(&image_env).unwrap().as_str(),
            "RUST_LOG=info\nBIND_PORT=18081\nRUST_BACKTRACE=1\n"
        );
        assert!(!format!("{c:?}").contains("BIND_PORT"));
    }

    #[test]
    fn unportable_containers_are_refused_before_anything_stops() {
        let patch = |from: &str, to: &str| INSPECT.replace(from, to);
        for bad in [
            patch("\"Type\": \"bind\"", "\"Type\": \"tmpfs\""),
            patch("/srv/trust-message/data", "/srv/a:b"),
            patch(
                "\"NetworkMode\": \"trustme\"",
                "\"NetworkMode\": \"container:abc\"",
            ),
            patch("\"on-failure\"", "\"sometimes\""),
            patch("18081/tcp", "18081/quic"),
            patch("\"Name\": \"blobs\"", "\"Name\": \"-rm\""),
            patch("sha256:0123abcd", "sha256:01 23"),
            "[]".to_owned(),
        ] {
            assert!(parse_container(&bad).is_err(), "{bad}");
        }
        let c = parse_container(&patch("RUST_BACKTRACE=1", "MULTI=a\\nb")).unwrap();
        assert!(c.carried_env(&[]).is_err());

        let host = parse_container(&patch(
            "\"NetworkMode\": \"trustme\"",
            "\"NetworkMode\": \"host\"",
        ))
        .unwrap();
        assert_eq!(host.network.as_deref(), Some("host"));
        assert!(host.ports.is_empty() && host.extra_networks.is_empty());
        let default = parse_container(
            &patch(
                "\"NetworkMode\": \"trustme\"",
                "\"NetworkMode\": \"default\"",
            )
            .replace("\"trustme\": {}", "\"bridge\": {}"),
        )
        .unwrap();
        assert_eq!(default.network, None);
        assert_eq!(default.extra_networks, vec!["monitoring".to_owned()]);
    }

    #[test]
    fn image_env_is_read() {
        let env =
            parse_image_env(r#"[{"Config": {"Env": ["PATH=/bin", "RUST_LOG=info"]}}]"#).unwrap();
        assert_eq!(env.len(), 2);
        assert!(parse_image_env(r#"[{"Config": null}]"#).unwrap().is_empty());
        assert!(parse_image_env("[]").is_err());
    }
}
