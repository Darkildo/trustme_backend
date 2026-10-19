//! Команды, которые меняют машину: `install`, `enroll`, `agent`, `update`
//! (docs/tmnode.md). `doctor` и `config check` — только чтение, они в
//! `cli`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::agent::{self, AdminApi, AgentConfig, HttpAdmin};
use crate::install::{self, Installed, Layout, NodeMeta, Runner};
use crate::node_config::Backend;
use crate::protocol::{CoturnSpec, InstallSpec, RuntimeDoc, UpdateStatus};
use crate::update::{self, HttpFetch, Origin, Outcome, Progress, Sources, Updater, Version};

/// Образ ноды по умолчанию для установки без админки.
pub const DEFAULT_IMAGE: &str = "ghcr.io/darkildo/trustme_backend:stable";
pub const DEFAULT_COTURN_IMAGE: &str = "coturn/coturn:4.6.3";
pub const DEFAULT_PORT: u16 = 18081;

/// Аргументы `tmnode install` (без админки).
#[derive(Debug, Clone, PartialEq)]
pub struct LocalInstall {
    pub public_host: String,
    pub port: u16,
    pub backend: Backend,
    pub image: String,
    pub with_turn: bool,
}

pub fn parse_install(args: &[&str]) -> Result<LocalInstall, String> {
    let mut out = LocalInstall {
        public_host: String::new(),
        port: DEFAULT_PORT,
        backend: Backend::Sled,
        image: DEFAULT_IMAGE.to_owned(),
        with_turn: false,
    };
    let mut iter = args.iter();
    while let Some(&flag) = iter.next() {
        let mut value = || {
            iter.next()
                .copied()
                .ok_or_else(|| format!("{flag}: нужно значение"))
        };
        match flag {
            "--public-host" => out.public_host = value()?.to_owned(),
            "--port" => {
                out.port = value()?
                    .parse()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or("--port: число от 1 до 65535")?;
            }
            "--backend" => {
                out.backend = match value()? {
                    "sled" => Backend::Sled,
                    "jetstream" => Backend::Jetstream,
                    _ => return Err("--backend: sled или jetstream".into()),
                }
            }
            "--image" => out.image = value()?.to_owned(),
            "--with-turn" => out.with_turn = true,
            other => return Err(format!("неизвестный флаг `{other}`")),
        }
    }
    if out.public_host.is_empty() {
        return Err("--public-host обязателен: адрес, по которому к ноде ходят клиенты".into());
    }
    Ok(out)
}

/// Спецификация и настройки для установки без админки. С TURN — свой
/// секрет и секция `[ice]`, указывающая на coturn этого же хоста.
pub fn local_plan(args: &LocalInstall, secret: &str) -> (InstallSpec, Option<RuntimeDoc>) {
    let coturn = args.with_turn.then(|| CoturnSpec {
        image: DEFAULT_COTURN_IMAGE.to_owned(),
        realm: args.public_host.clone(),
        secret: secret.to_owned(),
        port: 3478,
        relay_min_port: 49160,
        relay_max_port: 49200,
    });
    let runtime = coturn.as_ref().map(|c| {
        let host = &args.public_host;
        RuntimeDoc {
            version: "local-1".to_owned(),
            content: format!(
                "# Создано tmnode install: TURN этого же хоста.\n\
                 version = \"local-1\"\n\n\
                 [[ice.servers]]\nurls = [\"stun:{host}:{port}\"]\n\n\
                 [[ice.servers]]\nurls = [\"turn:{host}:{port}?transport=udp\", \"turn:{host}:{port}?transport=tcp\"]\n\
                 secret = \"{secret}\"\n",
                port = c.port,
                secret = c.secret,
            ),
        }
    });
    (
        InstallSpec {
            image: args.image.clone(),
            public_host: args.public_host.clone(),
            port: args.port,
            backend: args.backend,
            coturn,
        },
        runtime,
    )
}

pub fn random_secret() -> String {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("operating system randomness");
    hex::encode(bytes)
}

pub fn print_installed(out: &mut impl Write, done: &Installed) {
    let _ = writeln!(
        out,
        "Нода установлена.\n\n  Адрес:     {}\n  Ключ ноды: {}\n  Отпечаток: {}\n\n\
         Добавьте ноду в приложение по адресу и ключу. Сохраните ключ — без него клиенты\n\
         не подключатся. Проверка: tmnode doctor",
        done.addr, done.node_key, done.fingerprint
    );
}

/// Аргументы `tmnode enroll`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrollArgs {
    pub url: String,
    pub token: String,
    pub no_install: bool,
}

pub fn parse_enroll(args: &[&str]) -> Result<EnrollArgs, String> {
    let mut out = EnrollArgs {
        url: String::new(),
        token: String::new(),
        no_install: false,
    };
    let mut iter = args.iter();
    while let Some(&flag) = iter.next() {
        let mut value = || {
            iter.next()
                .copied()
                .ok_or_else(|| format!("{flag}: нужно значение"))
        };
        match flag {
            "--url" => out.url = value()?.to_owned(),
            "--token" => out.token = value()?.to_owned(),
            "--no-install" => out.no_install = true,
            other => return Err(format!("неизвестный флаг `{other}`")),
        }
    }
    if out.url.is_empty() || out.token.is_empty() {
        return Err("нужны --url и --token из панели".into());
    }
    agent::check_url(&out.url).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Подключиться к админке и поставить ноду по её заданию.
pub async fn enroll_and_install(
    api: &impl AdminApi,
    runner: &dyn Runner,
    layout: &Layout,
    args: &EnrollArgs,
    hostname: &str,
    tmnode_path: &str,
) -> Result<Option<Installed>> {
    let response = agent::enroll(api, runner, layout, &args.url, &args.token, hostname).await?;
    if args.no_install {
        return Ok(None);
    }
    // Панель выдавала id как ULID в верхнем регистре, а node.toml пускает
    // только строчные. ULID к регистру нечувствителен, ноду в heartbeat
    // админка узнаёт по токену агента — приводим, а не отказываем.
    let node_id = response.node_id.to_ascii_lowercase();
    let done = install::install(
        runner,
        layout,
        &response.install,
        response.runtime.as_ref(),
        &NodeMeta {
            id: Some(&node_id),
            name: Some(&response.node_name),
            managed: true,
        },
    )?;
    install::install_agent_service(runner, layout, tmnode_path)?;
    Ok(Some(done))
}

/// Имя хоста для панели.
pub fn hostname(runner: &dyn Runner) -> String {
    runner
        .read_file(std::path::Path::new("/etc/hostname"))
        .ok()
        .flatten()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Служба агента: токен из `agent.toml`, `node.toml` из каталога настроек.
/// Возвращается, когда `tmnode` заменён: systemd перезапустит службу.
pub async fn agent_service<S: crate::system::System>(
    runner: &dyn Runner,
    sys: &S,
    layout: &Layout,
) -> Result<()> {
    let config = AgentConfig::load(runner, layout)?;
    let api = HttpAdmin::new(&config.url, Some(config.token.clone()))
        .context("адрес админки в agent.toml")?;
    let node_toml = layout.etc_dir.join("node.toml");
    if runner.read_file(&node_toml)?.is_none() {
        bail!("{} нет: нода не установлена", node_toml.display());
    }
    // Пока служба работает, `tmnode update` на этом сервере не запустится.
    let _lock = lock_updates(layout)?;
    let sources = Sources::from_env(|key| std::env::var(key).ok())?;
    let fetch = HttpFetch::new(&sources)?;
    let tmnode_path = tmnode_path()?;
    let updater = Updater {
        runner,
        sys,
        fetch: &fetch,
        layout,
        sources: &sources,
        node_toml: &node_toml,
        tmnode_path: &tmnode_path,
        tmnode_version: env!("CARGO_PKG_VERSION"),
        origin: Origin::Admin,
        now: &now,
    };
    agent::run_forever(&api, &updater, |line| eprintln!("tmnode agent: {line}")).await;
    Ok(())
}

/// Обновлением на сервере занят один процесс: служба агента или
/// `tmnode update`. Блокировка снимается с завершением процесса.
pub fn lock_updates(layout: &Layout) -> Result<std::fs::File> {
    use fs2::FileExt;
    std::fs::create_dir_all(&layout.etc_dir)
        .with_context(|| format!("каталог {}", layout.etc_dir.display()))?;
    let path = layout.etc_dir.join("update.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("блокировка {}", path.display()))?;
    file.try_lock_exclusive().map_err(|_| {
        anyhow::anyhow!(
            "{} занят: работает служба tmnode-agent или другой tmnode update",
            path.display()
        )
    })?;
    Ok(file)
}

/// Путь к работающему бинарю: рядом с ним кладётся новый.
pub fn tmnode_path() -> Result<std::path::PathBuf> {
    let path = std::env::current_exe().context("путь к tmnode")?;
    // Бинарь подменили, пока процесс работал: ядро дописывает пометку.
    Ok(
        match path.to_str().and_then(|p| p.strip_suffix(" (deleted)")) {
            Some(stripped) => stripped.into(),
            None => path,
        },
    )
}

/// Аргументы `tmnode update`.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateArgs {
    pub node_version: Option<Version>,
    pub tmnode_version: Option<Version>,
    pub allow_downgrade: bool,
    pub json: bool,
    /// Только дочитать прерванное обновление.
    pub resume: bool,
}

pub fn parse_update(args: &[&str]) -> Result<UpdateArgs, String> {
    let mut out = UpdateArgs {
        node_version: None,
        tmnode_version: None,
        allow_downgrade: false,
        json: false,
        resume: false,
    };
    let mut iter = args.iter();
    while let Some(&flag) = iter.next() {
        let mut version = || {
            let raw = iter
                .next()
                .copied()
                .ok_or_else(|| format!("{flag}: нужно значение"))?;
            Version::parse(raw).ok_or_else(|| format!("{flag}: ожидается X.Y.Z, получено `{raw}`"))
        };
        match flag {
            "--node-version" => out.node_version = Some(version()?),
            "--tmnode-version" => out.tmnode_version = Some(version()?),
            "--allow-downgrade" => out.allow_downgrade = true,
            "--json" => out.json = true,
            "--resume" => out.resume = true,
            other => return Err(format!("неизвестный флаг `{other}`")),
        }
    }
    let versions = out.node_version.is_some() || out.tmnode_version.is_some();
    if out.resume && versions {
        return Err("--resume дочитывает прерванное обновление: без версий".into());
    }
    if !out.resume && !versions {
        return Err("нужна --node-version и/или --tmnode-version".into());
    }
    Ok(out)
}

/// Ход `tmnode update` — шаги в stderr.
struct StepPrinter<'a, W: Write> {
    out: std::cell::RefCell<&'a mut W>,
}

impl<W: Write> Progress for StepPrinter<'_, W> {
    async fn running(&self, status: &UpdateStatus) {
        if let Some(step) = status.step {
            let _ = writeln!(self.out.borrow_mut(), "→ {}", update::step_text(step));
        }
    }
}

/// `tmnode update`: сначала дочитать прерванное обновление, потом
/// выполнить новое. `None` — делать нечего.
pub async fn update<S: crate::system::System, F: update::Fetch>(
    up: &Updater<'_, S, F>,
    args: &UpdateArgs,
    log: &mut impl Write,
) -> Result<Option<Outcome>> {
    let config = crate::node_config::NodeConfig::load(up.node_toml)
        .context("tmnode update работает с нодой, поставленной tmnode install")?;
    if config.management.mode == crate::node_config::ManagementMode::Managed {
        // До дочитывания: прерванное задание админки доводит её агент.
        bail!(
            "нода под управлением админки (management.mode = \"managed\"): обновляйте её из панели"
        );
    }
    let progress = StepPrinter {
        out: std::cell::RefCell::new(log),
    };
    if let Some(outcome) = up.resume(&progress).await {
        if args.resume || matches!(outcome, Outcome::Restart(_)) {
            return Ok(Some(outcome));
        }
        let status = outcome.status();
        let _ = writeln!(
            progress.out.borrow_mut(),
            "Прерванное обновление {}: {}",
            status.id,
            update::state_name(status.state)
        );
    }
    if args.resume {
        return Ok(None);
    }
    let own = Version::parse(up.tmnode_version);
    if args.node_version.is_none() && args.tmnode_version == own {
        let _ = writeln!(
            progress.out.borrow_mut(),
            "tmnode {} уже стоит",
            up.tmnode_version
        );
        return Ok(None);
    }
    let order = up
        .local_order(args.node_version, args.tmnode_version, args.allow_downgrade)
        .await?;
    Ok(Some(up.execute(&order, &progress).await))
}

/// Итог `tmnode update`: текст или JSON (`UpdateStatus`, как в протоколе).
pub fn print_update(out: &mut impl Write, status: &UpdateStatus, json: bool) {
    if json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(status).expect("status serializes")
        );
        return;
    }
    let state = match status.state {
        crate::protocol::UpdateState::Succeeded => "готово",
        crate::protocol::UpdateState::Failed => "не удалось",
        crate::protocol::UpdateState::RolledBack => "откат: новая нода не прошла проверку",
        crate::protocol::UpdateState::Refused => "отказ",
        crate::protocol::UpdateState::Running => "выполняется",
    };
    let _ = writeln!(out, "Обновление {}: {state}", status.id);
    let pair = |from: &Option<String>, to: &Option<String>| match (from, to) {
        (Some(from), Some(to)) if from != to => format!("{from} → {to}"),
        (_, Some(to)) => to.clone(),
        (Some(from), None) => from.clone(),
        (None, None) => "—".to_owned(),
    };
    let _ = writeln!(
        out,
        "  нода:   {}\n  tmnode: {}",
        pair(&status.from_node_image, &status.node_image),
        pair(&status.from_tmnode, &status.tmnode)
    );
    if let Some(error) = &status.error {
        let _ = writeln!(out, "\n{error}");
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_flags() {
        let args = parse_install(&[
            "--public-host",
            "203.0.113.10",
            "--port",
            "5000",
            "--backend",
            "jetstream",
            "--image",
            "img:1",
            "--with-turn",
        ])
        .unwrap();
        assert_eq!(args.port, 5000);
        assert_eq!(args.backend, Backend::Jetstream);
        assert!(args.with_turn);
        for bad in [
            &[][..],
            &["--public-host"],
            &["--public-host", "h", "--port", "0"],
            &["--public-host", "h", "--backend", "kafka"],
            &["--public-host", "h", "--bogus"],
        ] {
            assert!(parse_install(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn local_plan_with_turn_points_ice_at_this_host() {
        let args = parse_install(&["--public-host", "node.example.org", "--with-turn"]).unwrap();
        let (spec, runtime) = local_plan(&args, &"a".repeat(48));
        assert_eq!(spec.coturn.as_ref().unwrap().realm, "node.example.org");
        let runtime = runtime.unwrap();
        let file = trust_message_tcp::runtime::RuntimeFile::parse(&runtime.content).unwrap();
        assert_eq!(file.version.as_deref(), Some("local-1"));
        let tunables = file
            .overlay(&Default::default(), 8 * 1024 * 1024)
            .expect("generated ice section is valid");
        assert_eq!(tunables.ice.servers.len(), 2);

        let plain = parse_install(&["--public-host", "h"]).unwrap();
        let (spec, runtime) = local_plan(&plain, "x");
        assert!(spec.coturn.is_none() && runtime.is_none());
        assert_eq!(random_secret().len(), 48);
        assert_ne!(random_secret(), random_secret());
    }

    #[test]
    fn enroll_flags() {
        let args =
            parse_enroll(&["--url", "https://admin.example.org/", "--token", "tme_x"]).unwrap();
        assert!(!args.no_install);
        assert!(parse_enroll(&["--url", "http://admin.example.org", "--token", "t"]).is_err());
        assert!(parse_enroll(&["--url", "https://a"]).is_err());
        assert!(
            parse_enroll(&["--url", "https://a", "--token", "t", "--no-install"])
                .unwrap()
                .no_install
        );
        assert!(parse_enroll(&["--x"]).is_err());
        assert!(parse_enroll(&["--url"]).is_err());
    }

    #[test]
    fn one_update_at_a_time() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tmnode_lock_{nanos}"));
        let layout = Layout {
            data_dir: root.join("data"),
            etc_dir: root.join("etc"),
            unit_path: root.join("unit"),
        };
        let held = lock_updates(&layout).unwrap();
        let err = lock_updates(&layout).unwrap_err();
        assert!(err.to_string().contains("tmnode-agent"), "{err}");
        drop(held);
        assert!(lock_updates(&layout).is_ok());
        assert!(tmnode_path().unwrap().is_absolute());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn installed_summary_mentions_the_key() {
        let mut out = Vec::new();
        print_installed(
            &mut out,
            &Installed {
                node_key: "ab".repeat(32),
                fingerprint: "ABAB".into(),
                addr: "h:1".into(),
            },
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&"ab".repeat(32)) && text.contains("h:1"));
    }
}
