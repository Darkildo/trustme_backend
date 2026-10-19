//! Команды, которые меняют машину: `install`, `enroll`, `agent`
//! (docs/tmnode.md). `doctor` и `config check` — только чтение, они в
//! `cli`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::agent::{self, AdminApi, AgentConfig, HttpAdmin};
use crate::install::{self, Installed, Layout, NodeMeta, Runner};
use crate::node_config::Backend;
use crate::protocol::{CoturnSpec, InstallSpec, RuntimeDoc};

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
    let done = install::install(
        runner,
        layout,
        &response.install,
        response.runtime.as_ref(),
        &NodeMeta {
            id: Some(&response.node_id),
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
    agent::run_forever(&api, runner, sys, &node_toml, now, |line| {
        eprintln!("tmnode agent: {line}")
    })
    .await
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
