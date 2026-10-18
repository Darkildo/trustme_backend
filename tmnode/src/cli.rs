//! Разбор командной строки `tmnode`. Без интерактивных вопросов: всё
//! задаётся флагами или `node.toml`, чтобы тот же вызов работал из
//! скриптов, cloud-init и агента admin-сервиса.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::doctor::{self, ConfigSource, Input};
use crate::node_config::{self, NodeConfig};
use crate::system::System;

/// Неверный вызов: отчёта нет.
pub const EXIT_USAGE: i32 = 2;

const USAGE: &str = "\
tmnode — обслуживание ноды TrustMe

Использование:
  tmnode doctor [опции]       проверить ноду (только чтение)
  tmnode config check [ФАЙЛ]  проверить node.toml
  tmnode version

Опции doctor:
  --config ФАЙЛ      node.toml (по умолчанию /etc/tmnode/node.toml, если он есть)
  --container ИМЯ    контейнер ноды (по умолчанию message-service)
  --addr ХОСТ:ПОРТ   адрес ноды для проверки снаружи
  --node-key HEX     пин ноды (node_key=… из лога), 64 hex
  --remote           машина — не хост ноды: проверить только сеть
  --json             отчёт в JSON (формат tmnode.report/1)
  --strict           предупреждения тоже дают код выхода 1
  --timeout СЕК      предел каждого сетевого шага (по умолчанию 5)

Коды выхода: 0 — в порядке, 1 — есть проблемы, 2 — неверный вызов.
";

struct DoctorArgs {
    config: Option<PathBuf>,
    container: Option<String>,
    addr: Option<String>,
    node_key: Option<[u8; 32]>,
    remote: bool,
    json: bool,
    strict: bool,
    timeout: Duration,
}

/// Выполнить команду и вернуть код выхода.
pub async fn run<S: System>(
    args: &[String],
    sys: &S,
    default_config: &Path,
    now: u64,
    out: &mut impl Write,
    err: &mut impl Write,
) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["doctor", rest @ ..] => match parse_doctor(rest) {
            Ok(parsed) => doctor(parsed, sys, default_config, now, out, err).await,
            Err(msg) => usage_error(err, &msg),
        },
        ["config", "check"] => config_check(default_config, out, err),
        ["config", "check", path] => config_check(Path::new(path), out, err),
        ["version"] | ["--version"] | ["-V"] => {
            let _ = writeln!(out, "tmnode {}", env!("CARGO_PKG_VERSION"));
            0
        }
        [] | ["help"] | ["--help"] | ["-h"] => {
            let _ = write!(out, "{USAGE}");
            0
        }
        [other, ..] => usage_error(err, &format!("неизвестная команда `{other}`")),
    }
}

fn usage_error(err: &mut impl Write, msg: &str) -> i32 {
    let _ = writeln!(err, "tmnode: {msg}\n\n{USAGE}");
    EXIT_USAGE
}

fn parse_doctor(args: &[&str]) -> Result<DoctorArgs, String> {
    let mut parsed = DoctorArgs {
        config: None,
        container: None,
        addr: None,
        node_key: None,
        remote: false,
        json: false,
        strict: false,
        timeout: Duration::from_secs(5),
    };
    let mut iter = args.iter();
    while let Some(&flag) = iter.next() {
        let mut value = || {
            iter.next()
                .copied()
                .ok_or_else(|| format!("{flag}: нужно значение"))
        };
        match flag {
            "--config" => parsed.config = Some(PathBuf::from(value()?)),
            "--container" => parsed.container = Some(value()?.to_owned()),
            "--addr" => {
                let addr = value()?;
                node_config::check_addr(addr).map_err(|e| format!("--addr: {e:#}"))?;
                parsed.addr = Some(addr.to_owned());
            }
            "--node-key" => {
                parsed.node_key = Some(
                    node_config::parse_node_key(value()?)
                        .map_err(|e| format!("--node-key: {e:#}"))?,
                );
            }
            "--timeout" => {
                let secs: u64 = value()?
                    .parse()
                    .ok()
                    .filter(|s| (1..=120).contains(s))
                    .ok_or("--timeout: целое число секунд от 1 до 120")?;
                parsed.timeout = Duration::from_secs(secs);
            }
            "--remote" => parsed.remote = true,
            "--json" => parsed.json = true,
            "--strict" => parsed.strict = true,
            other => return Err(format!("неизвестный флаг `{other}`")),
        }
    }
    if parsed.remote && parsed.addr.is_none() && parsed.config.is_none() {
        return Err("--remote без --addr или --config: нечего проверять".to_owned());
    }
    Ok(parsed)
}

async fn doctor<S: System>(
    args: DoctorArgs,
    sys: &S,
    default_config: &Path,
    now: u64,
    out: &mut impl Write,
    err: &mut impl Write,
) -> i32 {
    // Явно заданный файл обязан существовать; файл по умолчанию — нет:
    // на ноде, поставленной без tmnode, его и не бывает.
    let config = match &args.config {
        Some(path) if !path.exists() => {
            return usage_error(err, &format!("--config: файла {} нет", path.display()));
        }
        Some(path) => load(path),
        None if default_config.exists() => load(default_config),
        None => ConfigSource::Absent,
    };
    let input = Input {
        config,
        container: args.container,
        addr: args.addr,
        node_key: args.node_key,
        remote: args.remote,
        step_timeout: args.timeout,
    };
    let report = doctor::run(sys, &input, now).await;
    let text = if args.json {
        report.to_json() + "\n"
    } else {
        report.to_text()
    };
    let _ = out.write_all(text.as_bytes());
    report.exit_code(args.strict)
}

fn load(path: &Path) -> ConfigSource {
    match NodeConfig::load(path) {
        Ok(config) => ConfigSource::Loaded(path.to_owned(), Box::new(config)),
        Err(e) => ConfigSource::Invalid(path.to_owned(), format!("{e:#}")),
    }
}

fn config_check(path: &Path, out: &mut impl Write, err: &mut impl Write) -> i32 {
    match NodeConfig::load(path) {
        Ok(_) => {
            let _ = writeln!(out, "{}: в порядке", path.display());
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e:#}");
            1
        }
    }
}
