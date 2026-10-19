use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tmnode::node_config::DEFAULT_PATH;
use tmnode::system::HostSystem;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let ops = matches!(
        args.first().map(String::as_str),
        Some("install" | "enroll" | "agent")
    );
    if ops {
        std::process::exit(runtime.block_on(run_ops(&args)));
    }
    let code = runtime.block_on(tmnode::cli::run(
        &args,
        &HostSystem::default(),
        Path::new(DEFAULT_PATH),
        now,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ));
    std::process::exit(code);
}

/// Команды, которые меняют машину. Ошибки — по-человечески в stderr.
async fn run_ops(args: &[String]) -> i32 {
    use tmnode::install::{HostRunner, Layout};
    use tmnode::ops;

    let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    let layout = Layout::default();
    let runner = HostRunner;
    let usage = |msg: String| {
        eprintln!("tmnode: {msg}\n\nСправка: tmnode help");
        tmnode::cli::EXIT_USAGE
    };
    let result = match args[0].as_str() {
        "install" => match ops::parse_install(&rest) {
            Err(msg) => return usage(msg),
            Ok(parsed) => {
                let (spec, runtime) = ops::local_plan(&parsed, &ops::random_secret());
                let meta = tmnode::install::NodeMeta {
                    id: None,
                    name: None,
                    managed: false,
                };
                tmnode::install::install(&runner, &layout, &spec, runtime.as_ref(), &meta)
                    .map(|done| ops::print_installed(&mut std::io::stdout(), &done))
            }
        },
        "enroll" => match ops::parse_enroll(&rest) {
            Err(msg) => return usage(msg),
            Ok(parsed) => {
                let tmnode_path = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "/usr/local/bin/tmnode".into());
                match tmnode::agent::HttpAdmin::new(&parsed.url, None) {
                    Err(err) => Err(err),
                    Ok(api) => ops::enroll_and_install(
                        &api,
                        &runner,
                        &layout,
                        &parsed,
                        &ops::hostname(&runner),
                        &tmnode_path,
                    )
                    .await
                    .map(|done| match done {
                        Some(done) => ops::print_installed(&mut std::io::stdout(), &done),
                        None => println!("Сервер подключён к админке."),
                    }),
                }
            }
        },
        _ => ops::agent_service(&runner, &HostSystem::default(), &layout).await,
    };
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("tmnode: {err:#}");
            1
        }
    }
}
