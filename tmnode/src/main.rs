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
