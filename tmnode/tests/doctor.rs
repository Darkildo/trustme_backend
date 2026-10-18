//! Сценарии `tmnode doctor` на подставной машине: что видит оператор в
//! каждой типовой поломке и что получает admin-сервис в JSON.

mod common;

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use common::{Answer, DATA, Fake, GIB, healthy, node_public};
use tmnode::doctor::{CHECK_IDS, ConfigSource, Input, run};
use tmnode::node_config::NodeConfig;
use tmnode::report::{Report, Status};
use tmnode::system::{DiskSpace, DockerError, MemInfo};
use trust_message_tcp::net::probe::ProbeStage;

fn input() -> Input {
    Input {
        config: ConfigSource::Absent,
        container: None,
        addr: None,
        node_key: None,
        remote: false,
        step_timeout: Duration::from_secs(1),
    }
}

fn with_config(text: &str) -> Input {
    Input {
        config: ConfigSource::Loaded(
            PathBuf::from("/etc/tmnode/node.toml"),
            Box::new(NodeConfig::parse(text).unwrap()),
        ),
        ..input()
    }
}

async fn doctor(sys: &Fake, input: &Input) -> HashMap<&'static str, (Status, String)> {
    let report = run(sys, input, 1_800_000_000).await;
    statuses(&report)
}

fn statuses(report: &Report) -> HashMap<&'static str, (Status, String)> {
    let ids: Vec<&str> = report.checks.iter().map(|c| c.id).collect();
    assert_eq!(ids, CHECK_IDS, "набор и порядок проверок — контракт");
    report
        .checks
        .iter()
        .map(|c| (c.id, (c.status, c.summary.clone())))
        .collect()
}

fn status(map: &HashMap<&'static str, (Status, String)>, id: &str) -> Status {
    map[id].0
}

#[tokio::test]
async fn healthy_node_without_node_toml_checks_itself() {
    let sys = healthy();
    let report = run(&sys, &input(), 1_800_000_000).await;
    let map = statuses(&report);

    for id in CHECK_IDS {
        let expected = match *id {
            "config.file" | "config.drift" => Status::Skip,
            _ => Status::Ok,
        };
        assert_eq!(status(&map, id), expected, "{id}: {}", map[id].1);
    }
    assert_eq!(report.status, Status::Skip);
    assert_eq!(report.exit_code(true), 0);

    // Без node.toml нода проверяется по опубликованному порту и своему ключу.
    let probed = sys.probed.borrow();
    assert_eq!(
        probed.as_slice(),
        &[("127.0.0.1:18081".to_owned(), node_public())]
    );
    assert_eq!(report.target.node_key, Some(hex::encode(node_public())));
    assert_eq!(report.target.container.as_deref(), Some("message-service"));

    let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
    let pin = &json["checks"][7];
    assert_eq!(pin["id"], "identity.pin");
    assert_eq!(pin["data"]["node_key"], hex::encode(node_public()));
    // Секрет ключа в отчёт не попадает ни в каком виде.
    assert!(!report.to_json().contains(&hex::encode(common::SEED)));
}

#[tokio::test]
async fn prod_like_disk_warns_about_blob_quota() {
    let mut sys = healthy();
    sys.disk = Some(DiskSpace {
        total: 14 * GIB,
        available: 1_800_000_000,
    });
    let report = run(&sys, &input(), 0).await;
    let map = statuses(&report);

    assert_eq!(status(&map, "host.disk"), Status::Warn);
    assert_eq!(status(&map, "host.blob_reserve"), Status::Warn);
    assert!(
        map["host.blob_reserve"].1.contains("QUOTA"),
        "{}",
        map["host.blob_reserve"].1
    );
    assert_eq!(report.exit_code(false), 0);
    assert_eq!(report.exit_code(true), 1);

    sys.disk = Some(DiskSpace {
        total: 14 * GIB,
        available: 100 * 1024 * 1024,
    });
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.disk"), Status::Fail);

    sys.disk = None;
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.disk"), Status::Error);
    assert_eq!(status(&map, "host.blob_reserve"), Status::Error);
}

const KEY_LINE: &str = "node_key = \"";

fn toml_for(addr: &str, key: [u8; 32], backend: &str) -> String {
    format!(
        "schema = 1\n[endpoint]\naddr = \"{addr}\"\n{KEY_LINE}{}\"\n[delivery]\nbackend = \"{backend}\"\n",
        hex::encode(key)
    )
}

#[tokio::test]
async fn node_toml_drives_the_endpoint_and_drift() {
    let sys = healthy();
    let input = with_config(&toml_for("203.0.113.10:18081", node_public(), "jetstream"));
    let map = doctor(&sys, &input).await;

    assert_eq!(status(&map, "config.file"), Status::Ok);
    assert_eq!(status(&map, "config.drift"), Status::Ok);
    assert_eq!(status(&map, "identity.pin"), Status::Ok);
    assert!(map["identity.pin"].1.contains("совпадает"));
    assert_eq!(
        sys.probed.borrow()[0],
        ("203.0.113.10:18081".to_owned(), node_public())
    );
}

#[tokio::test]
async fn foreign_pin_and_drift_are_reported() {
    let sys = healthy();
    let input = with_config(&toml_for("203.0.113.10:5000", [1u8; 32], "sled"));
    let map = doctor(&sys, &input).await;

    assert_eq!(status(&map, "identity.pin"), Status::Fail);
    assert_eq!(status(&map, "config.drift"), Status::Warn);
    let drift = &map["config.drift"].1;
    assert!(
        drift.contains("бэкенд") && drift.contains("порт"),
        "{drift}"
    );
}

#[tokio::test]
async fn invalid_node_toml_fails_but_the_rest_still_runs() {
    let sys = healthy();
    let input = Input {
        config: ConfigSource::Invalid(PathBuf::from("/etc/tmnode/node.toml"), "schema".into()),
        ..input()
    };
    let report = run(&sys, &input, 0).await;
    let map = statuses(&report);
    assert_eq!(status(&map, "config.file"), Status::Fail);
    assert_eq!(status(&map, "endpoint.config"), Status::Ok);
    assert_eq!(
        report.target.config.as_deref(),
        Some("/etc/tmnode/node.toml")
    );
    assert_eq!(report.exit_code(false), 1);
}

#[tokio::test]
async fn docker_problems_skip_what_depends_on_the_container() {
    let mut sys = healthy();
    sys.container = Err(DockerError::Missing);
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "runtime.docker"), Status::Error);
    for id in [
        "runtime.container",
        "runtime.config",
        "host.data_dir",
        "identity.secret",
        "identity.pin",
        "host.disk",
        "host.blob_reserve",
        "endpoint.tcp",
    ] {
        assert_eq!(status(&map, id), Status::Skip, "{id}");
    }
    // Память и часы от Docker не зависят.
    assert_eq!(status(&map, "host.memory"), Status::Ok);
    assert_eq!(status(&map, "host.clock"), Status::Ok);
    assert!(sys.probed.borrow().is_empty());

    sys.container = Err(DockerError::Failed("permission denied".into()));
    let map = doctor(&sys, &input()).await;
    assert!(map["runtime.docker"].1.contains("permission denied"));

    sys.container = Ok(None);
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "runtime.docker"), Status::Ok);
    assert_eq!(status(&map, "runtime.container"), Status::Fail);
}

#[tokio::test]
async fn container_state_maps_to_status() {
    for (state, health, expected) in [
        ("running", Some("unhealthy"), Status::Fail),
        ("running", Some("starting"), Status::Warn),
        ("running", None, Status::Ok),
        ("exited", None, Status::Fail),
        ("restarting", Some("unhealthy"), Status::Fail),
    ] {
        let mut sys = healthy();
        sys.container_mut().status = state.into();
        sys.container_mut().health = health.map(Into::into);
        let map = doctor(&sys, &input()).await;
        assert_eq!(
            status(&map, "runtime.container"),
            expected,
            "{state} {health:?}"
        );
    }
}

#[tokio::test]
async fn environment_the_node_would_refuse_is_a_failure() {
    let mut sys = healthy();
    sys.set_env("DELIVERY_BACKEND", "kafka");
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "runtime.config"), Status::Fail);
    assert!(map["runtime.config"].1.contains("DELIVERY_BACKEND"));
    assert_eq!(status(&map, "identity.secret"), Status::Skip);
    assert_eq!(status(&map, "host.blob_reserve"), Status::Skip);
}

#[tokio::test]
async fn data_inside_the_container_layer_is_a_failure() {
    let mut sys = healthy();
    sys.container_mut().mounts.clear();
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.data_dir"), Status::Fail);
    assert_eq!(status(&map, "identity.secret"), Status::Skip);
    assert_eq!(status(&map, "host.disk"), Status::Skip);
    assert_eq!(status(&map, "host.blob_reserve"), Status::Fail);

    // runtime.data_dir в node.toml перекрывает точки монтирования.
    let input = with_config(&format!("schema = 1\n[runtime]\ndata_dir = \"{DATA}\"\n"));
    let map = doctor(&sys, &input).await;
    assert_eq!(status(&map, "host.data_dir"), Status::Ok);
    assert_eq!(status(&map, "identity.secret"), Status::Ok);
    assert_eq!(status(&map, "host.blob_reserve"), Status::Ok);
}

#[tokio::test]
async fn key_file_problems() {
    // Содержимое файла ключа и его права — или ошибка чтения.
    type KeyFile = io::Result<(String, u32)>;
    let cases: [(KeyFile, Status, &str); 4] = [
        (
            Ok((hex::encode(common::SEED), 0o644)),
            Status::Warn,
            "chmod",
        ),
        (Ok(("not hex".into(), 0o600)), Status::Fail, "повреждён"),
        (
            Err(io::ErrorKind::NotFound.into()),
            Status::Fail,
            "новый ключ",
        ),
        (
            Err(io::ErrorKind::PermissionDenied.into()),
            Status::Error,
            "прочитать",
        ),
    ];
    for (file, expected, needle) in cases {
        let mut sys = healthy();
        *sys.key_file() = file;
        let report = run(&sys, &input(), 0).await;
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "identity.secret")
            .unwrap();
        assert_eq!(check.status, expected, "{}", check.summary);
        let text = format!(
            "{} {}",
            check.summary,
            check.hint.clone().unwrap_or_default()
        );
        assert!(text.contains(needle), "{text}");
    }
}

#[tokio::test]
async fn key_from_the_environment_wins_over_the_file() {
    let mut sys = healthy();
    let other = [0xabu8; 32];
    sys.set_env("NODE_IDENTITY_KEY", &hex::encode(other));
    let report = run(&sys, &input(), 0).await;
    let map = statuses(&report);
    assert_eq!(status(&map, "identity.secret"), Status::Ok);
    let expected = trust_message_tcp::net::noise::NodeIdentity::from_seed(
        other,
        trust_message_tcp::net::noise::NodeKeySource::Configured,
    )
    .public();
    assert_eq!(sys.probed.borrow()[0].1, expected);
    assert!(!report.to_json().contains(&hex::encode(other)));

    sys.set_env("NODE_IDENTITY_KEY", "zz");
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "identity.secret"), Status::Fail);
    assert_eq!(status(&map, "identity.pin"), Status::Skip);
}

#[tokio::test]
async fn disabled_blob_store_skips_the_reserve() {
    let mut sys = healthy();
    sys.set_env("BLOB_ENABLED", "false");
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.blob_reserve"), Status::Skip);
}

#[tokio::test]
async fn memory_and_clock() {
    let mut sys = healthy();
    sys.memory = Some(MemInfo {
        total: 768 * 1024 * 1024,
        available: 512 * 1024 * 1024,
    });
    let map = doctor(&sys, &input()).await;
    // JetStream хочет от 1 ГиБ, sled хватает 512 МиБ.
    assert_eq!(status(&map, "host.memory"), Status::Warn);
    // Машина «1 ГиБ» видит около 960 МиБ — это не повод для предупреждения.
    sys.memory = Some(MemInfo {
        total: 961 * 1024 * 1024,
        available: 400 * 1024 * 1024,
    });
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.memory"), Status::Ok);
    sys.memory = Some(MemInfo {
        total: 768 * 1024 * 1024,
        available: 512 * 1024 * 1024,
    });
    sys.set_env("DELIVERY_BACKEND", "sled");
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.memory"), Status::Ok);

    sys.memory = Some(MemInfo {
        total: 4 * GIB,
        available: 10 * 1024 * 1024,
    });
    sys.clock = Some(false);
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.memory"), Status::Warn);
    assert_eq!(status(&map, "host.clock"), Status::Warn);

    sys.memory = None;
    sys.clock = None;
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "host.memory"), Status::Error);
    assert_eq!(status(&map, "host.clock"), Status::Skip);
}

#[tokio::test]
async fn remote_mode_checks_only_the_network() {
    let mut sys = healthy();
    sys.container = Err(DockerError::Missing);
    let remote = Input {
        addr: Some("203.0.113.10:18081".into()),
        node_key: Some(node_public()),
        remote: true,
        ..input()
    };
    let report = run(&sys, &remote, 0).await;
    let map = statuses(&report);
    for id in &CHECK_IDS[1..12] {
        assert_eq!(status(&map, id), Status::Skip, "{id}");
    }
    assert_eq!(status(&map, "endpoint.config"), Status::Ok);
    assert!(report.target.container.is_none());

    let expectations = [
        (
            ProbeStage::Connect,
            [Status::Fail, Status::Skip, Status::Skip],
        ),
        (
            ProbeStage::Handshake,
            [Status::Ok, Status::Fail, Status::Skip],
        ),
        (ProbeStage::Auth, [Status::Ok, Status::Fail, Status::Skip]),
        (ProbeStage::Config, [Status::Ok, Status::Ok, Status::Fail]),
    ];
    for (stage, expected) in expectations {
        sys.answer = Answer::Fail(stage);
        let map = doctor(&sys, &remote).await;
        let got = [
            status(&map, "endpoint.tcp"),
            status(&map, "endpoint.handshake"),
            status(&map, "endpoint.config"),
        ];
        assert_eq!(got, expected, "{stage:?}");
    }
}

#[tokio::test]
async fn missing_key_or_address_skips_the_network() {
    let mut sys = healthy();
    sys.container_mut().ports.clear();
    let map = doctor(&sys, &input()).await;
    assert_eq!(status(&map, "endpoint.tcp"), Status::Skip);
    assert!(map["endpoint.tcp"].1.contains("адрес"));

    let mut sys = healthy();
    sys.container = Ok(None);
    let only_addr = Input {
        addr: Some("203.0.113.10:18081".into()),
        ..input()
    };
    let map = doctor(&sys, &only_addr).await;
    assert!(map["endpoint.tcp"].1.contains("ключ"));
}

#[tokio::test]
async fn ipv6_binding_is_probed_in_brackets() {
    let mut sys = healthy();
    sys.container_mut().ports[0].host_ip = "2001:db8::1".into();
    doctor(&sys, &input()).await;
    assert_eq!(sys.probed.borrow()[0].0, "[2001:db8::1]:18081");
}

#[test]
fn human_bytes_reads_well() {
    use tmnode::doctor::human_bytes;
    assert_eq!(human_bytes(512), "512 Б");
    assert_eq!(human_bytes(1_800_000_000), "1.7 ГиБ");
    assert_eq!(human_bytes(5 * GIB), "5.0 ГиБ");
    assert_eq!(human_bytes(14 * GIB), "14 ГиБ");
}
