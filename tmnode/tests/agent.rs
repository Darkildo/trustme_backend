//! Агент `tmnode`: подключение к админке, heartbeat с отчётом и статусом,
//! запись желаемых настроек — на подставной админке и подставной машине;
//! HTTP-клиент — против настоящего локального сервера.

mod common;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};
use tmnode::agent::{self, AdminApi, AgentConfig, HttpAdmin};
use tmnode::install::{Layout, Runner};
use tmnode::node_config::Backend;
use tmnode::ops::{self, EnrollArgs};
use tmnode::protocol::{
    EnrollRequest, EnrollResponse, Heartbeat, HeartbeatResponse, InstallSpec, RuntimeDoc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Записанный файл: содержимое, права, владелец.
type WrittenFile = (String, u32, Option<u32>);

#[derive(Default)]
struct MemRunner {
    files: RefCell<HashMap<PathBuf, WrittenFile>>,
    commands: RefCell<Vec<String>>,
}

impl Runner for MemRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<String> {
        let line = format!("{program} {}", args.join(" "));
        self.commands.borrow_mut().push(line.clone());
        // Чистая машина: контейнера и сети нет, остальное проходит.
        if line.starts_with("docker inspect") || line.starts_with("docker network inspect") {
            bail!("no such object");
        }
        Ok(String::new())
    }
    fn write_file(&self, path: &Path, contents: &[u8], mode: u32, uid: Option<u32>) -> Result<()> {
        self.files.borrow_mut().insert(
            path.to_owned(),
            (String::from_utf8(contents.to_vec())?, mode, uid),
        );
        Ok(())
    }
    fn create_dir(&self, _path: &Path, _uid: Option<u32>) -> Result<()> {
        Ok(())
    }
    fn read_file(&self, path: &Path) -> Result<Option<String>> {
        if path.ends_with("node_identity_key") {
            return Ok(Some(hex::encode([0xcd_u8; 32])));
        }
        Ok(self.files.borrow().get(path).map(|f| f.0.clone()))
    }
    fn sleep(&self, _duration: Duration) {}
}

/// Админка, которая запоминает запросы и отвечает заготовками.
struct FakeAdmin {
    enrolled: RefCell<Vec<EnrollRequest>>,
    beats: RefCell<Vec<Heartbeat>>,
    runtime: RefCell<Option<RuntimeDoc>>,
}

impl FakeAdmin {
    fn new() -> Self {
        Self {
            enrolled: RefCell::new(Vec::new()),
            beats: RefCell::new(Vec::new()),
            runtime: RefCell::new(None),
        }
    }
}

impl AdminApi for FakeAdmin {
    async fn enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse> {
        if request.token != "tme_good" {
            bail!("админка ответила 401: токен неверен");
        }
        self.enrolled.borrow_mut().push(request.clone());
        Ok(EnrollResponse {
            agent_id: "agent-1".into(),
            agent_token: "tma_secret".into(),
            node_id: "01NODE".into(),
            node_name: "Офис".into(),
            install: InstallSpec {
                image: "ghcr.io/darkildo/trustme_backend:v0.6.0".into(),
                public_host: "203.0.113.10".into(),
                port: 18081,
                backend: Backend::Sled,
                coturn: None,
            },
            runtime: Some(runtime_doc("v1", 10)),
        })
    }

    async fn heartbeat(&self, beat: &Heartbeat) -> Result<HeartbeatResponse> {
        self.beats.borrow_mut().push(beat.clone());
        Ok(HeartbeatResponse {
            interval_secs: 1,
            runtime: self.runtime.borrow().clone(),
        })
    }
}

fn runtime_doc(version: &str, rate: u32) -> RuntimeDoc {
    RuntimeDoc {
        version: version.into(),
        content: format!(
            "version = \"{version}\"\n[settings]\nrate_limit_send_msgs_per_sec = {rate}\n"
        ),
    }
}

fn temp_layout(label: &str) -> Layout {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tmnode_agent_{label}_{nanos}"));
    std::fs::create_dir_all(root.join("etc")).unwrap();
    Layout {
        data_dir: root.join("data"),
        etc_dir: root.join("etc"),
        unit_path: root.join("tmnode-agent.service"),
    }
}

#[tokio::test]
async fn enroll_installs_and_remembers_the_agent() {
    let layout = temp_layout("enroll");
    let runner = MemRunner::default();
    let admin = FakeAdmin::new();
    let args = EnrollArgs {
        url: "https://admin.example.org".into(),
        token: "tme_good".into(),
        no_install: false,
    };
    let done = ops::enroll_and_install(
        &admin,
        &runner,
        &layout,
        &args,
        "srv-1",
        "/usr/local/bin/tmnode",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(done.addr, "203.0.113.10:18081");
    assert_eq!(admin.enrolled.borrow()[0].hostname, "srv-1");

    let saved = AgentConfig::load(&runner, &layout).unwrap();
    assert_eq!(saved.token, "tma_secret");
    assert_eq!(saved.url, "https://admin.example.org");
    assert!(!format!("{saved:?}").contains("tma_secret"));
    let files = runner.files.borrow().clone();
    assert_eq!(files[&AgentConfig::path(&layout)].1, 0o600);
    let node_toml = &files[&layout.etc_dir.join("node.toml")].0;
    assert!(node_toml.contains("mode = \"managed\"") && node_toml.contains("01NODE"));
    assert!(
        files[&layout.data_dir.join("runtime.toml")]
            .0
            .contains("version = \"v1\"")
    );
    assert!(
        runner
            .commands
            .borrow()
            .iter()
            .any(|c| c == "systemctl enable --now tmnode-agent.service")
    );
    drop(files);

    let bad = EnrollArgs {
        token: "tme_bad".into(),
        ..args.clone()
    };
    assert!(
        ops::enroll_and_install(&admin, &runner, &layout, &bad, "h", "t")
            .await
            .is_err()
    );
    let only = EnrollArgs {
        no_install: true,
        ..args
    };
    assert!(
        ops::enroll_and_install(&admin, &runner, &layout, &only, "h", "t")
            .await
            .unwrap()
            .is_none()
    );
    assert!(AgentConfig::load(&MemRunner::default(), &layout).is_err());
}

#[tokio::test]
async fn heartbeat_reports_and_applies_desired_settings() {
    let layout = temp_layout("tick");
    let node_toml = layout.etc_dir.join("node.toml");
    std::fs::write(
        &node_toml,
        format!(
            "schema = 1\n[endpoint]\naddr = \"127.0.0.1:18081\"\nnode_key = \"{}\"\n[runtime]\ndata_dir = \"{}\"\n",
            hex::encode(common::node_public()),
            layout.data_dir.display()
        ),
    )
    .unwrap();
    let runner = MemRunner::default();
    runner
        .write_file(
            &layout.data_dir.join("runtime.status.json"),
            br#"{"result":"applied","version":"v0"}"#,
            0o644,
            None,
        )
        .unwrap();
    let sys = common::healthy();
    let admin = FakeAdmin::new();

    // Желаемых настроек нет — на диск ничего не пишется.
    let interval = agent::tick(&admin, &runner, &sys, &node_toml, 1_800_000_000)
        .await
        .unwrap();
    assert_eq!(interval, 5, "interval is clamped to the protocol minimum");
    {
        let beats = admin.beats.borrow();
        assert_eq!(beats[0].node_key, Some(hex::encode(common::node_public())));
        assert_eq!(
            beats[0].report.as_ref().unwrap()["format"],
            "tmnode.report/1"
        );
        assert_eq!(beats[0].runtime_status.as_ref().unwrap()["version"], "v0");
    }
    assert!(
        !runner
            .files
            .borrow()
            .contains_key(&layout.data_dir.join("runtime.toml"))
    );

    *admin.runtime.borrow_mut() = Some(runtime_doc("v2", 7));
    agent::tick(&admin, &runner, &sys, &node_toml, 1_800_000_000)
        .await
        .unwrap();
    let (content, mode, uid) = runner.files.borrow()[&layout.data_dir.join("runtime.toml")].clone();
    assert!(content.contains("= 7"));
    assert_eq!((mode, uid), (0o600, Some(10001)));

    // Та же версия второй раз не пишется.
    assert!(!agent::apply_runtime(&runner, &layout.data_dir, &runtime_doc("v2", 99)).unwrap());
    // Битый или несогласованный документ не попадает на диск.
    let broken = RuntimeDoc {
        version: "v3".into(),
        content: "[settings]\nx = \"y\"\n".into(),
    };
    assert!(agent::apply_runtime(&runner, &layout.data_dir, &broken).is_err());
    let mismatch = RuntimeDoc {
        version: "v4".into(),
        content: "version = \"v5\"\n".into(),
    };
    assert!(agent::apply_runtime(&runner, &layout.data_dir, &mismatch).is_err());
    assert!(
        runner.files.borrow()[&layout.data_dir.join("runtime.toml")]
            .0
            .contains("= 7")
    );

    // Без data_dir в node.toml агенту некуда писать.
    std::fs::write(&node_toml, "schema = 1\n").unwrap();
    assert!(
        agent::tick(&admin, &runner, &sys, &node_toml, 0)
            .await
            .is_err()
    );
}

/// Однократный HTTP-ответ на локальном порту.
async fn serve_once(
    status: &'static str,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 16 * 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).into_owned();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        request
    });
    (url, task)
}

#[tokio::test]
async fn http_client_speaks_the_protocol() {
    let (url, request) = serve_once("200 OK", r#"{"interval_secs":30,"runtime":null}"#).await;
    let api = HttpAdmin::new(&url, Some("tma_tok".into())).unwrap();
    let beat = Heartbeat {
        tmnode_version: "0".into(),
        node_key: None,
        report: None,
        runtime_status: None,
    };
    let reply = api.heartbeat(&beat).await.unwrap();
    assert_eq!(reply.interval_secs, 30);
    let request = request.await.unwrap();
    assert!(request.starts_with("POST /api/v1/agent/heartbeat"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer tma_tok")
    );

    let (url, _) = serve_once(
        "401 Unauthorized",
        r#"{"error":{"code":"unauthorized","message":"токен неверен"}}"#,
    )
    .await;
    let api = HttpAdmin::new(&url, None).unwrap();
    let err = api
        .enroll(&EnrollRequest {
            token: "x".into(),
            hostname: "h".into(),
            arch: "x86_64".into(),
            tmnode_version: "0".into(),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("токен неверен"));

    assert!(HttpAdmin::new("http://admin.example.org", None).is_err());
    assert!(agent::check_url("https://a/").unwrap() == "https://a");
    assert!(agent::check_url("http://localhost:8088").is_ok());

    // Админка недоступна.
    let api = HttpAdmin::new("http://127.0.0.1:1", None).unwrap();
    assert!(
        api.heartbeat(&beat)
            .await
            .unwrap_err()
            .to_string()
            .contains("недоступна")
    );
}
