//! Подставная машина для проверок `tmnode doctor`: контейнер, файлы, диск,
//! память и ответ ноды задаются тестом.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::anyhow;
use tmnode::system::{Container, DiskSpace, DockerError, MemInfo, Mount, PortBinding, System};
use trust_message_tcp::net::noise::{NodeIdentity, NodeKeySource};
use trust_message_tcp::net::probe::{ProbeError, ProbeOutcome, ProbeStage};
use trust_message_tcp::wire;
use zeroize::Zeroizing;

pub const GIB: u64 = 1024 * 1024 * 1024;
pub const SEED: [u8; 32] = [42u8; 32];
pub const DATA: &str = "/root/deploy/data";

pub fn node_public() -> [u8; 32] {
    NodeIdentity::from_seed(SEED, NodeKeySource::File).public()
}

pub enum Answer {
    Ok,
    Fail(ProbeStage),
}

pub struct Fake {
    pub container: Result<Option<Container>, DockerError>,
    pub files: HashMap<PathBuf, io::Result<(String, u32)>>,
    pub disk: Option<DiskSpace>,
    pub memory: Option<MemInfo>,
    pub clock: Option<bool>,
    pub answer: Answer,
    /// С какими адресом и пином нода проверялась снаружи.
    pub probed: RefCell<Vec<(String, [u8; 32])>>,
}

/// Нода как на проде: JetStream, данные на хосте, ключ в файле, порт 18081.
pub fn healthy() -> Fake {
    let mut files = HashMap::new();
    files.insert(
        PathBuf::from(DATA).join("node_identity_key"),
        Ok((format!("{}\n", hex::encode(SEED)), 0o600)),
    );
    Fake {
        container: Ok(Some(container(&[
            ("STORAGE_PATH", "/srv/trust-message/data"),
            ("DELIVERY_BACKEND", "jetstream"),
            ("BIND_PORT", "18081"),
        ]))),
        files,
        disk: Some(DiskSpace {
            total: 14 * GIB,
            available: 8 * GIB,
        }),
        memory: Some(MemInfo {
            total: 2 * GIB,
            available: GIB,
        }),
        clock: Some(true),
        answer: Answer::Ok,
        probed: RefCell::new(Vec::new()),
    }
}

pub fn container(env: &[(&str, &str)]) -> Container {
    Container {
        status: "running".into(),
        health: Some("healthy".into()),
        image: "trust-message-service:jetstream".into(),
        restart_count: 0,
        env: env
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect(),
        mounts: vec![Mount {
            source: PathBuf::from(DATA),
            destination: PathBuf::from("/srv/trust-message/data"),
        }],
        ports: vec![PortBinding {
            container_port: 18081,
            host_ip: "0.0.0.0".into(),
            host_port: 18081,
        }],
    }
}

impl Fake {
    pub fn container_mut(&mut self) -> &mut Container {
        self.container.as_mut().unwrap().as_mut().unwrap()
    }

    pub fn set_env(&mut self, key: &str, value: &str) {
        let env = &mut self.container_mut().env;
        env.retain(|(k, _)| k != key);
        env.push((key.to_owned(), Zeroizing::new(value.to_owned())));
    }

    pub fn key_file(&mut self) -> &mut io::Result<(String, u32)> {
        self.files
            .get_mut(&PathBuf::from(DATA).join("node_identity_key"))
            .unwrap()
    }
}

impl System for Fake {
    fn container(&self, _name: &str) -> Result<Option<Container>, DockerError> {
        self.container.clone()
    }

    fn read_secret(&self, path: &Path) -> io::Result<Zeroizing<String>> {
        match self.files.get(path) {
            Some(Ok((text, _))) => Ok(Zeroizing::new(text.clone())),
            Some(Err(err)) => Err(io::Error::new(err.kind(), err.to_string())),
            None => Err(io::ErrorKind::NotFound.into()),
        }
    }

    fn file_mode(&self, path: &Path) -> io::Result<u32> {
        match self.files.get(path) {
            Some(Ok((_, mode))) => Ok(*mode),
            _ => Err(io::ErrorKind::NotFound.into()),
        }
    }

    fn disk_space(&self, _path: &Path) -> io::Result<DiskSpace> {
        self.disk
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
    }

    fn memory(&self) -> io::Result<MemInfo> {
        self.memory
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no /proc/meminfo"))
    }

    fn clock_synced(&self) -> Option<bool> {
        self.clock
    }

    async fn probe(
        &self,
        addr: &str,
        node_key: &[u8; 32],
        _step_timeout: Duration,
    ) -> Result<ProbeOutcome, ProbeError> {
        self.probed.borrow_mut().push((addr.to_owned(), *node_key));
        match self.answer {
            Answer::Ok => Ok(ProbeOutcome {
                connect_time: Duration::from_millis(3),
                handshake_time: Duration::from_millis(7),
                config: wire::ServerConfig {
                    proto_version: 1,
                    supports_blobs: true,
                    supports_delivery_ack: true,
                    expires_at: 2_000_000_000,
                    ..Default::default()
                },
            }),
            Answer::Fail(stage) => Err(ProbeError {
                stage,
                error: anyhow!("simulated {}", stage.as_str()),
            }),
        }
    }
}
