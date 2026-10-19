//! Агент `tmnode`: связь ноды с админкой (docs/agent-protocol.md).
//!
//! `tmnode enroll` меняет одноразовый токен на постоянный и задание на
//! установку. `tmnode agent` (служба systemd) раз в полминуты присылает
//! отчёт `doctor` и статус настроек и забирает желаемый `runtime.toml` —
//! нода подхватывает его сама, без перезапуска.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_message_tcp::runtime::RuntimeFile;

use crate::doctor::{self, ConfigSource, Input};
use crate::install::{Layout, Runner};
use crate::node_config::NodeConfig;
use crate::protocol::{
    API_PREFIX, DEFAULT_INTERVAL_SECS, EnrollRequest, EnrollResponse, Heartbeat, HeartbeatResponse,
    MAX_INTERVAL_SECS, MIN_INTERVAL_SECS, RuntimeDoc,
};
use crate::system::System;

/// Пользователь ноды в контейнере: `runtime.toml` читает она.
const NODE_UID: u32 = 10001;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// `/etc/tmnode/agent.toml`: куда звонить и с каким токеном. Права 0600.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub url: String,
    pub agent_id: String,
    pub token: String,
}

/// Токен агента в отладочный вывод не попадает.
impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("url", &self.url)
            .field("agent_id", &self.agent_id)
            .finish_non_exhaustive()
    }
}

impl AgentConfig {
    pub fn path(layout: &Layout) -> PathBuf {
        layout.etc_dir.join("agent.toml")
    }

    pub fn load(runner: &dyn Runner, layout: &Layout) -> Result<Self> {
        let path = Self::path(layout);
        let text = runner
            .read_file(&path)?
            .ok_or_else(|| anyhow!("{} нет: сначала tmnode enroll", path.display()))?;
        toml::from_str(&text).with_context(|| format!("{} повреждён", path.display()))
    }

    pub fn save(&self, runner: &dyn Runner, layout: &Layout) -> Result<()> {
        let text = toml::to_string(self).expect("agent config serializes");
        runner.write_file(&Self::path(layout), text.as_bytes(), 0o600, None)
    }
}

/// Адрес админки: только HTTPS, кроме локальной машины — токены по
/// открытому каналу не ходят.
pub fn check_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| url.starts_with(prefix));
    if !(url.starts_with("https://") || local) {
        bail!("адрес админки должен начинаться с https:// (http — только для localhost)");
    }
    Ok(url.to_owned())
}

/// Админка с точки зрения агента.
pub trait AdminApi {
    fn enroll(&self, request: &EnrollRequest) -> impl Future<Output = Result<EnrollResponse>>;
    fn heartbeat(&self, beat: &Heartbeat) -> impl Future<Output = Result<HeartbeatResponse>>;
}

pub struct HttpAdmin {
    client: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl HttpAdmin {
    pub fn new(url: &str, token: Option<String>) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .user_agent(concat!("tmnode/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base: format!("{}{API_PREFIX}", check_url(url)?),
            token,
        })
    }

    async fn post<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R> {
        let mut request = self.client.post(format!("{}{path}", self.base)).json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.context("админка недоступна")?;
        let status = response.status();
        if !status.is_success() {
            let body: Value = response.json().await.unwrap_or(Value::Null);
            let message = body["error"]["message"].as_str().unwrap_or("").to_owned();
            bail!("админка ответила {status}: {message}");
        }
        response
            .json()
            .await
            .context("ответ админки не по протоколу")
    }
}

impl AdminApi for HttpAdmin {
    async fn enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse> {
        self.post("/enroll", request).await
    }

    async fn heartbeat(&self, beat: &Heartbeat) -> Result<HeartbeatResponse> {
        self.post("/heartbeat", beat).await
    }
}

/// Подключить хост к админке: сохранить токен агента и вернуть задание.
pub async fn enroll(
    api: &impl AdminApi,
    runner: &dyn Runner,
    layout: &Layout,
    url: &str,
    token: &str,
    hostname: &str,
) -> Result<EnrollResponse> {
    let response = api
        .enroll(&EnrollRequest {
            token: token.trim().to_owned(),
            hostname: hostname.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            tmnode_version: env!("CARGO_PKG_VERSION").to_owned(),
        })
        .await?;
    runner.create_dir(&layout.etc_dir, None)?;
    AgentConfig {
        url: check_url(url)?,
        agent_id: response.agent_id.clone(),
        token: response.agent_token.clone(),
    }
    .save(runner, layout)?;
    Ok(response)
}

/// Один цикл: отчёт и статус в админку, желаемые настройки — на диск.
/// Возвращает, через сколько секунд повторить.
pub async fn tick<S: System>(
    api: &impl AdminApi,
    runner: &dyn Runner,
    sys: &S,
    node_toml: &Path,
    now: u64,
) -> Result<u64> {
    let config = NodeConfig::load(node_toml)?;
    let data_dir = config
        .runtime
        .data_dir
        .clone()
        .ok_or_else(|| anyhow!("в node.toml нет runtime.data_dir"))?;

    let report = doctor::run(
        sys,
        &Input {
            config: ConfigSource::Loaded(node_toml.to_owned(), Box::new(config.clone())),
            container: None,
            addr: None,
            node_key: None,
            remote: false,
            step_timeout: Duration::from_secs(5),
        },
        now,
    )
    .await;
    let runtime_status = runner
        .read_file(&data_dir.join("runtime.status.json"))?
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());

    let response = api
        .heartbeat(&Heartbeat {
            tmnode_version: env!("CARGO_PKG_VERSION").to_owned(),
            node_key: config.endpoint.as_ref().map(|e| e.node_key.clone()),
            report: Some(serde_json::to_value(&report).expect("report serializes")),
            runtime_status,
            node_image: None,
            update: None,
        })
        .await?;

    if let Some(desired) = &response.runtime {
        apply_runtime(runner, &data_dir, desired)?;
    }
    Ok(response
        .interval_secs
        .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS))
}

/// Записать желаемый `runtime.toml`, если на диске другая версия. Файл
/// проверяется до записи: битый документ не должен даже попасть к ноде.
pub fn apply_runtime(runner: &dyn Runner, data_dir: &Path, desired: &RuntimeDoc) -> Result<bool> {
    let path = data_dir.join("runtime.toml");
    let current = runner
        .read_file(&path)?
        .and_then(|text| RuntimeFile::parse(&text).ok())
        .and_then(|file| file.version);
    if current.as_deref() == Some(desired.version.as_str()) {
        return Ok(false);
    }
    let parsed =
        RuntimeFile::parse(&desired.content).context("админка прислала неверный runtime.toml")?;
    if parsed.version.as_deref() != Some(desired.version.as_str()) {
        bail!("версия в runtime.toml не совпадает с объявленной");
    }
    runner.write_file(&path, desired.content.as_bytes(), 0o600, Some(NODE_UID))?;
    Ok(true)
}

/// Служба: циклы без конца, с паузой при ошибках.
pub async fn run_forever<S: System>(
    api: &impl AdminApi,
    runner: &dyn Runner,
    sys: &S,
    node_toml: &Path,
    now: impl Fn() -> u64,
    mut log: impl FnMut(&str),
) -> ! {
    let mut failures: u32 = 0;
    loop {
        let wait = match tick(api, runner, sys, node_toml, now()).await {
            Ok(interval) => {
                failures = 0;
                interval
            }
            Err(err) => {
                failures = failures.saturating_add(1);
                log(&format!("heartbeat не прошёл: {err:#}"));
                // 10, 20, 40 … секунд, не дольше стандартного интервала x10.
                (10u64 << failures.min(5)).min(DEFAULT_INTERVAL_SECS * 10)
            }
        };
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}
