//! Проверка живой ноды снаружи — тем же путём, что проходит клиент:
//! TCP, Noise IK с пином, вход одноразовым ключом и подписанный
//! `ServerConfig`. Нужна `tmnode doctor` и любому, кто хочет убедиться,
//! что нода по адресу — та самая и отвечает.
//!
//! Ошибка помечена этапом: «порт закрыт», «ключ не тот» и «нода отказала во
//! входе» чинятся по-разному, и вызывающему нужно их различать без разбора
//! текста.

use std::fmt;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::net::framing::{PROTO_VERSION, verify_signed_server_config};
use crate::net::noise::{NoiseFramed, SessionRole};
use crate::net::rate_limit::unix_now_secs;
use crate::wire::{self, Frame, frame};

/// Потолок кадра на приёме. Снапшот конфигурации — сотни байт; потолок
/// ноды по умолчанию взят с запасом, чтобы не спорить с её настройкой.
const PROBE_FRAME_MAX: usize = 8 * 1024 * 1024;

/// Этап, на котором проверка остановилась.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStage {
    /// TCP-соединение не установилось: адрес, порт, файрвол.
    Connect,
    /// Noise-хендшейк не прошёл: чаще всего пин не совпадает с ключом ноды
    /// или по адресу отвечает не нода.
    Handshake,
    /// Хендшейк прошёл, но нода отказала во входе (`AuthError`) или закрыла
    /// сессию.
    Auth,
    /// Сессия есть, но подписанный `ServerConfig` не пришёл или не прошёл
    /// проверку.
    Config,
}

impl ProbeStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Handshake => "handshake",
            Self::Auth => "auth",
            Self::Config => "config",
        }
    }
}

#[derive(Debug)]
pub struct ProbeError {
    pub stage: ProbeStage,
    pub error: anyhow::Error,
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:#}", self.stage.as_str(), self.error)
    }
}

impl std::error::Error for ProbeError {}

/// Что удалось узнать о ноде.
#[derive(Debug)]
pub struct ProbeOutcome {
    /// Время установки TCP-соединения.
    pub connect_time: Duration,
    /// Время от соединения до `AuthOk` (хендшейк и вход).
    pub handshake_time: Duration,
    /// Проверенный снапшот: подпись, связь подписанта с пином, срок.
    pub config: wire::ServerConfig,
}

/// Проверить ноду по адресу `addr` с пином `node_key` (X25519-статик).
/// `step_timeout` ограничивает каждый этап отдельно.
///
/// Вход выполняется свежим случайным ключом: проба не выдаёт себя ни за
/// кого и на ноде не оставляет ничего, кроме короткой сессии.
pub async fn probe(
    addr: &str,
    node_key: &[u8; 32],
    step_timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let fail = |stage| move |error| ProbeError { stage, error };

    let started = Instant::now();
    let stream = timeout(step_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("no TCP connection within {step_timeout:?}"))
        .and_then(|res| res.with_context(|| format!("connect to {addr}")))
        .map_err(fail(ProbeStage::Connect))?;
    let connect_time = started.elapsed();
    stream.set_nodelay(true).ok();

    let identity = fresh_identity().map_err(fail(ProbeStage::Handshake))?;
    let mut conn = NoiseFramed::connect_with_role(
        stream,
        node_key,
        &identity,
        None,
        SessionRole::Messages,
        step_timeout,
        PROBE_FRAME_MAX,
    )
    .await
    .context("noise handshake")
    .map_err(fail(ProbeStage::Handshake))?;

    match next_payload(&mut conn, step_timeout, "AuthOk")
        .await
        .map_err(fail(ProbeStage::Auth))?
    {
        frame::Payload::AuthOk(_) => {}
        frame::Payload::AuthError(err) => {
            return Err(ProbeError {
                stage: ProbeStage::Auth,
                error: anyhow!("node rejected the session: {} {}", err.code, err.message),
            });
        }
        _ => {
            return Err(ProbeError {
                stage: ProbeStage::Auth,
                error: anyhow!("expected AuthOk right after the handshake"),
            });
        }
    }
    let handshake_time = started.elapsed() - connect_time;

    // Запрос конфигурации — первый кадр клиента, он же подтверждает сессию.
    let request = Frame {
        proto_version: u32::from(PROTO_VERSION),
        payload: Some(frame::Payload::GetServerConfig(wire::GetServerConfig {})),
    }
    .encode_to_vec();
    conn.send_frame(&request)
        .await
        .context("send GetServerConfig")
        .map_err(fail(ProbeStage::Config))?;

    // До ответа на запрос нода может прислать что-то своё (у свежего
    // ключа офлайн-очереди нет, но контракт этого не запрещает) — такое
    // пропускаем.
    let deadline = Instant::now() + step_timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match next_payload(&mut conn, left, "SignedServerConfig").await {
            Ok(frame::Payload::SignedServerConfig(signed)) => {
                let config = verify_signed_server_config(&signed, node_key, unix_now_secs())
                    .map_err(fail(ProbeStage::Config))?;
                return Ok(ProbeOutcome {
                    connect_time,
                    handshake_time,
                    config,
                });
            }
            Ok(frame::Payload::AuthError(err)) => {
                return Err(ProbeError {
                    stage: ProbeStage::Auth,
                    error: anyhow!("node closed the session: {} {}", err.code, err.message),
                });
            }
            Ok(_) => continue,
            Err(error) => {
                return Err(ProbeError {
                    stage: ProbeStage::Config,
                    error,
                });
            }
        }
    }
}

async fn next_payload(
    conn: &mut NoiseFramed<TcpStream>,
    wait: Duration,
    what: &str,
) -> anyhow::Result<frame::Payload> {
    let bytes = timeout(wait, conn.next_frame())
        .await
        .map_err(|_| anyhow!("no {what} within {wait:?}"))?
        .with_context(|| format!("read {what}"))?
        .ok_or_else(|| anyhow!("node closed the connection before {what}"))?;
    Frame::decode(bytes.as_ref())
        .context("undecodable frame")?
        .payload
        .ok_or_else(|| anyhow!("frame without payload"))
}

fn fresh_identity() -> anyhow::Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| anyhow!("no randomness for a probe key: {err}"))?;
    Ok(SigningKey::from_bytes(&seed))
}
