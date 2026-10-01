//! Нагрузочный генератор и soak-прогон против живой ноды.
//!
//! Отвечает на три вопроса, на которые юнит-тесты не отвечают: сколько
//! конвертов нода пропускает, какова задержка подтверждения под нагрузкой и
//! что происходит, когда отправители упираются в квоты.
//!
//! Клиенты шлют друг другу, поэтому работает горячий путь доставки онлайн:
//! маршрутизация в живую сессию, а не только приём в очередь.
//!
//! ```text
//! cargo run --release --example load_gen -- \
//!   --message 127.0.0.1:5000 --node-key <hex32> \
//!   --clients 50 --rate 20 --duration 60 --body-bytes 512
//! ```
//!
//! `--metrics <url>` дополнительно снимает дельту счётчиков ноды за прогон:
//! клиентская картина без серверной врёт ровно там, где интереснее всего —
//! в отказах и дропах.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{interval, timeout};
use trust_message_tcp::net::noise::NoiseFramed;
use trust_message_tcp::wire::{self, Frame, frame};

const PROTO_VERSION: u32 = 1;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_MAX: usize = 8 * 1024 * 1024;

struct Args {
    message_addr: String,
    node_key: [u8; 32],
    clients: usize,
    rate_per_client: u64,
    duration: Duration,
    body_bytes: usize,
    metrics_url: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut message_addr = "127.0.0.1:5000".to_string();
    let mut node_key: Option<String> = None;
    let mut clients = 10usize;
    let mut rate_per_client = 10u64;
    let mut duration = Duration::from_secs(30);
    let mut body_bytes = 256usize;
    let mut metrics_url: Option<String> = None;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        let mut take = |name: &str| -> Result<String> {
            iter.next()
                .ok_or_else(|| anyhow!("expected value after {name}"))
        };
        match arg.as_str() {
            "--message" => message_addr = take("--message")?,
            "--node-key" => node_key = Some(take("--node-key")?),
            "--node-key-file" => {
                let path = take("--node-key-file")?;
                let raw = std::fs::read_to_string(&path)
                    .with_context(|| format!("read node key file {path}"))?;
                node_key = Some(raw.trim().to_string());
            }
            "--clients" => clients = take("--clients")?.parse().context("--clients")?,
            "--rate" => rate_per_client = take("--rate")?.parse().context("--rate")?,
            "--duration" => {
                duration = Duration::from_secs(take("--duration")?.parse().context("--duration")?)
            }
            "--body-bytes" => body_bytes = take("--body-bytes")?.parse().context("--body-bytes")?,
            "--metrics" => metrics_url = Some(take("--metrics")?),
            "-h" | "--help" => {
                println!(
                    "usage: load_gen --node-key <hex32> [--message host:port] \
                     [--clients N] [--rate msgs/s] [--duration secs] \
                     [--body-bytes N] [--metrics url]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown arg `{other}`"),
        }
    }

    let node_key = node_key.ok_or_else(|| anyhow!("--node-key <hex32> is required"))?;
    let decoded = hex::decode(node_key.trim()).context("--node-key must be hex")?;
    if decoded.len() != 32 {
        bail!("--node-key must decode to 32 bytes, got {}", decoded.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);

    if clients < 2 {
        bail!("--clients must be at least 2: clients send to each other");
    }

    Ok(Args {
        message_addr,
        node_key: key,
        clients,
        rate_per_client,
        duration,
        body_bytes,
        metrics_url,
    })
}

#[derive(Default)]
struct Stats {
    sent: AtomicU64,
    delivered_online: AtomicU64,
    queued: AtomicU64,
    rejected: AtomicU64,
    incoming: AtomicU64,
    errors: AtomicU64,
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut buf)
        .context("read random bytes")?;
    Ok(buf)
}

fn encode_send(recipient: &[u8; 32], body: &[u8]) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(frame::Payload::ClientSend(wire::ClientSend {
            recipient_id: recipient.to_vec(),
            body: body.to_vec(),
            ..wire::ClientSend::default()
        })),
    }
    .encode_to_vec()
}

async fn open_session(args: &Args, key: &SigningKey) -> Result<NoiseFramed<TcpStream>> {
    let stream = TcpStream::connect(&args.message_addr)
        .await
        .with_context(|| format!("connect to {}", args.message_addr))?;
    stream.set_nodelay(true).ok();

    let mut conn = NoiseFramed::connect(
        stream,
        &args.node_key,
        key,
        Some(1),
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await
    .context("noise handshake failed")?;

    // AuthOk нода шлёт сама.
    let bytes = timeout(Duration::from_secs(10), conn.next_frame())
        .await
        .context("waiting for AuthOk timed out")?
        .context("read AuthOk")?
        .ok_or_else(|| anyhow!("connection closed before AuthOk"))?;
    match Frame::decode(bytes.as_ref())?.payload {
        Some(frame::Payload::AuthOk(_)) => {}
        Some(frame::Payload::AuthError(err)) => {
            bail!(
                "session rejected: code={} message={}",
                err.code,
                err.message
            )
        }
        _ => bail!("expected AuthOk"),
    }

    // Сессия начинается с первого кадра клиента: до него нода не
    // доставляет ничего. `Pong` в ответ цикл клиента просто пропустит.
    let ping = Frame {
        proto_version: PROTO_VERSION,
        payload: Some(frame::Payload::Ping(wire::Ping {})),
    }
    .encode_to_vec();
    conn.send_frame(&ping)
        .await
        .context("send the confirming Ping")?;
    Ok(conn)
}

/// Один клиент: шлёт с заданной частотой и читает всё, что приходит.
///
/// Отправка и чтение живут в одной задаче через `select!` — так же, как это
/// делает нода. Разносить их по разным задачам значило бы мерить не тот
/// путь.
async fn run_client(
    index: usize,
    args: Arc<Args>,
    keys: Arc<Vec<SigningKey>>,
    stats: Arc<Stats>,
    latencies: Arc<Mutex<Vec<Duration>>>,
    deadline: Instant,
) {
    let key = keys[index].clone();
    let mut conn = match open_session(&args, &key).await {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("client {index}: session failed: {err:#}");
            stats.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Получатель — сосед по кольцу: каждый клиент и шлёт, и принимает.
    let recipient = keys[(index + 1) % keys.len()].verifying_key().to_bytes();
    let body = vec![0x5Au8; args.body_bytes];

    let period = if args.rate_per_client == 0 {
        Duration::from_secs(3600)
    } else {
        Duration::from_secs_f64(1.0 / args.rate_per_client as f64)
    };
    let mut ticker = interval(period);
    let mut pending_send: Option<Instant> = None;
    let mut local_latencies: Vec<Duration> = Vec::new();

    while Instant::now() < deadline {
        tokio::select! {
            _ = ticker.tick() => {
                if pending_send.is_some() {
                    // Предыдущий ack ещё не пришёл — нода не успевает,
                    // и досылать поверх значит мерить очередь, а не ноду.
                    continue;
                }
                if conn.send_frame(&encode_send(&recipient, &body)).await.is_err() {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                stats.sent.fetch_add(1, Ordering::Relaxed);
                pending_send = Some(Instant::now());
            }
            frame = conn.next_frame() => {
                let Ok(Some(bytes)) = frame else {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    break;
                };
                let Ok(decoded) = Frame::decode(bytes.as_ref()) else {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                match decoded.payload {
                    Some(frame::Payload::SendAck(ack)) => {
                        if let Some(started) = pending_send.take() {
                            local_latencies.push(started.elapsed());
                        }
                        if ack.ok {
                            stats.delivered_online.fetch_add(1, Ordering::Relaxed);
                        } else if ack.queued {
                            stats.queued.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.rejected.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Some(frame::Payload::Incoming(_)) => {
                        stats.incoming.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }
    }

    latencies.lock().await.extend(local_latencies);
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[index]
}

async fn scrape(url: &str) -> Result<Vec<(String, f64)>> {
    let body = reqwest::get(url)
        .await
        .with_context(|| format!("scrape {url}"))?
        .text()
        .await?;
    let mut out = Vec::new();
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.rsplit_once(' ') else {
            continue;
        };
        if !name.starts_with("trust_message_tcp_") {
            continue;
        }
        if let Ok(value) = value.parse::<f64>() {
            out.push((name.to_string(), value));
        }
    }
    Ok(out)
}

fn metric_delta(before: &[(String, f64)], after: &[(String, f64)]) -> Vec<(String, f64)> {
    let mut deltas = Vec::new();
    for (name, after_value) in after {
        let before_value = before
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
            .unwrap_or(0.0);
        let delta = after_value - before_value;
        if delta.abs() > f64::EPSILON {
            deltas.push((name.clone(), delta));
        }
    }
    deltas.sort_by(|a, b| a.0.cmp(&b.0));
    deltas
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arc::new(parse_args()?);
    println!(
        "load_gen: node={} clients={} rate={}/s each body={}B duration={}s",
        args.message_addr,
        args.clients,
        args.rate_per_client,
        args.body_bytes,
        args.duration.as_secs()
    );

    let mut keys = Vec::with_capacity(args.clients);
    for _ in 0..args.clients {
        keys.push(SigningKey::from_bytes(&random_bytes::<32>()?));
    }
    let keys = Arc::new(keys);

    let before = match args.metrics_url.as_deref() {
        Some(url) => Some(scrape(url).await?),
        None => None,
    };

    let stats = Arc::new(Stats::default());
    let latencies = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let deadline = started + args.duration;

    let mut handles = Vec::with_capacity(args.clients);
    for index in 0..args.clients {
        handles.push(tokio::spawn(run_client(
            index,
            args.clone(),
            keys.clone(),
            stats.clone(),
            latencies.clone(),
            deadline,
        )));
    }
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = started.elapsed();
    let sent = stats.sent.load(Ordering::Relaxed);
    let mut samples = latencies.lock().await.clone();
    samples.sort_unstable();

    println!("\n--- результат за {:.1}s ---", elapsed.as_secs_f64());
    println!(
        "отправлено:        {sent} ({:.0}/s)",
        sent as f64 / elapsed.as_secs_f64()
    );
    println!(
        "доставлено онлайн: {}",
        stats.delivered_online.load(Ordering::Relaxed)
    );
    println!(
        "в очередь:         {}",
        stats.queued.load(Ordering::Relaxed)
    );
    println!(
        "отказов:           {}",
        stats.rejected.load(Ordering::Relaxed)
    );
    println!(
        "принято входящих:  {}",
        stats.incoming.load(Ordering::Relaxed)
    );
    println!(
        "ошибок сессий:     {}",
        stats.errors.load(Ordering::Relaxed)
    );

    if samples.is_empty() {
        println!("задержка ack:      нет данных");
    } else {
        println!(
            "задержка ack:      p50={:?} p90={:?} p99={:?} max={:?}",
            percentile(&samples, 0.50),
            percentile(&samples, 0.90),
            percentile(&samples, 0.99),
            samples[samples.len() - 1]
        );
    }

    if let (Some(url), Some(before)) = (args.metrics_url.as_deref(), before) {
        let after = scrape(url).await?;
        println!("\n--- дельта метрик ноды ---");
        for (name, delta) in metric_delta(&before, &after) {
            println!("  {name} {delta:+.0}");
        }
    }

    Ok(())
}
