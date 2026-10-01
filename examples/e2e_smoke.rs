//! End-to-end smoke test against a running deployment.
//!
//! Default target is a local node (127.0.0.1:5000, the port published by
//! `compose.yaml`). Override via flags:
//!   cargo run --example e2e_smoke -- \
//!       --message <host:port> \
//!       --node-key <hex32> \
//!       --scenario online_roundtrip
//!
//! A session is a Noise IK handshake, so the node's static key (it prints
//! `node_key=...` at startup) has to be known up front.
//!
//! Scenarios:
//!   - online_roundtrip      A and B online, A->B, expect Incoming on B
//!   - offline_then_online   A sends while B is offline, B reconnects, expects replay/redelivery
//!   - delivery_ack          like online_roundtrip, then B sends DeliveryAck (the node sends no confirmation)
//!   - crash_before_ack      B receives Incoming, drops TCP without DeliveryAck, reconnects;
//!     expects JetStream redelivery after ack_wait (NATS_ACK_WAIT_SECS, 30s by default)
//!   - no_dup_after_ack      B receives, sends DeliveryAck, reconnects; expects NO redelivery for some grace window
//!   - device_routing        B logs in twice with device_id=1 and device_id=2, A targets device 2;
//!     expects only device-2 connection to receive
//!   - queue_lifecycle       allocate, list and revoke a queue; a stranger's revoke gets NOT_FOUND
//!   - probe_config          ask for ServerConfig inside an established noise session
//!   - probe_tofu            first contact without a pin: learn the node key, print its
//!     fingerprint, verify the signed config against it
//!   - quota_flood           blast ClientSend until a quota answers with a reason;
//!     with --metrics <url> also checks reject_total{reason} grew
//!
//! Generates fresh Ed25519 keypairs each run, so userIds are unique per invocation.

use std::collections::VecDeque;
use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::net::TcpStream;
use tokio::time::timeout;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::net::framing::verify_signed_server_config;
use trust_message_tcp::net::noise::{NoiseFramed, fingerprint};
use trust_message_tcp::wire::{self, Frame, frame};

/// Версия wire-протокола, которую заявляет этот клиент. Нода с другой
/// версией закрывает соединение на хендшейке.
const PROTO_VERSION: u32 = 1;

const DEFAULT_MESSAGE: &str = "127.0.0.1:5000";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_MAX: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    OnlineRoundtrip,
    OfflineThenOnline,
    DeliveryAck,
    CrashBeforeAck,
    NoDupAfterAck,
    DeviceRouting,
    ProbeConfig,
    ProbeTofu,
    QuotaFlood,
    QueueLifecycle,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "online_roundtrip" => Ok(Self::OnlineRoundtrip),
            "offline_then_online" => Ok(Self::OfflineThenOnline),
            "delivery_ack" => Ok(Self::DeliveryAck),
            "crash_before_ack" => Ok(Self::CrashBeforeAck),
            "no_dup_after_ack" => Ok(Self::NoDupAfterAck),
            "device_routing" => Ok(Self::DeviceRouting),
            "queue_lifecycle" => Ok(Self::QueueLifecycle),
            "probe_config" => Ok(Self::ProbeConfig),
            "probe_tofu" => Ok(Self::ProbeTofu),
            "quota_flood" => Ok(Self::QuotaFlood),
            other => bail!("unknown scenario `{other}`"),
        }
    }
}

struct Args {
    /// Статик ноды (X25519, hex): без него IK-хендшейк начать нечем.
    /// `None` допустим только для `probe_tofu` — сценария первого
    /// контакта, который ключ как раз узнаёт.
    node_key: Option<[u8; 32]>,
    message_addr: String,
    scenario: Scenario,
    /// Prometheus-эндпоинт ноды. Задан — флуд-тест дополнительно сверяет
    /// прирост `reject_total{reason=...}`, то есть что отказ виден не
    /// только клиенту, но и оператору.
    metrics_url: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut message = DEFAULT_MESSAGE.to_string();
    let mut scenario = Scenario::OnlineRoundtrip;
    let mut node_key: Option<String> = None;
    let mut metrics_url: Option<String> = None;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        let take = |name: &str, iter: &mut dyn Iterator<Item = String>| -> Result<String> {
            iter.next()
                .ok_or_else(|| anyhow!("expected value after {name}"))
        };
        match arg.as_str() {
            "--node-key" => node_key = Some(take("--node-key", &mut iter)?),
            "--metrics" => metrics_url = Some(take("--metrics", &mut iter)?),
            "--node-key-file" => {
                let path = take("--node-key-file", &mut iter)?;
                let raw = std::fs::read_to_string(&path)
                    .with_context(|| format!("read node key file {path}"))?;
                node_key = Some(raw.trim().to_string());
            }
            "--message" => message = take("--message", &mut iter)?,
            "--scenario" => scenario = Scenario::parse(&take("--scenario", &mut iter)?)?,
            "-h" | "--help" => {
                println!(
                    "usage: e2e_smoke --node-key <hex32> [--message host:port] [--scenario name]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown arg `{other}`"),
        }
    }

    let node_key = match node_key {
        None => None,
        Some(raw) => {
            let decoded = hex::decode(raw.trim()).context("--node-key must be hex")?;
            if decoded.len() != 32 {
                bail!("--node-key must decode to 32 bytes, got {}", decoded.len());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            Some(key)
        }
    };

    if node_key.is_none() && !matches!(scenario, Scenario::ProbeTofu) {
        bail!("--node-key <hex32> is required: IK needs the node static key");
    }

    Ok(Args {
        node_key,
        message_addr: message,
        scenario,
        metrics_url,
    })
}

impl Args {
    fn node_key(&self) -> Result<[u8; 32]> {
        self.node_key
            .ok_or_else(|| anyhow!("this scenario needs --node-key <hex32>"))
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut buf)
        .context("read random bytes")?;
    Ok(buf)
}

fn fresh_keypair() -> Result<SigningKey> {
    let seed: [u8; 32] = random_bytes()?;
    Ok(SigningKey::from_bytes(&seed))
}

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn encode_client_send(
    recipient: &[u8; 32],
    device_id: Option<u16>,
    body: &[u8],
) -> Result<Vec<u8>> {
    Ok(wrap(frame::Payload::ClientSend(wire::ClientSend {
        recipient_id: recipient.to_vec(),
        body: body.to_vec(),
        recipient_device_id: device_id.map(u32::from),
        ..wire::ClientSend::default()
    })))
}

fn encode_delivery_ack(message_id: u64) -> Result<Vec<u8>> {
    Ok(wrap(frame::Payload::DeliveryAck(wire::DeliveryAck {
        message_id,
    })))
}

fn decode_payload(bytes: &[u8]) -> Result<frame::Payload> {
    Frame::decode(bytes)
        .context("decode frame from message server")?
        .payload
        .context("message server sent a frame without payload")
}

/// Открыть сессию: Noise IK, `AuthOk`, который нода шлёт сама, и
/// подтверждение сессии. Токена нет — identity доказана статиком,
/// выведенным из ключа клиента.
async fn login(args: &Args, identity: &SigningKey, device_id: Option<u16>) -> Result<Session> {
    let stream = TcpStream::connect(&args.message_addr)
        .await
        .with_context(|| format!("connect to message server at {}", args.message_addr))?;
    stream.set_nodelay(true).ok();

    let conn = NoiseFramed::connect(
        stream,
        &args.node_key()?,
        identity,
        device_id,
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await
    .context("noise handshake failed")?;

    confirm_session(conn, &identity.verifying_key().to_bytes()).await
}

/// Установленная сессия смоук-клиента.
///
/// Нода считает сессию своей только после первого кадра клиента, поэтому
/// вход сразу отвечает на `AuthOk` пингом и ждёт `Pong`. Кадры, пришедшие
/// раньше `Pong` (офлайн-реплей), сохраняются и отдаются сценарию первыми,
/// так что для него это обычный канал.
struct Session {
    conn: NoiseFramed<TcpStream>,
    early: VecDeque<BytesMut>,
}

impl Session {
    async fn next_frame(&mut self) -> std::io::Result<Option<BytesMut>> {
        match self.early.pop_front() {
            Some(frame) => Ok(Some(frame)),
            None => self.conn.next_frame().await,
        }
    }

    async fn send_frame(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.conn.send_frame(payload).await
    }
}

/// Принять `AuthOk` и подтвердить сессию первым кадром (`Ping`).
async fn confirm_session(
    mut conn: NoiseFramed<TcpStream>,
    expected_user: &[u8; 32],
) -> Result<Session> {
    let bytes = timeout(Duration::from_secs(10), conn.next_frame())
        .await
        .context("waiting for AuthOk timed out")?
        .context("read AuthOk")?
        .ok_or_else(|| anyhow!("connection closed before AuthOk"))?;

    match decode_payload(bytes.as_ref())? {
        frame::Payload::AuthOk(ok) => {
            if ok.user_id != expected_user {
                bail!("AuthOk returned wrong user_id");
            }
        }
        frame::Payload::AuthError(err) => {
            bail!(
                "session rejected: code={} message={}",
                err.code,
                err.message
            );
        }
        _ => bail!("expected AuthOk right after the noise handshake"),
    }

    conn.send_frame(&wrap(frame::Payload::Ping(wire::Ping {})))
        .await
        .context("send the confirming Ping")?;
    let mut early = VecDeque::new();
    loop {
        let bytes = timeout(Duration::from_secs(10), conn.next_frame())
            .await
            .context("waiting for Pong timed out")?
            .context("read Pong")?
            .ok_or_else(|| anyhow!("connection closed before Pong"))?;
        match decode_payload(bytes.as_ref())? {
            frame::Payload::Pong(_) => break,
            frame::Payload::AuthError(err) => {
                bail!(
                    "session rejected on confirmation: code={} message={}",
                    err.code,
                    err.message
                );
            }
            _ => early.push_back(bytes),
        }
    }
    Ok(Session { conn, early })
}

#[derive(Debug)]
struct ReceivedIncoming {
    from_user_id: [u8; 32],
    from_device_id: Option<u16>,
    message_id: u64,
    body: Vec<u8>,
}

#[derive(Debug)]
struct ReceivedSendAck {
    ok: bool,
    queued: bool,
    queue_id: u64,
    reason: SendRejectReason,
}

#[derive(Debug)]
enum InFrame {
    Incoming(ReceivedIncoming),
    SendAck(ReceivedSendAck),
    Other(&'static str),
}

fn parse_in_frame(bytes: &[u8]) -> Result<InFrame> {
    Ok(match decode_payload(bytes)? {
        frame::Payload::Incoming(msg) => {
            if msg.from_user_id.len() != 32 {
                bail!("Incoming.fromUserId unexpected length");
            }
            let mut from_arr = [0u8; 32];
            from_arr.copy_from_slice(&msg.from_user_id[..32]);
            let from_device_id = match msg.from_device_id {
                None => None,
                Some(id) => Some(
                    u16::try_from(id).context("Incoming.fromDeviceId does not fit into 16 bits")?,
                ),
            };
            InFrame::Incoming(ReceivedIncoming {
                from_user_id: from_arr,
                from_device_id,
                message_id: msg.message_id,
                body: msg.body,
            })
        }
        frame::Payload::SendAck(ack) => InFrame::SendAck(ReceivedSendAck {
            ok: ack.ok,
            queued: ack.queued,
            queue_id: ack.queue_id,
            reason: SendRejectReason::from_wire(ack.reason),
        }),
        frame::Payload::AuthOk(_) => InFrame::Other("AuthOk"),
        frame::Payload::AuthError(_) => InFrame::Other("AuthError"),
        frame::Payload::Pong(_) => InFrame::Other("Pong"),
        frame::Payload::SignedServerConfig(_) => InFrame::Other("SignedServerConfig"),
        _ => InFrame::Other("Unknown"),
    })
}

async fn run_online_roundtrip(args: &Args, expect_delivery_ack_path: bool) -> Result<()> {
    println!("==> generating ephemeral keypairs A and B");
    let key_a = fresh_keypair()?;
    let key_b = fresh_keypair()?;
    let user_a = key_a.verifying_key().to_bytes();
    let user_b = key_b.verifying_key().to_bytes();
    println!("    A.pub = {}", hex::encode(user_a));
    println!("    B.pub = {}", hex::encode(user_b));

    println!(
        "==> noise IK against node {}",
        hex::encode(args.node_key()?)
    );

    println!(
        "==> connecting B to message server first ({})",
        args.message_addr
    );
    let mut framed_b = login(args, &key_b, None).await.context("B login failed")?;
    println!("    B session established");

    // Small grace period so JetStream pump for B is registered before A publishes.
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("==> connecting A");
    let mut framed_a = login(args, &key_a, None).await.context("A login failed")?;
    println!("    A session established");

    let nonce: [u8; 8] = random_bytes()?;
    let body = format!("e2e-smoke {}", hex::encode(nonce)).into_bytes();
    println!("==> A -> B body=`{}`", String::from_utf8_lossy(&body));
    let send_bytes = encode_client_send(&user_b, None, &body)?;
    framed_a.send_frame(&send_bytes).await.context("A send")?;
    let started = Instant::now();

    let mut got_send_ack = false;
    let mut got_incoming: Option<ReceivedIncoming> = None;

    let deadline = Duration::from_secs(15);
    while (got_incoming.is_none() || !got_send_ack) && started.elapsed() < deadline {
        tokio::select! {
            biased;
            res = timeout(Duration::from_millis(500), framed_b.next_frame()) => {
                match res {
                    Ok(Ok(Some(bytes))) => {
                        match parse_in_frame(bytes.as_ref())? {
                            InFrame::Incoming(inc) => {
                                println!(
                                    "    B <- Incoming: from={} device={:?} message_id={} body=`{}`",
                                    hex::encode(inc.from_user_id),
                                    inc.from_device_id,
                                    inc.message_id,
                                    String::from_utf8_lossy(&inc.body)
                                );
                                if inc.from_user_id != user_a {
                                    bail!("Incoming.from_user_id mismatch (expected A)");
                                }
                                if inc.body != body {
                                    bail!("Incoming.body mismatch (got `{}`)", String::from_utf8_lossy(&inc.body));
                                }
                                got_incoming = Some(inc);
                            }
                            InFrame::SendAck(_) => println!("    B <- (unexpected) SendAck"),
                            InFrame::Other(label) => println!("    B <- {label}"),
                        }
                    }
                    Ok(Ok(None)) => bail!("B connection closed unexpectedly"),
                    Ok(Err(err)) => bail!("B read error: {err}"),
                    Err(_) => {}
                }
            }
            res = timeout(Duration::from_millis(500), framed_a.next_frame()) => {
                match res {
                    Ok(Ok(Some(bytes))) => {
                        match parse_in_frame(bytes.as_ref())? {
                            InFrame::SendAck(ack) => {
                                println!(
                                    "    A <- SendAck: ok={} queued={} queue_id={} reason={}",
                                    ack.ok,
                                    ack.queued,
                                    ack.queue_id,
                                    ack.reason.as_metric_label()
                                );
                                got_send_ack = true;
                            }
                            InFrame::Incoming(_) => println!("    A <- (unexpected) Incoming"),
                            InFrame::Other(label) => println!("    A <- {label}"),
                        }
                    }
                    Ok(Ok(None)) => bail!("A connection closed unexpectedly"),
                    Ok(Err(err)) => bail!("A read error: {err}"),
                    Err(_) => {}
                }
            }
        }
    }

    let inc =
        got_incoming.ok_or_else(|| anyhow!("B never received Incoming within {deadline:?}"))?;
    if !got_send_ack {
        return Err(anyhow!("A never received SendAck within {deadline:?}"));
    }

    if expect_delivery_ack_path {
        println!("==> B -> DeliveryAck(message_id={})", inc.message_id);
        let ack_bytes = encode_delivery_ack(inc.message_id)?;
        framed_b
            .send_frame(&ack_bytes)
            .await
            .context("B send DeliveryAck")?;
        // Server doesn't echo a confirmation; give it a moment to process before exit.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!("==> OK");
    Ok(())
}

async fn run_offline_then_online(args: &Args) -> Result<()> {
    println!("==> generating ephemeral keypairs A and B");
    let key_a = fresh_keypair()?;
    let key_b = fresh_keypair()?;
    let user_a = key_a.verifying_key().to_bytes();
    let user_b = key_b.verifying_key().to_bytes();
    println!("    A.pub = {}", hex::encode(user_a));
    println!("    B.pub = {}", hex::encode(user_b));

    println!("==> A connects, B is offline");
    let mut framed_a = login(args, &key_a, None).await.context("A login")?;
    let nonce: [u8; 8] = random_bytes()?;
    let body = format!("e2e-offline {}", hex::encode(nonce)).into_bytes();
    println!(
        "==> A sends to B (B not connected) body=`{}`",
        String::from_utf8_lossy(&body)
    );
    let send_bytes = encode_client_send(&user_b, None, &body)?;
    framed_a.send_frame(&send_bytes).await.context("A send")?;

    let bytes = timeout(Duration::from_secs(10), framed_a.next_frame())
        .await
        .context("waiting for SendAck timed out")?
        .context("A read")?
        .ok_or_else(|| anyhow!("A connection closed before SendAck"))?;
    match parse_in_frame(bytes.as_ref())? {
        InFrame::SendAck(ack) => {
            println!(
                "    A <- SendAck: ok={} queued={} queue_id={}",
                ack.ok, ack.queued, ack.queue_id
            );
        }
        other => bail!("expected SendAck, got {other:?}"),
    }

    drop(framed_a);
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("==> now B connects, expecting replay/redelivery");
    let mut framed_b = login(args, &key_b, None).await.context("B login")?;

    let started = Instant::now();
    let deadline = Duration::from_secs(15);
    let mut got: Option<ReceivedIncoming> = None;
    while got.is_none() && started.elapsed() < deadline {
        match timeout(Duration::from_millis(500), framed_b.next_frame()).await {
            Ok(Ok(Some(bytes))) => match parse_in_frame(bytes.as_ref())? {
                InFrame::Incoming(inc) => {
                    println!(
                        "    B <- Incoming: from={} message_id={} body=`{}`",
                        hex::encode(inc.from_user_id),
                        inc.message_id,
                        String::from_utf8_lossy(&inc.body)
                    );
                    if inc.from_user_id != user_a || inc.body != body {
                        bail!("body or sender mismatch");
                    }
                    got = Some(inc);
                }
                other => println!("    B <- {other:?}"),
            },
            Ok(Ok(None)) => bail!("B connection closed unexpectedly"),
            Ok(Err(err)) => bail!("B read error: {err}"),
            Err(_) => {}
        }
    }

    got.ok_or_else(|| anyhow!("B did not receive replayed message within {deadline:?}"))?;
    println!("==> OK");
    Ok(())
}

async fn drain_until_incoming(
    framed: &mut Session,
    expect_from: &[u8; 32],
    expect_body: &[u8],
    deadline: Duration,
) -> Result<Option<ReceivedIncoming>> {
    let started = Instant::now();
    while started.elapsed() < deadline {
        match timeout(Duration::from_millis(500), framed.next_frame()).await {
            Ok(Ok(Some(bytes))) => match parse_in_frame(bytes.as_ref())? {
                InFrame::Incoming(inc) => {
                    if inc.from_user_id == *expect_from && inc.body == expect_body {
                        return Ok(Some(inc));
                    } else {
                        println!(
                            "    (ignored) Incoming: from={} body=`{}`",
                            hex::encode(inc.from_user_id),
                            String::from_utf8_lossy(&inc.body)
                        );
                    }
                }
                other => println!("    (drained) {other:?}"),
            },
            Ok(Ok(None)) => bail!("connection closed unexpectedly"),
            Ok(Err(err)) => bail!("read error: {err}"),
            Err(_) => {}
        }
    }
    Ok(None)
}

async fn expect_send_ack(framed: &mut Session, deadline: Duration) -> Result<ReceivedSendAck> {
    let started = Instant::now();
    while started.elapsed() < deadline {
        match timeout(Duration::from_millis(500), framed.next_frame()).await {
            Ok(Ok(Some(bytes))) => match parse_in_frame(bytes.as_ref())? {
                InFrame::SendAck(ack) => return Ok(ack),
                other => println!("    (waiting for SendAck) ignored {other:?}"),
            },
            Ok(Ok(None)) => bail!("connection closed before SendAck"),
            Ok(Err(err)) => bail!("read error: {err}"),
            Err(_) => {}
        }
    }
    Err(anyhow!("SendAck not received within {deadline:?}"))
}

async fn run_crash_before_ack(args: &Args) -> Result<()> {
    println!("==> generating ephemeral keypairs A and B");
    let key_a = fresh_keypair()?;
    let key_b = fresh_keypair()?;
    let user_a = key_a.verifying_key().to_bytes();
    let user_b = key_b.verifying_key().to_bytes();
    println!("    A.pub = {}", hex::encode(user_a));
    println!("    B.pub = {}", hex::encode(user_b));

    println!("==> B logs in (first session)");
    let mut framed_b = login(args, &key_b, None).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("==> A logs in and sends");
    let mut framed_a = login(args, &key_a, None).await?;
    let nonce: [u8; 8] = random_bytes()?;
    let body = format!("e2e-crash {}", hex::encode(nonce)).into_bytes();
    framed_a
        .send_frame(&encode_client_send(&user_b, None, &body)?)
        .await?;
    let ack = expect_send_ack(&mut framed_a, Duration::from_secs(10)).await?;
    println!(
        "    A <- SendAck: ok={} queued={} message_id={}",
        ack.ok, ack.queued, ack.queue_id
    );
    let expected_message_id = ack.queue_id;

    println!("==> B reads first Incoming, then drops TCP without DeliveryAck");
    let inc = drain_until_incoming(&mut framed_b, &user_a, &body, Duration::from_secs(15))
        .await?
        .ok_or_else(|| anyhow!("B did not receive first Incoming"))?;
    if inc.message_id != expected_message_id {
        bail!(
            "first delivery message_id mismatch: ack={}, incoming={}",
            expected_message_id,
            inc.message_id
        );
    }
    println!(
        "    B <- Incoming message_id={}, dropping connection",
        inc.message_id
    );
    drop(framed_b);

    // Redelivery happens once the broker's ack_wait timer fires (30s by default);
    // wait a bit longer than that.
    let redelivery_deadline = Duration::from_secs(60);
    println!(
        "==> B reconnects; waiting up to {:?} for JetStream redelivery (ack_wait ~30s)",
        redelivery_deadline
    );
    let mut framed_b2 = login(args, &key_b, None).await?;

    let inc2 = drain_until_incoming(&mut framed_b2, &user_a, &body, redelivery_deadline)
        .await?
        .ok_or_else(|| {
            anyhow!("B never received redelivered Incoming within {redelivery_deadline:?} - this would mean the message is LOST")
        })?;
    println!(
        "    B <- Incoming (redelivered) message_id={} body=`{}`",
        inc2.message_id,
        String::from_utf8_lossy(&inc2.body)
    );
    if inc2.message_id != expected_message_id {
        bail!(
            "redelivered message_id changed: first={}, redelivered={}",
            expected_message_id,
            inc2.message_id
        );
    }

    println!("==> B sends DeliveryAck so the message is finally drained");
    framed_b2
        .send_frame(&encode_delivery_ack(inc2.message_id)?)
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("==> OK (server retried after crash; no data loss)");
    Ok(())
}

async fn run_no_dup_after_ack(args: &Args) -> Result<()> {
    println!("==> generating ephemeral keypairs A and B");
    let key_a = fresh_keypair()?;
    let key_b = fresh_keypair()?;
    let user_a = key_a.verifying_key().to_bytes();
    let user_b = key_b.verifying_key().to_bytes();
    println!("    A.pub = {}", hex::encode(user_a));
    println!("    B.pub = {}", hex::encode(user_b));

    let mut framed_b = login(args, &key_b, None).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut framed_a = login(args, &key_a, None).await?;
    let nonce: [u8; 8] = random_bytes()?;
    let body = format!("e2e-nodup {}", hex::encode(nonce)).into_bytes();
    framed_a
        .send_frame(&encode_client_send(&user_b, None, &body)?)
        .await?;
    let ack = expect_send_ack(&mut framed_a, Duration::from_secs(10)).await?;
    println!(
        "    A <- SendAck: ok={} queued={} message_id={}",
        ack.ok, ack.queued, ack.queue_id
    );

    let inc = drain_until_incoming(&mut framed_b, &user_a, &body, Duration::from_secs(15))
        .await?
        .ok_or_else(|| anyhow!("B did not receive first Incoming"))?;
    println!("    B <- Incoming message_id={}", inc.message_id);

    println!("==> B sends DeliveryAck and disconnects");
    framed_b
        .send_frame(&encode_delivery_ack(inc.message_id)?)
        .await?;
    // Give the server a moment to actually call broker ack().
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(framed_b);

    // A redelivery would show up only if DeliveryAck wasn't honored, and only after
    // ack_wait (30s by default); watching past it gives the strongest "no dup" signal.
    let watch_window = Duration::from_secs(35);
    println!(
        "==> B reconnects; watching for {:?} that NO duplicate is delivered",
        watch_window
    );
    let mut framed_b2 = login(args, &key_b, None).await?;

    let started = Instant::now();
    while started.elapsed() < watch_window {
        match timeout(Duration::from_millis(500), framed_b2.next_frame()).await {
            Ok(Ok(Some(bytes))) => match parse_in_frame(bytes.as_ref())? {
                InFrame::Incoming(extra) => {
                    if extra.from_user_id == user_a && extra.body == body {
                        bail!(
                            "DUPLICATE DELIVERY: B got the same body again, message_id={}",
                            extra.message_id
                        );
                    } else {
                        println!(
                            "    (unrelated) Incoming from={} body=`{}`",
                            hex::encode(extra.from_user_id),
                            String::from_utf8_lossy(&extra.body)
                        );
                    }
                }
                other => println!("    (received) {other:?}"),
            },
            Ok(Ok(None)) => bail!("B reconnect closed unexpectedly"),
            Ok(Err(err)) => bail!("B reconnect read error: {err}"),
            Err(_) => {}
        }
    }

    println!("==> OK (no duplicate within {:?} after ack)", watch_window);
    Ok(())
}

async fn run_device_routing(args: &Args) -> Result<()> {
    const DEVICE_TARGET: u16 = 2;
    const DEVICE_OTHER: u16 = 1;

    println!("==> generating ephemeral keypairs A and B");
    let key_a = fresh_keypair()?;
    let key_b = fresh_keypair()?;
    let user_a = key_a.verifying_key().to_bytes();
    let user_b = key_b.verifying_key().to_bytes();
    println!("    A.pub = {}", hex::encode(user_a));
    println!("    B.pub = {}", hex::encode(user_b));

    println!(
        "==> B logs in twice: device_id={} and device_id={}",
        DEVICE_OTHER, DEVICE_TARGET
    );
    let mut framed_b_other = login(args, &key_b, Some(DEVICE_OTHER)).await?;
    let mut framed_b_target = login(args, &key_b, Some(DEVICE_TARGET)).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!(
        "==> A logs in and sends to (B, device_id={})",
        DEVICE_TARGET
    );
    let mut framed_a = login(args, &key_a, None).await?;
    let nonce: [u8; 8] = random_bytes()?;
    let body = format!("e2e-device {}", hex::encode(nonce)).into_bytes();
    framed_a
        .send_frame(&encode_client_send(&user_b, Some(DEVICE_TARGET), &body)?)
        .await?;
    let ack = expect_send_ack(&mut framed_a, Duration::from_secs(10)).await?;
    println!(
        "    A <- SendAck: ok={} queued={} message_id={}",
        ack.ok, ack.queued, ack.queue_id
    );

    println!(
        "==> waiting up to 15s for device {} to receive",
        DEVICE_TARGET
    );
    let inc = drain_until_incoming(
        &mut framed_b_target,
        &user_a,
        &body,
        Duration::from_secs(15),
    )
    .await?
    .ok_or_else(|| anyhow!("device {DEVICE_TARGET} did not receive Incoming"))?;
    println!(
        "    B(dev={}) <- Incoming message_id={}",
        DEVICE_TARGET, inc.message_id
    );

    println!(
        "==> watching device {} for 3s; it must NOT receive the same message",
        DEVICE_OTHER
    );
    let watch = Duration::from_secs(3);
    let started = Instant::now();
    while started.elapsed() < watch {
        match timeout(Duration::from_millis(500), framed_b_other.next_frame()).await {
            Ok(Ok(Some(bytes))) => match parse_in_frame(bytes.as_ref())? {
                InFrame::Incoming(extra) => {
                    if extra.from_user_id == user_a && extra.body == body {
                        bail!(
                            "ROUTING LEAK: device {} received message targeted at device {}",
                            DEVICE_OTHER,
                            DEVICE_TARGET
                        );
                    } else {
                        println!(
                            "    (unrelated on dev={}) from={} body=`{}`",
                            DEVICE_OTHER,
                            hex::encode(extra.from_user_id),
                            String::from_utf8_lossy(&extra.body)
                        );
                    }
                }
                other => println!("    (dev={}) {other:?}", DEVICE_OTHER),
            },
            Ok(Ok(None)) => bail!("device {DEVICE_OTHER} connection closed unexpectedly"),
            Ok(Err(err)) => bail!("device {DEVICE_OTHER} read error: {err}"),
            Err(_) => {}
        }
    }

    framed_b_target
        .send_frame(&encode_delivery_ack(inc.message_id)?)
        .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("==> OK (device routing isolates traffic to the targeted device)");
    Ok(())
}

fn encode_get_server_config() -> Result<Vec<u8>> {
    Ok(wrap(frame::Payload::GetServerConfig(
        wire::GetServerConfig {},
    )))
}

/// Control-канал: завести очередь, увидеть её в списке, отозвать.
///
/// Отдельно проверяется то, что дороже остального: чужая очередь и
/// выдуманный идентификатор дают один и тот же `NOT_FOUND`. Разные ответы
/// превратили бы отзыв в оракул существования, а существование очереди —
/// это право в неё писать.
async fn run_queue_lifecycle(args: &Args) -> Result<()> {
    let owner = fresh_keypair()?;
    let stranger = fresh_keypair()?;

    println!("==> opening a noise session to {}", args.message_addr);
    let mut conn = login(args, &owner, None).await?;

    println!("==> AllocateQueue");
    conn.send_frame(&wrap(frame::Payload::AllocateQueue(wire::AllocateQueue {})))
        .await
        .context("send AllocateQueue")?;
    let ack = expect_queue_ack(&mut conn).await?;
    if !ack.ok || ack.queue_id.len() != 32 {
        bail!(
            "allocation failed: ok={} len={}",
            ack.ok,
            ack.queue_id.len()
        );
    }
    let queue_id = ack.queue_id.clone();
    println!("    <- queue_id={}", hex::encode(&queue_id));

    println!("==> ListQueues");
    conn.send_frame(&wrap(frame::Payload::ListQueues(wire::ListQueues {})))
        .await
        .context("send ListQueues")?;
    let bytes = read_frame(&mut conn, "QueueList").await?;
    match decode_payload(bytes.as_ref())? {
        frame::Payload::QueueList(list) => {
            if !list.queues.iter().any(|q| q.queue_id == queue_id) {
                bail!("freshly allocated queue is missing from the listing");
            }
            println!("    <- {} queue(s), ours is present", list.queues.len());
        }
        other => bail!("expected QueueList, got {other:?}"),
    }

    println!("==> a stranger tries to revoke it");
    let mut other = login(args, &stranger, None).await?;
    other
        .send_frame(&wrap(frame::Payload::RevokeQueue(wire::RevokeQueue {
            queue_id: queue_id.clone(),
        })))
        .await
        .context("send RevokeQueue as a stranger")?;
    let ack = expect_queue_ack(&mut other).await?;
    if ack.ok || ack.reason != wire::QueueRejectReason::NotFound as i32 {
        bail!(
            "a stranger must get NOT_FOUND: ok={} reason={}",
            ack.ok,
            ack.reason
        );
    }
    println!("    <- NOT_FOUND, indistinguishable from a non-existent queue");

    println!("==> RevokeQueue by the owner");
    conn.send_frame(&wrap(frame::Payload::RevokeQueue(wire::RevokeQueue {
        queue_id: queue_id.clone(),
    })))
    .await
    .context("send RevokeQueue")?;
    let ack = expect_queue_ack(&mut conn).await?;
    if !ack.ok {
        bail!("owner failed to revoke: reason={}", ack.reason);
    }

    conn.send_frame(&wrap(frame::Payload::ListQueues(wire::ListQueues {})))
        .await
        .context("send ListQueues after revoke")?;
    let bytes = read_frame(&mut conn, "QueueList").await?;
    match decode_payload(bytes.as_ref())? {
        frame::Payload::QueueList(list) => {
            if list.queues.iter().any(|q| q.queue_id == queue_id) {
                bail!("revoked queue is still listed");
            }
            println!("    <- revoked queue is gone from the listing");
        }
        other => bail!("expected QueueList, got {other:?}"),
    }

    println!("==> OK");
    Ok(())
}

async fn expect_queue_ack(conn: &mut Session) -> Result<wire::QueueAck> {
    let bytes = read_frame(conn, "QueueAck").await?;
    match decode_payload(bytes.as_ref())? {
        frame::Payload::QueueAck(ack) => Ok(ack),
        other => bail!("expected QueueAck, got {other:?}"),
    }
}

async fn read_frame(conn: &mut Session, what: &str) -> Result<BytesMut> {
    match timeout(Duration::from_secs(5), conn.next_frame()).await {
        Ok(Ok(Some(bytes))) => Ok(bytes),
        Ok(Ok(None)) => bail!("server closed the session while waiting for {what}"),
        Ok(Err(err)) => bail!("read error while waiting for {what}: {err}"),
        Err(_) => bail!("no {what} within 5s"),
    }
}

/// Просит `ServerConfig` внутри установленной Noise-сессии: вне сессии
/// нода конфиг не отдаёт, поэтому bootstrap начинается со знания статика ноды.
async fn run_probe_config(args: &Args) -> Result<()> {
    let key = fresh_keypair()?;
    println!("==> opening a noise session to {}", args.message_addr);
    let mut conn = login(args, &key, None).await?;

    println!("==> sending GetServerConfig inside the session");
    conn.send_frame(&encode_get_server_config()?)
        .await
        .context("send GetServerConfig")?;

    let bytes = match timeout(Duration::from_secs(5), conn.next_frame()).await {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => bail!("server closed the session without sending ServerConfig"),
        Ok(Err(err)) => bail!("read error before any ServerConfig reply: {err}"),
        Err(_) => bail!("no ServerConfig within 5s"),
    };

    match decode_payload(bytes.as_ref())? {
        frame::Payload::SignedServerConfig(signed) => {
            // Проверка идёт тем же путём, что предписан клиентам: подпись,
            // связь identity-ключа со статиком хендшейка, срок.
            let cfg = verify_signed_server_config(&signed, &args.node_key()?, unix_now_secs())
                .context("signed server config did not verify")?;
            println!(
                "    <- ServerConfig: protoVersion={} maxFrameLen={} deviceAddressing={} offlineMessages={} deliveryAck={}",
                cfg.proto_version,
                cfg.max_frame_len,
                cfg.supports_device_addressing,
                cfg.supports_offline_messages,
                cfg.supports_delivery_ack,
            );
            println!(
                "    <- signed by {} valid until {}",
                hex::encode(&cfg.node_identity_key),
                cfg.expires_at
            );
            if cfg.proto_version != PROTO_VERSION {
                bail!(
                    "ServerConfig.protoVersion is {} but we handshook as {PROTO_VERSION}",
                    cfg.proto_version
                );
            }
            println!("==> OK (config signed by the node we handshook with)");
            Ok(())
        }
        frame::Payload::AuthError(err) => {
            bail!(
                "session rejected: code={} message={}",
                err.code,
                err.message
            )
        }
        _ => bail!("expected SignedServerConfig"),
    }
}

/// Первый контакт с незнакомой нодой: ключ узнаётся в ходе хендшейка.
///
/// Сценарий существует ради операторской задачи «снять отпечаток ноды и
/// сверить его с тем, что раздан клиентам». Доверие здесь принимается
/// явно — и печатается, чтобы решение было видно, а не подразумевалось.
async fn run_probe_tofu(args: &Args) -> Result<()> {
    let key = fresh_keypair()?;
    let stream = TcpStream::connect(&args.message_addr)
        .await
        .with_context(|| format!("connect to message server at {}", args.message_addr))?;
    stream.set_nodelay(true).ok();

    println!(
        "==> opening a TOFU session to {} (no pin)",
        args.message_addr
    );
    let (conn, learned) = NoiseFramed::connect_unpinned(
        stream,
        &key,
        None,
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
        |node_key| {
            println!("    node fingerprint: {}", fingerprint(node_key));
            true
        },
    )
    .await
    .context("tofu handshake failed (is NOISE_ALLOW_TOFU disabled?)")?;
    let mut conn = confirm_session(conn, &key.verifying_key().to_bytes()).await?;

    // Подпись конфига проверяется против только что узнанного ключа: это и
    // есть проверка, что снапшот выдала та нода, с которой мы говорим.
    conn.send_frame(&encode_get_server_config()?).await?;
    let bytes = timeout(Duration::from_secs(5), conn.next_frame())
        .await
        .context("no ServerConfig within 5s")?
        .context("read ServerConfig")?
        .ok_or_else(|| anyhow!("connection closed without ServerConfig"))?;
    let frame::Payload::SignedServerConfig(signed) = decode_payload(bytes.as_ref())? else {
        bail!("expected SignedServerConfig");
    };
    let cfg = verify_signed_server_config(&signed, &learned, unix_now_secs())
        .context("signed server config did not verify against the learned key")?;
    println!(
        "    config signed by {} valid until {}",
        hex::encode(&cfg.node_identity_key),
        cfg.expires_at
    );

    match args.node_key {
        Some(expected) if expected != learned => {
            bail!(
                "learned key does not match --node-key:\n  learned:  {}\n  expected: {}",
                fingerprint(&learned),
                fingerprint(&expected)
            );
        }
        Some(_) => println!("==> OK (learned key matches the pin we were given)"),
        None => println!(
            "==> OK (first contact succeeded; pin this key before trusting the node: {})",
            hex::encode(learned)
        ),
    }
    Ok(())
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

/// Сумма всех `reject_total` по причинам — снимок «сколько отказов нода
/// выдала к этому моменту». Разбор построчный: тянуть prometheus-парсер
/// ради двух чисел незачем.
async fn reject_totals(metrics_url: &str) -> Result<Vec<(String, f64)>> {
    let body = reqwest::get(metrics_url)
        .await
        .with_context(|| format!("GET {metrics_url}"))?
        .text()
        .await
        .context("read metrics body")?;

    let mut out = Vec::new();
    for line in body.lines() {
        if !line.starts_with("trust_message_tcp_reject_total{") {
            continue;
        }
        let Some((labels, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let reason = labels
            .split("reason=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("?")
            .to_string();
        if let Ok(value) = value.trim().parse::<f64>() {
            out.push((reason, value));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn total_of(snapshot: &[(String, f64)]) -> f64 {
    snapshot.iter().map(|(_, v)| v).sum()
}

/// Флуд-тест квот: шлём `ClientSend` подряд и ждём, что нода ответит
/// отказом с причиной, а не молча проглотит поток. Сессия обязана пережить отказ — гасится поток, а не соединение.
async fn run_quota_flood(args: &Args) -> Result<()> {
    let sender = fresh_keypair()?;
    let recipient = fresh_keypair()?;
    let target = recipient.verifying_key().to_bytes();

    let before = match args.metrics_url.as_deref() {
        Some(url) => {
            let snapshot = reject_totals(url).await?;
            println!("==> reject_total before: {snapshot:?}");
            Some(snapshot)
        }
        None => {
            println!("==> --metrics not given; checking the wire only");
            None
        }
    };

    println!("==> opening a session and blasting ClientSend");
    let mut conn = login(args, &sender, None).await?;

    let body = vec![42u8; 4096];
    let mut accepted = 0u32;
    let mut rejected: Vec<SendRejectReason> = Vec::new();

    // 400 кадров подряд перекрывают дефолтный секундный лимит (100/с) с
    // запасом; если нода настроена мягче, упрёмся в байтовый бюджет или в
    // квоту очереди — любой из отказов закрывает критерий.
    for i in 0..400u32 {
        conn.send_frame(&encode_client_send(&target, None, &body)?)
            .await
            .context("send ClientSend")?;

        let bytes = timeout(Duration::from_secs(10), conn.next_frame())
            .await
            .context("waiting for SendAck timed out")?
            .context("read SendAck")?
            .ok_or_else(|| anyhow!("connection closed mid-flood after {i} frames"))?;

        match parse_in_frame(bytes.as_ref())? {
            InFrame::SendAck(ack) if ack.reason == SendRejectReason::Unspecified => {
                accepted += 1;
            }
            InFrame::SendAck(ack) => {
                rejected.push(ack.reason);
                if rejected.len() >= 3 {
                    break;
                }
            }
            other => bail!("unexpected frame during flood: {other:?}"),
        }
    }

    println!("    accepted={accepted} rejected={rejected:?}");
    if rejected.is_empty() {
        bail!(
            "flood of 400 frames hit no quota at all: either limits are disabled \
             on this node or enforcement regressed"
        );
    }

    println!("==> checking the session survived the rejects");
    conn.send_frame(&encode_get_server_config()?).await?;
    let bytes = timeout(Duration::from_secs(5), conn.next_frame())
        .await
        .context("session died after a quota reject")?
        .context("read ServerConfig")?
        .ok_or_else(|| anyhow!("connection closed after a quota reject"))?;
    match decode_payload(bytes.as_ref())? {
        frame::Payload::SignedServerConfig(_) => println!("    session still serves config"),
        _ => bail!("expected SignedServerConfig after the flood"),
    }

    if let (Some(url), Some(before)) = (args.metrics_url.as_deref(), before) {
        let after = reject_totals(url).await?;
        println!("==> reject_total after: {after:?}");
        let growth = total_of(&after) - total_of(&before);
        if growth <= 0.0 {
            bail!(
                "wire showed {} rejects but reject_total did not grow — \
                 operators would be blind to this flood",
                rejected.len()
            );
        }
        println!("    reject_total grew by {growth}");
    }

    println!("==> OK (quotas answered with a reason, session survived)");
    Ok(())
}

async fn run(args: Args) -> Result<()> {
    match args.scenario {
        Scenario::OnlineRoundtrip => run_online_roundtrip(&args, false).await,
        Scenario::DeliveryAck => run_online_roundtrip(&args, true).await,
        Scenario::OfflineThenOnline => run_offline_then_online(&args).await,
        Scenario::CrashBeforeAck => run_crash_before_ack(&args).await,
        Scenario::NoDupAfterAck => run_no_dup_after_ack(&args).await,
        Scenario::DeviceRouting => run_device_routing(&args).await,
        Scenario::QueueLifecycle => run_queue_lifecycle(&args).await,
        Scenario::ProbeConfig => run_probe_config(&args).await,
        Scenario::ProbeTofu => run_probe_tofu(&args).await,
        Scenario::QuotaFlood => run_quota_flood(&args).await,
    }
}

fn main() -> Result<()> {
    let args = parse_args()?;
    println!(
        "e2e_smoke: message={} node_key={} scenario={:?}",
        args.message_addr,
        args.node_key
            .map(hex::encode)
            .unwrap_or_else(|| "<none, tofu>".to_string()),
        args.scenario
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(args))
}
