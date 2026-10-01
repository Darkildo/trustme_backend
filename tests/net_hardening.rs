//! Защита сетевого слоя на настоящем `accept_loop`: потолок открытых
//! соединений, TCP keepalive на принятых сокетах и строгая длина
//! идентификатора получателя.

mod common;

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use common::{
    PROTO_VERSION, connect, decode, expect_auth_ok, next_frame, next_incoming_within, spawn_server,
    user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::wire::{self, Frame, frame};

/// Нода закрыла соединение, ничего в него не написав. Таймаут — значит,
/// соединение живо и ждёт клиента.
async fn closed_without_reply(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 64];
    match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

/// Сверх потолка соединение закрывается сразу после `accept`, до
/// хендшейка, а место возвращается, когда занявшее его соединение
/// закрылось. Соединение, ещё не прошедшее хендшейк, место тоже занимает:
/// иначе потолок обходился бы сокетами, которые молчат.
#[tokio::test]
async fn connection_cap_closes_extra_connections_before_handshake() -> Result<()> {
    let limits = LimitsConfig {
        max_connections: 2,
        ..LimitsConfig::default()
    };
    let server = spawn_server("conn_cap", limits).await?;

    let first = SigningKey::from_bytes(&[61u8; 32]);
    let mut session = connect(&server, &first).await?;
    expect_auth_ok(&next_frame(&mut session).await?, &user_id_of(&first))?;
    let silent = TcpStream::connect(server.addr).await?;

    let mut extra = TcpStream::connect(server.addr).await?;
    assert!(
        closed_without_reply(&mut extra).await,
        "a connection over the cap must be closed before the handshake"
    );
    let second = SigningKey::from_bytes(&[62u8; 32]);
    assert!(
        connect(&server, &second).await.is_err(),
        "a handshake over the cap must not succeed"
    );

    // Молчащее соединение уходит — его место достаётся следующему. Задача
    // ноды замечает закрытие не мгновенно, поэтому попыток несколько.
    drop(silent);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut admitted = loop {
        match connect(&server, &second).await {
            Ok(conn) => break conn,
            Err(err) if Instant::now() >= deadline => {
                bail!("the freed slot was never handed out: {err:#}")
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    };
    expect_auth_ok(&next_frame(&mut admitted).await?, &user_id_of(&second))?;

    // Установленная сессия, с которой всё началось, по-прежнему жива.
    session
        .send_frame(&common::encode_get_server_config()?)
        .await?;
    common::expect_signed_config(&next_frame(&mut session).await?, &server.node_public)?;
    Ok(())
}

/// Сокет, который нода приняла, получает keepalive с временем простоя из
/// конфигурации. Снаружи опции чужого сокета не видны, поэтому проверка
/// идёт по таблице сокетов ядра: у соединения, которое ничего не ждёт,
/// единственный взведённый таймер — keepalive (`tr = 2`), и срабатывает он
/// через настроенное время.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn accepted_connections_get_tcp_keepalive() -> Result<()> {
    const KEEPALIVE_SECS: u64 = 777;
    // `tm->when` в /proc — в тиках USER_HZ (100 в секунду).
    const TICKS_PER_SEC: u64 = 100;

    let limits = LimitsConfig {
        tcp_keepalive_secs: KEEPALIVE_SECS,
        ..LimitsConfig::default()
    };
    let server = spawn_server("keepalive", limits).await?;
    let client = TcpStream::connect(server.addr).await?;
    let client_port = client.local_addr()?.port();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((timer, when)) = server_side_timer(server.addr.port(), client_port)?
            && timer == 2
        {
            assert!(
                when > (KEEPALIVE_SECS - 70) * TICKS_PER_SEC
                    && when <= KEEPALIVE_SECS * TICKS_PER_SEC,
                "keepalive fires in {when} ticks, expected about {KEEPALIVE_SECS} s"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("keepalive timer never armed on the accepted socket");
        }
        sleep(Duration::from_millis(20)).await;
    }
}

/// Таймер серверной стороны соединения из `/proc/net/tcp`: вид (`tr`) и
/// время до срабатывания в тиках. `None` — сокет ещё не принят.
#[cfg(target_os = "linux")]
fn server_side_timer(server_port: u16, client_port: u16) -> Result<Option<(u8, u64)>> {
    let table = std::fs::read_to_string("/proc/net/tcp")?;
    let port_of = |addr: &str| {
        addr.rsplit_once(':')
            .and_then(|(_, port)| u16::from_str_radix(port, 16).ok())
    };
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        if port_of(fields[1]) != Some(server_port) || port_of(fields[2]) != Some(client_port) {
            continue;
        }
        let Some((timer, when)) = fields[5].split_once(':') else {
            bail!("unexpected timer column `{}`", fields[5]);
        };
        return Ok(Some((
            u8::from_str_radix(timer, 16)?,
            u64::from_str_radix(when, 16)?,
        )));
    }
    Ok(None)
}

/// `recipient_id` длиннее 32 байт не усекается до первых 32: иначе
/// 33-байтовое поле, начинающееся с чужого ключа, адресовало бы этого
/// получателя. Нода отвергает кадр, и до получателя ничего не доходит.
#[tokio::test]
async fn oversized_recipient_id_is_not_truncated() -> Result<()> {
    let server = spawn_server("long_recipient", LimitsConfig::default()).await?;
    let sender = SigningKey::from_bytes(&[63u8; 32]);
    let recipient = SigningKey::from_bytes(&[64u8; 32]);

    let mut sender_conn = connect(&server, &sender).await?;
    expect_auth_ok(&next_frame(&mut sender_conn).await?, &user_id_of(&sender))?;
    let mut recipient_conn = connect(&server, &recipient).await?;
    expect_auth_ok(
        &next_frame(&mut recipient_conn).await?,
        &user_id_of(&recipient),
    )?;

    let mut long_id = user_id_of(&recipient).to_vec();
    long_id.push(0xAA);
    let send = Frame {
        proto_version: PROTO_VERSION,
        payload: Some(frame::Payload::ClientSend(wire::ClientSend {
            recipient_id: long_id,
            body: b"misaddressed".to_vec(),
            ..wire::ClientSend::default()
        })),
    }
    .encode_to_vec();
    sender_conn.send_frame(&send).await?;

    // Отказ — разрыв сессии или отрицательный ack; принятым кадр быть не
    // может.
    match timeout(Duration::from_secs(5), sender_conn.next_frame()).await {
        Ok(Ok(None)) | Ok(Err(_)) => {}
        Ok(Ok(Some(bytes))) => match decode(&bytes)? {
            frame::Payload::SendAck(ack) => {
                assert!(!ack.ok, "an oversized recipient id must not be accepted")
            }
            other => bail!("unexpected reply to a malformed send: {other:?}"),
        },
        Err(_) => bail!("the node neither rejected the frame nor closed the session"),
    }

    assert!(
        next_incoming_within(&mut recipient_conn, Duration::from_millis(500))
            .await?
            .is_none(),
        "the message must not reach the owner of the 32-byte prefix"
    );
    Ok(())
}
