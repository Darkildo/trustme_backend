//! Доставка с подтверждением на прямом (sled) бэкенде.
//!
//! Конверт лежит в очереди получателя, пока клиент не пришлёт `DeliveryAck`
//! той же области: запись в сокет его больше не снимает. Отсюда то, что
//! проверяется: гибель клиента между чтением и подтверждением ничего не
//! теряет, подтверждение снимает запись, молчание живой сессии дольше
//! `ack_wait` приводит к повторной выдаче, разрыв с конвертами в канале
//! ничего не теряет, клиент без подтверждений получает конверт ограниченное
//! число раз, а сессия держит не больше `max_unacked` неподтверждённых.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use common::{
    Conn, FRAME_MAX, HANDSHAKE_TIMEOUT, Incoming, NodeOptions, ServerHandle, confirm, connect,
    connect_as, encode_client_send, encode_delivery_ack, encode_get_server_config, encode_ping,
    expect_auth_ok, expect_incoming, expect_signed_config, next_frame, next_incoming_within,
    random_identity, send_and_read_ack, send_raw_and_read_ack, spawn_node_with, user_id_of,
};
use ed25519_dalek::SigningKey;
use tokio::net::TcpSocket;
use tokio::time::Instant;
use trust_message_tcp::config::{LimitsConfig, RetentionPolicy, SledAckConfig};
use trust_message_tcp::net::noise::NoiseFramed;
use trust_message_tcp::state::storage::InboxScope;
use trust_message_tcp::wire::frame;

/// Сколько ждать конверта, который обязан прийти.
const ARRIVAL: Duration = Duration::from_secs(5);
/// Сколько ждать, чтобы убедиться, что конверт не придёт.
const SILENCE: Duration = Duration::from_millis(500);

fn open_limits() -> LimitsConfig {
    LimitsConfig {
        send_msgs_per_sec: 0,
        send_bytes_per_day: 0,
        max_messages_per_queue: 0,
        max_bytes_per_queue: 0,
        max_messages_sender_pair: 0,
        ..LimitsConfig::default()
    }
}

async fn node(
    label: &str,
    sled_ack: SledAckConfig,
) -> Result<(ServerHandle, common::NodeInternals)> {
    spawn_node_with(
        label,
        open_limits(),
        NodeOptions {
            sled_ack: Some(sled_ack),
            ..NodeOptions::default()
        },
    )
    .await
}

fn ack_cfg(ack_wait: Duration, max_deliveries: u32, max_unacked: usize) -> SledAckConfig {
    SledAckConfig {
        ack_wait,
        max_deliveries,
        max_unacked,
    }
}

async fn session(server: &ServerHandle, identity: &SigningKey, device: u16) -> Result<Conn> {
    let mut conn = connect_as(server, identity, Some(device), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

/// Подтвердить и убедиться, что нода его обработала: кадры сессии
/// обрабатываются по порядку, и `Pong` приходит после подтверждения.
/// Конверты, пришедшие до `Pong`, возвращаются.
async fn ack_and_sync(conn: &mut Conn, message_id: u64) -> Result<Vec<Incoming>> {
    conn.send_frame(&encode_delivery_ack(message_id)).await?;
    conn.send_frame(&encode_ping()).await?;
    let mut early = Vec::new();
    loop {
        let bytes = next_frame(conn).await?;
        match common::decode(&bytes)? {
            frame::Payload::Pong(_) => return Ok(early),
            frame::Payload::Incoming(_) => early.push(expect_incoming(&bytes)?),
            other => bail!("expected Pong, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn sled_node_advertises_delivery_acks() -> Result<()> {
    let (server, _node) = node("ack_advertised", SledAckConfig::default()).await?;
    let alice = random_identity();
    let mut conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(&alice))?;
    conn.send_frame(&encode_get_server_config()?).await?;
    let config = expect_signed_config(&next_frame(&mut conn).await?, &server.node_public)?;
    assert!(config.supports_delivery_ack);
    Ok(())
}

/// Клиент прочитал конверт и умер, не подтвердив: конверт приходит
/// следующей сессии с тем же `message_id`, а после подтверждения — больше
/// никогда.
#[tokio::test]
async fn envelope_read_but_not_acked_reaches_the_next_session() -> Result<()> {
    let (server, node) = node("ack_crash", SledAckConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = session(&server, &bob, 1).await?;
    let mut alice_conn = session(&server, &alice, 1).await?;
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"fragile", 0).await?;
    assert!(ack.ok && !ack.queued, "bob is online: {ack:?}");
    assert_ne!(ack.queue_id, 0, "the online envelope must be stored");

    let first = next_incoming_within(&mut bob_conn, ARRIVAL)
        .await?
        .context("online delivery")?;
    assert_eq!(first.body, b"fragile");
    assert_eq!(first.message_id, ack.queue_id);
    // Процесс получателя гибнет до подтверждения.
    drop(bob_conn);

    let mut again = session(&server, &bob, 1).await?;
    let second = next_incoming_within(&mut again, ARRIVAL)
        .await?
        .context("the unacknowledged envelope was lost")?;
    assert_eq!(second.body, b"fragile");
    assert_eq!(second.message_id, first.message_id);

    ack_and_sync(&mut again, second.message_id).await?;
    assert_eq!(
        node.storage
            .inbox_failures(&bob_id, InboxScope::Account, second.message_id)?,
        None,
        "the acknowledged record must leave the queue"
    );
    drop(again);
    let mut third = session(&server, &bob, 1).await?;
    assert!(next_incoming_within(&mut third, SILENCE).await?.is_none());
    Ok(())
}

/// Подтверждение чужого конверта ничего не снимает: ни чужому аккаунту, ни
/// другому устройству того же аккаунта конверт устройства не подтвердить.
#[tokio::test]
async fn foreign_acks_do_not_remove_the_envelope() -> Result<()> {
    let (server, node) = node("ack_foreign", SledAckConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut alice_conn = session(&server, &alice, 1).await?;

    let ack = send_raw_and_read_ack(
        &mut alice_conn,
        &encode_client_send(&bob_id, Some(7), b"for device 7", 0)?,
    )
    .await?;
    assert!(ack.queued);
    let id = ack.queue_id;

    // Чужой аккаунт и другое устройство подтверждают тот же идентификатор.
    ack_and_sync(&mut alice_conn, id).await?;
    let mut other_device = session(&server, &bob, 8).await?;
    ack_and_sync(&mut other_device, id).await?;
    assert_eq!(
        node.storage
            .inbox_failures(&bob_id, InboxScope::Device(7), id)?,
        Some(0)
    );

    let mut target = session(&server, &bob, 7).await?;
    let incoming = next_incoming_within(&mut target, ARRIVAL)
        .await?
        .context("device envelope")?;
    assert_eq!(incoming.message_id, id);
    ack_and_sync(&mut target, id).await?;
    assert_eq!(
        node.storage
            .inbox_failures(&bob_id, InboxScope::Device(7), id)?,
        None
    );
    Ok(())
}

/// Живая сессия молчит дольше `ack_wait` — конверт приходит ей снова; после
/// подтверждения повторов нет.
#[tokio::test]
async fn ack_timeout_in_a_live_session_redelivers() -> Result<()> {
    let (server, _node) =
        node("ack_timeout", ack_cfg(Duration::from_millis(300), 10, 1024)).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut bob_conn = session(&server, &bob, 1).await?;
    let mut alice_conn = session(&server, &alice, 1).await?;
    send_and_read_ack(&mut alice_conn, &bob_id, b"are you there", 0).await?;

    let first = next_incoming_within(&mut bob_conn, ARRIVAL)
        .await?
        .context("first delivery")?;
    let started = Instant::now();
    let second = next_incoming_within(&mut bob_conn, ARRIVAL)
        .await?
        .context("no redelivery after ack_wait")?;
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "redelivered before ack_wait: {:?}",
        started.elapsed()
    );
    assert_eq!(second.message_id, first.message_id);
    assert_eq!(second.body, first.body);

    ack_and_sync(&mut bob_conn, second.message_id).await?;
    assert!(
        next_incoming_within(&mut bob_conn, Duration::from_millis(900))
            .await?
            .is_none(),
        "an acknowledged envelope must not come back"
    );
    Ok(())
}

/// Сессия рвётся, пока в её канале и окне лежат конверты: ни один не
/// теряется — все приходят следующей сессии.
#[tokio::test]
async fn envelopes_in_the_channel_survive_a_disconnect() -> Result<()> {
    const SENT: usize = 1_500;
    let (server, _node) = node("ack_channel", SledAckConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    // Получатель с крошечным приёмным буфером и не читает: конверты копятся
    // в окне и канале его сессии на ноде.
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(4096)?;
    let stream = socket.connect(server.addr).await?;
    let raw = NoiseFramed::connect(
        stream,
        &server.node_public,
        &bob,
        Some(1),
        HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await?;
    let mut stuck = confirm(raw).await?;
    expect_auth_ok(&next_frame(&mut stuck).await?, &bob_id)?;

    let mut alice_conn = session(&server, &alice, 1).await?;
    let mut sent = HashSet::new();
    for index in 0..SENT {
        let body = format!("{index:06}:{}", "x".repeat(1000)).into_bytes();
        let ack = send_and_read_ack(&mut alice_conn, &bob_id, &body, 0).await?;
        assert!(ack.ok || ack.queued, "unexpected reject: {ack:?}");
        sent.insert(body);
    }
    // Разрыв без единого прочитанного кадра.
    drop(stuck);

    let mut received = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut conn = session(&server, &bob, 1).await?;
    while received.len() < SENT {
        anyhow::ensure!(Instant::now() < deadline, "only {} arrived", received.len());
        let incoming = next_incoming_within(&mut conn, ARRIVAL)
            .await?
            .with_context(|| {
                format!("lost envelopes: only {} of {SENT} arrived", received.len())
            })?;
        conn.send_frame(&encode_delivery_ack(incoming.message_id))
            .await?;
        received.insert(incoming.body);
    }
    assert_eq!(received, sent);
    Ok(())
}

/// Прочитать сессию за `window`: тела входящих (Pong и прочее
/// пропускаются). Пингует каждые `ping_every`, если задано.
async fn collect(
    conn: &mut Conn,
    window: Duration,
    ping_every: Option<Duration>,
) -> Result<Vec<Vec<u8>>> {
    let deadline = Instant::now() + window;
    let mut bodies = Vec::new();
    let mut next_ping = Instant::now();
    while Instant::now() < deadline {
        if let Some(every) = ping_every
            && Instant::now() >= next_ping
        {
            conn.send_frame(&encode_ping()).await?;
            next_ping = Instant::now() + every;
        }
        let step =
            Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now()));
        match tokio::time::timeout(step, conn.next_frame()).await {
            Ok(Ok(Some(bytes))) => {
                if let frame::Payload::Incoming(incoming) = common::decode(&bytes)? {
                    bodies.push(incoming.body);
                }
            }
            Ok(Ok(None)) | Ok(Err(_)) => bail!("session closed"),
            Err(_) => {}
        }
    }
    Ok(bodies)
}

/// Явный предел (`SLED_MAX_DELIVERIES`) для клиента, который
/// `DeliveryAck` не шлёт: живая сессия пингует, конверт повторяется по
/// `ack_wait`, и выдача номер три — последняя.
#[tokio::test]
async fn client_without_acks_gets_a_bounded_number_of_deliveries() -> Result<()> {
    let (server, node) = node("ack_legacy", ack_cfg(Duration::from_millis(200), 3, 1024)).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut alice_conn = session(&server, &alice, 1).await?;
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"legacy", 0).await?;
    assert!(ack.queued);

    let mut conn = session(&server, &bob, 1).await?;
    let bodies = collect(
        &mut conn,
        Duration::from_secs(2),
        Some(Duration::from_millis(50)),
    )
    .await?;
    assert_eq!(bodies, vec![b"legacy".to_vec(); 3]);
    assert_eq!(
        node.storage
            .inbox_failures(&bob_id, InboxScope::Account, ack.queue_id)?,
        None
    );
    Ok(())
}

/// Полуоткрытый сокет: клиент молчит (ни кадров, ни подтверждений), повторы
/// по `ack_wait` идут, но неудачами не считаются — даже с пределом выдач
/// запись доживает до следующей сессии.
#[tokio::test]
async fn silent_session_does_not_burn_the_delivery_limit() -> Result<()> {
    let (server, node) = node("ack_silent", ack_cfg(Duration::from_millis(100), 3, 1024)).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut alice_conn = session(&server, &alice, 1).await?;
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"keep me", 0).await?;

    let mut silent = session(&server, &bob, 1).await?;
    // Около пятнадцати сроков без единого кадра клиента.
    let bodies = collect(&mut silent, Duration::from_millis(1500), None).await?;
    assert!(bodies.len() > 3, "redelivery must go on: {}", bodies.len());
    drop(silent);
    assert_eq!(
        node.storage
            .inbox_failures(&bob_id, InboxScope::Account, ack.queue_id)?,
        Some(0)
    );

    let mut back = session(&server, &bob, 1).await?;
    let incoming = next_incoming_within(&mut back, ARRIVAL)
        .await?
        .context("the record must survive a silent session")?;
    assert_eq!(incoming.body, b"keep me");
    Ok(())
}

/// Большой бэклог и короткие пробуждения: за каждое клиент подтверждает
/// одну запись и гибнет. Необработанный хвост неудачей не считается — с
/// пределом в две выдачи доходит всё.
#[tokio::test]
async fn short_wakeups_keep_the_unprocessed_tail() -> Result<()> {
    const QUEUED: usize = 8;
    let (server, node) = node("ack_wakeups", ack_cfg(Duration::from_secs(30), 2, 4)).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut alice_conn = session(&server, &alice, 1).await?;
    for index in 0..QUEUED {
        let ack = send_and_read_ack(&mut alice_conn, &bob_id, &[index as u8], 0).await?;
        assert!(ack.queued);
    }

    let mut processed = Vec::new();
    for _ in 0..QUEUED {
        let mut wake = session(&server, &bob, 1).await?;
        let first = next_incoming_within(&mut wake, ARRIVAL)
            .await?
            .context("the backlog must still be there")?;
        ack_and_sync(&mut wake, first.message_id).await?;
        processed.push(first.body[0]);
        // Процесс убит: окно с остальным не подтверждено.
    }
    processed.sort_unstable();
    assert_eq!(processed, (0..QUEUED as u8).collect::<Vec<_>>());
    assert_eq!(node.storage.queue_usage(&bob_id, None)?.messages, 0);
    Ok(())
}

/// Сессия держит не больше `max_unacked` неподтверждённых конвертов:
/// остальные ждут в очереди (сессия не выписывается, отправитель получает
/// `ok`) и приходят по мере подтверждений.
#[tokio::test]
async fn unacked_window_applies_backpressure() -> Result<()> {
    const WINDOW: usize = 4;
    const SENT: usize = 10;
    let (server, _node) = node("ack_window", ack_cfg(Duration::from_secs(30), 10, WINDOW)).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);
    let mut bob_conn = session(&server, &bob, 1).await?;
    let mut alice_conn = session(&server, &alice, 1).await?;
    for index in 0..SENT {
        let ack = send_and_read_ack(&mut alice_conn, &bob_id, &[index as u8], 0).await?;
        assert!(
            ack.ok && !ack.queued,
            "the session must stay routable: {ack:?}"
        );
    }

    let mut window = Vec::new();
    while let Some(incoming) = next_incoming_within(&mut bob_conn, SILENCE).await? {
        window.push(incoming);
    }
    assert_eq!(window.len(), WINDOW, "only a full window may be in flight");

    let mut bodies: Vec<u8> = window.iter().map(|incoming| incoming.body[0]).collect();
    // Каждое подтверждение освобождает место ровно под один конверт.
    let first = window.remove(0);
    let mut early = ack_and_sync(&mut bob_conn, first.message_id).await?;
    let next = match early.pop() {
        Some(next) => next,
        None => next_incoming_within(&mut bob_conn, ARRIVAL)
            .await?
            .context("an ack must free a slot")?,
    };
    assert!(early.is_empty(), "one ack frees exactly one slot");
    bodies.push(next.body[0]);
    assert!(
        next_incoming_within(&mut bob_conn, SILENCE)
            .await?
            .is_none()
    );

    // Подтвердить всё остальное — придёт остаток.
    for incoming in window.into_iter().chain([next]) {
        bob_conn
            .send_frame(&encode_delivery_ack(incoming.message_id))
            .await?;
    }
    let deadline = Instant::now() + ARRIVAL;
    while bodies.len() < SENT && Instant::now() < deadline {
        if let Some(incoming) = next_incoming_within(&mut bob_conn, ARRIVAL).await? {
            bob_conn
                .send_frame(&encode_delivery_ack(incoming.message_id))
                .await?;
            bodies.push(incoming.body[0]);
        }
    }
    bodies.sort_unstable();
    assert_eq!(bodies, (0..SENT as u8).collect::<Vec<_>>());
    Ok(())
}

/// Account-конверт, отданный одной сессии и ещё не подтверждённый, другое
/// устройство аккаунта дочитывает из очереди при подключении; его
/// подтверждение снимает конверт для всего аккаунта.
#[tokio::test]
async fn second_device_reads_and_settles_an_unacked_account_envelope() -> Result<()> {
    let (server, _node) = node("ack_handover", SledAckConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut phone = session(&server, &bob, 1).await?;
    let mut alice_conn = session(&server, &alice, 1).await?;
    send_and_read_ack(&mut alice_conn, &bob_id, b"handover", 0).await?;
    let held = next_incoming_within(&mut phone, ARRIVAL)
        .await?
        .context("phone delivery")?;

    // Планшет приходит позже и уже отданное телефону не получает онлайн;
    // при подключении он дочитывает очередь, где конверт ещё лежит.
    let mut tablet = session(&server, &bob, 2).await?;
    let first = next_incoming_within(&mut tablet, ARRIVAL)
        .await?
        .context("the tablet must read the unacknowledged account envelope")?;
    assert_eq!(first.message_id, held.message_id);
    ack_and_sync(&mut tablet, first.message_id).await?;

    // Подтверждено планшетом — телефону после разрыва ничего не приходит.
    drop(phone);
    let mut phone = session(&server, &bob, 1).await?;
    assert!(next_incoming_within(&mut phone, SILENCE).await?.is_none());
    Ok(())
}

/// Хранение выключено (`OFFLINE_MESSAGES_RETENTION=instant`): подтверждения
/// не объявляются, живой сессии конверт приходит с `messageId = 0`, окна нет,
/// офлайн-получателю конверт не сохраняется.
#[tokio::test]
async fn immediate_retention_keeps_the_online_only_path() -> Result<()> {
    let (server, node) = spawn_node_with(
        "ack_instant",
        open_limits(),
        NodeOptions {
            offline_retention: Some(RetentionPolicy::Immediate),
            ..NodeOptions::default()
        },
    )
    .await?;
    let alice = random_identity();
    let bob = random_identity();
    let bob_id = user_id_of(&bob);

    let mut bob_conn = session(&server, &bob, 1).await?;
    bob_conn.send_frame(&encode_get_server_config()?).await?;
    let config = expect_signed_config(&next_frame(&mut bob_conn).await?, &server.node_public)?;
    assert!(!config.supports_delivery_ack);

    let mut alice_conn = session(&server, &alice, 1).await?;
    let ack = send_and_read_ack(&mut alice_conn, &bob_id, b"live only", 0).await?;
    assert!(ack.ok && !ack.queued && ack.queue_id == 0, "{ack:?}");
    let incoming = next_incoming_within(&mut bob_conn, ARRIVAL)
        .await?
        .context("online delivery")?;
    assert_eq!(incoming.message_id, 0);
    assert_eq!(incoming.body, b"live only");
    assert_eq!(node.storage.queue_usage(&bob_id, None)?.messages, 0);

    drop(bob_conn);
    let stranger = random_identity();
    let ack = send_and_read_ack(&mut alice_conn, &user_id_of(&stranger), b"nobody", 0).await?;
    assert!(!ack.ok && !ack.queued, "nothing may be stored: {ack:?}");
    Ok(())
}
