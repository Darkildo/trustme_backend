//! Подтверждение сессии на брокерном бэкенде. Требует живого NATS с
//! JetStream и потому помечен `#[ignore]`; запуск — как у
//! `jetstream_delivery.rs`:
//!
//! ```sh
//! nats-server -js -sd /tmp/nats-test &
//! cargo test --test jetstream_session_confirmation -- --ignored --test-threads=1
//! ```
//!
//! Адрес переопределяется переменной `TRUST_MESSAGE_TEST_NATS_URL`.

mod common;

use std::time::Duration;

use anyhow::{Context, Result};
use common::{
    connect, expect_auth_ok, next_frame, next_incoming_within, random_identity, record_session,
    replay_msg1, send_and_read_ack, spawn_jetstream_server, user_id_of,
};
use trust_message_tcp::config::LimitsConfig;

fn nats_url() -> String {
    std::env::var("TRUST_MESSAGE_TEST_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into())
}

/// Повтор записанного msg1 не поднимает пул доставки. Иначе конверт из
/// потока ушёл бы в сессию, которая его не прочитает и не подтвердит, а
/// честный клиент получил бы его только по истечении `ack_wait`.
#[tokio::test]
#[ignore = "требует живого NATS с JetStream"]
async fn replayed_msg1_does_not_start_delivery() -> Result<()> {
    // Боевой `ack_wait`: конверт, отданный повтору, вернулся бы в поток
    // только через него — заведомо позже окна ожидания ниже.
    let server = spawn_jetstream_server(
        "js_confirm_replay",
        LimitsConfig::default(),
        &nats_url(),
        Duration::from_secs(30),
    )
    .await?;
    let alice = random_identity();
    let alice_id = user_id_of(&alice);
    let bob = random_identity();

    let recorded = record_session(&server, &alice, false).await?;

    let mut bob_conn = connect(&server, &bob).await?;
    expect_auth_ok(&next_frame(&mut bob_conn).await?, &user_id_of(&bob))?;
    let ack = send_and_read_ack(&mut bob_conn, &alice_id, b"for alice only", 0).await?;
    assert!(
        ack.ok && ack.queued,
        "the broker must take the envelope: {ack:?}"
    );

    let _replay = replay_msg1(&server, &recorded).await?;
    // Прежде нода поднимала пул сразу после `AuthOk`, и конверт уходил в
    // повтор; пауза даёт этому время случиться, если оно случается.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut alice_conn = connect(&server, &alice).await?;
    expect_auth_ok(&next_frame(&mut alice_conn).await?, &alice_id)?;
    let incoming = next_incoming_within(&mut alice_conn, Duration::from_secs(5))
        .await?
        .context("the envelope went to the replay instead of the honest client")?;
    assert_eq!(incoming.body, b"for alice only");
    Ok(())
}
