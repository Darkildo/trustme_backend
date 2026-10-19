//! Настройки без перезапуска (docs/runtime-config.md): правка
//! `runtime.toml` меняет лимиты живой ноды — уже открытые сессии видят их в
//! следующей операции и в следующем подписанном конфиге.

mod common;

use std::path::PathBuf;

use anyhow::Result;
use common::{
    NodeOptions, connect, encode_get_server_config, expect_signed_config, next_frame,
    random_identity, send_and_read_ack, spawn_node_with, user_id_of,
};
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::domain::reject::SendRejectReason;
use trust_message_tcp::runtime::{self, Reloader};

#[tokio::test]
async fn live_session_sees_new_limits_after_reload() -> Result<()> {
    let limits = LimitsConfig {
        ttl_min_seconds: 0,
        send_msgs_per_sec: 0,
        ..LimitsConfig::default()
    };
    let (server, node) = spawn_node_with("runtime_reload", limits, NodeOptions::default()).await?;
    let path = PathBuf::from(&node.cfg.runtime_config_path);
    let mut running = node.cfg.clone();
    let startup = runtime::apply_at_startup(&mut running, &path);
    let mut reloader = Reloader::new(
        path.clone(),
        node.cfg.clone(),
        &running,
        node.live.clone(),
        &startup,
    );

    let alice = random_identity();
    let bob = user_id_of(&random_identity());
    let mut conn = connect(&server, &alice).await?;
    next_frame(&mut conn).await?; // AuthOk
    for _ in 0..5 {
        let ack = send_and_read_ack(&mut conn, &bob, b"x", 3600).await?;
        assert!(ack.queued, "{ack:?}");
    }

    std::fs::write(
        &path,
        "version = \"r1\"\n[settings]\nrate_limit_send_msgs_per_sec = 2\nblob_max_size_bytes = 4096\n",
    )?;
    let status = reloader.reload(false).expect("file changed");
    assert_eq!(status.result, "applied", "{status:?}");

    // Та же сессия: третья отправка в секунду — уже отказ. Окно секунды
    // могло смениться между отправками, поэтому ищем отказ за несколько.
    let mut rejected = false;
    for _ in 0..6 {
        let ack = send_and_read_ack(&mut conn, &bob, b"x", 3600).await?;
        if !ack.queued {
            assert_eq!(ack.reason, SendRejectReason::RateLimited);
            rejected = true;
            break;
        }
    }
    assert!(rejected, "the new send limit must apply to a live session");

    // И подписанный конфиг той же сессии — с новым потолком файла.
    conn.send_frame(&encode_get_server_config()?).await?;
    let config = expect_signed_config(&next_frame(&mut conn).await?, &server.node_public)?;
    assert_eq!(config.blob_max_size, 4096);
    Ok(())
}
