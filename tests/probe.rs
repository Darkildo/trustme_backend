//! Проверка ноды снаружи (`net::probe`): живая нода отвечает проверенным
//! снапшотом, а каждая поломка помечена своим этапом — по нему `tmnode`
//! говорит оператору, что чинить.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::spawn_server;
use tokio::net::TcpListener;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::net::probe::{ProbeStage, probe};

const STEP: Duration = Duration::from_secs(5);

#[tokio::test]
async fn live_node_answers_with_a_verified_config() -> Result<()> {
    let server = spawn_server("probe_ok", LimitsConfig::default()).await?;

    let outcome = probe(&server.addr.to_string(), &server.node_public, STEP).await?;

    assert_eq!(outcome.config.node_static_key, server.node_public.to_vec());
    assert_eq!(outcome.config.proto_version, 1);
    assert!(outcome.config.supports_offline_messages);
    Ok(())
}

#[tokio::test]
async fn wrong_pin_fails_at_the_handshake() -> Result<()> {
    let server = spawn_server("probe_wrong_pin", LimitsConfig::default()).await?;
    let mut other = server.node_public;
    other[0] ^= 0xff;

    let err = probe(&server.addr.to_string(), &other, STEP)
        .await
        .expect_err("a foreign pin must not pass");

    assert_eq!(err.stage, ProbeStage::Handshake);
    Ok(())
}

#[tokio::test]
async fn closed_port_fails_at_connect() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let err = probe(&addr.to_string(), &[7u8; 32], STEP)
        .await
        .expect_err("nothing listens there");

    assert_eq!(err.stage, ProbeStage::Connect);
    assert!(err.to_string().starts_with("connect: "));
    Ok(())
}

#[tokio::test]
async fn silent_peer_times_out_in_the_handshake() -> Result<()> {
    // Порт открыт, но за ним не нода: соединение принимается и молчит.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let silent = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await?;
        tokio::time::sleep(Duration::from_secs(10)).await;
        anyhow::Ok(())
    });

    let err = probe(&addr.to_string(), &[7u8; 32], Duration::from_millis(300))
        .await
        .expect_err("a silent peer is not a node");

    assert_eq!(err.stage, ProbeStage::Handshake);
    silent.abort();
    Ok(())
}
