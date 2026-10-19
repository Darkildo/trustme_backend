//! Учётки ICE для звонков (server-contract.md §6.12): нода без серверов
//! отвечает `NOT_CONFIGURED`, после правки `runtime.toml` — выдаёт STUN и
//! подписанные учётки TURN тем же сессиям, а частые запросы упираются в
//! общий лимит управляющих кадров.

mod common;

use std::path::PathBuf;

use anyhow::{Result, bail};
use common::{
    NodeOptions, connect, decode, encode_get_server_config, expect_signed_config, next_frame,
    random_identity, spawn_node_with, user_id_of,
};
use prost::Message;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::net::ice::{pseudonym, turn_credential};
use trust_message_tcp::runtime::{self, Reloader};
use trust_message_tcp::wire::{self, Frame, IceRejectReason, frame};

const SECRET: &str = "north-wind-shared-secret";

fn get_ice_servers() -> Vec<u8> {
    Frame {
        proto_version: 1,
        payload: Some(frame::Payload::GetIceServers(wire::GetIceServers {})),
    }
    .encode_to_vec()
}

async fn ask(conn: &mut common::Conn) -> Result<wire::IceServers> {
    conn.send_frame(&get_ice_servers()).await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::IceServers(reply) => Ok(reply),
        _ => bail!("expected IceServers"),
    }
}

#[tokio::test]
async fn credentials_follow_runtime_config() -> Result<()> {
    let limits = LimitsConfig {
        control_per_sec: 3,
        ..LimitsConfig::default()
    };
    let (server, node) = spawn_node_with("ice", limits, NodeOptions::default()).await?;
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
    let mut conn = connect(&server, &alice).await?;
    next_frame(&mut conn).await?; // AuthOk

    let reply = ask(&mut conn).await?;
    assert_eq!(reply.reason, IceRejectReason::NotConfigured as i32);
    conn.send_frame(&encode_get_server_config()?).await?;
    let config = expect_signed_config(&next_frame(&mut conn).await?, &server.node_public)?;
    assert!(!config.supports_ice_servers);

    std::fs::write(
        &path,
        format!(
            "[settings]\nice_credential_ttl_secs = 900\n\n\
             [[ice.servers]]\nurls = [\"stun:stun.example.org:3478\"]\n\n\
             [[ice.servers]]\nurls = [\"turn:turn.example.org:3478?transport=udp\"]\nsecret = \"{SECRET}\"\n"
        ),
    )?;
    assert_eq!(reloader.reload(false).unwrap().result, "applied");

    let before = common::unix_now_secs();
    let reply = ask(&mut conn).await?;
    assert_eq!(reply.reason, IceRejectReason::Unspecified as i32);
    assert!((before + 900..=before + 902).contains(&reply.expires_at));
    assert_eq!(reply.servers.len(), 2);
    assert!(reply.servers[0].username.is_empty());
    let turn = &reply.servers[1];
    let expected_user = format!("{}:{}", reply.expires_at, pseudonym(&user_id_of(&alice)));
    assert_eq!(turn.username, expected_user);
    assert_eq!(turn.credential, turn_credential(SECRET, &expected_user));

    conn.send_frame(&encode_get_server_config()?).await?;
    let config = expect_signed_config(&next_frame(&mut conn).await?, &server.node_public)?;
    assert!(config.supports_ice_servers);

    // Лимит управляющих кадров — 3 в секунду: в пачке запросов отказ
    // появится не позже четвёртого.
    let mut limited = false;
    for _ in 0..8 {
        if ask(&mut conn).await?.reason == IceRejectReason::RateLimited as i32 {
            limited = true;
            break;
        }
    }
    assert!(limited);
    Ok(())
}
