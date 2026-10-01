//! One-off admin helper: wipe every push-token row in `device_push_tokens`
//! belonging to a specific user. Intended for the welcome-push retest case
//! where a pre-existing token row suppresses the first-registration trigger.
//!
//! Usage:
//!   admin_clear_push_tokens <sled-path> <user-hex-64-chars>
//!
//! The message-service process must be stopped before running this — sled
//! takes an exclusive lock on the DB directory.

use std::env;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use trust_message_tcp::state::push_tokens::PushTokenStore;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("admin_clear_push_tokens: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let sled_path = args
        .next()
        .context("missing arg 1: sled DB path (e.g. /srv/trust-message/data)")?;
    let user_hex = args
        .next()
        .context("missing arg 2: user_id as 64-char hex")?;

    let user = parse_user_hex(&user_hex)?;

    let db =
        sled::open(&sled_path).with_context(|| format!("failed to open sled DB at {sled_path}"))?;
    let store = PushTokenStore::open(&db)?;

    let entries = store.list_user(&user)?;
    eprintln!(
        "admin_clear_push_tokens: found {} push token row(s) for user {}",
        entries.len(),
        user_hex
    );

    let mut removed = 0u32;
    for entry in entries {
        let did = entry.device_id;
        if store.remove(&user, did)? {
            removed += 1;
            eprintln!("  removed device_id={did} platform={:?}", entry.platform);
        }
    }
    db.flush().context("sled flush failed")?;

    eprintln!("admin_clear_push_tokens: removed {removed} row(s)");
    Ok(())
}

fn parse_user_hex(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("user_id hex must be 64 chars, got {}", s.len());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).context("user_id is not valid hex")?;
    Ok(out)
}
