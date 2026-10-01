//! One-off admin helper: send a push to every registered device of a single
//! user, identified by a hex prefix (or full 64-char hex) of their `user_id`.
//!
//! Bypasses the scheduler and its throttling — useful for production smoke
//! tests when you want to verify FCM credentials, the device token, and the
//! client's wake handler end-to-end without sending a real chat message.
//!
//! Usage:
//!   admin_send_push <sled-path> <user-hex-prefix> [--kind wake|welcome] [--priority high|medium|low|none] [--dry-run]
//!
//! Env vars (not needed with `--dry-run`):
//!   FCM_PROJECT_ID            Firebase project id
//!   FCM_SERVICE_ACCOUNT_PATH  path to the Firebase service-account JSON
//!
//! Safety: if the prefix matches more than one user, the tool lists the
//! candidates and exits without sending — so a too-short prefix can never
//! blast pushes across accounts. The message-service process must be stopped
//! before running this (sled takes an exclusive lock on the DB directory).

use std::collections::BTreeMap;
use std::env;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use trust_message_tcp::domain::priority::MessagePriority;
use trust_message_tcp::push::{FcmHttpV1Client, PushKind, PushPayload, PushTransport, SendOutcome};
use trust_message_tcp::state::push_tokens::{PushTokenStore, StoredPushToken};
use trust_message_tcp::state::registry::UserId;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("admin_send_push: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
struct Args {
    sled_path: String,
    user_prefix_hex: String,
    kind: PushKind,
    priority: Option<MessagePriority>,
    dry_run: bool,
}

fn run() -> Result<()> {
    let args = parse_args()?;

    let prefix_bytes = parse_hex_prefix(&args.user_prefix_hex)?;

    let db = sled::open(&args.sled_path)
        .with_context(|| format!("failed to open sled DB at {}", args.sled_path))?;
    let store = PushTokenStore::open(&db)?;

    let (user, devices) = resolve_user_by_prefix(&db, &store, &prefix_bytes)?;
    let user_hex = hex::encode(user);
    eprintln!(
        "admin_send_push: user={user_hex} devices={} kind={:?} priority={:?}",
        devices.len(),
        args.kind,
        args.priority
    );
    let now_for_age = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for d in &devices {
        let age_secs = now_for_age.saturating_sub(d.updated_at_secs);
        eprintln!(
            "  registered: device_id={} platform={:?} updated_at={} (age {}h {}m) token={}...{}",
            d.device_id,
            d.platform,
            d.updated_at_secs,
            age_secs / 3600,
            (age_secs % 3600) / 60,
            &d.token[..d.token.len().min(8)],
            &d.token[d.token.len().saturating_sub(6)..]
        );
    }
    if args.dry_run {
        eprintln!("admin_send_push: --dry-run, nothing dispatched");
        return Ok(());
    }

    let project_id = env::var("FCM_PROJECT_ID")
        .context("FCM_PROJECT_ID env var not set (Firebase project id)")?;
    let service_account_path = env::var("FCM_SERVICE_ACCOUNT_PATH")
        .context("FCM_SERVICE_ACCOUNT_PATH env var not set (path to firebase-adminsdk JSON)")?;

    let transport =
        FcmHttpV1Client::new(project_id, &service_account_path, Duration::from_secs(10))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    let mut ok = 0u32;
    let mut failed = 0u32;
    for d in devices {
        let device_id = d.device_id;
        let token = d.token;
        let payload = PushPayload {
            user_id: user,
            device_id,
            token: token.clone(),
            pending: if args.kind == PushKind::Welcome { 0 } else { 1 },
            max_priority: if args.kind == PushKind::Welcome {
                None
            } else {
                args.priority
            },
            server_ts_secs: now,
            kind: args.kind,
        };

        let outcome = runtime.block_on(transport.send(payload));
        match outcome {
            SendOutcome::Ok => {
                ok += 1;
                eprintln!(
                    "  device_id={device_id} token={}... -> Ok",
                    token_snippet(&token)
                );
            }
            other => {
                failed += 1;
                eprintln!(
                    "  device_id={device_id} token={}... -> {other:?}",
                    token_snippet(&token)
                );
            }
        }
    }

    eprintln!("admin_send_push: sent {ok} ok, {failed} failed");
    if failed > 0 && ok == 0 {
        bail!("all sends failed");
    }
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut iter = env::args().skip(1);
    let sled_path = iter
        .next()
        .context("missing arg 1: sled DB path (e.g. /srv/trust-message/data)")?;
    let user_prefix_hex = iter
        .next()
        .context("missing arg 2: user_id hex prefix (e.g. 6aa9 or full 64 chars)")?;

    let mut kind = PushKind::Wake;
    let mut priority = Some(MessagePriority::High);
    let mut dry_run = false;

    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--dry-run" => {
                dry_run = true;
            }
            "--kind" => {
                let value = iter.next().context("--kind requires a value")?;
                kind = match value.as_str() {
                    "wake" => PushKind::Wake,
                    "welcome" => PushKind::Welcome,
                    other => bail!("unknown --kind {other:?} (expected wake|welcome)"),
                };
            }
            "--priority" => {
                let value = iter.next().context("--priority requires a value")?;
                priority = match value.as_str() {
                    "high" => Some(MessagePriority::High),
                    "medium" => Some(MessagePriority::Medium),
                    "low" => Some(MessagePriority::Low),
                    "none" => None,
                    other => bail!("unknown --priority {other:?} (expected high|medium|low|none)"),
                };
            }
            other => bail!("unknown arg: {other}"),
        }
    }

    Ok(Args {
        sled_path,
        user_prefix_hex,
        kind,
        priority,
        dry_run,
    })
}

fn parse_hex_prefix(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        bail!("user_id hex prefix is empty");
    }
    if s.len() > 64 {
        bail!("user_id hex prefix longer than 64 chars (got {})", s.len());
    }
    if !s.len().is_multiple_of(2) {
        bail!(
            "user_id hex prefix must have an even number of hex chars (got {})",
            s.len()
        );
    }
    hex::decode(s).context("user_id prefix is not valid hex")
}

/// Scan the `device_push_tokens` tree for rows whose key begins with `prefix`,
/// group by the 32-byte user_id portion, and return the unique match. Bails if
/// zero or more-than-one users match — the caller must lengthen the prefix.
fn resolve_user_by_prefix(
    db: &sled::Db,
    store: &PushTokenStore,
    prefix: &[u8],
) -> Result<(UserId, Vec<StoredPushToken>)> {
    let tree = db
        .open_tree("device_push_tokens")
        .context("failed to open `device_push_tokens` tree")?;

    let mut by_user: BTreeMap<UserId, ()> = BTreeMap::new();
    for entry in tree.scan_prefix(prefix) {
        let (key, _) = entry?;
        if key.len() != 32 + 2 {
            continue;
        }
        let mut user = [0u8; 32];
        user.copy_from_slice(&key[..32]);
        by_user.insert(user, ());
    }

    if by_user.is_empty() {
        bail!(
            "no push tokens found for any user with prefix {}",
            hex::encode(prefix)
        );
    }
    if by_user.len() > 1 {
        eprintln!("admin_send_push: prefix matches multiple users:");
        for user in by_user.keys() {
            eprintln!("  {}", hex::encode(user));
        }
        bail!(
            "prefix {} matches {} users; lengthen it",
            hex::encode(prefix),
            by_user.len()
        );
    }

    let user = *by_user.keys().next().expect("checked non-empty");
    let listed = store.list_user(&user)?;
    Ok((user, listed))
}

fn token_snippet(token: &str) -> &str {
    let n = token.len().min(12);
    &token[..n]
}
