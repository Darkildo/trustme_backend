use anyhow::{Context, Result, bail};
use sled::{Db, Tree};
use tracing::warn;

use crate::push::PushState;
use crate::state::registry::{DeviceId, UserId};

/// Length of a `push_state` value (see `encode_value`).
const VALUE_LEN: usize = 8 + 4 + 1 + 8 + 8;

/// Persistent backing store for `crate::push::PushState`.
///
/// The scheduler keeps a `DashMap` cache for hot access; this store mirrors
/// every write so the throttling counters survive a restart and the node does
/// not re-push every recipient on startup.
///
/// Layout of the `push_state` tree:
/// - key   = `user_id(32) || device_id(u16 BE)`
/// - value = `last_push_at_secs(u64 BE) || pending_since_last_push(u32 BE) ||
///   highest_pending_priority(u8) || suppressed_until_secs(u64 BE) ||
///   current_backoff_secs(u64 BE)` — 29 bytes; longer values are accepted
///   and the tail is ignored.
#[derive(Clone)]
pub struct PushStateStore {
    tree: Tree,
}

impl PushStateStore {
    pub fn open(db: &Db) -> Result<Self> {
        let tree = db
            .open_tree("push_state")
            .context("failed to open `push_state` tree")?;
        Ok(Self { tree })
    }

    /// Load the persisted state for `(user, device)`. Returns `Ok(None)` if no
    /// row exists — callers should treat that as `PushState::default()`.
    pub fn load(&self, user: &UserId, device: DeviceId) -> Result<Option<PushState>> {
        let key = make_key(user, device);
        let Some(value) = self.tree.get(key)? else {
            return Ok(None);
        };
        decode_value(value.as_ref()).map(Some)
    }

    /// Persist the state for `(user, device)`. Overwrites any prior row.
    pub fn store(&self, user: &UserId, device: DeviceId, state: PushState) -> Result<()> {
        let key = make_key(user, device);
        let value = encode_value(&state);
        self.tree
            .insert(key, value.as_slice())
            .context("failed to write push state row")?;
        Ok(())
    }

    /// Best-effort load. On error we log and fall back to the default state, so
    /// a corrupt row cannot stall the scheduler — at worst the counters reset
    /// for that recipient.
    pub fn load_or_default(&self, user: &UserId, device: DeviceId) -> PushState {
        match self.load(user, device) {
            Ok(Some(state)) => state,
            Ok(None) => PushState::default(),
            Err(err) => {
                warn!(
                    user = %hex::encode(user),
                    device,
                    error = %err,
                    "push state load failed; using default"
                );
                PushState::default()
            }
        }
    }

    /// Best-effort store: a sled error is logged and does not stop the push
    /// worker.
    pub fn store_lossy(&self, user: &UserId, device: DeviceId, state: PushState) {
        if let Err(err) = self.store(user, device, state) {
            warn!(
                user = %hex::encode(user),
                device,
                error = %err,
                "push state persist failed"
            );
        }
    }

    /// Every persisted row, read at startup to seed the in-memory cache.
    /// Malformed rows are logged and skipped.
    pub fn iter_all(&self) -> Vec<((UserId, DeviceId), PushState)> {
        let mut out = Vec::new();
        for entry in self.tree.iter() {
            let (key, value) = match entry {
                Ok(pair) => pair,
                Err(err) => {
                    warn!(error = %err, "push state iter row error; skipping");
                    continue;
                }
            };
            if key.len() != 32 + 2 {
                warn!(key_len = key.len(), "push state row with malformed key");
                continue;
            }
            let mut user: UserId = [0u8; 32];
            user.copy_from_slice(&key[..32]);
            let device = u16::from_be_bytes(key[32..].try_into().unwrap());
            match decode_value(value.as_ref()) {
                Ok(state) => out.push(((user, device), state)),
                Err(err) => warn!(
                    user = %hex::encode(user),
                    device,
                    error = %err,
                    "push state row decode failed; skipping"
                ),
            }
        }
        out
    }
}

impl crate::push::PushStatePersistence for PushStateStore {
    fn load_all(&self) -> Vec<((UserId, DeviceId), PushState)> {
        self.iter_all()
    }
    fn save(&self, user: UserId, device: DeviceId, state: &PushState) {
        self.store_lossy(&user, device, *state);
    }
}

fn make_key(user: &UserId, device: DeviceId) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 2);
    key.extend_from_slice(user);
    key.extend_from_slice(&device.to_be_bytes());
    key
}

fn encode_value(state: &PushState) -> [u8; VALUE_LEN] {
    let mut out = [0u8; VALUE_LEN];
    out[0..8].copy_from_slice(&state.last_push_at_secs.to_be_bytes());
    out[8..12].copy_from_slice(&state.pending_since_last_push.to_be_bytes());
    out[12] = state.highest_pending_priority;
    out[13..21].copy_from_slice(&state.suppressed_until_secs.to_be_bytes());
    out[21..29].copy_from_slice(&state.current_backoff_secs.to_be_bytes());
    out
}

fn decode_value(bytes: &[u8]) -> Result<PushState> {
    if bytes.len() < VALUE_LEN {
        bail!(
            "push state row shorter than expected ({} < {VALUE_LEN})",
            bytes.len()
        );
    }
    let last_push_at_secs = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let pending_since_last_push = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let highest_pending_priority = bytes[12];
    let suppressed_until_secs = u64::from_be_bytes(bytes[13..21].try_into().unwrap());
    let current_backoff_secs = u64::from_be_bytes(bytes[21..29].try_into().unwrap());
    Ok(PushState {
        last_push_at_secs,
        pending_since_last_push,
        highest_pending_priority,
        suppressed_until_secs,
        current_backoff_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn user(seed: u8) -> UserId {
        [seed; 32]
    }

    fn temp_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("trust_push_state_{label}_{nanos}"));
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn store_and_load_roundtrip_all_fields() {
        let path = temp_path("roundtrip");
        let db = sled::open(&path).unwrap();
        let store = PushStateStore::open(&db).unwrap();

        let state = PushState {
            last_push_at_secs: 123_456_789,
            pending_since_last_push: 42,
            highest_pending_priority: 3,
            suppressed_until_secs: 987_654_321,
            current_backoff_secs: 240,
        };
        store.store(&user(1), 9, state).unwrap();
        let loaded = store.load(&user(1), 9).unwrap().unwrap();
        assert_eq!(loaded, state);

        drop(db);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn load_returns_none_for_missing_key() {
        let path = temp_path("missing");
        let db = sled::open(&path).unwrap();
        let store = PushStateStore::open(&db).unwrap();
        assert!(store.load(&user(2), 1).unwrap().is_none());
        drop(db);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn corrupt_row_logged_as_default() {
        let path = temp_path("corrupt");
        let db = sled::open(&path).unwrap();
        let tree = db.open_tree("push_state").unwrap();
        let key = make_key(&user(3), 2);
        tree.insert(key, &[0u8; 5][..]).unwrap();
        let store = PushStateStore { tree };

        let loaded = store.load_or_default(&user(3), 2);
        assert_eq!(loaded, PushState::default());
        drop(db);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn separate_users_do_not_collide() {
        let path = temp_path("separation");
        let db = sled::open(&path).unwrap();
        let store = PushStateStore::open(&db).unwrap();

        let s1 = PushState {
            pending_since_last_push: 1,
            ..PushState::default()
        };
        let s2 = PushState {
            pending_since_last_push: 2,
            ..PushState::default()
        };
        store.store(&user(1), 1, s1).unwrap();
        store.store(&user(2), 1, s2).unwrap();

        assert_eq!(store.load(&user(1), 1).unwrap().unwrap(), s1);
        assert_eq!(store.load(&user(2), 1).unwrap().unwrap(), s2);
        drop(db);
        let _ = fs::remove_dir_all(&path);
    }
}
