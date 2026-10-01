use anyhow::{Context, Result, bail};
use sled::{Db, Tree};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::domain::push::PushPlatform;
use crate::state::registry::{DeviceId, UserId};

/// Sanity cap on a stored token. Tokens are not validated beyond being
/// non-empty and under this cap; real FCM tokens are a few hundred bytes.
const MAX_TOKEN_LEN: usize = 4096;
const VALUE_HEADER_LEN: usize = 1 + 8;
const VOIP_KEY_SUFFIX: u8 = 0x01;

/// Строка дерева `device_push_tokens`.
///
/// Раскладка:
/// - alert-ключ = `user_id(32) || device_id(u16 BE)` — FCM-токен устройства
///   (AndroidFcm / IosFcm).
/// - voip-ключ  = `user_id(32) || device_id(u16 BE) || 0x01` — PushKit
///   VoIP-токен того же устройства (IosVoip). Слот отдельный, потому что
///   iOS-устройство держит оба токена одновременно. Версии ноды без
///   voip-слота пропускают 35-байтовые ключи как malformed, так что откат
///   на них не ломает чтение.
/// - значение (оба слота) = `platform(u8) || updated_at_secs(u64 BE) || token(UTF-8)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPushToken {
    pub device_id: DeviceId,
    pub platform: PushPlatform,
    pub token: String,
    pub updated_at_secs: u64,
}

/// Sled-backed registry of device push tokens (FCM alert slot and APNs VoIP
/// slot). Cloning is cheap — sled `Tree` is an internal `Arc`. Implements
/// `crate::push::TokenStore` so the scheduler can resolve and evict tokens via
/// the same handle.
#[derive(Clone)]
pub struct PushTokenStore {
    tree: Tree,
}

impl PushTokenStore {
    pub fn open(db: &Db) -> Result<Self> {
        let tree = db
            .open_tree("device_push_tokens")
            .context("failed to open `device_push_tokens` tree")?;
        Ok(Self { tree })
    }

    /// Insert or replace the token for `(user, device)`. `IosVoip` goes to the
    /// VoIP slot, every other platform to the alert slot. Returns `Ok(false)`
    /// if the token is invalid (empty after trimming / longer than
    /// `MAX_TOKEN_LEN`); the caller answers the client with a negative
    /// push-token ack.
    pub fn add(
        &self,
        user: &UserId,
        device: DeviceId,
        platform: PushPlatform,
        token: &str,
    ) -> Result<bool> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(false);
        }
        if token.len() > MAX_TOKEN_LEN {
            return Ok(false);
        }

        let key = match platform {
            PushPlatform::IosVoip => make_voip_key(user, device),
            _ => make_key(user, device),
        };
        let value = encode_value(platform, now_secs()?, token);
        self.tree
            .insert(key, value)
            .context("failed to write push token row")?;
        Ok(true)
    }

    /// Idempotent — returns `Ok(true)` if a row was removed, `Ok(false)` if no
    /// row existed for that `(user, device)`. Alert slot only; the VoIP slot
    /// is removed by [`Self::remove_voip`] / [`Self::remove_all`].
    pub fn remove(&self, user: &UserId, device: DeviceId) -> Result<bool> {
        let key = make_key(user, device);
        let removed = self
            .tree
            .remove(key)
            .context("failed to remove push token row")?;
        Ok(removed.is_some())
    }

    /// Idempotent removal of the voip slot.
    pub fn remove_voip(&self, user: &UserId, device: DeviceId) -> Result<bool> {
        let key = make_voip_key(user, device);
        let removed = self
            .tree
            .remove(key)
            .context("failed to remove voip push token row")?;
        Ok(removed.is_some())
    }

    /// Снять оба слота устройства (логаут / unregister). Возвращает `true`,
    /// если удалён хотя бы один.
    pub fn remove_all(&self, user: &UserId, device: DeviceId) -> Result<bool> {
        let alert = self.remove(user, device)?;
        let voip = self.remove_voip(user, device)?;
        Ok(alert || voip)
    }

    /// Fetch the voip-slot token for `(user, device)`, if registered.
    pub fn get_voip(&self, user: &UserId, device: DeviceId) -> Result<Option<StoredPushToken>> {
        let key = make_voip_key(user, device);
        let Some(value) = self.tree.get(key)? else {
            return Ok(None);
        };
        decode_value(device, value.as_ref()).map(Some)
    }

    /// Fetch the alert-slot token for `(user, device)`, if registered.
    pub fn get(&self, user: &UserId, device: DeviceId) -> Result<Option<StoredPushToken>> {
        let key = make_key(user, device);
        let Some(value) = self.tree.get(key)? else {
            return Ok(None);
        };
        decode_value(device, value.as_ref()).map(Some)
    }

    /// Does this user have any push token row (either slot)? Used to detect
    /// the first registration for the one-shot welcome push; stops at the
    /// first row without decoding it.
    pub fn has_any_for_user(&self, user: &UserId) -> Result<bool> {
        let prefix = user.as_slice();
        match self.tree.scan_prefix(prefix).next() {
            Some(Ok(_)) => Ok(true),
            Some(Err(err)) => Err(err).context("failed to scan push token tree"),
            None => Ok(false),
        }
    }

    /// Alert-slot tokens of all the user's devices, used for the account-scope
    /// push fan-out. VoIP rows (35-byte keys) are skipped on purpose: fan-out
    /// and wake go over the alert slot; the VoIP slot is read point-wise via
    /// `resolve_voip`.
    pub fn list_user(&self, user: &UserId) -> Result<Vec<StoredPushToken>> {
        let prefix = user.as_slice();
        let mut out = Vec::new();
        for entry in self.tree.scan_prefix(prefix) {
            let (key, value) = entry?;
            if key.len() == prefix.len() + 3 && key[prefix.len() + 2] == VOIP_KEY_SUFFIX {
                continue; // voip-слот — не участвует в alert fan-out
            }
            if key.len() != prefix.len() + 2 {
                warn!(
                    user = %hex::encode(user),
                    key_len = key.len(),
                    "skipping malformed push token key"
                );
                continue;
            }
            let device =
                u16::from_be_bytes(key[prefix.len()..].try_into().expect("checked length"));
            match decode_value(device, value.as_ref()) {
                Ok(token) => out.push(token),
                Err(err) => warn!(
                    user = %hex::encode(user),
                    device,
                    error = %err,
                    "skipping malformed push token row"
                ),
            }
        }
        Ok(out)
    }
}

impl crate::push::TokenStore for PushTokenStore {
    fn resolve(&self, user: &UserId, device: DeviceId) -> Option<String> {
        match self.get(user, device) {
            Ok(Some(stored)) => Some(stored.token),
            Ok(None) => None,
            Err(err) => {
                warn!(
                    user = %hex::encode(user),
                    device,
                    error = %err,
                    "push token resolve failed; treating as missing"
                );
                None
            }
        }
    }

    fn remove(&self, user: &UserId, device: DeviceId) {
        if let Err(err) = PushTokenStore::remove(self, user, device) {
            warn!(
                user = %hex::encode(user),
                device,
                error = %err,
                "push token remove failed"
            );
        }
    }

    fn resolve_voip(&self, user: &UserId, device: DeviceId) -> Option<String> {
        match self.get_voip(user, device) {
            Ok(Some(stored)) => Some(stored.token),
            Ok(None) => None,
            Err(err) => {
                warn!(
                    user = %hex::encode(user),
                    device,
                    error = %err,
                    "voip push token resolve failed; treating as missing"
                );
                None
            }
        }
    }

    fn remove_voip(&self, user: &UserId, device: DeviceId) {
        if let Err(err) = PushTokenStore::remove_voip(self, user, device) {
            warn!(
                user = %hex::encode(user),
                device,
                error = %err,
                "voip push token remove failed"
            );
        }
    }
}

fn make_key(user: &UserId, device: DeviceId) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 2);
    key.extend_from_slice(user);
    key.extend_from_slice(&device.to_be_bytes());
    key
}

fn make_voip_key(user: &UserId, device: DeviceId) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 2 + 1);
    key.extend_from_slice(user);
    key.extend_from_slice(&device.to_be_bytes());
    key.push(VOIP_KEY_SUFFIX);
    key
}

fn encode_value(platform: PushPlatform, updated_at_secs: u64, token: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(VALUE_HEADER_LEN + token.len());
    value.push(platform.as_storage_byte());
    value.extend_from_slice(&updated_at_secs.to_be_bytes());
    value.extend_from_slice(token.as_bytes());
    value
}

fn decode_value(device: DeviceId, bytes: &[u8]) -> Result<StoredPushToken> {
    if bytes.len() < VALUE_HEADER_LEN {
        bail!(
            "push token value shorter than header ({} bytes)",
            bytes.len()
        );
    }
    let platform = PushPlatform::from_storage_byte(bytes[0])?;
    let updated_at_secs = u64::from_be_bytes(bytes[1..9].try_into().expect("checked length"));
    let token = std::str::from_utf8(&bytes[VALUE_HEADER_LEN..])
        .context("stored push token is not valid UTF-8")?
        .to_string();
    Ok(StoredPushToken {
        device_id: device,
        platform,
        token,
        updated_at_secs,
    })
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn user(seed: u8) -> UserId {
        [seed; 32]
    }

    fn temp_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("trust_push_tokens_{label}_{nanos}"));
        path.to_string_lossy().into_owned()
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_dir_all(path);
    }

    fn open_store(label: &str) -> (Db, PushTokenStore, String) {
        let path = temp_path(label);
        let db = sled::open(&path).unwrap();
        let store = PushTokenStore::open(&db).unwrap();
        (db, store, path)
    }

    #[test]
    fn add_then_get_returns_stored_token() {
        let (_db, store, path) = open_store("add_get");
        assert!(
            store
                .add(&user(1), 7, PushPlatform::AndroidFcm, "fcm-token-A")
                .unwrap()
        );

        let got = store.get(&user(1), 7).unwrap().unwrap();
        assert_eq!(got.device_id, 7);
        assert_eq!(got.platform, PushPlatform::AndroidFcm);
        assert_eq!(got.token, "fcm-token-A");
        assert!(got.updated_at_secs > 0);
        cleanup(&path);
    }

    #[test]
    fn add_rejects_empty_and_oversized_tokens() {
        let (_db, store, path) = open_store("validate");
        assert!(
            !store
                .add(&user(1), 1, PushPlatform::AndroidFcm, "")
                .unwrap()
        );
        let huge = "a".repeat(MAX_TOKEN_LEN + 1);
        assert!(
            !store
                .add(&user(1), 1, PushPlatform::AndroidFcm, &huge)
                .unwrap()
        );
        cleanup(&path);
    }

    #[test]
    fn remove_is_idempotent() {
        let (_db, store, path) = open_store("remove");
        assert!(!store.remove(&user(1), 1).unwrap());

        store.add(&user(1), 1, PushPlatform::IosFcm, "t").unwrap();
        assert!(store.remove(&user(1), 1).unwrap());
        assert!(!store.remove(&user(1), 1).unwrap());
        assert!(store.get(&user(1), 1).unwrap().is_none());
        cleanup(&path);
    }

    #[test]
    fn list_user_returns_all_devices_of_one_user_only() {
        let (_db, store, path) = open_store("list_user");
        store
            .add(&user(1), 1, PushPlatform::AndroidFcm, "a1")
            .unwrap();
        store.add(&user(1), 2, PushPlatform::IosFcm, "a2").unwrap();
        store
            .add(&user(2), 1, PushPlatform::AndroidFcm, "b1")
            .unwrap();

        let listed = store.list_user(&user(1)).unwrap();
        assert_eq!(listed.len(), 2);
        let mut tokens: Vec<_> = listed.iter().map(|t| t.token.as_str()).collect();
        tokens.sort();
        assert_eq!(tokens, vec!["a1", "a2"]);
        cleanup(&path);
    }

    #[test]
    fn replace_overwrites_existing_token() {
        let (_db, store, path) = open_store("replace");
        store
            .add(&user(1), 1, PushPlatform::AndroidFcm, "old")
            .unwrap();
        store.add(&user(1), 1, PushPlatform::IosFcm, "new").unwrap();

        let got = store.get(&user(1), 1).unwrap().unwrap();
        assert_eq!(got.token, "new");
        assert_eq!(got.platform, PushPlatform::IosFcm);
        cleanup(&path);
    }

    #[test]
    fn has_any_for_user_flips_after_first_insert() {
        let (_db, store, path) = open_store("has_any");
        assert!(!store.has_any_for_user(&user(1)).unwrap());

        store
            .add(&user(1), 3, PushPlatform::AndroidFcm, "t")
            .unwrap();
        assert!(store.has_any_for_user(&user(1)).unwrap());
        // Distinct user remains untouched.
        assert!(!store.has_any_for_user(&user(2)).unwrap());

        store.remove(&user(1), 3).unwrap();
        assert!(!store.has_any_for_user(&user(1)).unwrap());
        cleanup(&path);
    }

    #[test]
    fn token_store_trait_resolve_and_remove() {
        use crate::push::TokenStore as _;
        let (_db, store, path) = open_store("trait_impl");
        store
            .add(&user(1), 4, PushPlatform::AndroidFcm, "tok")
            .unwrap();

        assert_eq!(store.resolve(&user(1), 4), Some("tok".to_string()));
        <PushTokenStore as crate::push::TokenStore>::remove(&store, &user(1), 4);
        assert_eq!(store.resolve(&user(1), 4), None);
        cleanup(&path);
    }

    #[test]
    fn voip_slot_is_independent_of_alert_slot() {
        let (_db, store, path) = open_store("voip_slot");
        store
            .add(&user(1), 7, PushPlatform::IosFcm, "fcm-tok")
            .unwrap();
        store
            .add(&user(1), 7, PushPlatform::IosVoip, "voip-tok")
            .unwrap();

        // Оба слота живут одновременно, не перетирая друг друга.
        assert_eq!(store.get(&user(1), 7).unwrap().unwrap().token, "fcm-tok");
        let voip = store.get_voip(&user(1), 7).unwrap().unwrap();
        assert_eq!(voip.token, "voip-tok");
        assert_eq!(voip.platform, PushPlatform::IosVoip);

        // Снятие alert-слота не трогает voip и наоборот.
        assert!(store.remove(&user(1), 7).unwrap());
        assert_eq!(
            store.get_voip(&user(1), 7).unwrap().unwrap().token,
            "voip-tok"
        );
        assert!(store.remove_voip(&user(1), 7).unwrap());
        assert!(store.get_voip(&user(1), 7).unwrap().is_none());
        cleanup(&path);
    }

    #[test]
    fn list_user_skips_voip_rows() {
        let (_db, store, path) = open_store("list_skips_voip");
        store.add(&user(1), 1, PushPlatform::IosFcm, "fcm").unwrap();
        store
            .add(&user(1), 1, PushPlatform::IosVoip, "voip")
            .unwrap();
        store
            .add(&user(1), 2, PushPlatform::IosVoip, "voip-only")
            .unwrap();

        // Fan-out видит только alert-слоты; voip-only девайс не попадает в
        // список (его будит APNs voip напрямую, не FCM).
        let listed = store.list_user(&user(1)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].token, "fcm");
        cleanup(&path);
    }

    #[test]
    fn remove_all_clears_both_slots() {
        let (_db, store, path) = open_store("remove_all");
        assert!(!store.remove_all(&user(1), 9).unwrap());

        store.add(&user(1), 9, PushPlatform::IosFcm, "fcm").unwrap();
        store
            .add(&user(1), 9, PushPlatform::IosVoip, "voip")
            .unwrap();
        assert!(store.remove_all(&user(1), 9).unwrap());
        assert!(store.get(&user(1), 9).unwrap().is_none());
        assert!(store.get_voip(&user(1), 9).unwrap().is_none());
        cleanup(&path);
    }

    #[test]
    fn token_store_trait_voip_resolve_and_remove() {
        use crate::push::TokenStore as _;
        let (_db, store, path) = open_store("trait_voip");
        store
            .add(&user(1), 4, PushPlatform::IosVoip, "vtok")
            .unwrap();

        assert_eq!(store.resolve_voip(&user(1), 4), Some("vtok".to_string()));
        assert_eq!(store.resolve(&user(1), 4), None);
        <PushTokenStore as crate::push::TokenStore>::remove_voip(&store, &user(1), 4);
        assert_eq!(store.resolve_voip(&user(1), 4), None);
        cleanup(&path);
    }
}
