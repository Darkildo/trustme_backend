use anyhow::{Context, Result, bail};
use sled::{Db, Tree};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::domain::push::PushPlatform;
use crate::state::registry::{DeviceId, UserId};

/// Sanity cap on a stored token. FCM tokens are not validated beyond being
/// non-empty and under this cap; real FCM tokens are a few hundred bytes.
/// VoIP tokens must additionally be hex (see [`normalize_token`]).
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
    /// Дерево `push_welcome_claims`: `user_id(32)` → `claimed_at_secs(u64 BE)`.
    /// Отдельное, а не префикс в `device_push_tokens`: скан токенов по
    /// префиксу `user_id` не должен натыкаться на ключи другого формата.
    welcome_claims: Tree,
}

/// Исход [`PushTokenStore::register`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// Токен записан — новый или поверх прежнего того же слота.
    Stored,
    /// Токен не прошёл проверку формата.
    InvalidToken,
    /// Устройство новое, а потолок устройств с токенами уже выбран.
    DeviceLimit,
}

impl PushTokenStore {
    pub fn open(db: &Db) -> Result<Self> {
        let tree = db
            .open_tree("device_push_tokens")
            .context("failed to open `device_push_tokens` tree")?;
        let welcome_claims = db
            .open_tree("push_welcome_claims")
            .context("failed to open `push_welcome_claims` tree")?;
        Ok(Self {
            tree,
            welcome_claims,
        })
    }

    /// Insert or replace the token for `(user, device)`. `IosVoip` goes to the
    /// VoIP slot, every other platform to the alert slot. Returns `Ok(false)`
    /// if the token is invalid (see [`normalize_token`]); the caller answers
    /// the client with a negative push-token ack.
    pub fn add(
        &self,
        user: &UserId,
        device: DeviceId,
        platform: PushPlatform,
        token: &str,
    ) -> Result<bool> {
        let Some(token) = normalize_token(platform, token) else {
            return Ok(false);
        };

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

    /// Регистрация токена с клиентского соединения: [`Self::add`] плюс
    /// потолок устройств с токенами на пользователя (`max_devices`, `0` — без
    /// потолка). Устройство, у которого уже есть токен в любом из слотов,
    /// потолком не ограничено: смена токена — обычная жизнь клиента.
    ///
    /// Подсчёт и запись не атомарны: две параллельные регистрации новых
    /// устройств могут превысить потолок на одно. Как и прочие лимиты ноды,
    /// это защита ресурса, а не бухгалтерия.
    pub fn register(
        &self,
        user: &UserId,
        device: DeviceId,
        platform: PushPlatform,
        token: &str,
        max_devices: usize,
    ) -> Result<RegisterOutcome> {
        if normalize_token(platform, token).is_none() {
            return Ok(RegisterOutcome::InvalidToken);
        }
        if max_devices > 0 {
            let census = self.device_census(user, device)?;
            if !census.includes_device && census.devices >= max_devices {
                return Ok(RegisterOutcome::DeviceLimit);
            }
        }
        if self.add(user, device, platform, token)? {
            Ok(RegisterOutcome::Stored)
        } else {
            Ok(RegisterOutcome::InvalidToken)
        }
    }

    /// Сколько разных устройств пользователя держат хотя бы один токен и
    /// есть ли среди них `device`. Ключи обоих слотов одного устройства
    /// лежат в дереве подряд (`user || device` и `user || device || 0x01`),
    /// поэтому новое устройство видно по смене `device` между соседними
    /// ключами.
    fn device_census(&self, user: &UserId, device: DeviceId) -> Result<DeviceCensus> {
        let prefix = user.as_slice();
        let mut census = DeviceCensus {
            devices: 0,
            includes_device: false,
        };
        let mut previous: Option<DeviceId> = None;
        for key in self.tree.scan_prefix(prefix).keys() {
            let key = key.context("failed to scan push token tree")?;
            let Some(&[high, low]) = key.get(prefix.len()..prefix.len() + 2) else {
                continue;
            };
            let current = u16::from_be_bytes([high, low]);
            if previous != Some(current) {
                census.devices += 1;
                previous = Some(current);
            }
            census.includes_device |= current == device;
        }
        Ok(census)
    }

    /// Отметить, что аккаунту положено приветствие. `true` возвращается
    /// ровно один раз за всё время жизни аккаунта — первому вызову, дальше
    /// всегда `false`. Отметка живёт отдельно от токенов и переживает их
    /// снятие: иначе цикл Register/Unregister выдавал бы приветствие на
    /// каждом круге.
    pub fn claim_welcome(&self, user: &UserId) -> Result<bool> {
        let claimed_at = now_secs()?.to_be_bytes();
        let swapped = self
            .welcome_claims
            .compare_and_swap(user, None::<&[u8]>, Some(&claimed_at[..]))
            .context("failed to write welcome claim")?;
        Ok(swapped.is_ok())
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

    /// Does this user have any push token row (either slot)? Stops at the
    /// first row without decoding it. Together with [`Self::claim_welcome`]
    /// it gates the one-shot welcome push: an account that held tokens before
    /// welcome claims existed gets its claim without being greeted.
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
            // Строка могла быть записана до проверки формата: не-hex токен в
            // путь запроса APNs не отдаётся.
            Ok(Some(stored)) if !is_hex_token(&stored.token) => {
                warn!(
                    user = %hex::encode(user),
                    device,
                    "stored voip push token is not hex; treating as missing"
                );
                None
            }
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

/// Результат [`PushTokenStore::device_census`].
struct DeviceCensus {
    devices: usize,
    includes_device: bool,
}

/// Токен, пригодный к записи: без пробелов по краям, непустой, не длиннее
/// `MAX_TOKEN_LEN`. VoIP-токен APNs подставляется в путь запроса
/// (`/3/device/{token}`), поэтому для него допустим только hex — иначе `/`,
/// `?` или `#` в токене меняли бы адрес запроса.
fn normalize_token(platform: PushPlatform, token: &str) -> Option<&str> {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return None;
    }
    if platform == PushPlatform::IosVoip && !is_hex_token(token) {
        return None;
    }
    Some(token)
}

/// Hex-запись байтов: непустая, чётной длины, только `[0-9a-fA-F]`.
fn is_hex_token(token: &str) -> bool {
    !token.is_empty()
        && token.len().is_multiple_of(2)
        && token.bytes().all(|b| b.is_ascii_hexdigit())
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
            .add(&user(1), 7, PushPlatform::IosVoip, "a0b1c2d3")
            .unwrap();

        // Оба слота живут одновременно, не перетирая друг друга.
        assert_eq!(store.get(&user(1), 7).unwrap().unwrap().token, "fcm-tok");
        let voip = store.get_voip(&user(1), 7).unwrap().unwrap();
        assert_eq!(voip.token, "a0b1c2d3");
        assert_eq!(voip.platform, PushPlatform::IosVoip);

        // Снятие alert-слота не трогает voip и наоборот.
        assert!(store.remove(&user(1), 7).unwrap());
        assert_eq!(
            store.get_voip(&user(1), 7).unwrap().unwrap().token,
            "a0b1c2d3"
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
            .add(&user(1), 1, PushPlatform::IosVoip, "beef")
            .unwrap();
        store
            .add(&user(1), 2, PushPlatform::IosVoip, "c0ffee")
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
            .add(&user(1), 9, PushPlatform::IosVoip, "beef")
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
            .add(&user(1), 4, PushPlatform::IosVoip, "0f1e2d3c")
            .unwrap();

        assert_eq!(
            store.resolve_voip(&user(1), 4),
            Some("0f1e2d3c".to_string())
        );
        assert_eq!(store.resolve(&user(1), 4), None);
        <PushTokenStore as crate::push::TokenStore>::remove_voip(&store, &user(1), 4);
        assert_eq!(store.resolve_voip(&user(1), 4), None);
        cleanup(&path);
    }

    /// VoIP-токен уходит в путь запроса APNs: всё, что не hex, — отказ, а
    /// не запись. Alert-слот (FCM) этим правилом не ограничен.
    #[test]
    fn voip_token_must_be_hex() {
        let (_db, store, path) = open_store("voip_hex");
        for bad in [
            "../../3/device/x",
            "abc?x=1",
            "beef#",
            "not-hex",
            "abc",
            "ab cd",
        ] {
            assert!(
                !store.add(&user(1), 1, PushPlatform::IosVoip, bad).unwrap(),
                "{bad:?} must be rejected"
            );
        }
        assert!(store.get_voip(&user(1), 1).unwrap().is_none());

        assert!(
            store
                .add(
                    &user(1),
                    1,
                    PushPlatform::IosVoip,
                    " 0123456789abcdefABCDEF00 "
                )
                .unwrap()
        );
        assert_eq!(
            store.get_voip(&user(1), 1).unwrap().unwrap().token,
            "0123456789abcdefABCDEF00"
        );
        assert!(
            store
                .add(
                    &user(1),
                    1,
                    PushPlatform::IosFcm,
                    "fcm:token/with-slashes_ok"
                )
                .unwrap()
        );
        cleanup(&path);
    }

    /// Строка, записанная до проверки формата, в путь APNs не попадает.
    #[test]
    fn resolve_voip_skips_legacy_non_hex_rows() {
        use crate::push::TokenStore as _;
        let (_db, store, path) = open_store("voip_legacy");
        store
            .tree
            .insert(
                make_voip_key(&user(1), 2),
                encode_value(PushPlatform::IosVoip, 1, "x/../evil"),
            )
            .unwrap();
        assert_eq!(store.resolve_voip(&user(1), 2), None);
        cleanup(&path);
    }

    #[test]
    fn register_enforces_device_ceiling_but_allows_updates() {
        let (_db, store, path) = open_store("device_ceiling");
        let max = 2;
        assert_eq!(
            store
                .register(&user(1), 1, PushPlatform::AndroidFcm, "a", max)
                .unwrap(),
            RegisterOutcome::Stored
        );
        // Второй слот того же устройства — не новое устройство.
        assert_eq!(
            store
                .register(&user(1), 1, PushPlatform::IosVoip, "beef", max)
                .unwrap(),
            RegisterOutcome::Stored
        );
        // VoIP-only устройство считается наравне с прочими.
        assert_eq!(
            store
                .register(&user(1), 2, PushPlatform::IosVoip, "c0ffee", max)
                .unwrap(),
            RegisterOutcome::Stored
        );
        assert_eq!(
            store
                .register(&user(1), 3, PushPlatform::AndroidFcm, "c", max)
                .unwrap(),
            RegisterOutcome::DeviceLimit
        );
        assert!(store.get(&user(1), 3).unwrap().is_none());

        // Обновление известного устройства проходит и на выбранном потолке.
        assert_eq!(
            store
                .register(&user(1), 2, PushPlatform::IosFcm, "b2", max)
                .unwrap(),
            RegisterOutcome::Stored
        );
        assert_eq!(
            store
                .register(&user(1), 1, PushPlatform::AndroidFcm, "a2", max)
                .unwrap(),
            RegisterOutcome::Stored
        );
        assert_eq!(store.get(&user(1), 1).unwrap().unwrap().token, "a2");

        // Чужой аккаунт потолок не делит.
        assert_eq!(
            store
                .register(&user(2), 3, PushPlatform::AndroidFcm, "z", max)
                .unwrap(),
            RegisterOutcome::Stored
        );

        // Снятое устройство освобождает место.
        store.remove_all(&user(1), 2).unwrap();
        assert_eq!(
            store
                .register(&user(1), 3, PushPlatform::AndroidFcm, "c", max)
                .unwrap(),
            RegisterOutcome::Stored
        );
        cleanup(&path);
    }

    #[test]
    fn register_without_ceiling_and_with_invalid_token() {
        let (_db, store, path) = open_store("register_misc");
        for device in 0..50u16 {
            assert_eq!(
                store
                    .register(&user(1), device, PushPlatform::AndroidFcm, "t", 0)
                    .unwrap(),
                RegisterOutcome::Stored
            );
        }
        assert_eq!(
            store
                .register(&user(1), 99, PushPlatform::IosVoip, "not-hex", 0)
                .unwrap(),
            RegisterOutcome::InvalidToken
        );
        assert_eq!(
            store
                .register(&user(1), 99, PushPlatform::AndroidFcm, "  ", 0)
                .unwrap(),
            RegisterOutcome::InvalidToken
        );
        cleanup(&path);
    }

    /// Приветствие — одно на аккаунт навсегда: снятие токенов отметку не
    /// сбрасывает, и она переживает переоткрытие базы.
    #[test]
    fn claim_welcome_is_granted_once_per_account() {
        let path = temp_path("welcome_claim");
        {
            let db = sled::open(&path).unwrap();
            let store = PushTokenStore::open(&db).unwrap();
            assert!(store.claim_welcome(&user(1)).unwrap());
            assert!(!store.claim_welcome(&user(1)).unwrap());

            store
                .add(&user(1), 1, PushPlatform::AndroidFcm, "t")
                .unwrap();
            store.remove_all(&user(1), 1).unwrap();
            assert!(!store.claim_welcome(&user(1)).unwrap());

            // Отметка не попадает в дерево токенов.
            assert!(!store.has_any_for_user(&user(1)).unwrap());
            assert!(store.list_user(&user(1)).unwrap().is_empty());

            assert!(store.claim_welcome(&user(2)).unwrap());
            db.flush().unwrap();
        }
        let db = sled::open(&path).unwrap();
        let store = PushTokenStore::open(&db).unwrap();
        assert!(!store.claim_welcome(&user(1)).unwrap());
        assert!(!store.claim_welcome(&user(2)).unwrap());
        drop(store);
        drop(db);
        cleanup(&path);
    }
}
