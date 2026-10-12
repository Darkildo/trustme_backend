//! Отзывы сертификатов устройств.
//!
//! Сертификат устройства открывает делегированную сессию «как это
//! устройство» до своего `not_after`. Украденный вместе с запертым
//! телефоном сертификат давал бы вору выгребать офлайн-очередь устройства и
//! account-scope входящие аккаунта. Отзыв закрывает это: владелец с другого
//! своего устройства просит ноду «не пускать делегированно устройство
//! `device_id` по сертификатам, выписанным раньше момента T» — то есть с
//! `not_before < issued_before`.
//!
//! Дерево `device_cert_revocations`: `owner(32) ‖ device_id(u16 BE)` →
//! `issued_before(u64 BE)`. Хранится максимум: более ранний отзыв ничего не
//! добавляет к более позднему.
//!
//! Отзыв устаревает: сертификат с `not_before < issued_before` истекает не
//! позже `issued_before + max_ttl` (потолок срока сертификата на ноде), так
//! что после `issued_before + max_ttl + NOT_BEFORE_SKEW_SECS` отзыву нечего
//! запрещать. Устаревшие записи удаляются лениво — при записи отзыва и при
//! перечислении. Если оператор потом поднимет потолок срока, удалённый по
//! старому потолку отзыв не вернётся (известное ограничение, контракт
//! §6.10).

use anyhow::{Context, Result};
use sled::transaction::TransactionError;
use sled::{Db, Tree};

use crate::net::device_cert::NOT_BEFORE_SKEW_SECS;
use crate::state::registry::{DeviceId, UserId};

/// Потолок действующих отзывов на пользователя. Клиент держит не больше
/// восьми устройств, так что потолок — защита ресурса ноды, а не
/// ограничение для честного клиента. Действующие отзывы при переполнении не
/// вытесняются: вытеснение вернуло бы вход украденному сертификату.
pub const MAX_DEVICE_CERT_REVOCATIONS_PER_USER: usize = 256;

const KEY_LEN: usize = 34;

/// Почему отзыв не записан.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationError {
    /// Негодные параметры: `device_id` вне u16, `issued_before = 0` или
    /// дальше `now + NOT_BEFORE_SKEW_SECS`.
    Invalid,
    /// Действующих отзывов у пользователя уже `MAX_…` и устаревших нет.
    Limit,
}

/// Действующий отзыв: делегированный вход устройства по сертификату с
/// `not_before < issued_before` запрещён.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceCertRevocation {
    pub device_id: DeviceId,
    pub issued_before: u64,
}

/// Проверить сырые поля `RevokeDeviceCerts`. `issued_before` в будущем
/// допускается в пределах того же допуска на часы, что и `not_before`
/// сертификата: клиент ставит «сейчас» по своим часам.
pub fn validate(
    device_id: u32,
    issued_before: u64,
    now_secs: u64,
) -> Result<DeviceCertRevocation, RevocationError> {
    let device_id = DeviceId::try_from(device_id).map_err(|_| RevocationError::Invalid)?;
    if issued_before == 0 || issued_before > now_secs.saturating_add(NOT_BEFORE_SKEW_SECS) {
        return Err(RevocationError::Invalid);
    }
    Ok(DeviceCertRevocation {
        device_id,
        issued_before,
    })
}

/// Отзыв больше ничего не запрещает: любой сертификат, который он
/// закрывал, уже истёк сам.
fn is_stale(issued_before: u64, now_secs: u64, max_ttl_secs: u64) -> bool {
    now_secs
        > issued_before
            .saturating_add(max_ttl_secs)
            .saturating_add(NOT_BEFORE_SKEW_SECS)
}

#[derive(Clone)]
pub struct CertRevocationStore {
    tree: Tree,
}

impl CertRevocationStore {
    pub fn open(db: &Db) -> Result<Self> {
        Ok(Self {
            tree: db
                .open_tree("device_cert_revocations")
                .context("failed to open `device_cert_revocations` tree")?,
        })
    }

    /// Записать отзыв (максимум из хранимого и нового — одной транзакцией).
    /// Перед проверкой потолка устаревшие отзывы владельца удаляются.
    /// Повтор и более ранний `issued_before` — успех без изменений.
    pub fn revoke(
        &self,
        owner: &UserId,
        revocation: DeviceCertRevocation,
        now_secs: u64,
        max_ttl_secs: u64,
    ) -> Result<Result<(), RevocationError>> {
        let active = self.purge_stale(owner, now_secs, max_ttl_secs)?;
        let key = compose_key(owner, revocation.device_id);
        let value = revocation.issued_before.to_be_bytes();
        let limit_reached = active.len() >= MAX_DEVICE_CERT_REVOCATIONS_PER_USER;

        let outcome: Result<bool, TransactionError> =
            self.tree.transaction(
                |tree| match tree.get(&key[..])?.map(|raw| decode_u64(&raw)) {
                    Some(current) if current >= revocation.issued_before => Ok(true),
                    Some(_) => {
                        tree.insert(&key[..], &value[..])?;
                        Ok(true)
                    }
                    None if limit_reached => Ok(false),
                    None => {
                        tree.insert(&key[..], &value[..])?;
                        Ok(true)
                    }
                },
            );
        if outcome.context("failed to store the device certificate revocation")? {
            Ok(Ok(()))
        } else {
            Ok(Err(RevocationError::Limit))
        }
    }

    /// `issued_before` действующего отзыва устройства, если он есть. Одно
    /// чтение на каждый делегированный вход; устаревание здесь не
    /// проверяется — устаревший отзыв не запрещает ничего, что не запретил
    /// бы срок самого сертификата.
    pub fn revoked_since(&self, owner: &UserId, device_id: DeviceId) -> Result<Option<u64>> {
        Ok(self
            .tree
            .get(&compose_key(owner, device_id)[..])
            .context("failed to read the device certificate revocation")?
            .map(|raw| decode_u64(&raw)))
    }

    /// Действующие отзывы владельца, по `device_id`. Устаревшие попутно
    /// удаляются и не отдаются.
    pub fn list(
        &self,
        owner: &UserId,
        now_secs: u64,
        max_ttl_secs: u64,
    ) -> Result<Vec<DeviceCertRevocation>> {
        self.purge_stale(owner, now_secs, max_ttl_secs)
    }

    /// Удалить устаревшие отзывы владельца; вернуть оставшиеся.
    fn purge_stale(
        &self,
        owner: &UserId,
        now_secs: u64,
        max_ttl_secs: u64,
    ) -> Result<Vec<DeviceCertRevocation>> {
        let mut active = Vec::new();
        for item in self.tree.scan_prefix(&owner[..]) {
            let (key, value) = item.context("failed to scan device certificate revocations")?;
            let Some(device_id) = device_id_of(&key) else {
                continue;
            };
            let issued_before = decode_u64(&value);
            if is_stale(issued_before, now_secs, max_ttl_secs) {
                // Удаляется только то самое значение: параллельный отзыв
                // мог успеть поднять `issued_before`.
                let _ = self
                    .tree
                    .compare_and_swap(&key, Some(value), None::<&[u8]>)
                    .context("failed to remove a stale device certificate revocation")?;
                continue;
            }
            active.push(DeviceCertRevocation {
                device_id,
                issued_before,
            });
        }
        Ok(active)
    }
}

fn compose_key(owner: &UserId, device_id: DeviceId) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..32].copy_from_slice(owner);
    key[32..].copy_from_slice(&device_id.to_be_bytes());
    key
}

fn device_id_of(key: &[u8]) -> Option<DeviceId> {
    if key.len() != KEY_LEN {
        return None;
    }
    Some(DeviceId::from_be_bytes([key[32], key[33]]))
}

fn decode_u64(raw: &[u8]) -> u64 {
    raw.try_into().map(u64::from_be_bytes).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: UserId = [1u8; 32];
    const BOB: UserId = [2u8; 32];
    const NOW: u64 = 1_000_000;
    const TTL: u64 = 30 * 24 * 3600;

    fn store() -> CertRevocationStore {
        let db = sled::Config::new().temporary(true).open().unwrap();
        CertRevocationStore::open(&db).unwrap()
    }

    fn rev(device_id: DeviceId, issued_before: u64) -> DeviceCertRevocation {
        DeviceCertRevocation {
            device_id,
            issued_before,
        }
    }

    #[test]
    fn validation() {
        assert_eq!(validate(7, NOW, NOW), Ok(rev(7, NOW)));
        assert_eq!(
            validate(7, NOW + NOT_BEFORE_SKEW_SECS, NOW),
            Ok(rev(7, NOW + NOT_BEFORE_SKEW_SECS))
        );
        assert_eq!(validate(65_535, 1, NOW), Ok(rev(65_535, 1)));
        assert_eq!(validate(65_536, NOW, NOW), Err(RevocationError::Invalid));
        assert_eq!(validate(7, 0, NOW), Err(RevocationError::Invalid));
        assert_eq!(
            validate(7, NOW + NOT_BEFORE_SKEW_SECS + 1, NOW),
            Err(RevocationError::Invalid)
        );
    }

    #[test]
    fn the_stored_value_is_the_maximum() {
        let store = store();
        assert_eq!(store.revoked_since(&ALICE, 7).unwrap(), None);
        store
            .revoke(&ALICE, rev(7, NOW), NOW, TTL)
            .unwrap()
            .unwrap();
        assert_eq!(store.revoked_since(&ALICE, 7).unwrap(), Some(NOW));
        // Более ранний не уменьшает, повтор идемпотентен.
        store
            .revoke(&ALICE, rev(7, NOW - 50), NOW, TTL)
            .unwrap()
            .unwrap();
        store
            .revoke(&ALICE, rev(7, NOW), NOW, TTL)
            .unwrap()
            .unwrap();
        assert_eq!(store.revoked_since(&ALICE, 7).unwrap(), Some(NOW));
        // Более поздний заменяет.
        store
            .revoke(&ALICE, rev(7, NOW + 10), NOW, TTL)
            .unwrap()
            .unwrap();
        assert_eq!(store.revoked_since(&ALICE, 7).unwrap(), Some(NOW + 10));
        assert_eq!(
            store.list(&ALICE, NOW, TTL).unwrap(),
            vec![rev(7, NOW + 10)]
        );
    }

    #[test]
    fn revocations_are_per_user_and_per_device() {
        let store = store();
        store
            .revoke(&ALICE, rev(7, NOW), NOW, TTL)
            .unwrap()
            .unwrap();
        assert_eq!(store.revoked_since(&ALICE, 8).unwrap(), None);
        assert_eq!(store.revoked_since(&BOB, 7).unwrap(), None);
        assert!(store.list(&BOB, NOW, TTL).unwrap().is_empty());
    }

    #[test]
    fn stale_revocations_are_dropped_and_not_listed() {
        let store = store();
        store
            .revoke(&ALICE, rev(1, NOW), NOW, TTL)
            .unwrap()
            .unwrap();
        store
            .revoke(&ALICE, rev(2, NOW + 100), NOW, TTL)
            .unwrap()
            .unwrap();
        // На самой границе отзыв ещё действует.
        let edge = NOW + TTL + NOT_BEFORE_SKEW_SECS;
        assert_eq!(store.list(&ALICE, edge, TTL).unwrap().len(), 2);
        // Секундой позже первый устарел: удалён, второй остался.
        assert_eq!(
            store.list(&ALICE, edge + 1, TTL).unwrap(),
            vec![rev(2, NOW + 100)]
        );
        assert_eq!(store.revoked_since(&ALICE, 1).unwrap(), None);
    }

    #[test]
    fn the_cap_refuses_new_devices_but_never_evicts() {
        let store = store();
        for device in 0..MAX_DEVICE_CERT_REVOCATIONS_PER_USER as u16 {
            store
                .revoke(&ALICE, rev(device, NOW), NOW, TTL)
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            store.revoke(&ALICE, rev(9_999, NOW), NOW, TTL).unwrap(),
            Err(RevocationError::Limit)
        );
        // Действующие на месте, существующее устройство можно поднять.
        assert_eq!(store.revoked_since(&ALICE, 0).unwrap(), Some(NOW));
        store
            .revoke(&ALICE, rev(0, NOW + 1), NOW, TTL)
            .unwrap()
            .unwrap();
        // Потолок чужой.
        store
            .revoke(&BOB, rev(9_999, NOW), NOW, TTL)
            .unwrap()
            .unwrap();

        // Устаревшие вычищаются перед проверкой потолка.
        let later = NOW + TTL + NOT_BEFORE_SKEW_SECS + 1;
        store
            .revoke(&ALICE, rev(9_999, later), later, TTL)
            .unwrap()
            .unwrap();
        // Устройство 0 (поднято до NOW + 1) на границе ещё действует.
        assert_eq!(
            store.list(&ALICE, later, TTL).unwrap(),
            vec![rev(0, NOW + 1), rev(9_999, later)]
        );
    }

    #[test]
    fn zero_ttl_still_stores_revocations() {
        let store = store();
        store.revoke(&ALICE, rev(3, NOW), NOW, 0).unwrap().unwrap();
        assert_eq!(store.list(&ALICE, NOW, 0).unwrap(), vec![rev(3, NOW)]);
        assert!(
            store
                .list(&ALICE, NOW + NOT_BEFORE_SKEW_SECS + 1, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn revocations_survive_reopening_the_database() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("trust_cert_revocations_{nanos}"));
        {
            let db = sled::open(&path).unwrap();
            let store = CertRevocationStore::open(&db).unwrap();
            store
                .revoke(&ALICE, rev(4, NOW), NOW, TTL)
                .unwrap()
                .unwrap();
        }
        let db = sled::open(&path).unwrap();
        let store = CertRevocationStore::open(&db).unwrap();
        assert_eq!(store.revoked_since(&ALICE, 4).unwrap(), Some(NOW));
        drop(store);
        drop(db);
        let _ = std::fs::remove_dir_all(&path);
    }
}
