//! Формат записей дерева `blobs` и ключей его индексов.
//!
//! Все целые — big-endian. Запись начинается с версии формата (сейчас 1) и
//! вида:
//!
//! - живой блоб (`UPLOADING` = 1, `READY` = 2): `flags(u8)` (бит 0 —
//!   есть очередь) ‖ `queue_id(32)`, если бит стоит ‖ `owner(32)` ‖
//!   `uploader(32)` ‖ `size(u64)` ‖ `sha256(32)` ‖ `delete_token_hash(32)` ‖
//!   `max_releases(u32)` ‖ `created_at(u64)` ‖ `ttl_secs(u64)` ‖
//!   `expires_at(u64)` ‖ `committed_offset(u64)` ‖ `last_activity(u64)` ‖
//!   `released(u16)` ‖ по `user(32) ‖ has_device(u8) ‖ device(u16)` на
//!   каждое отпустившее устройство;
//! - надгробие (`EXPIRED` = 3, `DELETED` = 4): `at(u64)` ‖ `until(u64)` ‖
//!   `delete_token_hash(32)`. Ни размера, ни участников: надгробие нужно
//!   только чтобы отличить «истёк» и «отозван» от «не было».
//!
//! Индекс `blob_expiry`: `due_at(u64)` ‖ `blob_id(32)` → пусто. Срок у
//! каждой записи один (см. [`BlobRecord::due_at`]), поэтому один индекс
//! ведёт и истечение, и протухшие загрузки, и надгробия.

use crate::state::registry::{DeviceId, UserId};

use super::BlobId;

const FORMAT_V1: u8 = 1;
const KIND_UPLOADING: u8 = 1;
const KIND_READY: u8 = 2;
const KIND_EXPIRED: u8 = 3;
const KIND_DELETED: u8 = 4;
const FLAG_QUEUE: u8 = 1;

/// Устройство, отпустившее блоб. Сессия без `device_id` — отдельное
/// «устройство» своего аккаунта.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Releaser {
    pub user: UserId,
    pub device: Option<DeviceId>,
}

/// Блоб в работе: загружается (`ready = false`) или готов.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveBlob {
    pub ready: bool,
    /// `Some` — личный файл (scope RECIPIENT), положенный по этой очереди.
    pub queue_id: Option<[u8; 32]>,
    /// Чья квота: владелец очереди или загрузивший (scope OWN).
    pub owner: UserId,
    pub uploader: UserId,
    pub size: u64,
    pub sha256: [u8; 32],
    pub delete_token_hash: [u8; 32],
    pub max_releases: u32,
    pub released_by: Vec<Releaser>,
    pub created_at: u64,
    /// Срок после `Commit`, уже зажатый потолком.
    pub ttl_secs: u64,
    /// У готового — когда истекает; у загружаемого — 0.
    pub expires_at: u64,
    /// Сколько байт загрузки сброшено на диск.
    pub committed_offset: u64,
    /// Последний сброс загрузки на диск (или `Init`).
    pub last_activity: u64,
}

impl LiveBlob {
    /// Своя загрузка (scope OWN): владелец квоты — сам загрузивший.
    pub fn is_own(&self) -> bool {
        self.queue_id.is_none()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombCause {
    Expired,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    pub cause: TombCause,
    pub at: u64,
    /// До какого момента надгробие помнится.
    pub until: u64,
    /// Для идемпотентного повтора `BlobDelete` верным токеном.
    pub delete_token_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobRecord {
    Live(LiveBlob),
    Tomb(Tombstone),
}

impl BlobRecord {
    /// Момент, когда записью должна заняться чистка: истечение готового,
    /// протухание загрузки, конец памяти надгробия.
    pub fn due_at(&self, upload_stale_secs: u64) -> u64 {
        match self {
            Self::Live(live) if live.ready => live.expires_at,
            Self::Live(live) => live.last_activity.saturating_add(upload_stale_secs),
            Self::Tomb(tomb) => tomb.until,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.push(FORMAT_V1);
        match self {
            Self::Live(live) => {
                out.push(if live.ready {
                    KIND_READY
                } else {
                    KIND_UPLOADING
                });
                match &live.queue_id {
                    Some(queue_id) => {
                        out.push(FLAG_QUEUE);
                        out.extend_from_slice(queue_id);
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(&live.owner);
                out.extend_from_slice(&live.uploader);
                out.extend_from_slice(&live.size.to_be_bytes());
                out.extend_from_slice(&live.sha256);
                out.extend_from_slice(&live.delete_token_hash);
                out.extend_from_slice(&live.max_releases.to_be_bytes());
                for value in [
                    live.created_at,
                    live.ttl_secs,
                    live.expires_at,
                    live.committed_offset,
                    live.last_activity,
                ] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                // Число отпустивших ограничено `MAX_RELEASES` (256) при
                // загрузке, поэтому u16 хватает с запасом.
                let released = u16::try_from(live.released_by.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&released.to_be_bytes());
                for releaser in live.released_by.iter().take(usize::from(released)) {
                    out.extend_from_slice(&releaser.user);
                    out.push(u8::from(releaser.device.is_some()));
                    out.extend_from_slice(&releaser.device.unwrap_or(0).to_be_bytes());
                }
            }
            Self::Tomb(tomb) => {
                out.push(match tomb.cause {
                    TombCause::Expired => KIND_EXPIRED,
                    TombCause::Deleted => KIND_DELETED,
                });
                out.extend_from_slice(&tomb.at.to_be_bytes());
                out.extend_from_slice(&tomb.until.to_be_bytes());
                out.extend_from_slice(&tomb.delete_token_hash);
            }
        }
        out
    }

    /// `None` — запись не разбирается (чужой формат или обрыв). Читатель
    /// обращается с ней как с отсутствующей, а сверка при старте её стирает.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let mut reader = Reader(raw);
        if reader.u8()? != FORMAT_V1 {
            return None;
        }
        let record = match reader.u8()? {
            kind @ (KIND_UPLOADING | KIND_READY) => {
                let queue_id = match reader.u8()? {
                    0 => None,
                    FLAG_QUEUE => Some(reader.array()?),
                    _ => return None,
                };
                let owner = reader.array()?;
                let uploader = reader.array()?;
                let size = reader.u64()?;
                let sha256 = reader.array()?;
                let delete_token_hash = reader.array()?;
                let max_releases = reader.u32()?;
                let created_at = reader.u64()?;
                let ttl_secs = reader.u64()?;
                let expires_at = reader.u64()?;
                let committed_offset = reader.u64()?;
                let last_activity = reader.u64()?;
                let released = reader.u16()?;
                let mut released_by = Vec::with_capacity(usize::from(released));
                for _ in 0..released {
                    let user = reader.array()?;
                    let has_device = reader.u8()?;
                    let device = reader.u16()?;
                    released_by.push(Releaser {
                        user,
                        device: (has_device != 0).then_some(device),
                    });
                }
                Self::Live(LiveBlob {
                    ready: kind == KIND_READY,
                    queue_id,
                    owner,
                    uploader,
                    size,
                    sha256,
                    delete_token_hash,
                    max_releases,
                    released_by,
                    created_at,
                    ttl_secs,
                    expires_at,
                    committed_offset,
                    last_activity,
                })
            }
            kind @ (KIND_EXPIRED | KIND_DELETED) => Self::Tomb(Tombstone {
                cause: if kind == KIND_EXPIRED {
                    TombCause::Expired
                } else {
                    TombCause::Deleted
                },
                at: reader.u64()?,
                until: reader.u64()?,
                delete_token_hash: reader.array()?,
            }),
            _ => return None,
        };
        reader.0.is_empty().then_some(record)
    }
}

/// Ключ индекса `blob_expiry`.
pub fn expiry_key(due_at: u64, id: &BlobId) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&due_at.to_be_bytes());
    key[8..].copy_from_slice(id);
    key
}

/// Разобрать ключ индекса `blob_expiry`.
pub fn parse_expiry_key(key: &[u8]) -> Option<(u64, BlobId)> {
    if key.len() != 40 {
        return None;
    }
    let mut due = [0u8; 8];
    due.copy_from_slice(&key[..8]);
    let mut id = [0u8; 32];
    id.copy_from_slice(&key[8..]);
    Some((u64::from_be_bytes(due), id))
}

/// Ключ счётчика `blob_usage`: всего на ящик или аккаунт владельца.
pub fn owner_usage_key(owner: &UserId) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = b'o';
    key[1..].copy_from_slice(owner);
    key
}

/// Ключ счётчика `blob_usage`: загружено одним пользователем в ящик
/// другого (аналог под-квоты пары SEC-43).
pub fn pair_usage_key(owner: &UserId, uploader: &UserId) -> [u8; 65] {
    let mut key = [0u8; 65];
    key[0] = b'p';
    key[1..33].copy_from_slice(owner);
    key[33..].copy_from_slice(uploader);
    key
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Option<&[u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|bytes| {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(bytes);
            u32::from_be_bytes(raw)
        })
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|bytes| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(bytes);
            u64::from_be_bytes(raw)
        })
    }

    fn array(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|bytes| {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(bytes);
            raw
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(ready: bool, queue: bool) -> LiveBlob {
        LiveBlob {
            ready,
            queue_id: queue.then_some([9u8; 32]),
            owner: [1u8; 32],
            uploader: [2u8; 32],
            size: 40_000_000,
            sha256: [3u8; 32],
            delete_token_hash: [4u8; 32],
            max_releases: 2,
            released_by: vec![
                Releaser {
                    user: [5u8; 32],
                    device: Some(7),
                },
                Releaser {
                    user: [5u8; 32],
                    device: None,
                },
            ],
            created_at: 100,
            ttl_secs: 3_600,
            expires_at: if ready { 3_700 } else { 0 },
            committed_offset: 4_194_304,
            last_activity: 150,
        }
    }

    #[test]
    fn live_and_tombstone_records_roundtrip() {
        for record in [
            BlobRecord::Live(live(true, true)),
            BlobRecord::Live(live(false, false)),
            BlobRecord::Tomb(Tombstone {
                cause: TombCause::Expired,
                at: 10,
                until: 20,
                delete_token_hash: [6u8; 32],
            }),
            BlobRecord::Tomb(Tombstone {
                cause: TombCause::Deleted,
                at: 11,
                until: 21,
                delete_token_hash: [7u8; 32],
            }),
        ] {
            assert_eq!(BlobRecord::decode(&record.encode()), Some(record));
        }
    }

    #[test]
    fn truncated_or_foreign_records_do_not_decode() {
        let encoded = BlobRecord::Live(live(true, true)).encode();
        for len in 0..encoded.len() {
            assert_eq!(BlobRecord::decode(&encoded[..len]), None, "prefix {len}");
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(BlobRecord::decode(&trailing), None);
        let mut foreign = encoded;
        foreign[0] = 2;
        assert_eq!(BlobRecord::decode(&foreign), None);
        assert_eq!(BlobRecord::decode(&[FORMAT_V1, 9]), None);
        assert_eq!(BlobRecord::decode(&[FORMAT_V1, KIND_READY, 5]), None);
    }

    #[test]
    fn due_time_follows_the_state() {
        assert_eq!(BlobRecord::Live(live(true, false)).due_at(86_400), 3_700);
        assert_eq!(
            BlobRecord::Live(live(false, false)).due_at(86_400),
            150 + 86_400
        );
        let tomb = BlobRecord::Tomb(Tombstone {
            cause: TombCause::Deleted,
            at: 1,
            until: 99,
            delete_token_hash: [0u8; 32],
        });
        assert_eq!(tomb.due_at(86_400), 99);
    }

    #[test]
    fn index_keys_roundtrip() {
        let id = [8u8; 32];
        assert_eq!(parse_expiry_key(&expiry_key(42, &id)), Some((42, id)));
        assert_eq!(parse_expiry_key(&[0u8; 39]), None);
        // Порядок ключей — порядок сроков.
        assert!(expiry_key(1, &[0xff; 32]) < expiry_key(2, &[0u8; 32]));
        assert_eq!(owner_usage_key(&[1u8; 32])[0], b'o');
        assert_eq!(pair_usage_key(&[1u8; 32], &[2u8; 32])[33], 2);
    }
}
