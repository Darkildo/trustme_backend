//! Хранилище файлов (server-contract.md, §6.11).
//!
//! Блоб — непрозрачный шифротекст, который клиент загружает один раз, а в
//! сообщении через очередь передаёт только E2E-указатель. Нода хранит его
//! под `blob_id = SHA-256(blob_secret)`: секрет — право на чтение, и его
//! знают только клиенты; хранимый id права не даёт.
//!
//! Байты лежат файлами в `BLOB_DIR` (имя — hex `blob_id`, подкаталог —
//! первый байт), метаданные — в деревьях sled `blobs`, `blob_expiry`,
//! `blob_usage` общей базы ноды (форматы — в [`record`]). Бэкенд доставки
//! на хранилище не влияет: оно одинаково на прямом и брокерном режиме.

pub mod record;
mod store;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::wire::BlobRejectReason as WireReason;

pub use store::{
    BlobReader, BlobStore, ChunkOk, ChunkReject, CleanupReport, InitOk, InitRequest, ReadChunk,
    StatEntry, StatQuery, StatState, StatusOk,
};

/// `SHA-256(blob_secret)`: под этим id блоб хранится на ноде.
pub type BlobId = [u8; 32];

/// Потолок `max_releases`: запись блоба хранит каждого отпустившего, и
/// без потолка один `Init` раздувал бы её без меры.
pub const MAX_RELEASES: u32 = 256;

/// Потолок записей в одном `BlobStat`.
pub const MAX_STAT_ITEMS: usize = 64;

/// Запас кадра под служебные поля `BlobUploadChunk` и `BlobData`, байт:
/// данных в кадре не больше `max_frame_len` минус запас. Худший
/// `BlobUploadChunk` — 66 байт сверх данных, худший `BlobData` — 44.
pub const BLOB_FRAME_RESERVE: usize = 128;

/// Причина отказа операции хранилища, `BlobAck.reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobReject {
    NotFound,
    Expired,
    Forbidden,
    TooLarge,
    Quota,
    RateLimited,
    Invalid,
    NotReady,
    Unsupported,
    Internal,
    Deleted,
    Conflict,
}

impl BlobReject {
    pub fn to_wire(self) -> i32 {
        (match self {
            Self::NotFound => WireReason::NotFound,
            Self::Expired => WireReason::Expired,
            Self::Forbidden => WireReason::Forbidden,
            Self::TooLarge => WireReason::TooLarge,
            Self::Quota => WireReason::Quota,
            Self::RateLimited => WireReason::RateLimited,
            Self::Invalid => WireReason::Invalid,
            Self::NotReady => WireReason::NotReady,
            Self::Unsupported => WireReason::Unsupported,
            Self::Internal => WireReason::Internal,
            Self::Deleted => WireReason::Deleted,
            Self::Conflict => WireReason::Conflict,
        }) as i32
    }

    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Expired => "expired",
            Self::Forbidden => "forbidden",
            Self::TooLarge => "too_large",
            Self::Quota => "quota",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::NotReady => "not_ready",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
            Self::Deleted => "deleted",
            Self::Conflict => "conflict",
        }
    }
}

/// `blob_id` по секрету читателя.
pub fn blob_id_of(secret: &[u8; 32]) -> BlobId {
    Sha256::digest(secret).into()
}

/// Хэш токена управления: в базе лежит только он.
pub fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

/// Совпадает ли предъявленный токен с хранимым хэшем. Сравнение за
/// постоянное время: по времени ответа нельзя подбирать хэш побайтно.
pub fn token_matches(token: &[u8; 32], stored_hash: &[u8; 32]) -> bool {
    token_hash(token).ct_eq(stored_hash).into()
}

/// Отпечаток блоба для логов: первые 4 байта `blob_id` в hex. Сам id права
/// не даёт, но гигиена логов общая (N-4): полные идентификаторы в них не
/// пишутся, отпечатка хватает, чтобы связать строки об одном блобе.
pub fn blob_fingerprint(id: &BlobId) -> String {
    hex::encode(&id[..4])
}

/// Скопировать ровно 32 байта; иначе `None`.
pub fn fixed_32(raw: &[u8]) -> Option<[u8; 32]> {
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_reasons_map_to_distinct_wire_values() {
        let all = [
            BlobReject::NotFound,
            BlobReject::Expired,
            BlobReject::Forbidden,
            BlobReject::TooLarge,
            BlobReject::Quota,
            BlobReject::RateLimited,
            BlobReject::Invalid,
            BlobReject::NotReady,
            BlobReject::Unsupported,
            BlobReject::Internal,
            BlobReject::Deleted,
            BlobReject::Conflict,
        ];
        let mut wire: Vec<i32> = all.iter().map(|reason| reason.to_wire()).collect();
        let mut labels: Vec<&str> = all.iter().map(|reason| reason.as_metric_label()).collect();
        wire.sort_unstable();
        wire.dedup();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(wire, (1..=12).collect::<Vec<_>>());
        assert_eq!(labels.len(), all.len());
    }

    #[test]
    fn token_check_and_ids_use_sha256() {
        let token = [5u8; 32];
        assert!(token_matches(&token, &token_hash(&token)));
        assert!(!token_matches(&[6u8; 32], &token_hash(&token)));
        assert_eq!(blob_id_of(&token), token_hash(&token));
        assert_eq!(blob_fingerprint(&[0xab; 32]), "abababab");
        assert_eq!(fixed_32(&[1u8; 31]), None);
        assert_eq!(fixed_32(&[1u8; 32]), Some([1u8; 32]));
    }
}
