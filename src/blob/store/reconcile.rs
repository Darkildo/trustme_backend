//! Сверка метаданных с каталогом при старте.
//!
//! После падения посреди коммита или удаления запись и файл могут
//! разойтись. Правила:
//!
//! - готовому блобу нужен файл `<id>`, иначе он становится надгробием
//!   `EXPIRED`: файл потерян (падение посреди удаления, восстановление из
//!   бэкапа, в который блобы не входят), и клиенту честнее попросить
//!   отправителя перезалить, чем считать, что файла не было;
//! - загрузке нужен `<id>.part`; нет его — загрузка начинается с нуля,
//!   файл короче сброшенного смещения — смещение опускается до длины;
//! - файл без записи в подходящем состоянии стирается — в том числе
//!   готовый файл загрузки, которую не успели перевести в `READY`:
//!   клиент увидит смещение 0 в `BlobUploadStatus` и загрузит заново;
//! - неразбираемая запись стирается.
//!
//! Индекс сроков и счётчики квот пересобираются с нуля: так они не могут
//! разойтись с записями необратимо, как и `queue_stats` очередей.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use sled::IVec;
use tracing::{info, warn};

use crate::observability;

use super::super::BlobId;
use super::super::record::{
    BlobRecord, TombCause, Tombstone, expiry_key, owner_usage_key, pair_usage_key,
};
use super::BlobStore;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FileKind {
    Final,
    Part,
}

/// Что нашла сверка; всё, кроме `blobs`, — исправленные расхождения.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ReconcileReport {
    pub blobs: usize,
    pub orphan_files: usize,
    pub missing_files: usize,
    pub rewound_uploads: usize,
    pub corrupt_records: usize,
}

impl BlobStore {
    pub(super) fn reconcile(&self, now: u64) -> Result<ReconcileReport> {
        let mut report = ReconcileReport::default();
        let mut files = self.scan_files()?;

        let _meta = self.meta();
        let mut keep: HashSet<(BlobId, FileKind)> = HashSet::new();
        for entry in self.inner.blobs.iter() {
            let (key, raw) = entry?;
            let record = <[u8; 32]>::try_from(key.as_ref())
                .ok()
                .zip(BlobRecord::decode(&raw));
            let Some((id, record)) = record else {
                self.inner.blobs.remove(&key)?;
                report.corrupt_records += 1;
                continue;
            };
            let BlobRecord::Live(mut live) = record else {
                continue;
            };
            if live.ready {
                if files.contains_key(&(id, FileKind::Final)) {
                    keep.insert((id, FileKind::Final));
                } else {
                    let tomb = BlobRecord::Tomb(Tombstone {
                        cause: TombCause::Expired,
                        at: now,
                        until: now.saturating_add(self.inner.cfg.tombstone_secs),
                        delete_token_hash: live.delete_token_hash,
                    });
                    self.inner.blobs.insert(id, tomb.encode())?;
                    report.missing_files += 1;
                }
                continue;
            }
            let part_len = files.get(&(id, FileKind::Part)).copied();
            let durable = part_len.unwrap_or(0).min(live.committed_offset);
            if durable != live.committed_offset {
                live.committed_offset = durable;
                self.inner
                    .blobs
                    .insert(id, BlobRecord::Live(live).encode())?;
                report.rewound_uploads += 1;
            }
            if part_len.is_some() {
                keep.insert((id, FileKind::Part));
            }
        }

        files.retain(|key, _| !keep.contains(key));
        for (id, kind) in files.keys() {
            let path = match kind {
                FileKind::Final => self.final_path(id),
                FileKind::Part => self.part_path(id),
            };
            match std::fs::remove_file(&path) {
                Ok(()) => report.orphan_files += 1,
                Err(err) => warn!(error = %err, "failed to remove an orphan blob file"),
            }
        }

        report.blobs = self.rebuild_indexes()?;
        for (kind, count) in [
            ("orphan_file", report.orphan_files),
            ("missing_file", report.missing_files),
            ("rewound_upload", report.rewound_uploads),
            ("corrupt_record", report.corrupt_records),
        ] {
            observability::observe_blob_reconcile(kind, count as u64);
        }
        // Без id: расхождения считаются, а не перечисляются.
        if report
            != (ReconcileReport {
                blobs: report.blobs,
                ..ReconcileReport::default()
            })
        {
            warn!(
                orphan_files = report.orphan_files,
                missing_files = report.missing_files,
                rewound_uploads = report.rewound_uploads,
                corrupt_records = report.corrupt_records,
                "blob store reconciled after an unclean shutdown"
            );
        }
        info!(blobs = report.blobs, "blob store opened");
        Ok(report)
    }

    /// Файлы каталога: `<hh>/<64 hex>` и `<hh>/<64 hex>.part` → длина.
    /// Остальное (чужие файлы) не трогается.
    fn scan_files(&self) -> Result<HashMap<(BlobId, FileKind), u64>> {
        let mut files = HashMap::new();
        let top =
            std::fs::read_dir(&self.inner.dir).context("failed to list the blob directory")?;
        for subdir in top {
            let subdir = subdir?;
            if !subdir.file_type()?.is_dir() {
                continue;
            }
            for file in std::fs::read_dir(subdir.path())? {
                let file = file?;
                let name = file.file_name();
                let Some(name) = name.to_str() else { continue };
                let (stem, kind) = match name.strip_suffix(".part") {
                    Some(stem) => (stem, FileKind::Part),
                    None => (name, FileKind::Final),
                };
                let Some(id) = hex::decode(stem)
                    .ok()
                    .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                else {
                    continue;
                };
                // Файл не на своём месте — тоже чужой.
                if subdir.file_name().to_str() != Some(hex::encode(&id[..1]).as_str()) {
                    continue;
                }
                files.insert((id, kind), file.metadata()?.len());
            }
        }
        Ok(files)
    }

    /// Пересобрать индекс сроков, счётчики квот и итоги по записям.
    /// Возвращает число записей.
    fn rebuild_indexes(&self) -> Result<usize> {
        let stale_secs = self.inner.cfg.upload_stale_secs;
        self.inner.expiry.clear()?;
        self.inner.usage.clear()?;
        let mut usage: HashMap<Vec<u8>, u64> = HashMap::new();
        let mut expiry = sled::Batch::default();
        let (mut ready_bytes, mut ready_count, mut uploading_bytes, mut uploading_count) =
            (0u64, 0u64, 0u64, 0u64);
        let mut records = 0usize;
        for entry in self.inner.blobs.iter() {
            let (key, raw) = entry?;
            let (Ok(id), Some(record)) =
                (<[u8; 32]>::try_from(key.as_ref()), BlobRecord::decode(&raw))
            else {
                continue;
            };
            records += 1;
            expiry.insert(
                &expiry_key(record.due_at(stale_secs), &id)[..],
                IVec::default(),
            );
            let BlobRecord::Live(live) = record else {
                continue;
            };
            let charge = self.charge(live.size);
            *usage
                .entry(owner_usage_key(&live.owner).to_vec())
                .or_default() += charge;
            if !live.is_own() {
                *usage
                    .entry(pair_usage_key(&live.owner, &live.uploader).to_vec())
                    .or_default() += charge;
            }
            if live.ready {
                ready_bytes += live.size;
                ready_count += 1;
            } else {
                uploading_bytes += live.size;
                uploading_count += 1;
            }
        }
        self.inner.expiry.apply_batch(expiry)?;
        let mut batch = sled::Batch::default();
        for (key, bytes) in usage {
            batch.insert(key, &bytes.to_be_bytes());
        }
        self.inner.usage.apply_batch(batch)?;
        let totals = &self.inner.totals;
        totals.ready_bytes.store(ready_bytes, Ordering::Relaxed);
        totals.ready_count.store(ready_count, Ordering::Relaxed);
        totals
            .uploading_bytes
            .store(uploading_bytes, Ordering::Relaxed);
        totals
            .uploading_count
            .store(uploading_count, Ordering::Relaxed);
        self.publish_totals();
        Ok(records)
    }
}
