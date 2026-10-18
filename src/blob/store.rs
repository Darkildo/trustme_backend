//! Хранилище блобов: метаданные в sled, байты файлами.
//!
//! Согласованность держится на трёх замках, которые всегда берутся в одном
//! порядке — ворота, слот, метаданные:
//!
//! - **ворота** блоба (`RwLock`) — читатели держат их на чтение, пока
//!   берут из файла очередной кусок; удаление, истечение и последний релиз
//!   берут на запись, закрывают ворота причиной и только потом стирают
//!   файл. После этого ни одного куска из файла уже не читается, а идущее
//!   скачивание получает причину вместо данных;
//! - **слот загрузки** (`Mutex`) — через него идёт вся запись в `.part`:
//!   куски, сброс на диск, `Commit`. Двух писателей у файла не бывает, а
//!   удаление ждёт, пока допишется текущий кусок;
//! - **метаданные** (`std::sync::Mutex`) — любое чтение-изменение-запись
//!   записи блоба, индексов и счётчиков квот. Под ним же проверяются квоты
//!   при `Init`, поэтому параллельные загрузки квоту не обходят. Через
//!   `await` не держится никогда.
//!
//! Порядок для устойчивости к падению: запись метаданных — до создания
//! файла; удаление — сначала файл, потом метаданные. Что осталось
//! рассогласованным после падения, убирает сверка при старте
//! ([`reconcile`]).

mod reconcile;

use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use sled::{Db, IVec, Tree};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedRwLockWriteGuard, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::config::BlobConfig;
use crate::net::rate_limit::{SendRateLimiter, unix_now_secs};
use crate::observability;
use crate::state::queues::QueueStore;
use crate::state::registry::UserId;

use super::record::{
    BlobRecord, LiveBlob, Releaser, TombCause, Tombstone, expiry_key, owner_usage_key,
    pair_usage_key, parse_expiry_key,
};
use super::{BlobId, BlobReject, MAX_RELEASES, blob_fingerprint, token_matches};

/// Параметры `BlobUploadInit` после проверки длин полей.
#[derive(Clone, Debug)]
pub struct InitRequest {
    /// `Some` — личный файл в ящик владельца этой очереди; `None` — свой.
    pub queue_id: Option<[u8; 32]>,
    pub size: u64,
    pub sha256: [u8; 32],
    pub ttl_secs: u64,
    pub max_releases: u32,
    pub blob_id: BlobId,
    pub delete_token_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitOk {
    /// Предварительный срок: окончательный считается от `Commit`.
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkOk {
    /// `Some` — после этого куска загрузка сброшена на диск до этого
    /// смещения, и клиенту уходит подтверждение прогресса.
    pub synced: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkReject {
    pub reason: BlobReject,
    /// С какого смещения нода ждёт следующий кусок.
    pub expected_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusOk {
    pub committed_offset: u64,
    pub expires_at: u64,
}

/// Кусок ответа на `BlobGet`.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadChunk {
    pub offset: u64,
    pub data: Vec<u8>,
    /// Последний кусок ответа.
    pub eof: bool,
}

/// Запись `BlobStat` после проверки длин.
pub enum StatQuery {
    /// Читатель: id, посчитанный из `blob_secret`.
    Reader(BlobId),
    /// Загрузивший: id и токен управления.
    Manager {
        id: BlobId,
        token: Zeroizing<[u8; 32]>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatState {
    Ready,
    Uploading,
    Expired,
    Deleted,
    NotFound,
    Forbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatEntry {
    pub state: StatState,
    pub expires_at: u64,
    /// `(отпустили, нужно)` — только загрузившему по токену.
    pub releases: Option<(u32, u32)>,
}

/// Что сделала чистка.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub expired: usize,
    pub stale_uploads: usize,
    pub tombstones: usize,
}

#[derive(Clone)]
pub struct BlobStore {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: BlobConfig,
    dir: PathBuf,
    /// `blob_id` → запись (`record`).
    blobs: Tree,
    /// `due_at ‖ blob_id` → пусто: когда записью заняться чистке.
    expiry: Tree,
    /// Счётчики квот: `'o' ‖ owner` и `'p' ‖ owner ‖ uploader` → байт.
    /// Пересобираются при каждом старте, как `queue_stats`.
    usage: Tree,
    queues: QueueStore,
    meta: Mutex<()>,
    gates: DashMap<BlobId, Arc<Gate>>,
    uploads: DashMap<BlobId, Arc<AsyncMutex<UploadSlot>>>,
    /// Суточный объём загрузок пользователя (`BLOB_UPLOAD_BYTES_PER_DAY`).
    upload_budget: SendRateLimiter,
    totals: Totals,
}

/// Ворота блоба (см. документацию модуля). `closed` повторяет причину
/// закрытия для дешёвой проверки без замка: сессия смотрит на неё перед
/// отправкой уже прочитанного куска.
#[derive(Default)]
struct Gate {
    state: Arc<RwLock<Option<BlobReject>>>,
    closed: AtomicU8,
}

/// Запись в `.part` одного блоба. `conn` — соединение, чей файловый
/// дескриптор открыт; другое соединение того же загрузившего перехватывает
/// слот и продолжает с последнего сброса на диск.
#[derive(Default)]
struct UploadSlot {
    conn: u64,
    file: Option<tokio::fs::File>,
    written: u64,
    synced: u64,
    /// Блоб удалён или загрузка закончена: слот больше не пишет.
    dead: bool,
}

#[derive(Default)]
struct Totals {
    ready_bytes: AtomicU64,
    ready_count: AtomicU64,
    uploading_bytes: AtomicU64,
    uploading_count: AtomicU64,
}

/// Удержание блоба на время удаления: ворота на запись и слот загрузки.
struct Exclusive {
    id: BlobId,
    gate: Arc<Gate>,
    gate_guard: OwnedRwLockWriteGuard<Option<BlobReject>>,
    slot: Arc<AsyncMutex<UploadSlot>>,
    slot_guard: OwnedMutexGuard<UploadSlot>,
}

/// Исход операции, которая может стереть блоб: ответ клиенту и, если блоб
/// стёрт, причина для закрытия ворот.
type Removal = Result<(Result<(), BlobReject>, Option<BlobReject>)>;

fn gone_of(outcome: &Removal) -> Option<BlobReject> {
    outcome.as_ref().ok().and_then(|(_, gone)| *gone)
}

#[derive(Clone, Copy)]
enum Sign {
    Add,
    Sub,
}

impl BlobStore {
    /// Открыть хранилище в общей базе ноды и сверить его с каталогом.
    pub fn open(db: &Db, cfg: &BlobConfig) -> Result<Self> {
        let dir = PathBuf::from(&cfg.dir);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create blob directory {}", dir.display()))?;
        let store = Self {
            inner: Arc::new(Inner {
                upload_budget: SendRateLimiter::new(0, cfg.upload_bytes_per_day),
                cfg: cfg.clone(),
                dir,
                blobs: db.open_tree("blobs")?,
                expiry: db.open_tree("blob_expiry")?,
                usage: db.open_tree("blob_usage")?,
                queues: QueueStore::open(db)?,
                meta: Mutex::new(()),
                gates: DashMap::new(),
                uploads: DashMap::new(),
                totals: Totals::default(),
            }),
        };
        store.reconcile(unix_now_secs())?;
        Ok(store)
    }

    pub fn config(&self) -> &BlobConfig {
        &self.inner.cfg
    }

    /// Сколько блоб занимает в квотах: не меньше `BLOB_MIN_CHARGE_BYTES`.
    /// Иначе квоты в байтах не ограничивали бы число записей: миллион
    /// однобайтовых блобов уложился бы в мегабайт. Резерв диска и метрики
    /// считают настоящий размер.
    pub fn charge(&self, size: u64) -> u64 {
        size.max(self.inner.cfg.min_charge)
    }

    /// Срок после зажима потолком: `0` — потолок.
    pub fn clamp_ttl(&self, requested: u64) -> u64 {
        let ceiling = self.inner.cfg.max_ttl_secs;
        if requested == 0 || requested > ceiling {
            ceiling
        } else {
            requested
        }
    }

    /// Фоновая чистка: истёкшие блобы, протухшие загрузки, надгробия.
    pub fn start_periodic_cleanup(&self, interval: Duration) -> JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                match store.cleanup(unix_now_secs()).await {
                    Ok(report) if report != CleanupReport::default() => info!(
                        expired = report.expired,
                        stale_uploads = report.stale_uploads,
                        tombstones = report.tombstones,
                        "blob cleanup completed"
                    ),
                    Ok(_) => {}
                    Err(err) => warn!(error = %err, "blob cleanup failed"),
                }
                tokio::time::sleep(interval).await;
            }
        })
    }

    // --- Загрузка ---

    /// Завести загрузку: проверить право, занять id и зарезервировать квоты
    /// по объявленному размеру.
    pub fn init(
        &self,
        uploader: &UserId,
        request: &InitRequest,
        now: u64,
    ) -> Result<Result<InitOk, BlobReject>> {
        let cfg = &self.inner.cfg;
        if request.size == 0 || request.max_releases > MAX_RELEASES {
            return Ok(Err(BlobReject::Invalid));
        }
        if cfg.max_size > 0 && request.size > cfg.max_size {
            return Ok(Err(BlobReject::TooLarge));
        }
        // Личный файл — только в живую очередь, как депозит: блокировка
        // контакта отзывом очереди закрывает и его файлы.
        let owner = match &request.queue_id {
            Some(queue_id) => match self.inner.queues.owner_of(queue_id, now)? {
                Some(owner) => owner,
                None => return Ok(Err(BlobReject::Forbidden)),
            },
            None => *uploader,
        };
        let ttl_secs = self.clamp_ttl(request.ttl_secs);

        {
            let _meta = self.meta();
            if self.inner.blobs.contains_key(request.blob_id)? {
                return Ok(Err(BlobReject::Conflict));
            }
            if let Some(reason) = self.quota_reason(&owner, uploader, request.size, now)? {
                return Ok(Err(reason));
            }
            let record = BlobRecord::Live(LiveBlob {
                ready: false,
                queue_id: request.queue_id,
                owner,
                uploader: *uploader,
                size: request.size,
                sha256: request.sha256,
                delete_token_hash: request.delete_token_hash,
                max_releases: request.max_releases,
                released_by: Vec::new(),
                created_at: now,
                ttl_secs,
                expires_at: 0,
                committed_offset: 0,
                last_activity: now,
            });
            self.put_record(&request.blob_id, None, &record)?;
            if let BlobRecord::Live(live) = &record {
                self.account(live, Sign::Add)?;
            }
        }

        // Метаданные уже записаны: упавшая здесь нода оставит загрузку без
        // файла, и его создаст первый кусок.
        if let Err(err) = std::fs::create_dir_all(self.subdir(&request.blob_id))
            .and_then(|()| std::fs::File::create(self.part_path(&request.blob_id)))
        {
            warn!(
                blob = %blob_fingerprint(&request.blob_id),
                error = %err,
                "failed to create the upload file; the first chunk will retry"
            );
        }
        Ok(Ok(InitOk {
            expires_at: now.saturating_add(ttl_secs),
        }))
    }

    /// Квоты нового блоба: владельца, пары, диска, суточная. Под замком
    /// метаданных. Суточный бюджет проверяется последним: успешная проверка
    /// его списывает.
    fn quota_reason(
        &self,
        owner: &UserId,
        uploader: &UserId,
        size: u64,
        now: u64,
    ) -> Result<Option<BlobReject>> {
        let cfg = &self.inner.cfg;
        let charge = self.charge(size);
        let over = |used: u64, ceiling: u64| ceiling > 0 && used.saturating_add(charge) > ceiling;
        if over(self.usage_of(&owner_usage_key(owner))?, cfg.quota_per_owner) {
            return Ok(Some(BlobReject::Quota));
        }
        // Пара — защита чужого ящика от одного контакта; свой аккаунт
        // ограничен квотой владельца.
        if owner != uploader
            && over(
                self.usage_of(&pair_usage_key(owner, uploader))?,
                cfg.quota_per_pair,
            )
        {
            return Ok(Some(BlobReject::Quota));
        }
        // Незавершённые загрузки уже заняли место объявленным размером, даже
        // если байт ещё не прислали.
        let available = fs2::available_space(&self.inner.dir)
            .context("failed to read free space of the blob directory")?;
        let pending = self.inner.totals.uploading_bytes.load(Ordering::Relaxed);
        if available.saturating_sub(pending) < cfg.disk_reserve.saturating_add(size) {
            return Ok(Some(BlobReject::Quota));
        }
        let size_for_budget = usize::try_from(charge).unwrap_or(usize::MAX);
        if !self
            .inner
            .upload_budget
            .check_at(uploader, size_for_budget, now)
        {
            return Ok(Some(BlobReject::Quota));
        }
        Ok(None)
    }

    /// Записать кусок загрузки. Принимается только со смещения, которое
    /// нода ждёт; каждые `sync_every` байт и на последнем куске файл
    /// сбрасывается на диск, и прогресс фиксируется в записи.
    pub async fn write_chunk(
        &self,
        conn: u64,
        uploader: &UserId,
        id: &BlobId,
        offset: u64,
        data: &[u8],
        now: u64,
    ) -> Result<Result<ChunkOk, ChunkReject>> {
        let live = match self.uploading(uploader, id)? {
            Ok(live) => live,
            Err(reject) => return Ok(Err(reject)),
        };
        let slot = self.slot(id);
        let mut guard = slot.clone().lock_owned().await;
        let outcome = self
            .write_chunk_locked(&mut guard, conn, uploader, id, &live, offset, data, now)
            .await;
        if !matches!(outcome, Ok(Ok(_))) && guard.dead {
            guard.file = None;
        }
        drop(guard);
        self.release_slot(id, slot);
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_chunk_locked(
        &self,
        slot: &mut UploadSlot,
        conn: u64,
        uploader: &UserId,
        id: &BlobId,
        live: &LiveBlob,
        offset: u64,
        data: &[u8],
        now: u64,
    ) -> Result<Result<ChunkOk, ChunkReject>> {
        if slot.dead || slot.conn != conn || slot.file.is_none() {
            // Пока ждали слот, блоб могли удалить или дописать.
            let current = match self.uploading(uploader, id)? {
                Ok(current) => current,
                Err(reject) => {
                    slot.dead = true;
                    return Ok(Err(reject));
                }
            };
            if let Err(err) = self.take_over(slot, conn, id, &current, now).await {
                return Ok(Err(ChunkReject {
                    reason: io_reject(&err)?,
                    expected_offset: current.committed_offset,
                }));
            }
        }
        let expected_offset = slot.written;
        let len = data.len() as u64;
        if data.is_empty() || offset != slot.written || offset.saturating_add(len) > live.size {
            return Ok(Err(ChunkReject {
                reason: BlobReject::Invalid,
                expected_offset,
            }));
        }
        let Some(file) = slot.file.as_mut() else {
            return Ok(Err(ChunkReject {
                reason: BlobReject::Internal,
                expected_offset,
            }));
        };
        if let Err(err) = file.write_all(data).await {
            // Дескриптор после сбоя записи не годится: следующий кусок
            // переоткроет файл и обрежет его до последнего сброса.
            slot.file = None;
            let reason = io_reject(&err)?;
            return Ok(Err(ChunkReject {
                reason,
                expected_offset: slot.synced,
            }));
        }
        slot.written += len;
        observability::observe_blob_bytes("upload", len);

        let due = slot.written - slot.synced >= self.inner.cfg.sync_every.max(1);
        if !due && slot.written < live.size {
            return Ok(Ok(ChunkOk { synced: None }));
        }
        match self.sync_slot(slot, uploader, id, now).await? {
            Ok(synced) => Ok(Ok(ChunkOk {
                synced: Some(synced),
            })),
            Err(reason) => Ok(Err(ChunkReject {
                reason,
                expected_offset: slot.synced,
            })),
        }
    }

    /// Открыть `.part` для этого соединения и продолжить с последнего
    /// сброса на диск: несброшенное прежним дескриптором отбрасывается.
    async fn take_over(
        &self,
        slot: &mut UploadSlot,
        conn: u64,
        id: &BlobId,
        live: &LiveBlob,
        now: u64,
    ) -> io::Result<()> {
        slot.file = None;
        tokio::fs::create_dir_all(self.subdir(id)).await?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.part_path(id))
            .await?;
        file.set_len(live.committed_offset).await?;
        file.seek(SeekFrom::Start(live.committed_offset)).await?;
        slot.conn = conn;
        slot.file = Some(file);
        slot.written = live.committed_offset;
        slot.synced = live.committed_offset;
        slot.dead = false;
        // Возобновлённая загрузка — активность: иначе чистка могла бы снять
        // её до следующего сброса на диск.
        let _meta = self.meta();
        if let Ok(Some(BlobRecord::Live(mut current))) = self.get_record(id)
            && !current.ready
        {
            let old = BlobRecord::Live(current.clone());
            current.last_activity = now;
            let _ = self.put_record(id, Some(&old), &BlobRecord::Live(current));
        }
        Ok(())
    }

    /// Сбросить файл слота на диск и записать прогресс в запись.
    async fn sync_slot(
        &self,
        slot: &mut UploadSlot,
        uploader: &UserId,
        id: &BlobId,
        now: u64,
    ) -> Result<Result<u64, BlobReject>> {
        if slot.written == slot.synced {
            return Ok(Ok(slot.synced));
        }
        let Some(file) = slot.file.as_mut() else {
            return Ok(Err(BlobReject::Internal));
        };
        if let Err(err) = file.sync_data().await {
            slot.file = None;
            return Ok(Err(io_reject(&err)?));
        }
        let _meta = self.meta();
        let mut live = match self.uploading(uploader, id)? {
            Ok(live) => live,
            Err(reject) => {
                slot.dead = true;
                return Ok(Err(reject.reason));
            }
        };
        let old = BlobRecord::Live(live.clone());
        live.committed_offset = slot.written;
        live.last_activity = now;
        self.put_record(id, Some(&old), &BlobRecord::Live(live))?;
        slot.synced = slot.written;
        Ok(Ok(slot.synced))
    }

    /// Закончить загрузку: размер и SHA-256 сошлись — блоб готов, срок
    /// считается отсюда. Иначе блоб удаляется без надгробия.
    pub async fn commit(
        &self,
        uploader: &UserId,
        id: &BlobId,
        now: u64,
    ) -> Result<Result<u64, BlobReject>> {
        match self.get_record(id)? {
            None => return Ok(Err(BlobReject::NotFound)),
            Some(BlobRecord::Tomb(tomb)) => return Ok(Err(tomb_reject(&tomb))),
            Some(BlobRecord::Live(live)) if live.uploader != *uploader => {
                return Ok(Err(BlobReject::Forbidden));
            }
            // Повтор `Commit`, чей ответ клиент не получил.
            Some(BlobRecord::Live(live)) if live.ready => {
                return Ok(if live.expires_at <= now {
                    Err(BlobReject::Expired)
                } else {
                    Ok(live.expires_at)
                });
            }
            Some(BlobRecord::Live(_)) => {}
        }
        let slot = self.slot(id);
        let mut guard = slot.clone().lock_owned().await;
        let outcome = self.commit_locked(&mut guard, uploader, id, now).await;
        guard.file = None;
        if matches!(outcome, Ok(Ok(_))) {
            guard.dead = true;
        }
        drop(guard);
        self.release_slot(id, slot);
        outcome
    }

    async fn commit_locked(
        &self,
        slot: &mut UploadSlot,
        uploader: &UserId,
        id: &BlobId,
        now: u64,
    ) -> Result<Result<u64, BlobReject>> {
        if slot.dead {
            return Ok(Err(self.gone_reason(id)?));
        }
        // Несброшенное — тоже байты загрузившего, кто бы их ни прислал.
        if slot.file.is_some()
            && let Err(reason) = self.sync_slot(slot, uploader, id, now).await?
        {
            return Ok(Err(reason));
        }
        let live = match self.uploading(uploader, id)? {
            Ok(live) => live,
            Err(reject) => return Ok(Err(reject.reason)),
        };
        slot.file = None;

        let verdict = if live.committed_offset != live.size {
            Some(BlobReject::Invalid)
        } else {
            let path = self.part_path(id);
            let size = live.size;
            let digest = tokio::task::spawn_blocking(move || sha256_of_prefix(&path, size))
                .await
                .context("blob hashing task failed")?;
            match digest {
                Ok(Some(digest)) if bool::from(digest.ct_eq(&live.sha256)) => None,
                Ok(_) => Some(BlobReject::Invalid),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Some(BlobReject::Invalid),
                Err(err) => return Err(err).context("failed to hash the uploaded blob"),
            }
        };
        let verdict = match (verdict, &live.queue_id) {
            (None, Some(queue_id)) => match self.inner.queues.owner_of(queue_id, now)? {
                Some(owner) if owner == live.owner => None,
                // Очередь отозвали, пока шла загрузка: контакт заблокирован.
                _ => Some(BlobReject::Forbidden),
            },
            (verdict, _) => verdict,
        };
        if let Some(reason) = verdict {
            slot.dead = true;
            let _meta = self.meta();
            if let Some(BlobRecord::Live(current)) = self.get_record(id)? {
                self.remove_live_locked(id, &current, None, now)?;
                observability::observe_blob_removed("invalid");
            }
            return Ok(Err(reason));
        }

        let part = self.part_path(id);
        let target = self.final_path(id);
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&part)
            .await?;
        // Лишнее за объявленным размером (перехват слота посреди записи)
        // в готовый блоб не попадает.
        file.set_len(live.size).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&part, &target).await?;
        sync_dir(&self.subdir(id)).await;

        let _meta = self.meta();
        let mut current = match self.uploading(uploader, id)? {
            Ok(current) => current,
            Err(reject) => {
                let _ = std::fs::remove_file(&target);
                return Ok(Err(reject.reason));
            }
        };
        let old = BlobRecord::Live(current.clone());
        current.ready = true;
        current.expires_at = now.saturating_add(current.ttl_secs);
        current.committed_offset = current.size;
        let expires_at = current.expires_at;
        self.put_record(id, Some(&old), &BlobRecord::Live(current.clone()))?;
        self.move_to_ready(&current);
        Ok(Ok(expires_at))
    }

    /// Где загрузка: сколько сброшено на диск. Только загрузившему.
    pub fn status(
        &self,
        uploader: &UserId,
        id: &BlobId,
        now: u64,
    ) -> Result<Result<StatusOk, BlobReject>> {
        Ok(match self.get_record(id)? {
            None => Err(BlobReject::NotFound),
            Some(BlobRecord::Tomb(tomb)) => Err(tomb_reject(&tomb)),
            Some(BlobRecord::Live(live)) if live.uploader != *uploader => {
                Err(BlobReject::Forbidden)
            }
            Some(BlobRecord::Live(live)) if live.ready => {
                if live.expires_at <= now {
                    Err(BlobReject::Expired)
                } else {
                    Ok(StatusOk {
                        committed_offset: live.size,
                        expires_at: live.expires_at,
                    })
                }
            }
            Some(BlobRecord::Live(live)) => Ok(StatusOk {
                committed_offset: live.committed_offset,
                expires_at: live
                    .last_activity
                    .saturating_add(self.inner.cfg.upload_stale_secs),
            }),
        })
    }

    // --- Чтение ---

    /// Начать ответ на `BlobGet`: проверить состояние и диапазон и открыть
    /// файл. `length = 0` — до конца; ответ не длиннее `window`.
    pub async fn open_reader(
        &self,
        id: &BlobId,
        offset: u64,
        length: u64,
        chunk: usize,
        now: u64,
    ) -> Result<Result<BlobReader, BlobReject>> {
        let gate = self.gate(id);
        let opened = {
            let guard = gate.state.read().await;
            match *guard {
                Some(reason) => Ok(Err(reason)),
                None => self.open_file_locked(id, offset, length, now).await,
            }
        };
        match opened {
            Ok(Ok((file, end))) => Ok(Ok(BlobReader {
                store: self.clone(),
                id: *id,
                gate: Some(gate),
                file,
                pos: offset,
                end,
                chunk: chunk.max(1),
            })),
            Ok(Err(reason)) => {
                self.release_gate(id, gate);
                if reason == BlobReject::Expired {
                    self.expire_if_due(id, now).await?;
                }
                Ok(Err(reason))
            }
            Err(err) => {
                self.release_gate(id, gate);
                Err(err)
            }
        }
    }

    async fn open_file_locked(
        &self,
        id: &BlobId,
        offset: u64,
        length: u64,
        now: u64,
    ) -> Result<Result<(tokio::fs::File, u64), BlobReject>> {
        let live = match self.get_record(id)? {
            None => return Ok(Err(BlobReject::NotFound)),
            Some(BlobRecord::Tomb(tomb)) => return Ok(Err(tomb_reject(&tomb))),
            Some(BlobRecord::Live(live)) if !live.ready => return Ok(Err(BlobReject::NotReady)),
            Some(BlobRecord::Live(live)) if live.expires_at <= now => {
                return Ok(Err(BlobReject::Expired));
            }
            Some(BlobRecord::Live(live)) => live,
        };
        if offset >= live.size {
            return Ok(Err(BlobReject::Invalid));
        }
        let available = live.size - offset;
        let wanted = if length == 0 { available } else { length };
        if wanted > available {
            return Ok(Err(BlobReject::Invalid));
        }
        let window = self.inner.cfg.get_window.max(1);
        let end = offset + wanted.min(window);
        let mut file = match tokio::fs::File::open(self.final_path(id)).await {
            Ok(file) => file,
            Err(err) => {
                return Err(err).context("ready blob has no readable file");
            }
        };
        file.seek(SeekFrom::Start(offset)).await?;
        Ok(Ok((file, end)))
    }

    /// Отпустить блоб от имени устройства. Когда отпустили все, блоб
    /// стирается без надгробия.
    pub async fn release(
        &self,
        id: &BlobId,
        releaser: Releaser,
        now: u64,
    ) -> Result<Result<(), BlobReject>> {
        let live = match self.get_record(id)? {
            None => return Ok(Err(BlobReject::NotFound)),
            Some(BlobRecord::Tomb(tomb)) => return Ok(Err(tomb_reject(&tomb))),
            Some(BlobRecord::Live(live)) if !live.ready => return Ok(Err(BlobReject::NotReady)),
            Some(BlobRecord::Live(live)) if live.expires_at <= now => {
                self.expire_if_due(id, now).await?;
                return Ok(Err(BlobReject::Expired));
            }
            Some(BlobRecord::Live(live)) => live,
        };
        if live.max_releases == 0 || live.released_by.contains(&releaser) {
            return Ok(Ok(()));
        }
        let completes = live.released_by.len() + 1 >= live.max_releases as usize;
        if !completes {
            // Пока ждали замок, другие устройства могли отпустить блоб, и
            // этот релиз стал последним: тогда — путь с удержанием ворот.
            let added = {
                let _meta = self.meta();
                self.add_releaser_locked(id, releaser, now)?
            };
            if let Some(result) = added {
                return Ok(result);
            }
        }
        let exclusive = self.exclusive(id).await;
        let outcome = self.last_release_locked(id, releaser, now);
        self.finish_exclusive(exclusive, gone_of(&outcome));
        outcome.map(|(result, _)| result)
    }

    /// Релиз, который может оказаться последним. Ворота и слот держит
    /// вызывающий.
    fn last_release_locked(&self, id: &BlobId, releaser: Releaser, now: u64) -> Removal {
        let _meta = self.meta();
        match self.get_record(id)? {
            Some(BlobRecord::Live(current))
                if current.ready
                    && current.expires_at > now
                    && !current.released_by.contains(&releaser)
                    && current.released_by.len() + 1 >= current.max_releases as usize =>
            {
                self.remove_live_locked(id, &current, None, now)?;
                observability::observe_blob_removed("released");
                Ok((Ok(()), Some(BlobReject::NotFound)))
            }
            // Последний релиз разобран выше, сюда он не доходит.
            _ => Ok((
                self.add_releaser_locked(id, releaser, now)?
                    .unwrap_or(Ok(())),
                None,
            )),
        }
    }

    /// Учесть релиз, который не последний. `None` — релиз оказался
    /// последним: стирать блоб можно только с удержанием ворот, а они под
    /// замком метаданных не берутся. Под замком метаданных.
    fn add_releaser_locked(
        &self,
        id: &BlobId,
        releaser: Releaser,
        now: u64,
    ) -> Result<Option<Result<(), BlobReject>>> {
        let mut live = match self.get_record(id)? {
            Some(BlobRecord::Live(live)) if live.ready && live.expires_at > now => live,
            Some(BlobRecord::Live(live)) if live.ready => {
                return Ok(Some(Err(BlobReject::Expired)));
            }
            Some(BlobRecord::Live(_)) => return Ok(Some(Err(BlobReject::NotReady))),
            Some(BlobRecord::Tomb(tomb)) => return Ok(Some(Err(tomb_reject(&tomb)))),
            None => return Ok(Some(Err(BlobReject::NotFound))),
        };
        if live.max_releases == 0 || live.released_by.contains(&releaser) {
            return Ok(Some(Ok(())));
        }
        if live.released_by.len() + 1 >= live.max_releases as usize {
            return Ok(None);
        }
        let old = BlobRecord::Live(live.clone());
        live.released_by.push(releaser);
        self.put_record(id, Some(&old), &BlobRecord::Live(live))?;
        Ok(Some(Ok(())))
    }

    // --- Управление по токену ---

    /// Удалить блоб загрузившим — в любом состоянии. Остаётся надгробие
    /// `DELETED`; повтор верным токеном — `ok`.
    pub async fn delete(
        &self,
        id: &BlobId,
        token: &[u8; 32],
        now: u64,
    ) -> Result<Result<(), BlobReject>> {
        match self.get_record(id)? {
            None => return Ok(Err(BlobReject::NotFound)),
            Some(BlobRecord::Tomb(_)) => {
                let _meta = self.meta();
                return self.delete_tomb_locked(id, token, now);
            }
            Some(BlobRecord::Live(live)) if !token_matches(token, &live.delete_token_hash) => {
                return Ok(Err(BlobReject::Forbidden));
            }
            Some(BlobRecord::Live(_)) => {}
        }
        let exclusive = self.exclusive(id).await;
        let outcome = self.delete_live_locked(id, token, now);
        self.finish_exclusive(exclusive, gone_of(&outcome));
        outcome.map(|(result, _)| result)
    }

    /// Удаление живого блоба. Ворота и слот держит вызывающий.
    fn delete_live_locked(&self, id: &BlobId, token: &[u8; 32], now: u64) -> Removal {
        let _meta = self.meta();
        match self.get_record(id)? {
            Some(BlobRecord::Live(live)) => {
                if !token_matches(token, &live.delete_token_hash) {
                    return Ok((Err(BlobReject::Forbidden), None));
                }
                self.remove_live_locked(id, &live, Some(TombCause::Deleted), now)?;
                observability::observe_blob_removed("deleted");
                Ok((Ok(()), Some(BlobReject::Deleted)))
            }
            Some(BlobRecord::Tomb(_)) => Ok((self.delete_tomb_locked(id, token, now)?, None)),
            None => Ok((Err(BlobReject::NotFound), None)),
        }
    }

    /// `Delete` по надгробию: удалённое — идемпотентный `ok`; истёкшее
    /// переводится в удалённое, чтобы клиенты не просили его заново.
    fn delete_tomb_locked(
        &self,
        id: &BlobId,
        token: &[u8; 32],
        now: u64,
    ) -> Result<Result<(), BlobReject>> {
        let Some(BlobRecord::Tomb(tomb)) = self.get_record(id)? else {
            return Ok(Err(BlobReject::NotFound));
        };
        if !token_matches(token, &tomb.delete_token_hash) {
            return Ok(Err(BlobReject::Forbidden));
        }
        if tomb.cause == TombCause::Expired {
            let old = BlobRecord::Tomb(tomb.clone());
            let deleted = Tombstone {
                cause: TombCause::Deleted,
                at: now,
                ..tomb
            };
            self.put_record(id, Some(&old), &BlobRecord::Tomb(deleted))?;
        }
        Ok(Ok(()))
    }

    /// Продлить готовый блоб: `expires_at = now + min(ttl, потолок)`.
    pub async fn extend(
        &self,
        id: &BlobId,
        token: &[u8; 32],
        ttl_secs: u64,
        now: u64,
    ) -> Result<Result<u64, BlobReject>> {
        let expired = {
            let _meta = self.meta();
            let mut live = match self.get_record(id)? {
                None => return Ok(Err(BlobReject::NotFound)),
                Some(BlobRecord::Tomb(tomb)) => return Ok(Err(tomb_reject(&tomb))),
                Some(BlobRecord::Live(live)) => live,
            };
            if !token_matches(token, &live.delete_token_hash) {
                return Ok(Err(BlobReject::Forbidden));
            }
            if !live.ready {
                return Ok(Err(BlobReject::NotReady));
            }
            if live.expires_at > now {
                let old = BlobRecord::Live(live.clone());
                live.expires_at = now.saturating_add(self.clamp_ttl(ttl_secs));
                let expires_at = live.expires_at;
                self.put_record(id, Some(&old), &BlobRecord::Live(live))?;
                return Ok(Ok(expires_at));
            }
            true
        };
        if expired {
            self.expire_if_due(id, now).await?;
        }
        Ok(Err(BlobReject::Expired))
    }

    /// Проверка наличия пачкой; ничего не меняет.
    pub fn stat(&self, queries: &[StatQuery], now: u64) -> Result<Vec<StatEntry>> {
        queries
            .iter()
            .map(|query| {
                let (id, token) = match query {
                    StatQuery::Reader(id) => (id, None),
                    StatQuery::Manager { id, token } => (id, Some(token)),
                };
                self.stat_one(id, token.map(|token| &**token), now)
            })
            .collect()
    }

    fn stat_one(&self, id: &BlobId, token: Option<&[u8; 32]>, now: u64) -> Result<StatEntry> {
        let entry = |state, expires_at| StatEntry {
            state,
            expires_at,
            releases: None,
        };
        let live = match self.get_record(id)? {
            None => return Ok(entry(StatState::NotFound, 0)),
            Some(BlobRecord::Tomb(tomb)) if tomb.until <= now => {
                return Ok(entry(StatState::NotFound, 0));
            }
            Some(BlobRecord::Tomb(tomb)) => {
                return Ok(entry(
                    match tomb.cause {
                        TombCause::Expired => StatState::Expired,
                        TombCause::Deleted => StatState::Deleted,
                    },
                    0,
                ));
            }
            Some(BlobRecord::Live(live)) => live,
        };
        if let Some(token) = token
            && !token_matches(token, &live.delete_token_hash)
        {
            return Ok(entry(StatState::Forbidden, 0));
        }
        let mut result = if live.ready {
            if live.expires_at <= now {
                entry(StatState::Expired, 0)
            } else {
                entry(StatState::Ready, live.expires_at)
            }
        } else {
            let stale_at = live
                .last_activity
                .saturating_add(self.inner.cfg.upload_stale_secs);
            if stale_at <= now {
                entry(StatState::NotFound, 0)
            } else {
                entry(StatState::Uploading, stale_at)
            }
        };
        if token.is_some() && matches!(result.state, StatState::Ready | StatState::Uploading) {
            let done = u32::try_from(live.released_by.len()).unwrap_or(u32::MAX);
            result.releases = Some((done, live.max_releases));
        }
        Ok(result)
    }

    // --- Чистка ---

    /// Один проход чистки по индексу сроков.
    pub async fn cleanup(&self, now: u64) -> Result<CleanupReport> {
        let mut report = CleanupReport::default();
        let bound = expiry_key(now.saturating_add(1), &[0u8; 32]);
        let due: Vec<(u64, BlobId)> = self
            .inner
            .expiry
            .range(..bound.as_slice())
            .keys()
            .filter_map(|key| key.ok().and_then(|key| parse_expiry_key(&key)))
            .collect();
        for (due_at, id) in due {
            let record = self.get_record(&id)?;
            let stale_key = match &record {
                None => true,
                Some(record) => record.due_at(self.inner.cfg.upload_stale_secs) != due_at,
            };
            if stale_key {
                // Индекс разошёлся с записью: ключ лишний, а нужный ключ
                // записи уже стоит (его ставит каждая запись записи).
                self.inner.expiry.remove(expiry_key(due_at, &id))?;
                continue;
            }
            match record {
                Some(BlobRecord::Live(live)) if live.ready => {
                    if self.expire_if_due(&id, now).await? {
                        report.expired += 1;
                    }
                }
                Some(BlobRecord::Live(_)) => {
                    if self.drop_stale_upload(&id, now).await? {
                        report.stale_uploads += 1;
                    }
                }
                Some(BlobRecord::Tomb(_)) => {
                    let _meta = self.meta();
                    if let Some(BlobRecord::Tomb(tomb)) = self.get_record(&id)?
                        && tomb.until <= now
                    {
                        self.delete_record(&id, &BlobRecord::Tomb(tomb))?;
                        report.tombstones += 1;
                    }
                }
                None => {}
            }
        }
        Ok(report)
    }

    /// Истечь готовый блоб, если срок наступил. `true` — истёк сейчас.
    async fn expire_if_due(&self, id: &BlobId, now: u64) -> Result<bool> {
        let exclusive = self.exclusive(id).await;
        let outcome = self.remove_due_locked(id, true, now);
        let gone = matches!(outcome, Ok(true)).then_some(BlobReject::Expired);
        self.finish_exclusive(exclusive, gone);
        outcome
    }

    /// Снять загрузку, которую не продолжали дольше `upload_stale_secs`.
    async fn drop_stale_upload(&self, id: &BlobId, now: u64) -> Result<bool> {
        let exclusive = self.exclusive(id).await;
        let outcome = self.remove_due_locked(id, false, now);
        let gone = matches!(outcome, Ok(true)).then_some(BlobReject::NotFound);
        self.finish_exclusive(exclusive, gone);
        outcome
    }

    /// Стереть блоб, чей срок наступил: готовый — с надгробием `EXPIRED`,
    /// протухшую загрузку — без. `ready` — какой ждём; запись другого вида
    /// или с ещё не наступившим сроком не трогается.
    fn remove_due_locked(&self, id: &BlobId, ready: bool, now: u64) -> Result<bool> {
        let _meta = self.meta();
        let Some(record @ BlobRecord::Live(_)) = self.get_record(id)? else {
            return Ok(false);
        };
        if record.due_at(self.inner.cfg.upload_stale_secs) > now {
            return Ok(false);
        }
        let BlobRecord::Live(live) = record else {
            return Ok(false);
        };
        if live.ready != ready {
            return Ok(false);
        }
        let (tomb, cause) = if ready {
            (Some(TombCause::Expired), "expired")
        } else {
            (None, "stale")
        };
        self.remove_live_locked(id, &live, tomb, now)?;
        observability::observe_blob_removed(cause);
        Ok(true)
    }

    /// Соединение закрылось: его дескрипторы загрузок больше не нужны.
    /// Следующий кусок любого соединения откроет файл заново.
    pub fn detach_connection(&self, conn: u64) {
        let ids: Vec<BlobId> = self
            .inner
            .uploads
            .iter()
            .filter_map(|entry| {
                let mut slot = entry.value().try_lock().ok()?;
                (slot.conn == conn).then(|| {
                    slot.file = None;
                    slot.conn = 0;
                    *entry.key()
                })
            })
            .collect();
        for id in ids {
            // Ссылка карты отпускается до `release_slot`: тот берёт замок
            // того же шарда.
            let slot = self.inner.uploads.get(&id).map(|entry| entry.clone());
            if let Some(slot) = slot {
                self.release_slot(&id, slot);
            }
        }
    }

    // --- Внутреннее ---

    fn meta(&self) -> MutexGuard<'_, ()> {
        self.inner
            .meta
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn subdir(&self, id: &BlobId) -> PathBuf {
        self.inner.dir.join(hex::encode(&id[..1]))
    }

    fn final_path(&self, id: &BlobId) -> PathBuf {
        self.subdir(id).join(hex::encode(id))
    }

    fn part_path(&self, id: &BlobId) -> PathBuf {
        self.subdir(id).join(format!("{}.part", hex::encode(id)))
    }

    /// Запись блоба. Неразбираемая читается как отсутствующая: её стирает
    /// сверка при старте.
    fn get_record(&self, id: &BlobId) -> Result<Option<BlobRecord>> {
        Ok(self
            .inner
            .blobs
            .get(id)
            .context("failed to read a blob record")?
            .and_then(|raw| BlobRecord::decode(&raw)))
    }

    /// Загрузка этого пользователя, ещё не законченная.
    fn uploading(&self, uploader: &UserId, id: &BlobId) -> Result<Result<LiveBlob, ChunkReject>> {
        let reject = |reason, expected_offset| {
            Ok(Err(ChunkReject {
                reason,
                expected_offset,
            }))
        };
        match self.get_record(id)? {
            None => reject(BlobReject::NotFound, 0),
            Some(BlobRecord::Tomb(tomb)) => reject(tomb_reject(&tomb), 0),
            Some(BlobRecord::Live(live)) if live.uploader != *uploader => {
                reject(BlobReject::Forbidden, 0)
            }
            Some(BlobRecord::Live(live)) if live.ready => reject(BlobReject::Invalid, live.size),
            Some(BlobRecord::Live(live)) => Ok(Ok(live)),
        }
    }

    /// Почему слот загрузки мёртв.
    fn gone_reason(&self, id: &BlobId) -> Result<BlobReject> {
        Ok(match self.get_record(id)? {
            Some(BlobRecord::Tomb(tomb)) => tomb_reject(&tomb),
            Some(BlobRecord::Live(live)) if live.ready => BlobReject::Invalid,
            Some(BlobRecord::Live(_)) => BlobReject::Internal,
            None => BlobReject::NotFound,
        })
    }

    /// Записать запись и переставить её ключ в индексе сроков.
    fn put_record(&self, id: &BlobId, old: Option<&BlobRecord>, new: &BlobRecord) -> Result<()> {
        let stale_secs = self.inner.cfg.upload_stale_secs;
        self.inner.blobs.insert(id, new.encode())?;
        let new_due = new.due_at(stale_secs);
        if let Some(old) = old {
            let old_due = old.due_at(stale_secs);
            if old_due != new_due {
                self.inner.expiry.remove(expiry_key(old_due, id))?;
            }
        }
        self.inner
            .expiry
            .insert(expiry_key(new_due, id), IVec::default())?;
        Ok(())
    }

    fn delete_record(&self, id: &BlobId, old: &BlobRecord) -> Result<()> {
        self.inner.blobs.remove(id)?;
        self.inner
            .expiry
            .remove(expiry_key(old.due_at(self.inner.cfg.upload_stale_secs), id))?;
        Ok(())
    }

    /// Стереть живой блоб: сначала файл, потом метаданные; освободить
    /// квоты. `tomb` — оставить надгробие с этой причиной. Под замком
    /// метаданных; ворота и слот держит вызывающий.
    fn remove_live_locked(
        &self,
        id: &BlobId,
        live: &LiveBlob,
        tomb: Option<TombCause>,
        now: u64,
    ) -> Result<()> {
        for path in [self.final_path(id), self.part_path(id)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err).context("failed to remove a blob file"),
            }
        }
        let old = BlobRecord::Live(live.clone());
        match tomb {
            Some(cause) => self.put_record(
                id,
                Some(&old),
                &BlobRecord::Tomb(Tombstone {
                    cause,
                    at: now,
                    until: now.saturating_add(self.inner.cfg.tombstone_secs),
                    delete_token_hash: live.delete_token_hash,
                }),
            )?,
            None => self.delete_record(id, &old)?,
        }
        self.account(live, Sign::Sub)
    }

    /// Учесть блоб в квотах и итогах (`Add` — при `Init`, `Sub` — при
    /// удалении). Под замком метаданных.
    fn account(&self, live: &LiveBlob, sign: Sign) -> Result<()> {
        let delta = |value: u64| match sign {
            Sign::Add => i128::from(value),
            Sign::Sub => -i128::from(value),
        };
        let charge = self.charge(live.size);
        self.adjust_usage(&owner_usage_key(&live.owner), delta(charge))?;
        if !live.is_own() {
            self.adjust_usage(&pair_usage_key(&live.owner, &live.uploader), delta(charge))?;
        }
        let totals = &self.inner.totals;
        let (bytes, count) = if live.ready {
            (&totals.ready_bytes, &totals.ready_count)
        } else {
            (&totals.uploading_bytes, &totals.uploading_count)
        };
        match sign {
            Sign::Add => {
                bytes.fetch_add(live.size, Ordering::Relaxed);
                count.fetch_add(1, Ordering::Relaxed);
            }
            Sign::Sub => {
                saturating_sub(bytes, live.size);
                saturating_sub(count, 1);
            }
        }
        self.publish_totals();
        Ok(())
    }

    /// Загрузка стала готовым блобом: квоты те же, меняются итоги.
    fn move_to_ready(&self, live: &LiveBlob) {
        let totals = &self.inner.totals;
        saturating_sub(&totals.uploading_bytes, live.size);
        saturating_sub(&totals.uploading_count, 1);
        totals.ready_bytes.fetch_add(live.size, Ordering::Relaxed);
        totals.ready_count.fetch_add(1, Ordering::Relaxed);
        self.publish_totals();
    }

    fn publish_totals(&self) {
        let totals = &self.inner.totals;
        observability::set_blob_usage(
            totals.ready_bytes.load(Ordering::Relaxed),
            totals.ready_count.load(Ordering::Relaxed),
            totals.uploading_bytes.load(Ordering::Relaxed),
            totals.uploading_count.load(Ordering::Relaxed),
        );
    }

    fn usage_of(&self, key: &[u8]) -> Result<u64> {
        Ok(self.inner.usage.get(key)?.map_or(0, |raw| decode_u64(&raw)))
    }

    fn adjust_usage(&self, key: &[u8], delta: i128) -> Result<()> {
        let next = i128::from(self.usage_of(key)?) + delta;
        let next = u64::try_from(next.max(0)).unwrap_or(u64::MAX);
        if next == 0 {
            self.inner.usage.remove(key)?;
        } else {
            self.inner.usage.insert(key, &next.to_be_bytes())?;
        }
        Ok(())
    }

    fn gate(&self, id: &BlobId) -> Arc<Gate> {
        self.inner.gates.entry(*id).or_default().clone()
    }

    /// Отпустить ворота; запись карты уходит, когда их больше никто не
    /// держит. Проверка счётчика идёт под замком шарда, а новые ссылки
    /// появляются только под ним же — гонки с `gate()` нет.
    fn release_gate(&self, id: &BlobId, gate: Arc<Gate>) {
        drop(gate);
        self.inner
            .gates
            .remove_if(id, |_, gate| Arc::strong_count(gate) == 1);
    }

    fn slot(&self, id: &BlobId) -> Arc<AsyncMutex<UploadSlot>> {
        self.inner.uploads.entry(*id).or_default().clone()
    }

    /// Отпустить слот. Слот без открытого файла и без других держателей
    /// уходит из карты: новый на его месте ничем от него не отличается —
    /// первый кусок всё равно переоткроет файл с последнего сброса.
    fn release_slot(&self, id: &BlobId, slot: Arc<AsyncMutex<UploadSlot>>) {
        drop(slot);
        self.inner.uploads.remove_if(id, |_, slot| {
            Arc::strong_count(slot) == 1 && slot.try_lock().is_ok_and(|slot| slot.file.is_none())
        });
    }

    async fn exclusive(&self, id: &BlobId) -> Exclusive {
        let gate = self.gate(id);
        let gate_guard = gate.state.clone().write_owned().await;
        let slot = self.slot(id);
        let slot_guard = slot.clone().lock_owned().await;
        Exclusive {
            id: *id,
            gate,
            gate_guard,
            slot,
            slot_guard,
        }
    }

    /// Отпустить удержание. `gone` — блоб стёрт с этой причиной: ворота
    /// закрываются (идущие скачивания получат её вместо данных), слот
    /// умирает и закрывает файл.
    fn finish_exclusive(&self, exclusive: Exclusive, gone: Option<BlobReject>) {
        let Exclusive {
            id,
            gate,
            mut gate_guard,
            slot,
            mut slot_guard,
        } = exclusive;
        if let Some(reason) = gone {
            *gate_guard = Some(reason);
            gate.closed.store(reject_code(reason), Ordering::SeqCst);
            slot_guard.dead = true;
            slot_guard.file = None;
        }
        drop(slot_guard);
        drop(gate_guard);
        self.release_slot(&id, slot);
        self.release_gate(&id, gate);
    }
}

/// Поток ответа на один `BlobGet`.
pub struct BlobReader {
    store: BlobStore,
    id: BlobId,
    gate: Option<Arc<Gate>>,
    file: tokio::fs::File,
    pos: u64,
    end: u64,
    chunk: usize,
}

impl BlobReader {
    /// Следующий кусок; `Ok(Ok(None))` — ответ отдан целиком. Причина
    /// вместо куска — блоб стёрт посреди ответа.
    pub async fn next_chunk(&mut self) -> Result<Result<Option<ReadChunk>, BlobReject>> {
        if self.pos >= self.end {
            return Ok(Ok(None));
        }
        let Some(gate) = self.gate.as_ref() else {
            return Ok(Err(BlobReject::Internal));
        };
        let guard = gate.state.read().await;
        if let Some(reason) = *guard {
            return Ok(Err(reason));
        }
        let len = usize::try_from(self.end - self.pos)
            .unwrap_or(usize::MAX)
            .min(self.chunk);
        let mut data = vec![0u8; len];
        self.file
            .read_exact(&mut data)
            .await
            .context("failed to read a blob file")?;
        drop(guard);
        let offset = self.pos;
        self.pos += len as u64;
        observability::observe_blob_bytes("download", len as u64);
        Ok(Ok(Some(ReadChunk {
            offset,
            data,
            eof: self.pos == self.end,
        })))
    }

    /// Закрыты ли ворота — без замка. Сессия проверяет это перед отправкой
    /// уже прочитанного куска.
    pub fn interrupted(&self) -> Option<BlobReject> {
        self.gate
            .as_ref()
            .and_then(|gate| reject_from_code(gate.closed.load(Ordering::SeqCst)))
    }
}

impl Drop for BlobReader {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.take() {
            self.store.release_gate(&self.id, gate);
        }
    }
}

fn tomb_reject(tomb: &Tombstone) -> BlobReject {
    match tomb.cause {
        TombCause::Expired => BlobReject::Expired,
        TombCause::Deleted => BlobReject::Deleted,
    }
}

/// Ошибка диска как ответ клиенту: кончилось место — `QUOTA`, остальное —
/// сбой ноды.
fn io_reject(err: &io::Error) -> Result<BlobReject> {
    if err.kind() == io::ErrorKind::StorageFull {
        warn!(error = %err, "blob directory is out of space");
        return Ok(BlobReject::Quota);
    }
    Err(anyhow::anyhow!("blob file I/O failed: {err}"))
}

fn reject_code(reason: BlobReject) -> u8 {
    u8::try_from(reason.to_wire()).unwrap_or(u8::MAX)
}

fn reject_from_code(code: u8) -> Option<BlobReject> {
    [
        BlobReject::NotFound,
        BlobReject::Expired,
        BlobReject::Deleted,
    ]
    .into_iter()
    .find(|reason| reject_code(*reason) == code)
}

fn decode_u64(raw: &[u8]) -> u64 {
    raw.try_into().map_or(0, u64::from_be_bytes)
}

/// Вычесть без ухода ниже нуля. Итоги меняются только под замком
/// метаданных, поэтому чтение и запись не обязаны быть одной операцией.
fn saturating_sub(counter: &AtomicU64, value: u64) {
    let current = counter.load(Ordering::Relaxed);
    counter.store(current.saturating_sub(value), Ordering::Relaxed);
}

/// SHA-256 первых `size` байт файла; `None` — файл короче.
fn sha256_of_prefix(path: &Path, size: u64) -> io::Result<Option<[u8; 32]>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() < size {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let len = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        file.read_exact(&mut buffer[..len])?;
        hasher.update(&buffer[..len]);
        remaining -= len as u64;
    }
    Ok(Some(hasher.finalize().into()))
}

/// Сбросить каталог после `rename`, чтобы переименование пережило падение.
/// Не вышло — не беда: сверка при старте разберётся с осиротевшим файлом.
async fn sync_dir(dir: &Path) {
    if let Ok(handle) = tokio::fs::File::open(dir).await {
        let _ = handle.sync_all().await;
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::*;
    use crate::blob::record::Releaser;
    use crate::blob::{blob_id_of, token_hash};
    use crate::state::queues::{AllocateParams, QueueStore};

    const NOW: u64 = 1_700_000_000;
    const OWNER: UserId = [1u8; 32];
    const SENDER: UserId = [2u8; 32];
    const STRANGER: UserId = [3u8; 32];
    const TOKEN: [u8; 32] = [9u8; 32];

    struct Fixture {
        store: BlobStore,
        db: sled::Db,
        path: PathBuf,
        cfg: BlobConfig,
        queue: [u8; 32],
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn config(path: &std::path::Path) -> BlobConfig {
        BlobConfig {
            dir: path.join("blobs").to_string_lossy().into_owned(),
            max_size: 1024 * 1024,
            max_ttl_secs: 3_600,
            quota_per_owner: 64 * 1024,
            quota_per_pair: 32 * 1024,
            upload_bytes_per_day: 0,
            disk_reserve: 0,
            upload_stale_secs: 600,
            tombstone_secs: 1_200,
            get_window: 4 * 1024,
            sync_every: 1024,
            // Квоты в этих тестах меряются настоящими размерами; минимальный
            // учётный размер — в своём тесте.
            min_charge: 0,
            ..BlobConfig::default()
        }
    }

    fn fixture(label: &str) -> Fixture {
        fixture_with(label, config)
    }

    fn fixture_with(label: &str, tune: impl FnOnce(&std::path::Path) -> BlobConfig) -> Fixture {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("trust_message_tcp_blob_{label}_{nanos}"));
        let db = sled::open(&path).unwrap();
        let queues = QueueStore::open(&db).unwrap();
        let queue = [7u8; 32];
        queues
            .allocate(
                &OWNER,
                queue,
                AllocateParams::parse(&[], 0, false, NOW).unwrap(),
                NOW,
                0,
            )
            .unwrap()
            .unwrap();
        let cfg = tune(&path);
        let store = BlobStore::open(&db, &cfg).unwrap();
        Fixture {
            store,
            db,
            path,
            cfg,
            queue,
        }
    }

    impl Fixture {
        /// Переоткрыть хранилище на той же базе — так выглядит рестарт ноды
        /// для сверки.
        fn reopen(&mut self) {
            self.store = BlobStore::open(&self.db, &self.cfg).unwrap();
        }

        fn queues(&self) -> QueueStore {
            QueueStore::open(&self.db).unwrap()
        }
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ seed)
            .collect()
    }

    fn secret(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn request(queue: Option<[u8; 32]>, data: &[u8], seed: u8) -> InitRequest {
        InitRequest {
            queue_id: queue,
            size: data.len() as u64,
            sha256: Sha256::digest(data).into(),
            ttl_secs: 0,
            max_releases: 0,
            blob_id: blob_id_of(&secret(seed)),
            delete_token_hash: token_hash(&TOKEN),
        }
    }

    /// Загрузить целиком кусками по 512 байт от имени `uploader`.
    async fn upload(store: &BlobStore, uploader: &UserId, req: &InitRequest, data: &[u8]) -> u64 {
        store.init(uploader, req, NOW).unwrap().unwrap();
        for (index, chunk) in data.chunks(512).enumerate() {
            store
                .write_chunk(1, uploader, &req.blob_id, (index * 512) as u64, chunk, NOW)
                .await
                .unwrap()
                .unwrap();
        }
        store
            .commit(uploader, &req.blob_id, NOW)
            .await
            .unwrap()
            .unwrap()
    }

    async fn read_all(store: &BlobStore, id: &BlobId, offset: u64, length: u64) -> Vec<u8> {
        let mut reader = store
            .open_reader(id, offset, length, 300, NOW)
            .await
            .unwrap()
            .unwrap();
        let mut out = Vec::new();
        let mut expected_offset = offset;
        while let Some(chunk) = reader.next_chunk().await.unwrap().unwrap() {
            assert_eq!(chunk.offset, expected_offset);
            assert!(chunk.data.len() <= 300);
            expected_offset += chunk.data.len() as u64;
            out.extend_from_slice(&chunk.data);
            if chunk.eof {
                assert!(reader.next_chunk().await.unwrap().unwrap().is_none());
                break;
            }
        }
        out
    }

    fn reader_of(device: u8) -> Releaser {
        Releaser {
            user: OWNER,
            device: Some(u16::from(device)),
        }
    }

    fn usage(fixture: &Fixture, key: &[u8]) -> u64 {
        fixture.store.usage_of(key).unwrap()
    }

    #[tokio::test]
    async fn upload_commit_and_read_whole_and_ranges() {
        let fx = fixture("roundtrip");
        let data = payload(3_000, 1);
        let req = request(Some(fx.queue), &data, 1);
        let expires_at = upload(&fx.store, &SENDER, &req, &data).await;
        assert_eq!(expires_at, NOW + 3_600, "ttl 0 — потолок");

        assert_eq!(read_all(&fx.store, &req.blob_id, 0, 0).await, data);
        assert_eq!(
            read_all(&fx.store, &req.blob_id, 100, 50).await,
            data[100..150]
        );
        assert_eq!(
            read_all(&fx.store, &req.blob_id, 2_999, 0).await,
            data[2_999..]
        );

        // Диапазон за пределами — отказ, не паника.
        for (offset, length) in [(3_000, 0), (2_000, 1_001), (u64::MAX, 1)] {
            let refused = fx
                .store
                .open_reader(&req.blob_id, offset, length, 300, NOW)
                .await
                .unwrap();
            assert!(
                matches!(refused, Err(BlobReject::Invalid)),
                "{offset}+{length}"
            );
        }
        // Квота владельца очереди и пары считается по размеру.
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 3_000);
        assert_eq!(usage(&fx, &pair_usage_key(&OWNER, &SENDER)), 3_000);
        // Повтор `Commit` — тот же срок.
        assert_eq!(
            fx.store
                .commit(&SENDER, &req.blob_id, NOW + 5)
                .await
                .unwrap(),
            Ok(expires_at)
        );
        // Готовый файл лежит под hex id в подкаталоге первого байта.
        assert!(fx.store.final_path(&req.blob_id).exists());
        assert!(!fx.store.part_path(&req.blob_id).exists());
        assert!(fx.store.inner.uploads.is_empty(), "слоты отпущены");
    }

    #[tokio::test]
    async fn one_get_returns_at_most_the_window() {
        let fx = fixture("window");
        let data = payload(10_000, 2);
        let req = request(None, &data, 2);
        upload(&fx.store, &SENDER, &req, &data).await;
        // Окно — 4 КиБ: запрос «до конца» отдаёт его начало.
        assert_eq!(read_all(&fx.store, &req.blob_id, 0, 0).await, data[..4_096]);
        assert_eq!(
            read_all(&fx.store, &req.blob_id, 8_192, 0).await,
            data[8_192..]
        );
    }

    #[tokio::test]
    async fn hash_or_size_mismatch_removes_the_blob() {
        let fx = fixture("mismatch");
        let data = payload(2_000, 3);
        let mut req = request(Some(fx.queue), &data, 3);
        req.sha256 = [0u8; 32];
        fx.store.init(&SENDER, &req, NOW).unwrap().unwrap();
        fx.store
            .write_chunk(1, &SENDER, &req.blob_id, 0, &data, NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.store.commit(&SENDER, &req.blob_id, NOW).await.unwrap(),
            Err(BlobReject::Invalid)
        );
        assert_eq!(
            fx.store.status(&SENDER, &req.blob_id, NOW).unwrap(),
            Err(BlobReject::NotFound)
        );
        assert!(!fx.store.part_path(&req.blob_id).exists());
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 0);

        // Без надгробия id снова свободен; недогруженный `Commit` — тоже INVALID.
        let req = request(Some(fx.queue), &data, 3);
        fx.store.init(&SENDER, &req, NOW).unwrap().unwrap();
        fx.store
            .write_chunk(1, &SENDER, &req.blob_id, 0, &data[..1_500], NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.store.commit(&SENDER, &req.blob_id, NOW).await.unwrap(),
            Err(BlobReject::Invalid)
        );
        assert_eq!(usage(&fx, &pair_usage_key(&OWNER, &SENDER)), 0);
    }

    #[tokio::test]
    async fn chunks_are_sequential_and_resume_from_the_last_sync() {
        let fx = fixture("resume");
        let data = payload(5_000, 4);
        let req = request(None, &data, 4);
        fx.store.init(&SENDER, &req, NOW).unwrap().unwrap();
        let id = req.blob_id;

        // Дыра — INVALID с ожидаемым смещением.
        let skipped = fx
            .store
            .write_chunk(1, &SENDER, &id, 512, &data[512..1_024], NOW)
            .await
            .unwrap();
        assert_eq!(
            skipped,
            Err(ChunkReject {
                reason: BlobReject::Invalid,
                expected_offset: 0,
            })
        );
        // 1000 байт — до порога сброса (1024) прогресса нет; ещё 200 — есть.
        let first = fx
            .store
            .write_chunk(1, &SENDER, &id, 0, &data[..1_000], NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.synced, None);
        let second = fx
            .store
            .write_chunk(1, &SENDER, &id, 1_000, &data[1_000..1_200], NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.synced, Some(1_200));
        // Несброшенное соединения 1 после обрыва пропадает.
        fx.store
            .write_chunk(1, &SENDER, &id, 1_200, &data[1_200..1_500], NOW)
            .await
            .unwrap()
            .unwrap();
        fx.store.detach_connection(1);
        assert!(fx.store.inner.uploads.is_empty(), "дескриптор закрыт");
        let status = fx.store.status(&SENDER, &id, NOW + 10).unwrap().unwrap();
        assert_eq!(status.committed_offset, 1_200);
        assert_eq!(status.expires_at, NOW + 600, "срок протухания загрузки");

        // Другое соединение того же загрузившего продолжает с 1200.
        let stale_offset = fx
            .store
            .write_chunk(2, &SENDER, &id, 1_500, &data[1_500..2_000], NOW)
            .await
            .unwrap();
        assert_eq!(
            stale_offset,
            Err(ChunkReject {
                reason: BlobReject::Invalid,
                expected_offset: 1_200,
            })
        );
        for start in (1_200..5_000).step_by(700) {
            let end = (start + 700).min(5_000);
            fx.store
                .write_chunk(2, &SENDER, &id, start as u64, &data[start..end], NOW)
                .await
                .unwrap()
                .unwrap();
        }
        // Кусок за объявленным размером — INVALID.
        let beyond = fx
            .store
            .write_chunk(2, &SENDER, &id, 5_000, b"x", NOW)
            .await
            .unwrap();
        assert!(matches!(
            beyond,
            Err(ChunkReject {
                reason: BlobReject::Invalid,
                ..
            })
        ));
        fx.store.commit(&SENDER, &id, NOW).await.unwrap().unwrap();
        assert_eq!(read_all(&fx.store, &id, 0, 0).await, data[..4_096]);
        assert_eq!(read_all(&fx.store, &id, 4_096, 0).await, data[4_096..]);
        // Кусок после коммита — INVALID с полным размером.
        let late = fx
            .store
            .write_chunk(2, &SENDER, &id, 0, b"x", NOW)
            .await
            .unwrap();
        assert_eq!(
            late,
            Err(ChunkReject {
                reason: BlobReject::Invalid,
                expected_offset: 5_000,
            })
        );
    }

    #[tokio::test]
    async fn rights_conflicts_and_limits() {
        let fx = fixture("rights");
        let data = payload(1_000, 5);
        let req = request(Some(fx.queue), &data, 5);
        fx.store.init(&SENDER, &req, NOW).unwrap().unwrap();

        // Чужая загрузка.
        let chunk = fx
            .store
            .write_chunk(1, &STRANGER, &req.blob_id, 0, &data, NOW)
            .await
            .unwrap();
        assert!(matches!(
            chunk,
            Err(ChunkReject {
                reason: BlobReject::Forbidden,
                ..
            })
        ));
        assert_eq!(
            fx.store.commit(&STRANGER, &req.blob_id, NOW).await.unwrap(),
            Err(BlobReject::Forbidden)
        );
        assert_eq!(
            fx.store.status(&STRANGER, &req.blob_id, NOW).unwrap(),
            Err(BlobReject::Forbidden)
        );
        // Занятый id.
        assert_eq!(
            fx.store.init(&STRANGER, &req, NOW).unwrap(),
            Err(BlobReject::Conflict)
        );
        // Неизвестная очередь.
        let mut unknown = request(Some([8u8; 32]), &data, 6);
        assert_eq!(
            fx.store.init(&SENDER, &unknown, NOW).unwrap(),
            Err(BlobReject::Forbidden)
        );
        // Пустой файл, слишком много релизов, слишком большой файл.
        unknown.queue_id = None;
        unknown.size = 0;
        assert_eq!(
            fx.store.init(&SENDER, &unknown, NOW).unwrap(),
            Err(BlobReject::Invalid)
        );
        unknown.size = 10;
        unknown.max_releases = MAX_RELEASES + 1;
        assert_eq!(
            fx.store.init(&SENDER, &unknown, NOW).unwrap(),
            Err(BlobReject::Invalid)
        );
        unknown.max_releases = 0;
        unknown.size = 1024 * 1024 + 1;
        assert_eq!(
            fx.store.init(&SENDER, &unknown, NOW).unwrap(),
            Err(BlobReject::TooLarge)
        );

        // Отозванная очередь: загрузка не стартует, а начатая не коммитится.
        fx.store
            .write_chunk(1, &SENDER, &req.blob_id, 0, &data, NOW)
            .await
            .unwrap()
            .unwrap();
        fx.queues().revoke(&OWNER, &fx.queue, NOW).unwrap().unwrap();
        assert_eq!(
            fx.store
                .init(&SENDER, &request(Some(fx.queue), &data, 7), NOW)
                .unwrap(),
            Err(BlobReject::Forbidden)
        );
        assert_eq!(
            fx.store.commit(&SENDER, &req.blob_id, NOW).await.unwrap(),
            Err(BlobReject::Forbidden)
        );
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 0);
    }

    #[tokio::test]
    async fn quotas_reserve_the_declared_size() {
        let fx = fixture_with("quotas", |path| BlobConfig {
            upload_bytes_per_day: 100 * 1024,
            ..config(path)
        });
        let declared = |seed: u8, size: u64, queue: Option<[u8; 32]>| InitRequest {
            queue_id: queue,
            size,
            sha256: [0u8; 32],
            ttl_secs: 0,
            max_releases: 0,
            blob_id: blob_id_of(&secret(seed)),
            delete_token_hash: token_hash(&TOKEN),
        };
        // Пара: 32 КиБ от одного отправителя в ящик — и всё, даже без байт.
        fx.store
            .init(&SENDER, &declared(10, 20 * 1024, Some(fx.queue)), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.store
                .init(&SENDER, &declared(11, 13 * 1024, Some(fx.queue)), NOW)
                .unwrap(),
            Err(BlobReject::Quota)
        );
        // Другой отправитель — до квоты владельца (64 КиБ).
        fx.store
            .init(&STRANGER, &declared(12, 30 * 1024, Some(fx.queue)), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.store
                .init(&STRANGER, &declared(13, 15 * 1024, Some(fx.queue)), NOW)
                .unwrap(),
            Err(BlobReject::Quota)
        );
        // Свои файлы владельца — в ту же квоту; пара для них не действует.
        fx.store
            .init(&OWNER, &declared(14, 14 * 1024, None), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.store.init(&OWNER, &declared(15, 1, None), NOW).unwrap(),
            Err(BlobReject::Quota)
        );
        // Суточный объём загрузившего: 100 КиБ.
        let heavy = [4u8; 32];
        for seed in 16..18 {
            fx.store
                .init(&heavy, &declared(seed, 30 * 1024, None), NOW)
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            fx.store
                .init(&heavy, &declared(18, 50 * 1024, None), NOW)
                .unwrap(),
            Err(BlobReject::Quota)
        );
        // Новые сутки — новый бюджет (квота владельца у `heavy` своя).
        fx.store
            .init(&heavy, &declared(19, 1024, None), NOW + 86_400)
            .unwrap()
            .unwrap();
    }

    /// Мелкий блоб занимает в квотах не меньше минимального учётного
    /// размера: байтовая квота ограничивает и число файлов.
    #[tokio::test]
    async fn tiny_blobs_are_charged_the_minimum() {
        let mut fx = fixture_with("min_charge", |path| BlobConfig {
            min_charge: 16 * 1024,
            upload_bytes_per_day: 48 * 1024,
            ..config(path)
        });
        let tiny = payload(10, 1);
        // Пара (32 КиБ): два крошечных по 16 КиБ — и всё.
        for seed in 0..2 {
            fx.store
                .init(&SENDER, &request(Some(fx.queue), &tiny, 140 + seed), NOW)
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            fx.store
                .init(&SENDER, &request(Some(fx.queue), &tiny, 142), NOW)
                .unwrap(),
            Err(BlobReject::Quota)
        );
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 32 * 1024);
        // Крупный считается по размеру.
        let big = payload(20 * 1024, 2);
        fx.store
            .init(&STRANGER, &request(Some(fx.queue), &big, 143), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 52 * 1024);
        // Удаление возвращает учтённое; сверка при старте считает так же.
        fx.store
            .delete(&blob_id_of(&secret(140)), &TOKEN, NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 36 * 1024);
        fx.reopen();
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 36 * 1024);
        // Суточный бюджет (48 КиБ) — тоже по учётному размеру: три
        // крошечных по 16 КиБ проходят, четвёртый — нет, хотя квота
        // владельца (64 КиБ) его бы пропустила.
        let heavy = [5u8; 32];
        for seed in 0..3 {
            fx.store
                .init(&heavy, &request(None, &tiny, 150 + seed), NOW)
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            fx.store
                .init(&heavy, &request(None, &tiny, 153), NOW)
                .unwrap(),
            Err(BlobReject::Quota)
        );
    }

    #[tokio::test]
    async fn parallel_inits_do_not_overrun_the_quota() {
        let fx = fixture("parallel");
        let mut tasks = Vec::new();
        for seed in 0..16u8 {
            let store = fx.store.clone();
            let queue = fx.queue;
            tasks.push(tokio::task::spawn_blocking(move || {
                let req = InitRequest {
                    queue_id: Some(queue),
                    size: 8 * 1024,
                    sha256: [0u8; 32],
                    ttl_secs: 0,
                    max_releases: 0,
                    blob_id: blob_id_of(&secret(100 + seed)),
                    delete_token_hash: token_hash(&TOKEN),
                };
                let uploader = [10 + seed; 32];
                store.init(&uploader, &req, NOW).unwrap().is_ok()
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }
        // 64 КиБ / 8 КиБ.
        assert_eq!(accepted, 8);
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 64 * 1024);
    }

    #[tokio::test]
    async fn disk_reserve_refuses_new_uploads() {
        let fx = fixture_with("reserve", |path| BlobConfig {
            disk_reserve: u64::MAX / 2,
            ..config(path)
        });
        let data = payload(10, 1);
        assert_eq!(
            fx.store
                .init(&SENDER, &request(None, &data, 20), NOW)
                .unwrap(),
            Err(BlobReject::Quota)
        );
    }

    #[tokio::test]
    async fn releases_count_distinct_devices() {
        let fx = fixture("releases");
        let data = payload(700, 6);
        let mut req = request(Some(fx.queue), &data, 30);
        req.max_releases = 2;
        upload(&fx.store, &SENDER, &req, &data).await;
        let id = req.blob_id;

        // Одно устройство дважды — блоб жив.
        for _ in 0..2 {
            fx.store
                .release(&id, reader_of(1), NOW)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(read_all(&fx.store, &id, 0, 0).await, data);
        // Второе устройство — блоба нет, квота свободна, надгробия нет.
        fx.store
            .release(&id, reader_of(2), NOW)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            fx.store.open_reader(&id, 0, 0, 300, NOW).await.unwrap(),
            Err(BlobReject::NotFound)
        ));
        assert_eq!(
            fx.store.release(&id, reader_of(3), NOW).await.unwrap(),
            Err(BlobReject::NotFound)
        );
        assert!(!fx.store.final_path(&id).exists());
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 0);
        assert!(
            fx.store.init(&SENDER, &req, NOW).unwrap().is_ok(),
            "id свободен"
        );

        // `max_releases = 0` — живёт до срока.
        let data = payload(100, 7);
        let req = request(None, &data, 31);
        upload(&fx.store, &SENDER, &req, &data).await;
        for device in 0..5 {
            fx.store
                .release(&req.blob_id, reader_of(device), NOW)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(read_all(&fx.store, &req.blob_id, 0, 0).await, data);

        // Релиз и чтение незавершённой загрузки — NOT_READY.
        let pending = request(None, &data, 32);
        fx.store.init(&SENDER, &pending, NOW).unwrap().unwrap();
        assert_eq!(
            fx.store
                .release(&pending.blob_id, reader_of(1), NOW)
                .await
                .unwrap(),
            Err(BlobReject::NotReady)
        );
        assert!(matches!(
            fx.store
                .open_reader(&pending.blob_id, 0, 0, 300, NOW)
                .await
                .unwrap(),
            Err(BlobReject::NotReady)
        ));
    }

    /// Устройства отпускают блоб одновременно: последний релиз стирает его,
    /// даже если каждое при первом взгляде видело себя не последним.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_releases_remove_the_blob_exactly_once() {
        let fx = fixture("concurrent_releases");
        let data = payload(100, 16);
        for seed in 0..20u8 {
            let mut req = request(None, &data, 120 + seed);
            req.max_releases = 3;
            upload(&fx.store, &SENDER, &req, &data).await;
            let releases: Vec<_> = (0..3u8)
                .map(|device| {
                    let store = fx.store.clone();
                    let id = req.blob_id;
                    tokio::spawn(async move { store.release(&id, reader_of(device), NOW).await })
                })
                .collect();
            for release in releases {
                release.await.unwrap().unwrap().unwrap();
            }
            assert_eq!(
                fx.store.status(&SENDER, &req.blob_id, NOW).unwrap(),
                Err(BlobReject::NotFound),
                "блоб {seed} пережил все релизы"
            );
        }
        assert_eq!(usage(&fx, &owner_usage_key(&SENDER)), 0);
    }

    #[tokio::test]
    async fn ttl_is_clamped_extended_and_expires_into_a_tombstone() {
        let fx = fixture("ttl");
        let data = payload(100, 8);
        let mut req = request(None, &data, 40);
        req.ttl_secs = 99_999;
        assert_eq!(upload(&fx.store, &SENDER, &req, &data).await, NOW + 3_600);
        let id = req.blob_id;

        // Продление: от «сейчас», зажато потолком; чужой токен — FORBIDDEN.
        assert_eq!(
            fx.store.extend(&id, &[0u8; 32], 60, NOW).await.unwrap(),
            Err(BlobReject::Forbidden)
        );
        assert_eq!(
            fx.store.extend(&id, &TOKEN, 0, NOW + 100).await.unwrap(),
            Ok(NOW + 3_700)
        );
        assert_eq!(
            fx.store.extend(&id, &TOKEN, 60, NOW + 100).await.unwrap(),
            Ok(NOW + 160)
        );

        // Чистка до срока ничего не трогает, после — надгробие EXPIRED.
        assert_eq!(
            fx.store.cleanup(NOW + 159).await.unwrap(),
            CleanupReport::default()
        );
        let report = fx.store.cleanup(NOW + 160).await.unwrap();
        assert_eq!(report.expired, 1);
        assert!(!fx.store.final_path(&id).exists());
        assert!(matches!(
            fx.store
                .open_reader(&id, 0, 0, 300, NOW + 200)
                .await
                .unwrap(),
            Err(BlobReject::Expired)
        ));
        assert_eq!(
            fx.store.extend(&id, &TOKEN, 60, NOW + 200).await.unwrap(),
            Err(BlobReject::Expired)
        );
        assert_eq!(
            fx.store.init(&SENDER, &req, NOW + 200).unwrap(),
            Err(BlobReject::Conflict),
            "надгробие держит id"
        );
        // Надгробие помнится `tombstone_secs`, потом — NOT_FOUND.
        let report = fx.store.cleanup(NOW + 160 + 1_200).await.unwrap();
        assert_eq!(report.tombstones, 1);
        assert_eq!(
            fx.store
                .release(&id, reader_of(1), NOW + 1_400)
                .await
                .unwrap(),
            Err(BlobReject::NotFound)
        );
    }

    #[tokio::test]
    async fn expiry_is_applied_on_access_before_the_cleanup() {
        let fx = fixture("lazy_expiry");
        let data = payload(100, 9);
        let mut req = request(None, &data, 41);
        req.ttl_secs = 10;
        upload(&fx.store, &SENDER, &req, &data).await;
        assert_eq!(
            fx.store
                .release(&req.blob_id, reader_of(1), NOW + 10)
                .await
                .unwrap(),
            Err(BlobReject::Expired)
        );
        assert!(!fx.store.final_path(&req.blob_id).exists());
        assert_eq!(
            fx.store.status(&SENDER, &req.blob_id, NOW + 11).unwrap(),
            Err(BlobReject::Expired)
        );
    }

    #[tokio::test]
    async fn stale_uploads_are_dropped_without_a_tombstone() {
        let fx = fixture("stale");
        let data = payload(2_000, 10);
        let req = request(Some(fx.queue), &data, 42);
        fx.store.init(&SENDER, &req, NOW).unwrap().unwrap();
        fx.store
            .write_chunk(1, &SENDER, &req.blob_id, 0, &data[..1_100], NOW + 100)
            .await
            .unwrap()
            .unwrap();
        fx.store.detach_connection(1);
        // Протухание считается от последнего сброса на диск.
        assert_eq!(
            fx.store.cleanup(NOW + 650).await.unwrap(),
            CleanupReport::default()
        );
        let report = fx.store.cleanup(NOW + 700).await.unwrap();
        assert_eq!(report.stale_uploads, 1);
        assert!(!fx.store.part_path(&req.blob_id).exists());
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 0);
        assert!(fx.store.init(&SENDER, &req, NOW + 700).unwrap().is_ok());
    }

    #[tokio::test]
    async fn delete_works_in_every_state_and_leaves_a_tombstone() {
        let fx = fixture("delete");
        let data = payload(3_000, 11);

        // Во время загрузки: следующий кусок и коммит получают DELETED.
        let uploading = request(Some(fx.queue), &data, 50);
        fx.store.init(&SENDER, &uploading, NOW).unwrap().unwrap();
        fx.store
            .write_chunk(1, &SENDER, &uploading.blob_id, 0, &data[..512], NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.store
                .delete(&uploading.blob_id, &[1u8; 32], NOW)
                .await
                .unwrap(),
            Err(BlobReject::Forbidden)
        );
        fx.store
            .delete(&uploading.blob_id, &TOKEN, NOW)
            .await
            .unwrap()
            .unwrap();
        assert!(!fx.store.part_path(&uploading.blob_id).exists());
        let next = fx
            .store
            .write_chunk(1, &SENDER, &uploading.blob_id, 512, &data[512..1_024], NOW)
            .await
            .unwrap();
        assert!(matches!(
            next,
            Err(ChunkReject {
                reason: BlobReject::Deleted,
                ..
            })
        ));
        assert_eq!(
            fx.store
                .commit(&SENDER, &uploading.blob_id, NOW)
                .await
                .unwrap(),
            Err(BlobReject::Deleted)
        );
        assert_eq!(
            fx.store.status(&SENDER, &uploading.blob_id, NOW).unwrap(),
            Err(BlobReject::Deleted)
        );

        // После коммита: все операции — DELETED, квоты свободны, файла нет.
        let ready = request(Some(fx.queue), &data, 51);
        upload(&fx.store, &SENDER, &ready, &data).await;
        fx.store
            .delete(&ready.blob_id, &TOKEN, NOW)
            .await
            .unwrap()
            .unwrap();
        assert!(!fx.store.final_path(&ready.blob_id).exists());
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 0);
        assert_eq!(usage(&fx, &pair_usage_key(&OWNER, &SENDER)), 0);
        assert!(matches!(
            fx.store
                .open_reader(&ready.blob_id, 0, 0, 300, NOW)
                .await
                .unwrap(),
            Err(BlobReject::Deleted)
        ));
        assert_eq!(
            fx.store
                .release(&ready.blob_id, reader_of(1), NOW)
                .await
                .unwrap(),
            Err(BlobReject::Deleted)
        );
        assert_eq!(
            fx.store
                .extend(&ready.blob_id, &TOKEN, 1, NOW)
                .await
                .unwrap(),
            Err(BlobReject::Deleted)
        );
        // Повтор: верный токен — ok, чужой — FORBIDDEN.
        assert_eq!(
            fx.store.delete(&ready.blob_id, &TOKEN, NOW).await.unwrap(),
            Ok(())
        );
        assert_eq!(
            fx.store
                .delete(&ready.blob_id, &[1u8; 32], NOW)
                .await
                .unwrap(),
            Err(BlobReject::Forbidden)
        );
        assert_eq!(
            fx.store
                .delete(&blob_id_of(&secret(99)), &TOKEN, NOW)
                .await
                .unwrap(),
            Err(BlobReject::NotFound)
        );

        // Истёкший можно отозвать: надгробие становится DELETED.
        let mut short = request(None, &data, 52);
        short.ttl_secs = 5;
        upload(&fx.store, &SENDER, &short, &data).await;
        fx.store.cleanup(NOW + 5).await.unwrap();
        let stat = |now| {
            fx.store
                .stat(&[StatQuery::Reader(short.blob_id)], now)
                .unwrap()[0]
                .state
        };
        assert_eq!(stat(NOW + 6), StatState::Expired);
        fx.store
            .delete(&short.blob_id, &TOKEN, NOW + 6)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stat(NOW + 7), StatState::Deleted);
    }

    #[tokio::test]
    async fn delete_interrupts_a_running_download() {
        let fx = fixture("delete_download");
        let data = payload(4_000, 12);
        let req = request(None, &data, 53);
        upload(&fx.store, &SENDER, &req, &data).await;

        let mut reader = fx
            .store
            .open_reader(&req.blob_id, 0, 0, 300, NOW)
            .await
            .unwrap()
            .unwrap();
        let first = reader.next_chunk().await.unwrap().unwrap().unwrap();
        assert_eq!(first.data, data[..300]);
        assert_eq!(reader.interrupted(), None);

        fx.store
            .delete(&req.blob_id, &TOKEN, NOW)
            .await
            .unwrap()
            .unwrap();
        // После ответа на Delete из файла не читается ни куска.
        assert_eq!(reader.interrupted(), Some(BlobReject::Deleted));
        assert_eq!(reader.next_chunk().await.unwrap(), Err(BlobReject::Deleted));
        drop(reader);
        assert!(fx.store.inner.gates.is_empty(), "ворота отпущены");
        assert!(fx.store.inner.uploads.is_empty(), "слоты отпущены");
    }

    #[tokio::test]
    async fn expiry_and_last_release_interrupt_downloads_too() {
        let fx = fixture("interrupt_other");
        let data = payload(2_000, 13);
        let mut req = request(None, &data, 54);
        req.ttl_secs = 30;
        upload(&fx.store, &SENDER, &req, &data).await;
        let mut reader = fx
            .store
            .open_reader(&req.blob_id, 0, 0, 300, NOW)
            .await
            .unwrap()
            .unwrap();
        reader.next_chunk().await.unwrap().unwrap().unwrap();
        fx.store.cleanup(NOW + 30).await.unwrap();
        assert_eq!(reader.next_chunk().await.unwrap(), Err(BlobReject::Expired));

        let req = InitRequest {
            max_releases: 1,
            ..request(None, &data, 55)
        };
        upload(&fx.store, &SENDER, &req, &data).await;
        let mut reader = fx
            .store
            .open_reader(&req.blob_id, 0, 0, 300, NOW)
            .await
            .unwrap()
            .unwrap();
        fx.store
            .release(&req.blob_id, reader_of(1), NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reader.next_chunk().await.unwrap(),
            Err(BlobReject::NotFound)
        );
    }

    #[tokio::test]
    async fn stat_reports_every_state_without_changing_anything() {
        let fx = fixture("stat");
        let data = payload(600, 14);

        let mut ready = request(Some(fx.queue), &data, 60);
        ready.max_releases = 3;
        upload(&fx.store, &SENDER, &ready, &data).await;
        fx.store
            .release(&ready.blob_id, reader_of(1), NOW)
            .await
            .unwrap()
            .unwrap();
        let uploading = request(None, &data, 61);
        fx.store.init(&SENDER, &uploading, NOW).unwrap().unwrap();
        let mut expired = request(None, &data, 62);
        expired.ttl_secs = 1;
        upload(&fx.store, &SENDER, &expired, &data).await;
        fx.store.cleanup(NOW + 1).await.unwrap();
        let deleted = request(None, &data, 63);
        upload(&fx.store, &SENDER, &deleted, &data).await;
        fx.store
            .delete(&deleted.blob_id, &TOKEN, NOW)
            .await
            .unwrap()
            .unwrap();

        let manager = |id: BlobId, token: [u8; 32]| StatQuery::Manager {
            id,
            token: Zeroizing::new(token),
        };
        let queries = [
            StatQuery::Reader(ready.blob_id),
            StatQuery::Reader(uploading.blob_id),
            StatQuery::Reader(expired.blob_id),
            StatQuery::Reader(deleted.blob_id),
            StatQuery::Reader(blob_id_of(&secret(200))),
            manager(ready.blob_id, [0u8; 32]),
            manager(ready.blob_id, TOKEN),
            // Токен для надгробия не проверяется.
            manager(deleted.blob_id, [0u8; 32]),
            manager(uploading.blob_id, TOKEN),
        ];
        let before: Vec<_> = fx.store.inner.blobs.iter().collect();
        let entries = fx.store.stat(&queries, NOW + 2).unwrap();
        let states: Vec<StatState> = entries.iter().map(|entry| entry.state).collect();
        assert_eq!(
            states,
            [
                StatState::Ready,
                StatState::Uploading,
                StatState::Expired,
                StatState::Deleted,
                StatState::NotFound,
                StatState::Forbidden,
                StatState::Ready,
                StatState::Deleted,
                StatState::Uploading,
            ]
        );
        assert_eq!(entries[0].expires_at, NOW + 3_600);
        assert_eq!(entries[1].expires_at, NOW + 600);
        // Число релизов — только по токену.
        assert_eq!(entries[0].releases, None);
        assert_eq!(entries[5].releases, None);
        assert_eq!(entries[6].releases, Some((1, 3)));
        assert_eq!(entries[8].releases, Some((0, 0)));
        let after: Vec<_> = fx.store.inner.blobs.iter().collect();
        assert_eq!(before, after, "проверка ничего не меняет");

        // Истёкший, но не вычищенный готовый — EXPIRED, и файл на месте.
        assert_eq!(
            fx.store
                .stat(&[StatQuery::Reader(ready.blob_id)], NOW + 3_600)
                .unwrap()[0]
                .state,
            StatState::Expired
        );
        assert!(fx.store.final_path(&ready.blob_id).exists());
    }

    #[tokio::test]
    async fn reconcile_repairs_a_crash_between_metadata_and_files() {
        let mut fx = fixture("reconcile");
        let data = payload(2_000, 15);

        // Готовый блоб, чей файл пропал (упали между удалением файла и записи).
        let lost = request(None, &data, 70);
        upload(&fx.store, &SENDER, &lost, &data).await;
        std::fs::remove_file(fx.store.final_path(&lost.blob_id)).unwrap();
        // Загрузка, у которой `.part` короче сброшенного.
        let short = request(Some(fx.queue), &data, 71);
        fx.store.init(&SENDER, &short, NOW).unwrap().unwrap();
        fx.store
            .write_chunk(1, &SENDER, &short.blob_id, 0, &data[..1_100], NOW)
            .await
            .unwrap()
            .unwrap();
        fx.store.detach_connection(1);
        std::fs::OpenOptions::new()
            .write(true)
            .open(fx.store.part_path(&short.blob_id))
            .unwrap()
            .set_len(700)
            .unwrap();
        // Загрузка без `.part` (упали между записью и созданием файла).
        let no_part = request(None, &data, 72);
        fx.store.init(&SENDER, &no_part, NOW).unwrap().unwrap();
        std::fs::remove_file(fx.store.part_path(&no_part.blob_id)).unwrap();
        // Переименованный файл загрузки, не переведённой в READY.
        let renamed = request(None, &data, 73);
        fx.store.init(&SENDER, &renamed, NOW).unwrap().unwrap();
        std::fs::write(fx.store.final_path(&renamed.blob_id), &data).unwrap();
        // Файлы без записи и запись, которую не разобрать.
        let orphan = blob_id_of(&secret(74));
        std::fs::create_dir_all(fx.store.subdir(&orphan)).unwrap();
        std::fs::write(fx.store.final_path(&orphan), b"orphan").unwrap();
        std::fs::write(fx.store.part_path(&orphan), b"orphan").unwrap();
        fx.store
            .inner
            .blobs
            .insert([0xEE; 32], &b"junk"[..])
            .unwrap();
        // Чужой файл в каталоге не трогается.
        std::fs::write(fx.path.join("blobs").join("README"), b"operator").unwrap();
        // Сбитые счётчики пересобираются.
        fx.store
            .inner
            .usage
            .insert(owner_usage_key(&OWNER), &999u64.to_be_bytes())
            .unwrap();

        fx.reopen();
        // Второй проход уже ничего не исправляет.
        let report = fx.store.reconcile(NOW).unwrap();
        assert_eq!(
            report,
            reconcile::ReconcileReport {
                blobs: 4,
                ..Default::default()
            }
        );

        // Потерянный файл — «истёк»: отправителя можно попросить перезалить.
        assert_eq!(
            fx.store.status(&SENDER, &lost.blob_id, NOW).unwrap(),
            Err(BlobReject::Expired)
        );
        assert_eq!(
            fx.store
                .status(&SENDER, &short.blob_id, NOW)
                .unwrap()
                .unwrap()
                .committed_offset,
            700
        );
        assert_eq!(
            fx.store
                .status(&SENDER, &no_part.blob_id, NOW)
                .unwrap()
                .unwrap()
                .committed_offset,
            0
        );
        assert!(!fx.store.final_path(&renamed.blob_id).exists());
        assert!(!fx.store.final_path(&orphan).exists());
        assert!(!fx.store.part_path(&orphan).exists());
        assert!(fx.store.inner.blobs.get([0xEE; 32]).unwrap().is_none());
        assert!(fx.path.join("blobs").join("README").exists());
        // Три незавершённые загрузки по 2000 байт: квота пересобрана.
        assert_eq!(usage(&fx, &owner_usage_key(&OWNER)), 2_000);
        assert_eq!(usage(&fx, &owner_usage_key(&SENDER)), 4_000);

        // Загрузку с обрезанным `.part` можно докачать и закоммитить.
        for start in (700..2_000).step_by(500) {
            let end = (start + 500).min(2_000);
            fx.store
                .write_chunk(
                    3,
                    &SENDER,
                    &short.blob_id,
                    start as u64,
                    &data[start..end],
                    NOW,
                )
                .await
                .unwrap()
                .unwrap();
        }
        fx.store
            .commit(&SENDER, &short.blob_id, NOW)
            .await
            .unwrap()
            .unwrap();
    }
}
