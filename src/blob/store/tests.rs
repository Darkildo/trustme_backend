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
    let report = fx.store.reconcile().unwrap();
    assert_eq!(
        report,
        reconcile::ReconcileReport {
            blobs: 3,
            ..Default::default()
        }
    );

    assert_eq!(
        fx.store.status(&SENDER, &lost.blob_id, NOW).unwrap(),
        Err(BlobReject::NotFound)
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
