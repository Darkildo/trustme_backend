//! Офлайн-очереди прямого (sled) бэкенда доставки и общая sled-база ноды.
//!
//! Деревья и форматы (все целые — big-endian):
//! - `inbox` — account-очередь: `recipient(32) || msg_id(u64)` → запись.
//! - `device_inbox` — очередь устройства:
//!   `recipient(32) || device_id(u16) || msg_id(u64)` → запись.
//! - Запись (v5): `created_at_secs(u64) || sender_id(32) ||
//!   has_sender_device(u8) || sender_device_id(u16) || priority(u8) ||
//!   ttl_seconds(u64) || body`.
//! - `queue_stats` — счётчики очередей; пересобираются при каждом старте.
//!   Ключ `prefix` (32 или 34 байта) → `messages(u64) || bytes(u64)`;
//!   ключ `prefix || sender_id` (64 или 66 байт) → `count(u64)`.
//! - `meta` — архив удалённых записей: тот же ключ →
//!   `removed_at_secs(u64) || исходная запись`, живёт по
//!   `deleted_messages_retention`.
//! - `system` — `storage_version` → номер формата записей (сейчас 5).

use crate::config::RetentionPolicy;
use crate::domain::priority::MessagePriority;
use crate::observability;
use crate::state::registry::DeviceId;
use anyhow::{Result, bail};
use sled::{Db, IVec, Tree};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::{task::JoinHandle, time::sleep};
use tracing::{info, warn};

const STORAGE_VERSION_KEY: &[u8] = b"storage_version";
const STORAGE_VERSION_V2: u8 = 2;
const STORAGE_VERSION_V3: u8 = 3;
const STORAGE_VERSION_V4: u8 = 4;
const STORAGE_VERSION_V5: u8 = 5;
const MESSAGE_HEADER_LEN_V3: usize = 8 + 32 + 1 + 2;
const MESSAGE_HEADER_LEN: usize = MESSAGE_HEADER_LEN_V3 + 1; // + priority byte
/// v5 = v4 + ttl_seconds (u64 be) между header и body.
const MESSAGE_HEADER_LEN_V5: usize = MESSAGE_HEADER_LEN + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub id: u64,
    pub sender_id: [u8; 32],
    pub sender_device_id: Option<DeviceId>,
    pub body: Vec<u8>,
    pub priority: Option<MessagePriority>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnqueueResult {
    pub id: u64,
    pub stored: bool,
}

/// Занятость очереди: число записей и суммарный размер значений.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueUsage {
    pub messages: u64,
    pub bytes: u64,
}

/// Потолки, с которыми сверяется квота. `0` — без ограничения.
///
/// Передаются в скан ради ранней остановки: как только любой потолок
/// достигнут, ответ «переполнено» известен и дочитывать очередь незачем.
#[derive(Clone, Copy, Debug, Default)]
pub struct QueueQuotaCeilings {
    pub messages: u64,
    pub bytes: u64,
    pub from_sender: u64,
}

/// Всё, что квотам нужно знать об очереди, за один проход.
///
/// Числа обрезаны потолком: они нужны для сравнения, а не для отчётности.
/// `truncated` означает, что скан остановился досрочно — тогда значения
/// являются нижними границами.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueQuotaScan {
    pub messages: u64,
    pub bytes: u64,
    pub from_sender: u64,
    pub truncated: bool,
}

/// Смещение senderId внутри хранимой записи (после 8-байтового created_at).
const SENDER_ID_OFFSET: usize = 8;

/// Длина префикса ключа account-очереди: только recipientId.
const USER_PREFIX_LEN: usize = 32;
/// Длина префикса ключа device-очереди: recipientId + deviceId.
const DEVICE_PREFIX_LEN: usize = 34;

/// Промежуточный аккумулятор при пересборке счётчиков.
#[derive(Default)]
struct QueueCounters {
    messages: u64,
    bytes: u64,
    per_sender: std::collections::HashMap<Vec<u8>, u64>,
}

fn encode_queue_counters(messages: u64, bytes: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(16);
    value.extend_from_slice(&messages.to_be_bytes());
    value.extend_from_slice(&bytes.to_be_bytes());
    value
}

fn decode_queue_counters(raw: &[u8]) -> (u64, u64) {
    if raw.len() < 16 {
        return (0, 0);
    }
    (
        u64::from_be_bytes(raw[..8].try_into().unwrap()),
        u64::from_be_bytes(raw[8..16].try_into().unwrap()),
    )
}

/// senderId прямо из хранимой записи, без полного разбора: смещение
/// неизменно с v3. Запись короче 40 байт отправителя не даёт.
fn sender_of(value: &[u8]) -> Option<&[u8]> {
    value.get(SENDER_ID_OFFSET..SENDER_ID_OFFSET + 32)
}

struct DecodedMessage {
    created_at_secs: u64,
    sender_id: [u8; 32],
    sender_device_id: Option<DeviceId>,
    priority: Option<MessagePriority>,
    /// Время жизни в очереди в секундах; 0 = не задано (legacy-сообщения).
    ttl_seconds: u64,
    body: Vec<u8>,
}

/// Истёк ли per-message TTL из node-header конверта v3. `ttl_seconds == 0`
/// означает «отправитель не задал срок» — сообщение живёт по общей
/// retention-политике ноды. Переполнение `created_at + ttl` трактуется как
/// «не истекает».
fn ttl_expired(ttl_seconds: u64, created_at_secs: u64, now_secs: u64) -> bool {
    match created_at_secs.checked_add(ttl_seconds) {
        Some(deadline) => ttl_seconds > 0 && deadline <= now_secs,
        None => false,
    }
}

#[derive(Clone)]
pub struct Storage {
    db: Db,
    inbox: Tree,        // ключ: [recipientId 32] + u64(be) msgId
    device_inbox: Tree, // ключ: [recipientId 32] + deviceId(be) + u64(be) msgId
    /// Счётчики очередей: сколько записей и байт лежит в каждой и сколько
    /// из них от каждого отправителя (форматы — в документации модуля).
    ///
    /// Счётчики считают все хранимые записи, включая протухшие, поэтому
    /// они — оценка сверху для числа живых. На этом и держится их
    /// применение: «счётчик ниже потолка» доказывает «живых записей ниже
    /// потолка», а обратное требует настоящего скана.
    queue_stats: Tree,
    meta: Tree,   // архив удалённых записей (removed_at + исходная запись)
    system: Tree, // служебные маркеры версии/миграции
    deleted_messages_retention: RetentionPolicy,
    offline_messages_retention: RetentionPolicy,
}

impl Storage {
    pub fn open(
        path: &str,
        deleted_messages_retention: RetentionPolicy,
        offline_messages_retention: RetentionPolicy,
    ) -> Result<Self> {
        let db = sled::open(path)?;
        let storage = Self {
            inbox: db.open_tree("inbox")?,
            device_inbox: db.open_tree("device_inbox")?,
            queue_stats: db.open_tree("queue_stats")?,
            meta: db.open_tree("meta")?,
            system: db.open_tree("system")?,
            db,
            deleted_messages_retention,
            offline_messages_retention,
        };
        storage.migrate_legacy_inbox()?;
        // Счётчики пересобираются на каждом старте, а не восстанавливаются
        // из состояния на диске. Так они не могут разъехаться с очередями
        // необратимо: любой сбой посреди обновления счётчика заживает при
        // следующем запуске. Цена — один проход по очередям на старте.
        storage.rebuild_queue_stats()?;
        Ok(storage)
    }

    /// Пересобрать счётчики очередей с нуля.
    fn rebuild_queue_stats(&self) -> Result<()> {
        let started = Instant::now();
        self.queue_stats.clear()?;

        let mut totals: std::collections::HashMap<Vec<u8>, QueueCounters> =
            std::collections::HashMap::new();
        for (tree, prefix_len) in [
            (&self.inbox, USER_PREFIX_LEN),
            (&self.device_inbox, DEVICE_PREFIX_LEN),
        ] {
            for entry in tree.iter() {
                let (key, value) = entry?;
                if key.len() < prefix_len {
                    continue;
                }
                let counters = totals.entry(key[..prefix_len].to_vec()).or_default();
                counters.messages += 1;
                counters.bytes += value.len() as u64;
                if let Some(sender) = sender_of(&value) {
                    let mut sender_key = key[..prefix_len].to_vec();
                    sender_key.extend_from_slice(sender);
                    *counters.per_sender.entry(sender_key).or_insert(0) += 1;
                }
            }
        }

        let mut batch = sled::Batch::default();
        for (prefix, counters) in totals {
            batch.insert(
                prefix,
                encode_queue_counters(counters.messages, counters.bytes),
            );
            for (sender_key, count) in counters.per_sender {
                batch.insert(sender_key, count.to_be_bytes().to_vec());
            }
        }
        self.queue_stats.apply_batch(batch)?;

        observability::observe_storage_operation("rebuild_queue_stats", "ok", started.elapsed());
        Ok(())
    }

    /// Монотонный идентификатор конверта, никогда не ноль: в протоколе
    /// `message_id = 0` означает «подтверждать нечего» (доставка в живую
    /// сессию на прямом бэкенде), а sled первым выдаёт именно ноль. В
    /// брокерном режиме такой конверт нельзя было бы подтвердить, и он
    /// передоставлялся бы до истечения срока в потоке.
    pub fn generate_id(&self) -> Result<u64> {
        Ok(self.db.generate_id()?.saturating_add(1))
    }

    /// Typed store over the `device_push_tokens` tree of the same sled
    /// database, so the bare `Db` is not passed around.
    pub fn push_token_store(&self) -> Result<crate::state::push_tokens::PushTokenStore> {
        crate::state::push_tokens::PushTokenStore::open(&self.db)
    }

    /// Сбросить незаписанное на диск с fsync. Вызывается при штатном
    /// завершении.
    ///
    /// В работе sled сбрасывает буферы фоновым флашером (по умолчанию раз
    /// в 500 мс): после аварийного падения база согласована, но записи
    /// последнего интервала могут пропасть. Флаш при остановке гарантирует,
    /// что штатный рестарт их не теряет.
    pub fn flush(&self) -> Result<usize> {
        Ok(self.db.flush()?)
    }

    /// Реестр mailbox-очередей: деревья живут в общей базе, наружу отдаётся
    /// типизированный store, а не голый `Db`.
    pub fn queue_store(&self) -> Result<crate::state::queues::QueueStore> {
        crate::state::queues::QueueStore::open(&self.db)
    }

    /// Same as `push_token_store`, for the `push_state` tree that persists
    /// push throttling counters across restarts.
    pub fn push_state_store(&self) -> Result<crate::state::push_state::PushStateStore> {
        crate::state::push_state::PushStateStore::open(&self.db)
    }

    pub fn enqueue_inbox(
        &self,
        recipient: &[u8; 32],
        sender: &[u8; 32],
        sender_device_id: Option<DeviceId>,
        body: &[u8],
        priority: Option<MessagePriority>,
        ttl_seconds: u64,
    ) -> Result<EnqueueResult> {
        let started = Instant::now();
        let id = self.generate_id()?;
        if self.offline_messages_retention.is_immediate() {
            observability::observe_storage_operation("enqueue_inbox", "ok", started.elapsed());
            return Ok(EnqueueResult { id, stored: false });
        }

        let created_at_secs = unix_timestamp_secs()?;
        let key = build_user_key(recipient, id);
        let value = encode_message_value(
            created_at_secs,
            sender,
            sender_device_id,
            priority,
            ttl_seconds,
            body,
        );
        self.insert_message(
            &self.inbox,
            key,
            value,
            USER_PREFIX_LEN,
            "enqueue_inbox",
            started,
        )?;
        Ok(EnqueueResult { id, stored: true })
    }

    // Поля конверта; отдельная структура ради одного вызова не нужна.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_device_inbox(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: DeviceId,
        sender: &[u8; 32],
        sender_device_id: Option<DeviceId>,
        body: &[u8],
        priority: Option<MessagePriority>,
        ttl_seconds: u64,
    ) -> Result<EnqueueResult> {
        let started = Instant::now();
        let id = self.generate_id()?;
        if self.offline_messages_retention.is_immediate() {
            observability::observe_storage_operation(
                "enqueue_device_inbox",
                "ok",
                started.elapsed(),
            );
            return Ok(EnqueueResult { id, stored: false });
        }

        let created_at_secs = unix_timestamp_secs()?;
        let key = build_device_key(recipient, recipient_device_id, id);
        let value = encode_message_value(
            created_at_secs,
            sender,
            sender_device_id,
            priority,
            ttl_seconds,
            body,
        );
        self.insert_message(
            &self.device_inbox,
            key,
            value,
            DEVICE_PREFIX_LEN,
            "enqueue_device_inbox",
            started,
        )?;
        Ok(EnqueueResult { id, stored: true })
    }

    pub fn drain_inbox(&self, recipient: &[u8; 32], limit: usize) -> Result<Vec<StoredMessage>> {
        let started = Instant::now();
        let prefix = build_user_prefix(recipient);
        self.drain_tree_messages(
            &self.inbox,
            prefix,
            USER_PREFIX_LEN,
            limit,
            "drain_inbox",
            started,
        )
    }

    pub fn drain_device_inbox(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: DeviceId,
        limit: usize,
    ) -> Result<Vec<StoredMessage>> {
        let started = Instant::now();
        let prefix = build_device_prefix(recipient, recipient_device_id);
        self.drain_tree_messages(
            &self.device_inbox,
            prefix,
            DEVICE_PREFIX_LEN,
            limit,
            "drain_device_inbox",
            started,
        )
    }

    pub fn remove_inbox(&self, recipient: &[u8; 32], id: u64) -> Result<()> {
        let key = build_user_key(recipient, id);
        self.remove_message(&self.inbox, key, USER_PREFIX_LEN, "remove_inbox")
    }

    pub fn remove_device_inbox(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: DeviceId,
        id: u64,
    ) -> Result<()> {
        let key = build_device_key(recipient, recipient_device_id, id);
        self.remove_message(
            &self.device_inbox,
            key,
            DEVICE_PREFIX_LEN,
            "remove_device_inbox",
        )
    }

    pub fn get_queue_depth(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: Option<DeviceId>,
    ) -> Result<usize> {
        let started = Instant::now();
        let tree = match recipient_device_id {
            Some(_) => &self.device_inbox,
            None => &self.inbox,
        };
        let prefix = match recipient_device_id {
            Some(device_id) => build_device_prefix(recipient, device_id),
            None => build_user_prefix(recipient),
        };

        let prefix_len = match recipient_device_id {
            Some(_) => DEVICE_PREFIX_LEN,
            None => USER_PREFIX_LEN,
        };
        let count = self.count_valid_messages(tree, prefix, prefix_len)?;
        observability::observe_storage_operation("get_queue_depth", "ok", started.elapsed());
        Ok(count)
    }

    /// Всё, что нужно квотам офлайн-очереди, за один проход: число живых
    /// записей, их объём и число записей от `sender`.
    ///
    /// Если счётчики `queue_stats` ниже всех потолков, очередь не читается
    /// вовсе. Иначе скан идёт по очереди, пропускает протухшие записи и
    /// удаляет их (мусор не должен держать квоту до фоновой чистки), а
    /// останавливается, как только достигнут любой потолок.
    pub fn scan_queue_quota(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: Option<DeviceId>,
        sender: &[u8; 32],
        ceilings: QueueQuotaCeilings,
    ) -> Result<QueueQuotaScan> {
        let started = Instant::now();
        let result: Result<QueueQuotaScan> = (|| {
            let tree = match recipient_device_id {
                Some(_) => &self.device_inbox,
                None => &self.inbox,
            };
            let (prefix, prefix_len) = match recipient_device_id {
                Some(device_id) => (build_device_prefix(recipient, device_id), DEVICE_PREFIX_LEN),
                None => (build_user_prefix(recipient), USER_PREFIX_LEN),
            };

            // Быстрый путь: счётчики — оценка сверху (включают протухшие
            // записи), поэтому «счётчик ниже потолка» доказывает «живых ниже
            // потолка». Обратное неверно, и тогда нужен настоящий скан.
            let counters = self.queue_counters(&prefix, sender)?;
            let under_all_ceilings = (ceilings.messages == 0
                || counters.messages < ceilings.messages)
                && (ceilings.bytes == 0 || counters.bytes < ceilings.bytes)
                && (ceilings.from_sender == 0 || counters.from_sender < ceilings.from_sender);
            if under_all_ceilings {
                observability::observe_storage_operation(
                    "queue_quota_fast_path",
                    "ok",
                    started.elapsed(),
                );
                return Ok(counters);
            }

            let now_secs = unix_timestamp_secs()?;
            let mut scan = QueueQuotaScan::default();
            let mut expired_keys = Vec::new();

            for entry in tree.scan_prefix(prefix) {
                let (key, value) = entry?;
                let decoded = decode_message_value(&value)?;
                if self
                    .offline_messages_retention
                    .expires(decoded.created_at_secs, now_secs)
                    || ttl_expired(decoded.ttl_seconds, decoded.created_at_secs, now_secs)
                {
                    expired_keys.push(key);
                    continue;
                }

                scan.messages += 1;
                scan.bytes += value.len() as u64;
                if value.len() >= SENDER_ID_OFFSET + 32
                    && &value[SENDER_ID_OFFSET..SENDER_ID_OFFSET + 32] == sender
                {
                    scan.from_sender += 1;
                }

                let reached = (ceilings.messages > 0 && scan.messages >= ceilings.messages)
                    || (ceilings.bytes > 0 && scan.bytes >= ceilings.bytes)
                    || (ceilings.from_sender > 0 && scan.from_sender >= ceilings.from_sender);
                if reached {
                    scan.truncated = true;
                    break;
                }
            }

            for key in expired_keys {
                self.remove_and_note(tree, &key, prefix_len)?;
            }

            Ok(scan)
        })();

        match result {
            Ok(scan) => {
                observability::observe_storage_operation(
                    "scan_queue_quota",
                    "ok",
                    started.elapsed(),
                );
                Ok(scan)
            }
            Err(err) => {
                observability::observe_storage_operation(
                    "scan_queue_quota",
                    "error",
                    started.elapsed(),
                );
                Err(err)
            }
        }
    }

    /// Занятость очереди получателя: количество хранимых записей (включая
    /// протухшие) и суммарный размер значений (header+body, байт).
    pub fn queue_usage(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: Option<DeviceId>,
    ) -> Result<QueueUsage> {
        let started = Instant::now();
        let result: Result<QueueUsage> = (|| {
            let tree = match recipient_device_id {
                Some(_) => &self.device_inbox,
                None => &self.inbox,
            };
            let prefix = match recipient_device_id {
                Some(device_id) => build_device_prefix(recipient, device_id),
                None => build_user_prefix(recipient),
            };

            let mut usage = QueueUsage {
                messages: 0,
                bytes: 0,
            };
            for entry in tree.scan_prefix(prefix) {
                let (_, value) = entry?;
                usage.messages += 1;
                usage.bytes += value.len() as u64;
            }
            Ok(usage)
        })();

        match result {
            Ok(usage) => {
                observability::observe_storage_operation("queue_usage", "ok", started.elapsed());
                Ok(usage)
            }
            Err(err) => {
                observability::observe_storage_operation("queue_usage", "error", started.elapsed());
                Err(err)
            }
        }
    }

    /// Сколько записей (включая протухшие) в очереди от конкретного
    /// отправителя. senderId читается по фиксированному смещению без
    /// разбора записи, поэтому повреждённые записи подсчёт не прерывают.
    pub fn count_from_sender(
        &self,
        recipient: &[u8; 32],
        recipient_device_id: Option<DeviceId>,
        sender: &[u8; 32],
    ) -> Result<u64> {
        let started = Instant::now();
        let result: Result<u64> = (|| {
            let tree = match recipient_device_id {
                Some(_) => &self.device_inbox,
                None => &self.inbox,
            };
            let prefix = match recipient_device_id {
                Some(device_id) => build_device_prefix(recipient, device_id),
                None => build_user_prefix(recipient),
            };

            let mut count = 0u64;
            for entry in tree.scan_prefix(prefix) {
                let (_, value) = entry?;
                if value.len() >= SENDER_ID_OFFSET + 32
                    && &value[SENDER_ID_OFFSET..SENDER_ID_OFFSET + 32] == sender
                {
                    count += 1;
                }
            }
            Ok(count)
        })();

        match result {
            Ok(count) => {
                observability::observe_storage_operation(
                    "count_from_sender",
                    "ok",
                    started.elapsed(),
                );
                Ok(count)
            }
            Err(err) => {
                observability::observe_storage_operation(
                    "count_from_sender",
                    "error",
                    started.elapsed(),
                );
                Err(err)
            }
        }
    }

    pub fn cleanup_expired_meta(&self) -> Result<usize> {
        let started = Instant::now();
        let result: Result<usize> = (|| {
            if self.deleted_messages_retention.is_disabled() {
                return Ok(0);
            }

            let current_time = unix_timestamp_secs()?;
            let mut to_remove = Vec::new();

            for result in self.meta.iter() {
                let (key, value) = result?;
                if value.len() < 8 {
                    to_remove.push(key);
                    continue;
                }
                let timestamp_bytes: [u8; 8] = value[0..8].try_into().unwrap();
                let removed_at_secs = u64::from_be_bytes(timestamp_bytes);
                if self
                    .deleted_messages_retention
                    .expires(removed_at_secs, current_time)
                {
                    to_remove.push(key);
                }
            }

            let removed_count = to_remove.len();
            for key in to_remove {
                self.meta.remove(&key)?;
            }

            Ok(removed_count)
        })();

        match result {
            Ok(removed_count) => {
                observability::observe_storage_operation(
                    "cleanup_expired_meta",
                    "ok",
                    started.elapsed(),
                );
                Ok(removed_count)
            }
            Err(err) => {
                observability::observe_storage_operation(
                    "cleanup_expired_meta",
                    "error",
                    started.elapsed(),
                );
                Err(err)
            }
        }
    }

    pub fn cleanup_expired_messages(&self) -> Result<usize> {
        let started = Instant::now();
        let result = (|| {
            // Per-message TTL (node-header v3) применяется независимо от
            // retention-политики: истёкшее по ttl сообщение удаляется даже при
            // Disabled-политике. При Immediate в очередях всё равно пусто.
            let now_secs = unix_timestamp_secs()?;
            let apply_retention = !self.offline_messages_retention.is_disabled();
            let account_removed = self.cleanup_tree_messages(
                &self.inbox,
                USER_PREFIX_LEN,
                now_secs,
                apply_retention,
            )?;
            let device_removed = self.cleanup_tree_messages(
                &self.device_inbox,
                DEVICE_PREFIX_LEN,
                now_secs,
                apply_retention,
            )?;
            Ok(account_removed + device_removed)
        })();

        match result {
            Ok(removed_count) => {
                observability::observe_storage_operation(
                    "cleanup_expired_messages",
                    "ok",
                    started.elapsed(),
                );
                Ok(removed_count)
            }
            Err(err) => {
                observability::observe_storage_operation(
                    "cleanup_expired_messages",
                    "error",
                    started.elapsed(),
                );
                Err(err)
            }
        }
    }

    pub fn start_periodic_cleanup(&self, interval: std::time::Duration) -> JoinHandle<()> {
        let storage = self.clone();
        tokio::spawn(async move {
            if let Err(err) = storage.run_cleanup_pass() {
                warn!(error = %err, "startup storage cleanup failed");
            }

            loop {
                sleep(interval).await;
                if let Err(err) = storage.run_cleanup_pass() {
                    warn!(error = %err, "periodic storage cleanup failed");
                }
            }
        })
    }

    fn run_cleanup_pass(&self) -> Result<()> {
        let removed_meta = self.cleanup_expired_meta()?;
        let removed_messages = self.cleanup_expired_messages()?;
        info!(
            removed_meta,
            removed_messages, "periodic storage cleanup completed"
        );
        Ok(())
    }

    fn migrate_legacy_inbox(&self) -> Result<()> {
        let current_version = self.system.get(STORAGE_VERSION_KEY)?;
        match current_version.as_deref() {
            Some([STORAGE_VERSION_V5]) => return Ok(()),
            Some([STORAGE_VERSION_V4]) => {
                self.migrate_tree_v4_to_v5(&self.inbox)?;
                self.migrate_tree_v4_to_v5(&self.device_inbox)?;
            }
            Some([STORAGE_VERSION_V3]) => {
                self.migrate_tree_v3_to_v5(&self.inbox)?;
                self.migrate_tree_v3_to_v5(&self.device_inbox)?;
            }
            Some([STORAGE_VERSION_V2]) => {
                let migrated_at_secs = unix_timestamp_secs()?;
                self.migrate_tree_v2_to_v5(&self.inbox, migrated_at_secs)?;
                self.migrate_tree_v2_to_v5(&self.device_inbox, migrated_at_secs)?;
            }
            None => {
                let migrated_at_secs = unix_timestamp_secs()?;
                self.migrate_tree_v1_to_v5(&self.inbox, migrated_at_secs)?;
                self.migrate_tree_v2_to_v5(&self.device_inbox, migrated_at_secs)?;
            }
            Some(version) => {
                bail!("unsupported storage version marker: {:?}", version);
            }
        }

        self.system
            .insert(STORAGE_VERSION_KEY, &[STORAGE_VERSION_V5])?;
        self.system.flush()?;
        Ok(())
    }

    fn migrate_tree_v1_to_v5(&self, tree: &Tree, migrated_at_secs: u64) -> Result<()> {
        let entries = tree.iter().collect::<std::result::Result<Vec<_>, _>>()?;
        for (key, value) in entries {
            if value.len() < 32 {
                bail!(
                    "legacy inbox value for key {:?} is shorter than 32 bytes",
                    key
                );
            }

            let sender_id: [u8; 32] = value[..32].try_into().unwrap();
            let body = &value[32..];
            let migrated = encode_message_value(migrated_at_secs, &sender_id, None, None, 0, body);
            tree.insert(key, migrated)?;
        }
        Ok(())
    }

    fn migrate_tree_v2_to_v5(&self, tree: &Tree, migrated_at_secs: u64) -> Result<()> {
        let entries = tree.iter().collect::<std::result::Result<Vec<_>, _>>()?;
        for (key, value) in entries {
            // The record layout is inferred from its length alone.
            // Long enough for a v5 header: left as is.
            if value.len() >= MESSAGE_HEADER_LEN_V5 {
                continue;
            }

            // Long enough for a v3 header: extend with priority=None, ttl=0.
            if value.len() >= MESSAGE_HEADER_LEN_V3 {
                let mut migrated = Vec::with_capacity(value.len() + 1 + 8);
                migrated.extend_from_slice(&value[..MESSAGE_HEADER_LEN_V3]);
                migrated.push(MessagePriority::as_storage_byte(None));
                migrated.extend_from_slice(&0u64.to_be_bytes());
                migrated.extend_from_slice(&value[MESSAGE_HEADER_LEN_V3..]);
                tree.insert(key, migrated)?;
                continue;
            }

            // Otherwise a v2 record: 32 (sender) + 1 (has_dev) + 2 (dev) + body.
            if value.len() < 35 {
                bail!("v2 inbox value for key {:?} is shorter than 35 bytes", key);
            }

            let sender_id: [u8; 32] = value[..32].try_into().unwrap();
            let has_sender_device_id = value[32] != 0;
            let sender_device_raw: [u8; 2] = value[33..35].try_into().unwrap();
            let sender_device_id =
                has_sender_device_id.then_some(u16::from_be_bytes(sender_device_raw));
            let body = &value[35..];
            let migrated = encode_message_value(
                migrated_at_secs,
                &sender_id,
                sender_device_id,
                None,
                0,
                body,
            );
            tree.insert(key, migrated)?;
        }
        Ok(())
    }

    fn migrate_tree_v3_to_v5(&self, tree: &Tree) -> Result<()> {
        let entries = tree.iter().collect::<std::result::Result<Vec<_>, _>>()?;
        for (key, value) in entries {
            if value.len() < MESSAGE_HEADER_LEN_V3 {
                bail!("v3 inbox value for key {:?} is shorter than v3 header", key);
            }
            let mut migrated = Vec::with_capacity(value.len() + 1 + 8);
            migrated.extend_from_slice(&value[..MESSAGE_HEADER_LEN_V3]);
            migrated.push(MessagePriority::as_storage_byte(None));
            migrated.extend_from_slice(&0u64.to_be_bytes());
            migrated.extend_from_slice(&value[MESSAGE_HEADER_LEN_V3..]);
            tree.insert(key, migrated)?;
        }
        Ok(())
    }

    /// v4 → v5: вставляем `ttl_seconds = 0` сразу после 44-байтового header.
    fn migrate_tree_v4_to_v5(&self, tree: &Tree) -> Result<()> {
        let entries = tree.iter().collect::<std::result::Result<Vec<_>, _>>()?;
        for (key, value) in entries {
            if value.len() < MESSAGE_HEADER_LEN {
                bail!("v4 inbox value for key {:?} is shorter than v4 header", key);
            }
            let mut migrated = Vec::with_capacity(value.len() + 8);
            migrated.extend_from_slice(&value[..MESSAGE_HEADER_LEN]);
            migrated.extend_from_slice(&0u64.to_be_bytes());
            migrated.extend_from_slice(&value[MESSAGE_HEADER_LEN..]);
            tree.insert(key, migrated)?;
        }
        Ok(())
    }

    /// Учесть появление записи в очереди. Принимает длину и отправителя, а
    /// не значение целиком: на горячем пути значение уже отдано в
    /// `insert`, и копировать его ради счётчиков незачем.
    fn note_stored(&self, prefix: &[u8], len: usize, sender: Option<&[u8]>) -> Result<()> {
        self.bump_queue_counters(prefix, 1, len as i64)?;
        if let Some(sender) = sender {
            self.bump_sender_counter(prefix, sender, 1)?;
        }
        Ok(())
    }

    /// Учесть исчезновение записи из очереди.
    fn note_removed(&self, prefix: &[u8], value: &[u8]) -> Result<()> {
        self.bump_queue_counters(prefix, -1, -(value.len() as i64))?;
        if let Some(sender) = sender_of(value) {
            self.bump_sender_counter(prefix, sender, -1)?;
        }
        Ok(())
    }

    fn bump_queue_counters(&self, prefix: &[u8], messages: i64, bytes: i64) -> Result<()> {
        self.queue_stats.update_and_fetch(prefix, |current| {
            let (mut have_messages, mut have_bytes) =
                current.map(decode_queue_counters).unwrap_or((0, 0));
            have_messages = have_messages.saturating_add_signed(messages);
            have_bytes = have_bytes.saturating_add_signed(bytes);
            if have_messages == 0 && have_bytes == 0 {
                // Пустая очередь не должна оставлять за собой запись:
                // иначе счётчики растут по числу когда-либо писавших.
                None
            } else {
                Some(encode_queue_counters(have_messages, have_bytes))
            }
        })?;
        Ok(())
    }

    fn bump_sender_counter(&self, prefix: &[u8], sender: &[u8], delta: i64) -> Result<()> {
        let mut key = prefix.to_vec();
        key.extend_from_slice(sender);
        self.queue_stats.update_and_fetch(key, |current| {
            let have = current
                .and_then(|raw| raw.get(..8))
                .map(|raw| u64::from_be_bytes(raw.try_into().unwrap()))
                .unwrap_or(0);
            let next = have.saturating_add_signed(delta);
            if next == 0 {
                None
            } else {
                Some(next.to_be_bytes().to_vec())
            }
        })?;
        Ok(())
    }

    /// Прочитать счётчики очереди. Возвращает оценку сверху для числа
    /// живых записей: протухшие тоже посчитаны.
    fn queue_counters(&self, prefix: &[u8], sender: &[u8]) -> Result<QueueQuotaScan> {
        let (messages, bytes) = self
            .queue_stats
            .get(prefix)?
            .map(|raw| decode_queue_counters(&raw))
            .unwrap_or((0, 0));
        let mut sender_key = prefix.to_vec();
        sender_key.extend_from_slice(sender);
        let from_sender = self
            .queue_stats
            .get(sender_key)?
            .and_then(|raw| {
                raw.get(..8)
                    .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            })
            .unwrap_or(0);
        Ok(QueueQuotaScan {
            messages,
            bytes,
            from_sender,
            truncated: false,
        })
    }

    /// Удалить запись и поправить счётчики. Значение приходит из самого
    /// `remove`, так что отдельного чтения не нужно.
    fn remove_and_note(&self, tree: &Tree, key: &[u8], prefix_len: usize) -> Result<Option<IVec>> {
        let removed = tree.remove(key)?;
        if let Some(value) = &removed {
            self.note_removed(&key[..prefix_len.min(key.len())], value)?;
        }
        Ok(removed)
    }

    fn insert_message(
        &self,
        tree: &Tree,
        key: Vec<u8>,
        value: Vec<u8>,
        prefix_len: usize,
        op_name: &'static str,
        started: Instant,
    ) -> Result<()> {
        let prefix = key[..prefix_len.min(key.len())].to_vec();
        let stored_len = value.len();
        let sender = sender_of(&value).map(|sender| sender.to_vec());
        match tree.insert(key, value) {
            Ok(_) => {
                self.note_stored(&prefix, stored_len, sender.as_deref())?;
                observability::observe_storage_operation(op_name, "ok", started.elapsed());
                Ok(())
            }
            Err(err) => {
                observability::observe_storage_operation(op_name, "error", started.elapsed());
                Err(err.into())
            }
        }
    }

    fn drain_tree_messages(
        &self,
        tree: &Tree,
        prefix: Vec<u8>,
        prefix_len: usize,
        limit: usize,
        op_name: &'static str,
        started: Instant,
    ) -> Result<Vec<StoredMessage>> {
        let now_secs = unix_timestamp_secs()?;
        let mut expired_keys = Vec::new();
        let mut messages = Vec::new();

        for entry in tree.scan_prefix(prefix) {
            let (key, value) = entry?;
            let decoded = decode_message_value(&value)?;
            if self
                .offline_messages_retention
                .expires(decoded.created_at_secs, now_secs)
                || ttl_expired(decoded.ttl_seconds, decoded.created_at_secs, now_secs)
            {
                expired_keys.push(key);
                continue;
            }

            messages.push(StoredMessage {
                id: u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap()),
                sender_id: decoded.sender_id,
                sender_device_id: decoded.sender_device_id,
                body: decoded.body,
                priority: decoded.priority,
            });

            if messages.len() >= limit {
                break;
            }
        }

        for key in expired_keys {
            self.remove_and_note(tree, &key, prefix_len)?;
        }

        observability::observe_storage_operation(op_name, "ok", started.elapsed());
        Ok(messages)
    }

    fn count_valid_messages(
        &self,
        tree: &Tree,
        prefix: Vec<u8>,
        prefix_len: usize,
    ) -> Result<usize> {
        let now_secs = unix_timestamp_secs()?;
        let mut expired_keys = Vec::new();
        let mut count = 0usize;

        for entry in tree.scan_prefix(prefix) {
            let (key, value) = entry?;
            let decoded = decode_message_value(&value)?;
            if self
                .offline_messages_retention
                .expires(decoded.created_at_secs, now_secs)
                || ttl_expired(decoded.ttl_seconds, decoded.created_at_secs, now_secs)
            {
                expired_keys.push(key);
                continue;
            }
            count += 1;
        }

        for key in expired_keys {
            self.remove_and_note(tree, &key, prefix_len)?;
        }

        Ok(count)
    }

    fn cleanup_tree_messages(
        &self,
        tree: &Tree,
        prefix_len: usize,
        now_secs: u64,
        apply_retention: bool,
    ) -> Result<usize> {
        let mut to_remove = Vec::new();

        for entry in tree.iter() {
            let (key, value) = entry?;
            let decoded = decode_message_value(&value)?;
            if (apply_retention
                && self
                    .offline_messages_retention
                    .expires(decoded.created_at_secs, now_secs))
                || ttl_expired(decoded.ttl_seconds, decoded.created_at_secs, now_secs)
            {
                to_remove.push(key);
            }
        }

        let removed_count = to_remove.len();
        for key in to_remove {
            self.remove_and_note(tree, &key, prefix_len)?;
        }
        Ok(removed_count)
    }

    fn remove_message(
        &self,
        tree: &Tree,
        key: Vec<u8>,
        prefix_len: usize,
        op_name: &'static str,
    ) -> Result<()> {
        let started = Instant::now();
        let result: Result<()> = (|| {
            let removed = self.remove_and_note(tree, &key, prefix_len)?;
            if let Some(value) = removed
                && !self.deleted_messages_retention.is_immediate()
            {
                let removed_at_secs = unix_timestamp_secs()?;
                let mut meta_value = Vec::with_capacity(8 + value.len());
                meta_value.extend_from_slice(&removed_at_secs.to_be_bytes());
                meta_value.extend_from_slice(&value);
                self.meta.insert(&key, meta_value)?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                observability::observe_storage_operation(op_name, "ok", started.elapsed());
                Ok(())
            }
            Err(err) => {
                observability::observe_storage_operation(op_name, "error", started.elapsed());
                Err(err)
            }
        }
    }
}

fn build_user_prefix(recipient: &[u8; 32]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(32);
    prefix.extend_from_slice(recipient);
    prefix
}

fn build_user_key(recipient: &[u8; 32], id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 8);
    key.extend_from_slice(recipient);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

fn build_device_prefix(recipient: &[u8; 32], recipient_device_id: DeviceId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(32 + 2);
    prefix.extend_from_slice(recipient);
    prefix.extend_from_slice(&recipient_device_id.to_be_bytes());
    prefix
}

fn build_device_key(recipient: &[u8; 32], recipient_device_id: DeviceId, id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 2 + 8);
    key.extend_from_slice(recipient);
    key.extend_from_slice(&recipient_device_id.to_be_bytes());
    key.extend_from_slice(&id.to_be_bytes());
    key
}

fn encode_message_value(
    created_at_secs: u64,
    sender_id: &[u8; 32],
    sender_device_id: Option<DeviceId>,
    priority: Option<MessagePriority>,
    ttl_seconds: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(MESSAGE_HEADER_LEN_V5 + body.len());
    value.extend_from_slice(&created_at_secs.to_be_bytes());
    value.extend_from_slice(sender_id);
    value.push(u8::from(sender_device_id.is_some()));
    value.extend_from_slice(&sender_device_id.unwrap_or_default().to_be_bytes());
    value.push(MessagePriority::as_storage_byte(priority));
    value.extend_from_slice(&ttl_seconds.to_be_bytes());
    value.extend_from_slice(body);
    value
}

fn decode_message_value(value: &[u8]) -> Result<DecodedMessage> {
    if value.len() < MESSAGE_HEADER_LEN_V5 {
        bail!(
            "stored message payload is shorter than expected header: {}",
            value.len()
        );
    }

    let created_at_secs = u64::from_be_bytes(value[..8].try_into().unwrap());
    let sender_id = value[8..40].try_into().unwrap();
    let has_sender_device_id = value[40] != 0;
    let sender_device_raw: [u8; 2] = value[41..43].try_into().unwrap();
    let sender_device_id = has_sender_device_id.then_some(u16::from_be_bytes(sender_device_raw));
    let priority = MessagePriority::from_storage_byte(value[43])?;
    let ttl_bytes: [u8; 8] = value[MESSAGE_HEADER_LEN..MESSAGE_HEADER_LEN_V5]
        .try_into()
        .unwrap();
    let ttl_seconds = u64::from_be_bytes(ttl_bytes);
    let body = value[MESSAGE_HEADER_LEN_V5..].to_vec();

    Ok(DecodedMessage {
        created_at_secs,
        sender_id,
        sender_device_id,
        priority,
        ttl_seconds,
        body,
    })
}

fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{
        EnqueueResult, MESSAGE_HEADER_LEN_V5, QueueQuotaCeilings, QueueUsage, Storage,
        build_device_key, build_user_key, encode_message_value, encode_queue_counters,
        unix_timestamp_secs,
    };
    use crate::config::RetentionPolicy;
    use crate::domain::priority::MessagePriority;
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn user(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn temp_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("trust_message_tcp_{label}_{nanos}"));
        path.to_string_lossy().into_owned()
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_dir_all(path);
    }

    fn keep_for_days(days: u64) -> RetentionPolicy {
        RetentionPolicy::KeepFor(Duration::from_secs(days * 24 * 60 * 60))
    }

    /// Ноль зарезервирован протоколом под «подтверждать нечего», поэтому
    /// выдавать его как идентификатор конверта нельзя: в брокерном режиме
    /// такой конверт клиент не подтвердит никогда, и поток будет
    /// передоставлять его по кругу.
    #[test]
    fn generated_ids_never_start_at_zero() {
        let path = temp_path("nonzero_ids");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();

        let first = storage.generate_id().unwrap();
        let second = storage.generate_id().unwrap();

        assert_ne!(first, 0);
        assert!(
            second > first,
            "идентификаторы обязаны расти: {first} -> {second}"
        );

        cleanup(&path);
    }

    #[test]
    fn account_queue_roundtrips_sender_device_id() {
        let path = temp_path("account_queue");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();

        let result = storage
            .enqueue_inbox(
                &user(1),
                &user(2),
                Some(7),
                b"hello",
                Some(MessagePriority::High),
                0,
            )
            .unwrap();
        let drained = storage.drain_inbox(&user(1), 10).unwrap();

        assert_eq!(
            result,
            EnqueueResult {
                id: result.id,
                stored: true
            }
        );
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].id, result.id);
        assert_eq!(drained[0].sender_id, user(2));
        assert_eq!(drained[0].sender_device_id, Some(7));
        assert_eq!(drained[0].body, b"hello");
        assert_eq!(drained[0].priority, Some(MessagePriority::High));

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn device_queue_is_scoped_to_matching_device() {
        let path = temp_path("device_queue");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();

        storage
            .enqueue_device_inbox(&user(1), 9, &user(2), Some(4), b"a", None, 0)
            .unwrap();
        storage
            .enqueue_device_inbox(
                &user(1),
                10,
                &user(2),
                None,
                b"b",
                Some(MessagePriority::Medium),
                0,
            )
            .unwrap();

        let for_nine = storage.drain_device_inbox(&user(1), 9, 10).unwrap();
        let for_ten = storage.drain_device_inbox(&user(1), 10, 10).unwrap();

        assert_eq!(for_nine.len(), 1);
        assert_eq!(for_nine[0].body, b"a");
        assert_eq!(for_nine[0].priority, None);
        assert_eq!(for_ten.len(), 1);
        assert_eq!(for_ten[0].body, b"b");
        assert_eq!(for_ten[0].priority, Some(MessagePriority::Medium));

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn open_migrates_legacy_v1_account_messages() {
        let path = temp_path("legacy_migration_v1");
        let db = sled::open(&path).unwrap();
        let inbox = db.open_tree("inbox").unwrap();

        let mut legacy_value = Vec::new();
        legacy_value.extend_from_slice(&user(2));
        legacy_value.extend_from_slice(b"legacy");
        inbox
            .insert(
                {
                    let mut key = Vec::new();
                    key.extend_from_slice(&user(1));
                    key.extend_from_slice(&1u64.to_be_bytes());
                    key
                },
                legacy_value,
            )
            .unwrap();
        db.flush().unwrap();
        drop(inbox);
        drop(db);

        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let drained = storage.drain_inbox(&user(1), 10).unwrap();

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].sender_id, user(2));
        assert_eq!(drained[0].sender_device_id, None);
        assert_eq!(drained[0].body, b"legacy");
        assert_eq!(drained[0].priority, None);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn open_migrates_v2_messages_to_v5() {
        let path = temp_path("migration_v2");
        let db = sled::open(&path).unwrap();
        db.open_tree("system")
            .unwrap()
            .insert(b"storage_version", &[2u8])
            .unwrap();
        db.open_tree("inbox")
            .unwrap()
            .insert(build_user_key(&user(1), 1), {
                let mut value = Vec::new();
                value.extend_from_slice(&user(2));
                value.push(1);
                value.extend_from_slice(&7u16.to_be_bytes());
                value.extend_from_slice(b"hello");
                value
            })
            .unwrap();
        db.open_tree("device_inbox")
            .unwrap()
            .insert(build_device_key(&user(1), 9, 2), {
                let mut value = Vec::new();
                value.extend_from_slice(&user(3));
                value.push(0);
                value.extend_from_slice(&0u16.to_be_bytes());
                value.extend_from_slice(b"world");
                value
            })
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();

        let account = storage.drain_inbox(&user(1), 10).unwrap();
        let device = storage.drain_device_inbox(&user(1), 9, 10).unwrap();

        assert_eq!(account.len(), 1);
        assert_eq!(account[0].sender_device_id, Some(7));
        assert_eq!(account[0].body, b"hello");
        assert_eq!(account[0].priority, None);
        assert_eq!(device.len(), 1);
        assert_eq!(device[0].sender_device_id, None);
        assert_eq!(device[0].body, b"world");
        assert_eq!(device[0].priority, None);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn open_migrates_v3_messages_to_v5_with_none_priority() {
        let path = temp_path("migration_v3");
        let db = sled::open(&path).unwrap();
        db.open_tree("system")
            .unwrap()
            .insert(b"storage_version", &[3u8])
            .unwrap();

        // v3 header: 8 ts + 32 sender + 1 has_dev + 2 dev = 43 bytes, then body.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut v3_value = Vec::new();
        v3_value.extend_from_slice(&now_secs.to_be_bytes());
        v3_value.extend_from_slice(&user(2));
        v3_value.push(1);
        v3_value.extend_from_slice(&5u16.to_be_bytes());
        v3_value.extend_from_slice(b"v3body");

        db.open_tree("inbox")
            .unwrap()
            .insert(build_user_key(&user(1), 1), v3_value)
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let drained = storage.drain_inbox(&user(1), 10).unwrap();

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].sender_id, user(2));
        assert_eq!(drained[0].sender_device_id, Some(5));
        assert_eq!(drained[0].body, b"v3body");
        assert_eq!(drained[0].priority, None);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn open_migrates_v4_messages_to_v5_with_zero_ttl() {
        let path = temp_path("migration_v4");
        let db = sled::open(&path).unwrap();
        db.open_tree("system")
            .unwrap()
            .insert(b"storage_version", &[4u8])
            .unwrap();

        // v4 header: 8 ts + 32 sender + 1 has_dev + 2 dev + 1 priority = 44
        // bytes, then body.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut v4_value = Vec::new();
        v4_value.extend_from_slice(&now_secs.to_be_bytes());
        v4_value.extend_from_slice(&user(2));
        v4_value.push(1);
        v4_value.extend_from_slice(&5u16.to_be_bytes());
        v4_value.push(MessagePriority::as_storage_byte(Some(
            MessagePriority::High,
        )));
        v4_value.extend_from_slice(b"v4body");

        db.open_tree("inbox")
            .unwrap()
            .insert(build_user_key(&user(1), 1), v4_value)
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let drained = storage.drain_inbox(&user(1), 10).unwrap();

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].sender_id, user(2));
        assert_eq!(drained[0].sender_device_id, Some(5));
        assert_eq!(drained[0].body, b"v4body");
        assert_eq!(drained[0].priority, Some(MessagePriority::High));

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn expired_ttl_message_is_dropped_on_drain_and_depth() {
        let path = temp_path("ttl_drain");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        storage
            .inbox
            .insert(
                build_user_key(&user(1), 1),
                encode_message_value(
                    now.saturating_sub(120),
                    &user(2),
                    None,
                    None,
                    60,
                    b"expired",
                ),
            )
            .unwrap();
        storage
            .inbox
            .insert(
                build_user_key(&user(1), 2),
                encode_message_value(now.saturating_sub(30), &user(2), None, None, 3600, b"fresh"),
            )
            .unwrap();
        storage
            .inbox
            .insert(
                build_user_key(&user(1), 3),
                encode_message_value(now.saturating_sub(120), &user(2), None, None, 0, b"no-ttl"),
            )
            .unwrap();

        let drained = storage.drain_inbox(&user(1), 10).unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].body, b"fresh");
        assert_eq!(drained[1].body, b"no-ttl");
        assert_eq!(storage.inbox.len(), 2);
        assert_eq!(storage.get_queue_depth(&user(1), None).unwrap(), 2);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn expired_ttl_message_is_removed_by_cleanup_even_with_disabled_retention() {
        let path = temp_path("ttl_cleanup_disabled");
        let storage =
            Storage::open(&path, RetentionPolicy::Disabled, RetentionPolicy::Disabled).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        storage
            .inbox
            .insert(
                build_user_key(&user(1), 1),
                encode_message_value(
                    now.saturating_sub(120),
                    &user(2),
                    None,
                    None,
                    60,
                    b"expired",
                ),
            )
            .unwrap();
        storage
            .device_inbox
            .insert(
                build_device_key(&user(1), 9, 2),
                encode_message_value(now, &user(2), None, None, 3600, b"fresh"),
            )
            .unwrap();

        assert_eq!(storage.cleanup_expired_messages().unwrap(), 1);
        assert_eq!(storage.inbox.len(), 0);
        assert_eq!(storage.device_inbox.len(), 1);

        drop(storage);
        cleanup(&path);
    }

    /// Счётчики очередей обязаны сходиться с честным пересчётом после
    /// любой последовательности операций.
    ///
    /// Пропущенное место обновления даёт расхождение: заниженный счётчик
    /// пропускает быстрый путь квоты мимо потолка, завышенный стоит
    /// лишнего скана. Тест прогоняет все пути, которые трогают очередь
    /// (депозит, дренаж, точечное удаление, ленивое протухание, фоновая
    /// чистка), и сравнивает счётчики с пересобранными с нуля.
    #[test]
    fn queue_counters_agree_with_a_full_recount() {
        let path = temp_path("counter_drift");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let alice = user(1);
        let bob = user(2);
        let carol = user(3);

        // Депозиты в обе области видимости, от разных отправителей.
        for _ in 0..5 {
            storage
                .enqueue_inbox(&alice, &bob, None, b"from-bob", None, 0)
                .unwrap();
        }
        for _ in 0..3 {
            storage
                .enqueue_inbox(&alice, &carol, None, b"from-carol", None, 0)
                .unwrap();
        }
        for _ in 0..4 {
            storage
                .enqueue_device_inbox(&alice, 7, &bob, Some(2), b"to-device", None, 0)
                .unwrap();
        }

        // Точечное удаление.
        let drained = storage.drain_inbox(&alice, 2).unwrap();
        for message in &drained {
            storage.remove_inbox(&alice, message.id).unwrap();
        }
        let drained_device = storage.drain_device_inbox(&alice, 7, 1).unwrap();
        for message in &drained_device {
            storage.remove_device_inbox(&alice, 7, message.id).unwrap();
        }

        // Протухшая запись, которую подберёт ленивое удаление.
        let now = unix_timestamp_secs().unwrap();
        let stale = encode_message_value(now - 7_200, &bob, None, None, 60, b"stale");
        storage
            .inbox
            .insert(build_user_key(&alice, 90_001), stale.clone())
            .unwrap();
        storage
            .note_stored(&alice[..], stale.len(), Some(&bob[..]))
            .unwrap();
        // Обращение к очереди обязано её вычистить и поправить счётчики.
        let _ = storage.get_queue_depth(&alice, None).unwrap();

        // Фоновая чистка.
        storage.cleanup_expired_messages().unwrap();

        let before: Vec<(Vec<u8>, Vec<u8>)> = storage
            .queue_stats
            .iter()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect();

        storage.rebuild_queue_stats().unwrap();

        let after: Vec<(Vec<u8>, Vec<u8>)> = storage
            .queue_stats
            .iter()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect();

        assert_eq!(
            before, after,
            "счётчики разошлись с реальным содержимым очередей"
        );

        drop(storage);
        cleanup(&path);
    }

    /// Пересборка при старте лечит любой рассинхрон, накопленный до
    /// перезапуска: счётчики не восстанавливаются с диска, а считаются
    /// заново.
    #[test]
    fn restart_heals_counter_drift() {
        let path = temp_path("counter_heal");
        {
            let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
            storage
                .enqueue_inbox(&user(1), &user(2), None, b"real", None, 0)
                .unwrap();
            // Порча счётчика руками: как если бы обновление не доехало.
            storage
                .queue_stats
                .insert(&user(1)[..], encode_queue_counters(9_999, 9_999_999))
                .unwrap();
        }

        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let scan = storage
            .scan_queue_quota(&user(1), None, &user(2), QueueQuotaCeilings::default())
            .unwrap();
        assert_eq!(scan.messages, 1, "перезапуск обязан пересчитать счётчики");

        drop(storage);
        cleanup(&path);
    }

    /// Протухшие записи не занимают квоту. Иначе очередь, забитая
    /// сообщениями, которые всё равно никогда не доставят, держала бы
    /// отправителей заблокированными до ближайшей фоновой чистки — а она
    /// раз в сутки.
    #[test]
    fn expired_messages_do_not_hold_the_quota() {
        let path = temp_path("quota_expired");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let recipient = user(1);
        let sender = user(2);
        let now = unix_timestamp_secs().unwrap();

        // Три записи с истёкшим ttl и одна живая — кладём напрямую, чтобы
        // задать created_at в прошлом, но счётчики обновляем как обычно:
        // иначе тест проверял бы не тот путь.
        let stale = encode_message_value(now - 7_200, &sender, None, None, 3_600, b"stale");
        for index in 0..3u64 {
            storage
                .inbox
                .insert(build_user_key(&recipient, index), stale.clone())
                .unwrap();
            storage
                .note_stored(&recipient[..], stale.len(), Some(&sender[..]))
                .unwrap();
        }
        let fresh = encode_message_value(now, &sender, None, None, 3_600, b"fresh");
        storage
            .inbox
            .insert(build_user_key(&recipient, 3), fresh.clone())
            .unwrap();
        storage
            .note_stored(&recipient[..], fresh.len(), Some(&sender[..]))
            .unwrap();

        // Потолок ниже числа ХРАНИМЫХ записей: счётчик его перебивает, и
        // квота обязана пойти в настоящий скан, а не поверить счётчику.
        let ceilings = QueueQuotaCeilings {
            messages: 2,
            ..QueueQuotaCeilings::default()
        };
        let scan = storage
            .scan_queue_quota(&recipient, None, &sender, ceilings)
            .unwrap();

        assert_eq!(scan.messages, 1, "в квоту попадает только живая запись");
        assert_eq!(scan.from_sender, 1);
        assert!(!scan.truncated);
        // Протухшие удалены по дороге, а не оставлены до фоновой чистки.
        assert_eq!(storage.get_queue_depth(&recipient, None).unwrap(), 1);

        drop(storage);
        cleanup(&path);
    }

    /// Повреждённая запись в очереди — ошибка скана, а не молчаливый
    /// пропуск. Соединение из-за неё не рвётся: вызывающий отвечает
    /// отправителю отказом `INTERNAL` и оставляет сессию живой (на том же
    /// соединении продолжают приходить входящие).
    #[test]
    fn corrupt_record_makes_the_quota_scan_fail_loudly() {
        let path = temp_path("quota_corrupt");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let recipient = user(5);
        let sender = user(6);

        storage
            .enqueue_inbox(&recipient, &sender, None, b"fine", None, 0)
            .unwrap();
        // Запись короче заголовка: разобрать её нечем.
        let broken = vec![0u8; 4];
        storage
            .inbox
            .insert(build_user_key(&recipient, 999), broken.clone())
            .unwrap();
        storage
            .note_stored(&recipient[..], broken.len(), None)
            .unwrap();

        // Потолок ровно по числу хранимых записей: счётчик его достигает,
        // значит квота идёт в скан, и скан доходит до второй записи. Под
        // потолком она отвечала бы по счётчику и записи не читала вовсе.
        let ceilings = QueueQuotaCeilings {
            messages: 2,
            ..QueueQuotaCeilings::default()
        };
        assert!(
            storage
                .scan_queue_quota(&recipient, None, &sender, ceilings)
                .is_err(),
            "повреждённая запись обязана быть ошибкой, а не пропуском"
        );

        drop(storage);
        cleanup(&path);
    }

    /// Повреждённая запись ломает и чтение очереди при входе в сессию —
    /// то есть ветка «хранилище недоступно» в обработчике соединения
    /// достижима, а не гипотетична. Вызывающий отвечает на неё
    /// `AuthError(503)`: разрыв клиент не отличил бы от сетевого сбоя и
    /// переподключился бы немедленно в ту же неработающую ноду.
    #[test]
    fn corrupt_record_makes_the_offline_replay_fail_loudly() {
        let path = temp_path("replay_corrupt");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let recipient = user(7);

        // Запись короче заголовка: разобрать её нечем.
        let broken = vec![0u8; 4];
        storage
            .inbox
            .insert(build_user_key(&recipient, 1), broken.clone())
            .unwrap();
        storage
            .note_stored(&recipient[..], broken.len(), None)
            .unwrap();

        assert!(
            storage.drain_inbox(&recipient, 100).is_err(),
            "повреждённая запись обязана быть ошибкой чтения очереди"
        );

        drop(storage);
        cleanup(&path);
    }

    /// Скан останавливается, как только ответ «переполнено» уже известен:
    /// дочитывать очередь до конца незачем, а при потолке в 10 000 записей
    /// это разница между константой и полным проходом.
    #[test]
    fn quota_scan_stops_at_the_ceiling() {
        let path = temp_path("quota_early_exit");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let recipient = user(3);
        let sender = user(4);

        for _ in 0..50 {
            storage
                .enqueue_inbox(&recipient, &sender, None, b"payload", None, 0)
                .unwrap();
        }

        let scan = storage
            .scan_queue_quota(
                &recipient,
                None,
                &sender,
                QueueQuotaCeilings {
                    messages: 5,
                    ..QueueQuotaCeilings::default()
                },
            )
            .unwrap();
        assert_eq!(scan.messages, 5);
        assert!(scan.truncated, "скан обязан остановиться на потолке");

        // Без потолков считается вся очередь.
        let full = storage
            .scan_queue_quota(&recipient, None, &sender, QueueQuotaCeilings::default())
            .unwrap();
        assert_eq!(full.messages, 50);
        assert!(!full.truncated);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn ttl_expiry_semantics() {
        use super::ttl_expired;

        // ttl == 0 — срок не задан, не истекает никогда.
        assert!(!ttl_expired(0, 100, 10_000));
        // Границы: истекает ровно в created_at + ttl.
        assert!(!ttl_expired(60, 100, 159));
        assert!(ttl_expired(60, 100, 160));
        assert!(ttl_expired(60, 100, 161));
        // Переполнение дедлайна трактуется как «не истекает».
        assert!(!ttl_expired(u64::MAX, u64::MAX - 10, u64::MAX));
        assert!(!ttl_expired(1, u64::MAX, u64::MAX));
    }

    #[test]
    fn immediate_offline_retention_does_not_store_messages() {
        let path = temp_path("immediate_offline");
        let storage = Storage::open(&path, keep_for_days(30), RetentionPolicy::Immediate).unwrap();

        let account = storage
            .enqueue_inbox(&user(1), &user(2), None, b"drop", None, 0)
            .unwrap();
        let device = storage
            .enqueue_device_inbox(&user(1), 9, &user(2), None, b"drop", None, 0)
            .unwrap();

        assert!(!account.stored);
        assert!(!device.stored);
        assert_eq!(storage.drain_inbox(&user(1), 10).unwrap().len(), 0);
        assert_eq!(
            storage.drain_device_inbox(&user(1), 9, 10).unwrap().len(),
            0
        );
        assert_eq!(storage.get_queue_depth(&user(1), None).unwrap(), 0);
        assert_eq!(storage.get_queue_depth(&user(1), Some(9)).unwrap(), 0);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn expired_offline_messages_are_removed_during_cleanup() {
        let path = temp_path("expired_offline_cleanup");
        let storage = Storage::open(&path, keep_for_days(30), RetentionPolicy::Immediate).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = now.saturating_sub(60);

        storage
            .inbox
            .insert(
                build_user_key(&user(1), 1),
                encode_message_value(old, &user(2), None, None, 0, b"stale"),
            )
            .unwrap();
        storage
            .device_inbox
            .insert(
                build_device_key(&user(1), 9, 2),
                encode_message_value(
                    old,
                    &user(2),
                    Some(7),
                    Some(MessagePriority::Low),
                    0,
                    b"stale",
                ),
            )
            .unwrap();

        assert_eq!(storage.cleanup_expired_messages().unwrap(), 2);
        assert_eq!(storage.inbox.len(), 0);
        assert_eq!(storage.device_inbox.len(), 0);

        drop(storage);
        cleanup(&path);
    }

    #[test]
    fn immediate_deleted_retention_skips_meta_archive() {
        let path = temp_path("immediate_deleted");
        let storage = Storage::open(&path, RetentionPolicy::Immediate, keep_for_days(30)).unwrap();

        let queued = storage
            .enqueue_inbox(&user(1), &user(2), None, b"gone", None, 0)
            .unwrap();
        storage.remove_inbox(&user(1), queued.id).unwrap();

        assert_eq!(storage.meta.len(), 0);

        drop(storage);
        cleanup(&path);
    }

    /// `queue_usage` считает хранимые записи и их суммарный размер,
    /// раздельно для account- и device-очереди.
    #[test]
    fn queue_usage_counts_messages_and_bytes_per_scope() {
        let path = temp_path("queue_usage");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let recipient = user(1);
        let sender = user(2);

        assert_eq!(
            storage.queue_usage(&recipient, None).unwrap(),
            QueueUsage {
                messages: 0,
                bytes: 0
            }
        );

        storage
            .enqueue_inbox(&recipient, &sender, None, b"aaa", None, 0)
            .unwrap();
        storage
            .enqueue_inbox(&recipient, &sender, None, b"bbbbb", None, 0)
            .unwrap();
        storage
            .enqueue_device_inbox(&recipient, 7, &sender, None, b"c", None, 0)
            .unwrap();

        let account = storage.queue_usage(&recipient, None).unwrap();
        assert_eq!(account.messages, 2);
        // Байты — полный размер хранимых значений: заголовок v5 плюс тело.
        assert_eq!(account.bytes, (MESSAGE_HEADER_LEN_V5 as u64) * 2 + 3 + 5);

        let device = storage.queue_usage(&recipient, Some(7)).unwrap();
        assert_eq!(device.messages, 1);
        assert_eq!(device.bytes, MESSAGE_HEADER_LEN_V5 as u64 + 1);

        // Чужая очередь пуста.
        assert_eq!(storage.queue_usage(&user(3), None).unwrap().messages, 0);

        drop(storage);
        cleanup(&path);
    }

    /// `count_from_sender` считает только записи конкретного отправителя —
    /// это под-квота пары sender→recipient.
    #[test]
    fn count_from_sender_filters_by_sender() {
        let path = temp_path("count_from_sender");
        let storage = Storage::open(&path, keep_for_days(30), keep_for_days(30)).unwrap();
        let recipient = user(1);
        let loud = user(2);
        let quiet = user(3);

        for _ in 0..3 {
            storage
                .enqueue_inbox(&recipient, &loud, None, b"spam", None, 0)
                .unwrap();
        }
        storage
            .enqueue_inbox(&recipient, &quiet, None, b"hi", None, 0)
            .unwrap();
        storage
            .enqueue_device_inbox(&recipient, 4, &loud, None, b"dev", None, 0)
            .unwrap();

        assert_eq!(
            storage.count_from_sender(&recipient, None, &loud).unwrap(),
            3
        );
        assert_eq!(
            storage.count_from_sender(&recipient, None, &quiet).unwrap(),
            1
        );
        assert_eq!(
            storage
                .count_from_sender(&recipient, None, &user(9))
                .unwrap(),
            0
        );
        // Device-scope считается отдельно.
        assert_eq!(
            storage
                .count_from_sender(&recipient, Some(4), &loud)
                .unwrap(),
            1
        );

        drop(storage);
        cleanup(&path);
    }
}
