//! Доставка с подтверждением на прямом (sled) бэкенде.
//!
//! Запись очереди — единственный источник правды: конверт пишется в
//! account- или device-очередь получателя при приёме (и для живого
//! получателя тоже) и снимается только `DeliveryAck` клиента той же области
//! (см. [`Storage::ack_inbox`]). Канал сессии несёт лишь уведомление «вот
//! запись, отдай её»: потерянное уведомление — разрыв сессии, выписка,
//! переполненное окно — ничего не теряет, запись остаётся в очереди и
//! дочитывается оттуда.
//!
//! Каждая сессия держит своё окно: записи, отданные в сокет и ещё не
//! подтверждённые, со сроком `ack_wait`. Окно ограничено `max_unacked`;
//! полное окно не выписывает сессию, а откладывает выдачу — запись
//! дочитается из очереди, когда подтверждения освободят место. Истёкшая
//! запись выдаётся снова той же сессии. Неподтверждённые выдачи считаются в
//! хранилище; выдача номер `max_deliveries` — последняя: после записи в
//! сокет запись удаляется, как удалялась до подтверждений вовсе. Так клиент,
//! который `DeliveryAck` не шлёт, получает каждый конверт ограниченное
//! число раз.
//!
//! Семантика повторяет брокерный бэкенд (`ack_wait`, `max_ack_pending`,
//! области подтверждения); отличия — в документации `docs/architecture.md`.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use anyhow::Result;
use tokio::time::Instant;
use tracing::{debug, warn};

pub use crate::config::SledAckConfig;
use crate::observability;
use crate::state::registry::{ConnRegistry, ConnectionId, DeviceId, UserId};
use crate::state::storage::{InboxScope, Storage, StoredMessage};

/// Что делать с уведомлением из канала сессии.
#[derive(Debug, PartialEq, Eq)]
pub enum Offer {
    /// Отдать.
    Accept,
    /// Запись уже отдана этой сессией и ждёт подтверждения.
    Duplicate,
    /// Окно полно: запись дочитается из очереди, когда освободится место.
    Deferred,
}

/// Решение перед записью в сокет.
#[derive(Debug, PartialEq, Eq)]
pub enum WriteDecision {
    /// Записи больше нет (подтверждена другой сессией, истекла, удалена).
    Skip,
    /// Отдать. `last` — выдача последняя, после неё запись удаляется;
    /// `redelivery` — запись уже выдавалась без подтверждения.
    Deliver { last: bool, redelivery: bool },
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    scope: InboxScope,
    deadline: Instant,
}

/// Окно подтверждений одной сессии и курсоры дочитывания её очередей.
///
/// Живёт в задаче сессии и только там: мьютексов нет, через `await` ничего
/// не держится. Сессии одного получателя общаются через хранилище и сигнал
/// `resync` реестра.
pub struct SledSession {
    storage: Storage,
    cfg: SledAckConfig,
    user_id: UserId,
    device_id: Option<DeviceId>,
    pending: HashMap<u64, Pending>,
    /// Сроки окна. Удаление ленивое: запись кучи без совпадающей записи в
    /// `pending` устарела и пропускается.
    deadlines: BinaryHeap<Reverse<(Instant, u64)>>,
    /// Откуда дочитывать account-очередь; `None` — дочитана.
    account_from: Option<u64>,
    /// То же для очереди устройства сессии.
    device_from: Option<u64>,
    registry: ConnRegistry,
    connection_id: ConnectionId,
}

impl SledSession {
    /// Окно новой сессии. Обе её очереди помечены к чтению с начала: это и
    /// есть реплей при подключении.
    pub fn new(
        storage: Storage,
        cfg: SledAckConfig,
        user_id: UserId,
        device_id: Option<DeviceId>,
        registry: ConnRegistry,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            storage,
            cfg,
            user_id,
            device_id,
            pending: HashMap::new(),
            deadlines: BinaryHeap::new(),
            account_from: Some(0),
            device_from: device_id.map(|_| 0),
            registry,
            connection_id,
        }
    }

    pub fn unacked(&self) -> usize {
        self.pending.len()
    }

    fn has_room(&self) -> bool {
        self.pending.len() < self.cfg.max_unacked.max(1)
    }

    /// Есть место в окне и недочитанные записи.
    pub fn wants_pull(&self) -> bool {
        self.has_room() && (self.account_from.is_some() || self.device_from.is_some())
    }

    /// Откуда дочитывается очередь `scope`; `None` — дочитана (или это не
    /// очередь этой сессии).
    fn scan_from(&self, scope: InboxScope) -> Option<u64> {
        match scope {
            InboxScope::Account => self.account_from,
            InboxScope::Device(device_id) if Some(device_id) == self.device_id => self.device_from,
            InboxScope::Device(_) => None,
        }
    }

    /// Пометить очередь `scope` к дочитыванию с `from`.
    fn mark(&mut self, scope: InboxScope, from: u64) {
        let slot = match scope {
            InboxScope::Account => &mut self.account_from,
            InboxScope::Device(device_id) if Some(device_id) == self.device_id => {
                &mut self.device_from
            }
            // Чужое устройство: уведомление сюда попасть не могло.
            InboxScope::Device(_) => return,
        };
        *slot = Some(slot.map_or(from, |current| current.min(from)));
    }

    /// Перечитать обе очереди с начала: другая сессия получателя ушла, не
    /// подтвердив отданное, или уведомление могло потеряться.
    pub fn resync(&mut self) {
        self.mark(InboxScope::Account, 0);
        if let Some(device_id) = self.device_id {
            self.mark(InboxScope::Device(device_id), 0);
        }
    }

    /// Следующая порция недочитанных записей: не больше `limit` и не больше
    /// свободного места в окне. Записи, уже отданные этой сессией,
    /// пропускаются.
    pub fn pull(&mut self, limit: usize) -> Result<Vec<(InboxScope, StoredMessage)>> {
        let mut out = Vec::new();
        let scopes = [
            (InboxScope::Account, self.account_from),
            (
                InboxScope::Device(self.device_id.unwrap_or_default()),
                self.device_from,
            ),
        ];
        for (scope, from) in scopes {
            let Some(from) = from else { continue };
            let room = self
                .cfg
                .max_unacked
                .max(1)
                .saturating_sub(self.pending.len() + out.len())
                .min(limit.saturating_sub(out.len()));
            if room == 0 {
                break;
            }
            let pending = &self.pending;
            let scan = self
                .storage
                .scan_inbox(&self.user_id, scope, from, room, |id| {
                    pending.contains_key(&id)
                })?;
            let next_from = scan.next_from;
            out.extend(scan.messages.into_iter().map(|message| (scope, message)));
            match scope {
                InboxScope::Account => self.account_from = next_from,
                InboxScope::Device(_) => self.device_from = next_from,
            }
        }
        Ok(out)
    }

    /// Разобрать уведомление из канала сессии.
    ///
    /// Пока очередь области не дочитана до этой записи, уведомление тоже
    /// откладывается: запись дойдёт дочитыванием, по порядку
    /// идентификаторов, а не раньше более старых записей бэклога.
    pub fn offer(&mut self, scope: InboxScope, id: u64) -> Offer {
        if self.pending.contains_key(&id) {
            return Offer::Duplicate;
        }
        if self.scan_from(scope).is_some_and(|from| from <= id) {
            return Offer::Deferred;
        }
        if !self.has_room() {
            self.mark(scope, id);
            observability::observe_sled_window_full();
            return Offer::Deferred;
        }
        Offer::Accept
    }

    /// Проверить запись перед выдачей.
    pub fn prepare(&self, scope: InboxScope, id: u64) -> Result<WriteDecision> {
        Ok(
            match self.storage.inbox_failures(&self.user_id, scope, id)? {
                None => WriteDecision::Skip,
                Some(failures) => WriteDecision::Deliver {
                    last: failures.saturating_add(1) >= self.cfg.max_deliveries.max(1),
                    redelivery: failures > 0,
                },
            },
        )
    }

    /// Запись `id` отдана в сокет. Последняя выдача удаляет её; иначе она
    /// ждёт подтверждения в окне.
    pub fn written(&mut self, scope: InboxScope, id: u64, last: bool) -> Result<()> {
        if last {
            if self.storage.remove_inbox_record(&self.user_id, scope, id)? {
                observability::observe_sled_delivery_given_up();
                warn!(
                    user = %hex::encode(self.user_id),
                    device_id = ?self.device_id,
                    message_id = id,
                    max_deliveries = self.cfg.max_deliveries,
                    "envelope reached its delivery limit without a DeliveryAck; removed after the last delivery"
                );
            }
            return Ok(());
        }
        let deadline = Instant::now() + self.cfg.ack_wait;
        self.pending.insert(id, Pending { scope, deadline });
        self.deadlines.push(Reverse((deadline, id)));
        Ok(())
    }

    /// `DeliveryAck` этой сессии. Место в окне освобождается в любом
    /// случае; `true` — запись была и снята.
    pub fn ack(&mut self, id: u64) -> Result<bool> {
        self.pending.remove(&id);
        let acked = self.storage.ack_inbox(&self.user_id, self.device_id, id)?;
        if acked.is_some() {
            observability::observe_sled_delivery_acked();
        }
        Ok(acked.is_some())
    }

    /// Ближайший срок подтверждения в окне.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(Reverse((deadline, id))) = self.deadlines.peek().copied() {
            match self.pending.get(&id) {
                Some(pending) if pending.deadline == deadline => return Some(deadline),
                _ => {
                    self.deadlines.pop();
                }
            }
        }
        None
    }

    /// Снять из окна всё, что не подтверждено к `now`, учесть неудачу и
    /// пометить к повторной выдаче. Возвращает число истёкших записей.
    pub fn expire(&mut self, now: Instant) -> Result<usize> {
        let mut expired = 0usize;
        while let Some(Reverse((deadline, id))) = self.deadlines.peek().copied() {
            if deadline > now {
                break;
            }
            self.deadlines.pop();
            let Some(pending) = self.pending.get(&id).copied() else {
                continue;
            };
            if pending.deadline != deadline {
                continue;
            }
            self.pending.remove(&id);
            // Записи нет — её подтвердила другая сессия аккаунта или она
            // истекла: выдавать снова нечего.
            if self
                .storage
                .record_failed_delivery(&self.user_id, pending.scope, id)?
                .is_some()
            {
                expired += 1;
                observability::observe_sled_ack_timeout();
                self.mark(pending.scope, id);
            }
        }
        if expired > 0 {
            debug!(
                user = %hex::encode(self.user_id),
                device_id = ?self.device_id,
                expired,
                "delivery acks timed out; envelopes will be delivered again"
            );
        }
        Ok(expired)
    }
}

impl Drop for SledSession {
    /// Сессия кончилась. Отданное и неподтверждённое — неудачная выдача; всё
    /// это (и недочитанное) лежит в очереди. Другие сессии получателя
    /// перечитывают очереди, чтобы забрать его сразу, а не на следующем
    /// подключении.
    fn drop(&mut self) {
        let had_work = !self.pending.is_empty() || self.wants_pull_ignoring_room();
        for (id, pending) in std::mem::take(&mut self.pending) {
            if let Err(err) = self
                .storage
                .record_failed_delivery(&self.user_id, pending.scope, id)
            {
                warn!(
                    user = %hex::encode(self.user_id),
                    message_id = id,
                    error = %err,
                    "failed to count an unacknowledged delivery of a closed session"
                );
            }
        }
        if had_work {
            for target in self.registry.route_targets(&self.user_id, None) {
                if target.id != self.connection_id {
                    target.resync.notify_one();
                }
            }
        }
    }
}

impl SledSession {
    fn wants_pull_ignoring_room(&self) -> bool {
        self.account_from.is_some() || self.device_from.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RetentionPolicy;
    use std::time::Duration;

    fn storage(label: &str) -> (Storage, String) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("trust_message_tcp_sled_ack_{label}_{nanos}"))
            .to_string_lossy()
            .into_owned();
        let keep = RetentionPolicy::KeepFor(Duration::from_secs(86_400));
        (Storage::open(&path, keep, keep).unwrap(), path)
    }

    fn cfg(max_deliveries: u32, max_unacked: usize) -> SledAckConfig {
        SledAckConfig {
            ack_wait: Duration::from_secs(30),
            max_deliveries,
            max_unacked,
        }
    }

    const ME: [u8; 32] = [1; 32];
    const PEER: [u8; 32] = [2; 32];

    fn session(storage: &Storage, cfg: SledAckConfig, device: Option<DeviceId>) -> SledSession {
        SledSession::new(storage.clone(), cfg, ME, device, ConnRegistry::default(), 1)
    }

    fn enqueue(storage: &Storage, body: &[u8]) -> u64 {
        storage
            .enqueue_inbox(&ME, &PEER, None, body, None, 0)
            .unwrap()
            .id
    }

    /// Отдать порцию так, как это делает цикл сессии.
    fn deliver_all(session: &mut SledSession) -> Vec<u64> {
        let batch = session.pull(usize::MAX).unwrap();
        let mut ids = Vec::new();
        for (scope, message) in batch {
            if let WriteDecision::Deliver { last, .. } = session.prepare(scope, message.id).unwrap()
            {
                session.written(scope, message.id, last).unwrap();
                ids.push(message.id);
            }
        }
        ids
    }

    #[tokio::test]
    async fn ack_removes_the_record_and_frees_the_window() {
        let (storage, path) = storage("ack");
        let id = enqueue(&storage, b"one");
        let mut s = session(&storage, cfg(10, 4), None);
        assert_eq!(deliver_all(&mut s), vec![id]);
        assert_eq!(s.unacked(), 1);
        // Отдано, но не подтверждено: запись на месте.
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            Some(0)
        );
        assert!(s.ack(id).unwrap());
        assert_eq!(s.unacked(), 0);
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            None
        );
        // Повторный ack ничего не находит, но и не ломается.
        assert!(!s.ack(id).unwrap());
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn window_limits_unacked_and_defers_the_rest() {
        let (storage, path) = storage("window");
        let ids: Vec<u64> = (0..5).map(|i| enqueue(&storage, &[i])).collect();
        let mut s = session(&storage, cfg(10, 2), None);
        assert_eq!(deliver_all(&mut s), ids[..2].to_vec());
        assert!(!s.wants_pull(), "окно полно");
        // Уведомление при полном окне откладывается, а не теряется.
        let fresh = enqueue(&storage, b"fresh");
        assert_eq!(s.offer(InboxScope::Account, fresh), Offer::Deferred);
        assert!(s.ack(ids[0]).unwrap());
        assert!(s.wants_pull());
        assert_eq!(deliver_all(&mut s), vec![ids[2]]);
        assert!(s.ack(ids[1]).unwrap());
        assert!(s.ack(ids[2]).unwrap());
        assert_eq!(deliver_all(&mut s), vec![ids[3], ids[4]]);
        assert!(s.ack(ids[3]).unwrap());
        assert!(s.ack(ids[4]).unwrap());
        assert_eq!(deliver_all(&mut s), vec![fresh]);
        assert_eq!(s.offer(InboxScope::Account, fresh), Offer::Duplicate);
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn notifications_do_not_overtake_the_backlog() {
        let (storage, path) = storage("order");
        let old = enqueue(&storage, b"old");
        let mut s = session(&storage, cfg(10, 4), None);
        // Сессия ещё не дочитала очередь: свежая запись ждёт своей очереди.
        let fresh = enqueue(&storage, b"fresh");
        assert_eq!(s.offer(InboxScope::Account, fresh), Offer::Deferred);
        assert_eq!(deliver_all(&mut s), vec![old, fresh]);
        // Дочитано — уведомления снова отдаются сразу.
        let next = enqueue(&storage, b"next");
        assert_eq!(s.offer(InboxScope::Account, next), Offer::Accept);
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test(start_paused = true)]
    async fn ack_timeout_redelivers_and_counts_the_failure() {
        let (storage, path) = storage("timeout");
        let id = enqueue(&storage, b"slow");
        let mut s = session(&storage, cfg(10, 4), None);
        assert_eq!(deliver_all(&mut s), vec![id]);
        let deadline = s.next_deadline().expect("отдано — значит, есть срок");
        assert_eq!(s.expire(deadline - Duration::from_millis(1)).unwrap(), 0);
        assert_eq!(s.expire(deadline).unwrap(), 1);
        assert_eq!(s.unacked(), 0);
        assert!(s.wants_pull());
        let batch = s.pull(usize::MAX).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(
            s.prepare(InboxScope::Account, id).unwrap(),
            WriteDecision::Deliver {
                last: false,
                redelivery: true
            }
        );
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn record_acked_elsewhere_is_not_redelivered() {
        let (storage, path) = storage("acked_elsewhere");
        let id = enqueue(&storage, b"shared");
        let mut s = session(&storage, cfg(10, 4), None);
        assert_eq!(deliver_all(&mut s), vec![id]);
        // Другая сессия аккаунта подтвердила запись.
        storage.ack_inbox(&ME, Some(9), id).unwrap();
        let deadline = s.next_deadline().unwrap();
        assert_eq!(s.expire(deadline).unwrap(), 0);
        assert_eq!(
            s.prepare(InboxScope::Account, id).unwrap(),
            WriteDecision::Skip
        );
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn client_without_acks_gets_a_bounded_number_of_deliveries() {
        let (storage, path) = storage("no_acks");
        let id = enqueue(&storage, b"legacy");
        let mut deliveries = 0;
        for _ in 0..10 {
            let mut s = session(&storage, cfg(3, 4), None);
            deliveries += deliver_all(&mut s).len();
            // Сессия рвётся, ничего не подтвердив.
        }
        assert_eq!(deliveries, 3);
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            None,
            "после последней выдачи запись удалена"
        );
        assert_eq!(storage.cleanup_orphan_delivery_failures().unwrap(), 0);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn one_delivery_reproduces_the_pre_ack_behaviour() {
        let (storage, path) = storage("single");
        let id = enqueue(&storage, b"once");
        let mut s = session(&storage, cfg(1, 4), None);
        assert_eq!(deliver_all(&mut s), vec![id]);
        assert_eq!(s.unacked(), 0);
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            None
        );
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn device_records_are_acked_only_by_their_device() {
        let (storage, path) = storage("device_scope");
        let id = storage
            .enqueue_device_inbox(&ME, 7, &PEER, None, b"dev", None, 0)
            .unwrap()
            .id;
        // Сессия без устройства и сессия чужого устройства её не видят и не
        // подтверждают.
        let mut account_only = session(&storage, cfg(10, 4), None);
        assert!(deliver_all(&mut account_only).is_empty());
        assert!(!account_only.ack(id).unwrap());
        let mut other = session(&storage, cfg(10, 4), Some(8));
        assert!(deliver_all(&mut other).is_empty());
        assert!(!other.ack(id).unwrap());
        // Чужой пользователь — тем более.
        assert_eq!(storage.ack_inbox(&PEER, Some(7), id).unwrap(), None);
        let mut own = session(&storage, cfg(10, 4), Some(7));
        assert_eq!(deliver_all(&mut own), vec![id]);
        assert!(own.ack(id).unwrap());
        drop((account_only, other, own));
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn closed_session_wakes_the_other_sessions_of_the_user() {
        let (storage, path) = storage("resync");
        let registry = ConnRegistry::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let other = registry.insert(ME, Some(2), tx);
        let (tx, _rx2) = tokio::sync::mpsc::channel(1);
        let mine = registry.insert(ME, Some(1), tx);
        enqueue(&storage, b"held");
        let mut s = SledSession::new(
            storage.clone(),
            cfg(10, 4),
            ME,
            Some(1),
            registry.clone(),
            mine.connection_id,
        );
        assert_eq!(deliver_all(&mut s).len(), 1);
        drop(s);
        tokio::time::timeout(Duration::from_secs(1), other.resync.notified())
            .await
            .expect("другая сессия получателя обязана перечитать очередь");
        let _ = std::fs::remove_dir_all(path);
    }
}
