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
//! запись выдаётся снова той же сессии.
//!
//! По умолчанию повторы не ограничены, как у брокера: запись живёт до
//! подтверждения или конца хранения. `max_deliveries > 0` — ручка для
//! клиентов без `DeliveryAck`: неудачные выдачи считаются в хранилище, и
//! выдача номер `max_deliveries` — последняя (после записи в сокет запись
//! удаляется, как до подтверждений вовсе).
//!
//! Неудачей считается только выдача, про которую доказано, что клиент жив и
//! её не подтвердил: «не успел обработать» — не неудача. Доказательство —
//! клиент подтвердил то, что ему выдали позже (клиент обрабатывает по
//! порядку, значит, этот конверт он отверг; «позже» — по первой выдаче
//! записи в сессии, повтор номер не меняет), либо любой кадр клиента после
//! выдачи — но только у сессии, которая за всю жизнь не прислала ни одного
//! `DeliveryAck` и прожила дольше [`LEGACY_PROOF_AGE_FACTOR`] сроков
//! `ack_wait` (клиент без подтверждений, а не клиент, который ещё не успел
//! подтвердить первое). Мёртвый сокет (телефон пропал без FIN) кадров не
//! шлёт и неудач не копит, а рвёт его `TCP_USER_TIMEOUT`. Сессия, ушедшая
//! с хвостом необработанного (короткое фоновое пробуждение), засчитывает
//! неудачу только записям раньше последней подтверждённой.
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

/// Сколько сроков `ack_wait` должна прожить сессия без единого
/// `DeliveryAck`, чтобы её кадры после выдачи считались доказательством
/// неподтверждения (клиент без подтверждений). Раньше молчание об ack —
/// скорее медленная обработка первого конверта, чем старый клиент.
pub const LEGACY_PROOF_AGE_FACTOR: u32 = 3;

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
    /// Порядковый номер выдачи в этой сессии.
    seq: u64,
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
    /// Номер следующей выдачи в сессии (с 1).
    next_seq: u64,
    /// Наибольший номер выдачи, подтверждённой этой сессией; 0 — ни одной.
    acked_seq: u64,
    /// `next_seq` на момент последнего кадра клиента: выдачи с меньшим
    /// номером клиент застал живым.
    frame_seq: u64,
    /// Истёкшие и ждущие повторной выдачи → номер их первой выдачи в
    /// сессии. Повтор сохраняет номер: подтверждение после повтора иначе
    /// сопоставлялось бы с поздним номером, и более ранние неподтверждённые
    /// выдачи выглядели бы отвергнутыми.
    redeliver: HashMap<u64, u64>,
    /// Прислала ли сессия хоть один `DeliveryAck` (любой, даже чужой).
    acks_seen: bool,
    started: Instant,
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
            next_seq: 1,
            acked_seq: 0,
            frame_seq: 0,
            redeliver: HashMap::new(),
            acks_seen: false,
            started: Instant::now(),
        }
    }

    /// Кадр клиента прочитан: клиент жив на момент всех уже сделанных выдач.
    pub fn note_client_frame(&mut self) {
        self.frame_seq = self.next_seq;
    }

    /// Доказано ли, что живой клиент выдачу `seq` не подтвердил, а не просто
    /// не успел обработать (см. документацию модуля).
    fn proven_unacked(&self, seq: u64, now: Instant) -> bool {
        if seq < self.acked_seq {
            return true;
        }
        let legacy_age = self.cfg.ack_wait * LEGACY_PROOF_AGE_FACTOR;
        !self.acks_seen
            && now.saturating_duration_since(self.started) >= legacy_age
            && seq < self.frame_seq
    }

    /// Забыть запись, которую выдавать снова не придётся.
    fn forget(&mut self, id: u64) {
        self.redeliver.remove(&id);
    }

    /// Ведётся ли счёт неудач: только при заданном пределе выдач.
    fn counts_failures(&self) -> bool {
        self.cfg.max_deliveries > 0
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

    /// Проверить запись перед выдачей. Без предела выдач счётчик неудач не
    /// читается: одна точечная проверка, что запись на месте.
    pub fn prepare(&mut self, scope: InboxScope, id: u64) -> Result<WriteDecision> {
        if !self.counts_failures() {
            if !self.storage.inbox_contains(&self.user_id, scope, id)? {
                self.forget(id);
                return Ok(WriteDecision::Skip);
            }
            return Ok(WriteDecision::Deliver {
                last: false,
                redelivery: self.redeliver.contains_key(&id),
            });
        }
        Ok(
            match self.storage.inbox_failures(&self.user_id, scope, id)? {
                None => {
                    self.forget(id);
                    WriteDecision::Skip
                }
                Some(failures) => WriteDecision::Deliver {
                    last: failures.saturating_add(1) >= self.cfg.max_deliveries,
                    redelivery: self.redeliver.contains_key(&id) || failures > 0,
                },
            },
        )
    }

    /// Запись `id` отдана в сокет. Последняя выдача удаляет её; иначе она
    /// ждёт подтверждения в окне.
    pub fn written(&mut self, scope: InboxScope, id: u64, last: bool) -> Result<()> {
        let first_seq = self.redeliver.remove(&id);
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
        let seq = first_seq.unwrap_or_else(|| {
            let seq = self.next_seq;
            self.next_seq += 1;
            seq
        });
        self.pending.insert(
            id,
            Pending {
                scope,
                deadline,
                seq,
            },
        );
        self.deadlines.push(Reverse((deadline, id)));
        Ok(())
    }

    /// `DeliveryAck` этой сессии. Место в окне освобождается в любом
    /// случае; `true` — запись была и снята.
    pub fn ack(&mut self, id: u64) -> Result<bool> {
        self.acks_seen = true;
        if let Some(first_seq) = self.redeliver.remove(&id) {
            self.acked_seq = self.acked_seq.max(first_seq);
        }
        if let Some(pending) = self.pending.remove(&id) {
            self.acked_seq = self.acked_seq.max(pending.seq);
        }
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

    /// Снять из окна всё, что не подтверждено к `now`, и пометить к
    /// повторной выдаче. Неудача учитывается, только если доказана (см.
    /// документацию модуля) и задан предел выдач. Возвращает число истёкших
    /// записей.
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
            if self.counts_failures() && self.proven_unacked(pending.seq, now) {
                // Записи нет — её подтвердила другая сессия аккаунта или
                // она истекла; счёт тогда ничего не меняет.
                self.storage
                    .record_failed_delivery(&self.user_id, pending.scope, id)?;
            }
            // Запись, которой уже нет, дочитывание просто не найдёт.
            expired += 1;
            observability::observe_sled_ack_timeout();
            self.redeliver.insert(id, pending.seq);
            self.mark(pending.scope, id);
        }
        // Записи, подтверждённые другой сессией, дочитывание уже не найдёт,
        // и из карты они сами не уйдут; держать их дольше, чем помещается
        // в несколько окон, незачем — потеряется только метка «повтор».
        if self.redeliver.len() > self.cfg.max_unacked.max(1).saturating_mul(4) {
            let storage = &self.storage;
            let user_id = self.user_id;
            let device_id = self.device_id;
            self.redeliver.retain(|id, _| {
                storage
                    .ack_inbox_probe(&user_id, device_id, *id)
                    .unwrap_or(true)
            });
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
    /// Сессия кончилась. Отданное и неподтверждённое (и недочитанное) лежит
    /// в очереди. Неудачей считаются только записи раньше последней
    /// подтверждённой: хвост после неё клиент мог просто не успеть
    /// обработать. Другие сессии получателя перечитывают очереди, чтобы
    /// забрать оставленное сразу, а не на следующем подключении.
    fn drop(&mut self) {
        let had_work = !self.pending.is_empty() || self.wants_pull_ignoring_room();
        let pending = std::mem::take(&mut self.pending);
        let counts = self.counts_failures();
        for (id, pending) in pending {
            if !counts || pending.seq >= self.acked_seq {
                continue;
            }
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
    async fn ack_timeout_redelivers_in_the_same_session() {
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
        s.expire(deadline).unwrap();
        assert_eq!(
            s.prepare(InboxScope::Account, id).unwrap(),
            WriteDecision::Skip
        );
        assert!(s.pull(usize::MAX).unwrap().is_empty());
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn client_without_acks_gets_a_bounded_number_of_deliveries() {
        // Живая сессия старого клиента: пингует, но ничего не подтверждает.
        let (storage, path) = storage("no_acks");
        let id = enqueue(&storage, b"legacy");
        let mut s = session(&storage, cfg(3, 4), None);
        let mut deliveries = 0;
        for _ in 0..10 {
            deliveries += deliver_all(&mut s).len();
            s.note_client_frame();
            if let Some(deadline) = s.next_deadline() {
                // Сессия старше `LEGACY_PROOF_AGE_FACTOR` сроков.
                s.expire(deadline + Duration::from_secs(90)).unwrap();
            }
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
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    /// Без предела (по умолчанию) неудачи не считаются вовсе: повтор идёт,
    /// пока запись не подтвердят или она не истечёт.
    #[tokio::test]
    async fn without_a_limit_redelivery_never_gives_up() {
        let (storage, path) = storage("unlimited");
        let id = enqueue(&storage, b"forever");
        let mut s = session(&storage, cfg(0, 4), None);
        for round in 0..20 {
            assert_eq!(deliver_all(&mut s), vec![id], "round {round}");
            s.note_client_frame();
            let deadline = s.next_deadline().unwrap();
            s.expire(deadline).unwrap();
        }
        assert!(storage.delivery_failures_is_empty_for_tests());
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    /// Полуоткрытый сокет: клиент пропал без FIN, кадров от него нет.
    /// Повторы в такую сессию неудачами не считаются, и даже с пределом
    /// запись доживает до возвращения клиента.
    #[tokio::test]
    async fn dead_socket_does_not_burn_the_delivery_limit() {
        let (storage, path) = storage("dead_socket");
        let id = enqueue(&storage, b"later");
        {
            let mut s = session(&storage, cfg(3, 4), None);
            for _ in 0..20 {
                assert_eq!(deliver_all(&mut s), vec![id]);
                let deadline = s.next_deadline().unwrap();
                s.expire(deadline).unwrap();
            }
            assert_eq!(deliver_all(&mut s), vec![id]);
        }
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            Some(0)
        );
        let mut back = session(&storage, cfg(3, 4), None);
        assert_eq!(deliver_all(&mut back), vec![id]);
        assert!(back.ack(id).unwrap());
        drop(back);
        let _ = std::fs::remove_dir_all(path);
    }

    /// Большой бэклог и короткое фоновое пробуждение: клиент успел
    /// обработать и подтвердить начало, процесс убит. Хвост после последней
    /// подтверждённой неудачей не считается, сколько бы пробуждений ни было.
    #[tokio::test]
    async fn short_wakeups_do_not_burn_the_unprocessed_tail() {
        let (storage, path) = storage("short_wakeups");
        let ids: Vec<u64> = (0..40u8).map(|i| enqueue(&storage, &[i])).collect();
        for wake in 0..20usize {
            let mut s = session(&storage, cfg(3, 16), None);
            let delivered = deliver_all(&mut s);
            // За пробуждение обработаны и подтверждены два первых.
            for id in delivered.iter().take(2) {
                assert!(s.ack(*id).unwrap(), "wake {wake}");
            }
        }
        // 40 записей по две за пробуждение — всё дошло, ничего не потеряно.
        for id in ids {
            assert_eq!(
                storage
                    .inbox_failures(&ME, InboxScope::Account, id)
                    .unwrap(),
                None
            );
        }
        assert!(storage.delivery_failures_is_empty_for_tests());
        let _ = std::fs::remove_dir_all(path);
    }

    /// «Ядовитый» конверт: клиент подтвердил выданное позже, а этот — нет.
    /// Это доказанная неудача, и она считается и по истечении срока, и при
    /// уходе сессии.
    #[tokio::test]
    async fn skipped_envelope_counts_as_a_failure() {
        let (storage, path) = storage("poison");
        let poison = enqueue(&storage, b"poison");
        let good = enqueue(&storage, b"good");
        {
            let mut s = session(&storage, cfg(3, 4), None);
            assert_eq!(deliver_all(&mut s), vec![poison, good]);
            assert!(s.ack(good).unwrap());
        }
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, poison)
                .unwrap(),
            Some(1)
        );
        let mut s = session(&storage, cfg(3, 4), None);
        let fresh = enqueue(&storage, b"fresh");
        assert_eq!(deliver_all(&mut s), vec![poison, fresh]);
        assert!(s.ack(fresh).unwrap());
        let deadline = s.next_deadline().unwrap();
        s.expire(deadline).unwrap();
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, poison)
                .unwrap(),
            Some(2)
        );
        // Третья выдача последняя.
        assert_eq!(deliver_all(&mut s), vec![poison]);
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, poison)
                .unwrap(),
            None
        );
        drop(s);
        let _ = std::fs::remove_dir_all(path);
    }

    /// Повтор сохраняет номер первой выдачи: подтверждение повторённой
    /// записи не делает «отвергнутыми» выданные между оригиналом и повтором.
    #[tokio::test]
    async fn ack_of_a_redelivery_is_matched_to_the_first_delivery() {
        let (storage, path) = storage("first_seq");
        let a = enqueue(&storage, b"a");
        let mut s = session(&storage, cfg(3, 4), None);
        assert_eq!(deliver_all(&mut s), vec![a]);
        let deadline_a = s.next_deadline().unwrap();
        let b = enqueue(&storage, b"b");
        s.resync();
        assert_eq!(deliver_all(&mut s), vec![b]);
        // Срок вышел только у `a`; медленный клиент ещё обрабатывает.
        assert_eq!(s.expire(deadline_a).unwrap(), 1);
        assert_eq!(deliver_all(&mut s), vec![a]);
        assert!(s.ack(a).unwrap());
        drop(s);
        assert_eq!(
            storage.inbox_failures(&ME, InboxScope::Account, b).unwrap(),
            Some(0),
            "b was delivered after a's first delivery and must not count"
        );
        let _ = std::fs::remove_dir_all(path);
    }

    /// Кадры после выдачи доказывают неподтверждение только у сессии без
    /// единого `DeliveryAck`, прожившей дольше `LEGACY_PROOF_AGE_FACTOR`
    /// сроков: клиент с подтверждениями, который ещё обрабатывает первый
    /// конверт и пингует, неудач не копит.
    #[tokio::test]
    async fn frames_prove_nothing_for_young_or_acking_sessions() {
        let (storage, path) = storage("legacy_rule");
        let id = enqueue(&storage, b"slow");
        let mut s = session(&storage, cfg(3, 4), None);
        assert_eq!(deliver_all(&mut s), vec![id]);
        s.note_client_frame();
        let deadline = s.next_deadline().unwrap();
        s.expire(deadline).unwrap();
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            Some(0),
            "young session"
        );
        // Сессия прислала хоть один ack (пусть и чужой записи) — старой она
        // уже не считается, сколько бы ни жила.
        s.ack(u64::MAX).unwrap();
        assert_eq!(deliver_all(&mut s), vec![id]);
        s.note_client_frame();
        let deadline = s.next_deadline().unwrap();
        s.expire(deadline + Duration::from_secs(90)).unwrap();
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            Some(0),
            "acking session"
        );
        drop(s);
        // Старая сессия без единого ack — клиент без подтверждений.
        let mut legacy = session(&storage, cfg(3, 4), None);
        assert_eq!(deliver_all(&mut legacy), vec![id]);
        legacy.note_client_frame();
        let deadline = legacy.next_deadline().unwrap();
        legacy.expire(deadline + Duration::from_secs(90)).unwrap();
        assert_eq!(
            storage
                .inbox_failures(&ME, InboxScope::Account, id)
                .unwrap(),
            Some(1)
        );
        drop(legacy);
        let _ = std::fs::remove_dir_all(path);
    }

    /// Запись, пришедшая и уведомлением, и дочитыванием, выдаётся одной
    /// сессии ровно один раз — в каком порядке ни приди.
    #[tokio::test]
    async fn notification_and_scan_of_one_record_deliver_it_once() {
        let (storage, path) = storage("once");
        let mut s = session(&storage, cfg(0, 4), None);
        assert!(deliver_all(&mut s).is_empty());
        // Уведомление первым, дочитывание после.
        let first = enqueue(&storage, b"first");
        assert_eq!(s.offer(InboxScope::Account, first), Offer::Accept);
        assert!(matches!(
            s.prepare(InboxScope::Account, first).unwrap(),
            WriteDecision::Deliver { .. }
        ));
        s.written(InboxScope::Account, first, false).unwrap();
        s.resync();
        assert!(deliver_all(&mut s).is_empty());
        // Дочитывание первым, уведомление после.
        let second = enqueue(&storage, b"second");
        s.resync();
        assert_eq!(deliver_all(&mut s), vec![second]);
        assert_eq!(s.offer(InboxScope::Account, second), Offer::Duplicate);
        drop(s);
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
