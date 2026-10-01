//! Реестр mailbox-очередей резидентов.
//!
//! Очередь — адрес, по которому контакт кладёт депозит. Знание `queue_id`
//! и есть capability на запись, поэтому идентификатор обязан быть
//! случайным, непереборным и выданным **нодой**: пространство имён её,
//! уникальность в нём гарантирует только она, а клиент, называющий id сам,
//! однажды назовёт чужой.
//!
//! Два дерева, и второе — не кэш, а необходимость:
//! - `queues`      — `owner(32) || queue_id(32)` → `created_at(u64 BE)`.
//!   Отвечает на «какие очереди у этого пользователя» (перечисление,
//!   потолок, проверка владения).
//! - `queue_owner` — `queue_id(32)` → `owner(32)`. Отвечает на «чья это
//!   очередь» за одно чтение. Депозит приходит с одним лишь `queue_id`, и
//!   без обратного индекса маршрутизация означала бы скан всего дерева на
//!   каждое сообщение.
//!
//! Расхождение деревьев — это потерянная или неотзываемая очередь, поэтому
//! пишутся они одной транзакцией sled, а не двумя put'ами подряд.

use anyhow::{Context, Result};
use sled::Transactional;
use sled::transaction::TransactionError;
use sled::{Db, Tree};

use crate::state::registry::UserId;

/// Идентификатор очереди: 32 случайных байта.
pub type QueueId = [u8; 32];

const KEY_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueRecord {
    pub queue_id: QueueId,
    pub created_at_secs: u64,
}

/// Почему нода отказала в операции над очередью.
///
/// `NotFound` покрывает и «нет такой», и «есть, но чужая». Различать их
/// нельзя: ответ, подтверждающий существование чужой очереди, превращает
/// отзыв в оракул для перебора идентификаторов, а идентификатор — это
/// право писать.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    Limit,
    NotFound,
}

#[derive(Clone)]
pub struct QueueStore {
    queues: Tree,
    owners: Tree,
}

impl QueueStore {
    pub fn open(db: &Db) -> Result<Self> {
        Ok(Self {
            queues: db
                .open_tree("queues")
                .context("failed to open `queues` tree")?,
            owners: db
                .open_tree("queue_owner")
                .context("failed to open `queue_owner` tree")?,
        })
    }

    /// Завести очередь. Идентификатор генерирует вызывающий (нода, 32 байта
    /// из CSPRNG), сюда он приходит готовым — так функция тестируема без RNG.
    /// Занятость `queue_id` не проверяется: уникальность обеспечивает размер
    /// случайного идентификатора.
    ///
    /// `max_per_user = 0` означает «без ограничения». Потолок сверяется до
    /// транзакции, поэтому параллельные вызовы одного владельца могут его
    /// превысить.
    pub fn allocate(
        &self,
        owner: &UserId,
        queue_id: QueueId,
        created_at_secs: u64,
        max_per_user: usize,
    ) -> Result<Result<QueueRecord, QueueError>> {
        if max_per_user > 0 && self.count_for(owner)? >= max_per_user {
            return Ok(Err(QueueError::Limit));
        }

        let key = compose_key(owner, &queue_id);
        let value = created_at_secs.to_be_bytes();

        let outcome: Result<(), TransactionError> =
            (&self.queues, &self.owners).transaction(|(queues, owners)| {
                queues.insert(&key[..], &value[..])?;
                owners.insert(&queue_id[..], &owner[..])?;
                Ok(())
            });
        outcome.context("failed to persist the queue allocation")?;

        Ok(Ok(QueueRecord {
            queue_id,
            created_at_secs,
        }))
    }

    /// Отозвать очередь. Успех только если она принадлежит `owner` —
    /// проверка владения и удаление в одной транзакции, иначе параллельный
    /// отзыв мог бы удалить запись дважды и разъехаться с индексом.
    pub fn revoke(&self, owner: &UserId, queue_id: &QueueId) -> Result<Result<(), QueueError>> {
        let key = compose_key(owner, queue_id);

        // Отсутствие записи — флаг, а не abort: до первого удаления транзакция
        // ничего не изменила, откатывать нечего.
        let outcome: Result<bool, TransactionError> =
            (&self.queues, &self.owners).transaction(|(queues, owners)| {
                if queues.remove(&key[..])?.is_none() {
                    return Ok(false);
                }
                owners.remove(&queue_id[..])?;
                Ok(true)
            });

        if outcome.context("failed to revoke the queue")? {
            Ok(Ok(()))
        } else {
            Ok(Err(QueueError::NotFound))
        }
    }

    /// Владелец очереди — вход маршрутизации депозита. Значение индекса
    /// неверной длины читается как «очереди нет».
    pub fn owner_of(&self, queue_id: &QueueId) -> Result<Option<UserId>> {
        let Some(raw) = self
            .owners
            .get(&queue_id[..])
            .context("failed to read the queue owner index")?
        else {
            return Ok(None);
        };
        Ok(UserId::try_from(raw.as_ref()).ok())
    }

    /// Очереди пользователя. Порядок — по `queue_id`, то есть случайный:
    /// сортировать по времени создания нечем без второго индекса, а клиенту
    /// он и не нужен — `created_at` едет в каждой записи.
    pub fn list(&self, owner: &UserId) -> Result<Vec<QueueRecord>> {
        let mut out = Vec::new();
        for item in self.queues.scan_prefix(&owner[..]) {
            let (key, value) = item.context("failed to scan the queue tree")?;
            if key.len() != KEY_LEN {
                continue;
            }
            let Ok(queue_id) = QueueId::try_from(&key[32..]) else {
                continue;
            };
            let created_at_secs = value
                .as_ref()
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            out.push(QueueRecord {
                queue_id,
                created_at_secs,
            });
        }
        Ok(out)
    }

    fn count_for(&self, owner: &UserId) -> Result<usize> {
        Ok(self.queues.scan_prefix(&owner[..]).count())
    }
}

fn compose_key(owner: &UserId, queue_id: &QueueId) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..32].copy_from_slice(owner);
    key[32..].copy_from_slice(queue_id);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> QueueStore {
        let db = sled::Config::new().temporary(true).open().unwrap();
        QueueStore::open(&db).unwrap()
    }

    const ALICE: UserId = [1u8; 32];
    const BOB: UserId = [2u8; 32];

    #[test]
    fn allocated_queue_is_listed_and_resolvable() {
        let store = store();
        let q = [9u8; 32];
        store.allocate(&ALICE, q, 100, 0).unwrap().unwrap();

        let listed = store.list(&ALICE).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].queue_id, q);
        assert_eq!(listed[0].created_at_secs, 100);
        assert_eq!(store.owner_of(&q).unwrap(), Some(ALICE));
    }

    #[test]
    fn revoking_removes_both_the_record_and_the_owner_index() {
        // Разъехавшиеся деревья — это либо очередь, которую нельзя отозвать,
        // либо депозит, уходящий владельцу уже отозванной. Проверяем оба.
        let store = store();
        let q = [9u8; 32];
        store.allocate(&ALICE, q, 100, 0).unwrap().unwrap();
        store.revoke(&ALICE, &q).unwrap().unwrap();

        assert!(store.list(&ALICE).unwrap().is_empty());
        assert_eq!(store.owner_of(&q).unwrap(), None);
    }

    #[test]
    fn a_stranger_cannot_revoke_someone_elses_queue() {
        let store = store();
        let q = [9u8; 32];
        store.allocate(&ALICE, q, 100, 0).unwrap().unwrap();

        assert_eq!(store.revoke(&BOB, &q).unwrap(), Err(QueueError::NotFound));
        // И очередь на месте: неудачный отзыв не должен ничего трогать.
        assert_eq!(store.owner_of(&q).unwrap(), Some(ALICE));
    }

    #[test]
    fn revoking_a_missing_queue_is_not_found_not_success() {
        let store = store();
        assert_eq!(
            store.revoke(&ALICE, &[7u8; 32]).unwrap(),
            Err(QueueError::NotFound)
        );
    }

    #[test]
    fn the_per_user_limit_is_enforced_and_is_per_user() {
        let store = store();
        store.allocate(&ALICE, [1u8; 32], 1, 2).unwrap().unwrap();
        store.allocate(&ALICE, [2u8; 32], 2, 2).unwrap().unwrap();
        assert_eq!(
            store.allocate(&ALICE, [3u8; 32], 3, 2).unwrap(),
            Err(QueueError::Limit)
        );
        // Потолок чужого пользователя не расходуется.
        store.allocate(&BOB, [4u8; 32], 4, 2).unwrap().unwrap();
    }

    #[test]
    fn a_revoked_slot_frees_room_under_the_limit() {
        let store = store();
        store.allocate(&ALICE, [1u8; 32], 1, 1).unwrap().unwrap();
        assert_eq!(
            store.allocate(&ALICE, [2u8; 32], 2, 1).unwrap(),
            Err(QueueError::Limit)
        );
        store.revoke(&ALICE, &[1u8; 32]).unwrap().unwrap();
        store.allocate(&ALICE, [2u8; 32], 2, 1).unwrap().unwrap();
    }

    #[test]
    fn zero_limit_means_unbounded() {
        let store = store();
        for i in 0..32u8 {
            store.allocate(&ALICE, [i; 32], 1, 0).unwrap().unwrap();
        }
        assert_eq!(store.list(&ALICE).unwrap().len(), 32);
    }

    fn temp_path(label: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("trust_queues_{label}_{nanos}"));
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn queues_survive_reopening_the_database() {
        // Очередь, пережившая рестарт ноды, — это весь смысл её хранения:
        // контакт держит `queue_id` у себя и после перезапуска обязан
        // по-прежнему попадать по нему в того же владельца.
        let path = temp_path("reopen");
        let q = [9u8; 32];
        {
            let db = sled::open(&path).unwrap();
            let store = QueueStore::open(&db).unwrap();
            store.allocate(&ALICE, q, 100, 0).unwrap().unwrap();
        }
        let db = sled::open(&path).unwrap();
        let store = QueueStore::open(&db).unwrap();
        assert_eq!(store.owner_of(&q).unwrap(), Some(ALICE));
        assert_eq!(store.list(&ALICE).unwrap().len(), 1);
    }
}
