//! Реестр mailbox-очередей резидентов.
//!
//! Очередь — адрес, по которому контакт кладёт депозит. Знание `queue_id`
//! и есть capability на запись, поэтому идентификатор обязан быть
//! непереборным и выданным **нодой**: пространство имён её, уникальность в
//! нём гарантирует только она, а клиент, называющий id сам, однажды назовёт
//! чужой.
//!
//! Id получается одним из двух способов:
//! - случайно — 32 байта из CSPRNG ноды (`AllocateQueue` без тега);
//! - из тега клиента — `SHA-256("tm-queue-id-v1\0" ‖ owner ‖ tag)`
//!   ([`derive_queue_id`]). Тег клиент выводит из секрета аккаунта, поэтому
//!   любое устройство аккаунта выделяет ту же очередь, а владелец в хеше
//!   оставляет пространство имён за нодой: чужой id тегом не назвать. Тег
//!   ноде непрозрачен и не хранится — из него id вычисляет любой.
//!
//! Деревья:
//! - `queues`      — `owner(32) ‖ queue_id(32)` → `created_at(u64 BE) ‖
//!   expires_at(u64 BE)`; `expires_at = 0` — бессрочная. Значение из 8
//!   байт (до сроков) читается как бессрочная очередь. Отвечает на «какие
//!   живые очереди у пользователя» (перечисление, потолок, владение).
//! - `queue_owner` — `queue_id(32)` → `owner(32) ‖ expires_at(u64 BE)`.
//!   Отвечает на «чья это очередь» за одно чтение: депозит приходит с одним
//!   лишь `queue_id`, и без обратного индекса маршрутизация означала бы скан
//!   всего дерева на каждое сообщение. Срок лежит и здесь, чтобы депозит в
//!   истёкшую очередь отвергался тем же единственным чтением. Значение из
//!   32 байт — бессрочная очередь.
//! - `queue_tombstones` — `owner(32) ‖ queue_id(32)` → `revoked_at(u64 BE)`.
//!   Надгробие отозванной или истёкшей очереди: тот же id заново не
//!   выделяется, иначе устаревшее устройство вернуло бы заблокированному
//!   контакту доступ по старому адресу. В `queue_owner` надгробий нет —
//!   для маршрутизации отозванная очередь неотличима от неизвестной.
//! - `queue_tombstone_count` — `owner(32)` → число надгробий (u64 BE).
//!   Счётчик держит потолок надгробий без скана на каждом отзыве; сканом
//!   ищется только вытесняемое.
//!
//! Живая очередь и её надгробие взаимоисключающи, а индексы обязаны
//! сходиться с `queues`: расхождение — это потерянная, неотзываемая или
//! воскресшая очередь. Поэтому любое изменение пишется одной транзакцией
//! sled по всем затронутым деревьям.
//!
//! Истёкшая очередь ведёт себя как отозванная в момент `expires_at`.
//! Переводится в надгробие лениво: при разрешении депозита и при любой
//! операции владельца над своими очередями. Депозит в истёкшую не проходит
//! ни мгновения: срок сверяется на том же чтении, что и владелец.
//!
//! Рядом живут два свойства аккаунта, без очередей смысла не имеющие:
//! - `queue_only` — `owner(32)` → `set_at(u64 BE)`: ключ есть — режим
//!   «только по очередям» включён (блокировка контакта при нём — отзыв его
//!   очереди);
//! - `account_records` — `owner(32)` → `version(u64 BE) ‖ record`: запись
//!   аккаунта, непрозрачная для ноды (клиент шифрует в ней пул своих нод),
//!   с заменой по CAS версии. Через неё устройства аккаунта сходятся в
//!   составе пула.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sled::Transactional;
use sled::transaction::{TransactionError, TransactionalTree, UnabortableTransactionError};
use sled::{Db, Tree};

use crate::state::registry::UserId;

/// Идентификатор очереди: 32 байта.
pub type QueueId = [u8; 32];

/// Тег детерминированного выделения: 32 байта, которые клиент выводит из
/// секрета аккаунта. Ноде непрозрачен.
pub type QueueTag = [u8; 32];

/// Домен вывода id из тега: 15 байт ASCII с нулевым байтом в конце.
pub const QUEUE_ID_DOMAIN: &[u8; 15] = b"tm-queue-id-v1\0";

/// Потолок надгробий на пользователя. Сверх него вытесняется надгробие с
/// наименьшим `revoked_at` (при равенстве — с меньшим id); отзыв из-за
/// потолка не отказывает никогда.
///
/// Константа, а не переменная окружения: от неё зависит не ресурс ноды, а
/// гарантия клиенту (сколько отзывов нода помнит), и разные значения на
/// нодах одного пула значили бы разные гарантии.
pub const MAX_QUEUE_TOMBSTONES_PER_USER: usize = 8192;

/// Гистерезис вытеснения: при переполнении потолка надгробия вытесняются
/// до `потолок − TOMBSTONE_EVICTION_SLACK`. Без запаса аккаунт на потолке
/// сканировал бы все 8192 надгробия на каждом следующем отзыве; с ним скан
/// случается раз на 256 отзывов. Гарантия клиенту — «нода помнит не меньше
/// 7936 последних отзывов».
pub const TOMBSTONE_EVICTION_SLACK: usize = 256;

/// Потолок записи аккаунта, байт. Длиннее — `Invalid`.
pub const MAX_ACCOUNT_RECORD_LEN: usize = 4096;

const KEY_LEN: usize = 64;

/// Вывести id очереди из тега: `SHA-256("tm-queue-id-v1\0" ‖ owner ‖ tag)`.
/// Владелец в хеше — то, что не даёт назвать тегом чужую очередь: один и
/// тот же тег у разных владельцев даёт разные id.
pub fn derive_queue_id(owner: &UserId, tag: &QueueTag) -> QueueId {
    let mut hasher = Sha256::new();
    hasher.update(QUEUE_ID_DOMAIN);
    hasher.update(owner);
    hasher.update(tag);
    hasher.finalize().into()
}

/// Отпечаток очереди для логов: первые 4 байта `SHA-256(queue_id)` в hex.
///
/// Сам `queue_id` — право писать в очередь, и логам его доверять нельзя:
/// у логов другой круг читателей и другой срок хранения, чем у хранилища.
/// Отпечаток связывает строки лога об одной очереди, но права не даёт, а
/// 32 бита не позволяют восстановить id перебором.
pub fn queue_fingerprint(queue_id: &QueueId) -> String {
    let digest: [u8; 32] = Sha256::digest(queue_id).into();
    hex::encode(&digest[..4])
}

/// Запись `ListQueues`: живая очередь (`revoked_at_secs == 0`) или
/// надгробие (`created_at_secs == 0`, `revoked_at_secs` — момент отзыва).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueRecord {
    pub queue_id: QueueId,
    /// Unix-секунды выдачи; у надгробия — 0.
    pub created_at_secs: u64,
    /// 0 — живая; иначе Unix-секунды отзыва (у истёкшей — её срок).
    pub revoked_at_secs: u64,
    /// 0 — бессрочная. У надгробия — 0.
    pub expires_at_secs: u64,
}

impl QueueRecord {
    pub fn is_tombstone(&self) -> bool {
        self.revoked_at_secs != 0
    }
}

/// Почему нода отказала в операции над очередью.
///
/// `NotFound` покрывает и «нет такой», и «есть, но чужая». Различать их
/// нельзя: ответ, подтверждающий существование чужой очереди, превращает
/// отзыв в оракул для перебора идентификаторов, а идентификатор — это
/// право писать.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    /// Достигнут потолок живых очередей пользователя.
    Limit,
    /// Очереди нет либо она чужая.
    NotFound,
    /// Негодные параметры запроса.
    Invalid,
    /// Очередь с этим id отозвана или истекла (надгробие) и заново не
    /// выделяется.
    Revoked,
    /// Версия записи аккаунта не совпала с ожидаемой.
    Conflict,
}

/// Запись аккаунта и её версия (1, 2, …; записи нет — версия 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRecord {
    pub version: u64,
    pub record: Vec<u8>,
}

/// Параметры `AllocateQueue`, прошедшие проверку.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocateParams {
    /// `None` — случайное выделение.
    pub tag: Option<QueueTag>,
    /// 0 — бессрочно. При `revoked` всегда 0.
    pub expires_at_secs: u64,
    /// Записать сразу надгробие.
    pub revoked: bool,
}

impl AllocateParams {
    /// Проверить сырые поля кадра. Тег — пустой (случайное выделение) или
    /// ровно 32 байта; надгробие — только с тегом (у случайного id его
    /// никто не узнает); срок, если задан, — в будущем. При `revoked` срок
    /// игнорируется.
    pub fn parse(
        tag: &[u8],
        expires_at_secs: u64,
        revoked: bool,
        now_secs: u64,
    ) -> Result<Self, QueueError> {
        let tag = match tag.len() {
            0 => None,
            32 => Some(QueueTag::try_from(tag).map_err(|_| QueueError::Invalid)?),
            _ => return Err(QueueError::Invalid),
        };
        if revoked {
            if tag.is_none() {
                return Err(QueueError::Invalid);
            }
            return Ok(Self {
                tag,
                expires_at_secs: 0,
                revoked,
            });
        }
        if expires_at_secs != 0 && expires_at_secs <= now_secs {
            return Err(QueueError::Invalid);
        }
        Ok(Self {
            tag,
            expires_at_secs,
            revoked,
        })
    }
}

/// Значение живой очереди в дереве `queues`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LiveValue {
    created_at_secs: u64,
    expires_at_secs: u64,
}

impl LiveValue {
    fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.created_at_secs.to_be_bytes());
        out[8..].copy_from_slice(&self.expires_at_secs.to_be_bytes());
        out
    }

    /// 16 байт — текущий формат, 8 — прежний (бессрочная очередь).
    /// Остальное — порча: запись читается как бессрочная с нулевым временем
    /// создания, а не теряется молча.
    fn decode(raw: &[u8]) -> Self {
        let word = |at: usize| {
            raw.get(at..at + 8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .unwrap_or(0)
        };
        match raw.len() {
            16 => Self {
                created_at_secs: word(0),
                expires_at_secs: word(8),
            },
            _ => Self {
                created_at_secs: word(0),
                expires_at_secs: 0,
            },
        }
    }

    fn is_expired(self, now_secs: u64) -> bool {
        is_expired(self.expires_at_secs, now_secs)
    }
}

/// Срок наступил: в момент `expires_at` очередь уже отозвана.
fn is_expired(expires_at_secs: u64, now_secs: u64) -> bool {
    expires_at_secs != 0 && now_secs >= expires_at_secs
}

/// Значение индекса `queue_owner`: владелец и срок.
fn encode_owner_value(owner: &UserId, expires_at_secs: u64) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..32].copy_from_slice(owner);
    out[32..].copy_from_slice(&expires_at_secs.to_be_bytes());
    out
}

/// `None` — значение неверной длины, читается как «очереди нет».
fn decode_owner_value(raw: &[u8]) -> Option<(UserId, u64)> {
    let owner = UserId::try_from(raw.get(..32)?).ok()?;
    match raw.len() {
        32 => Some((owner, 0)),
        40 => Some((owner, u64::from_be_bytes(raw[32..].try_into().ok()?))),
        _ => None,
    }
}

/// `version(8) ‖ record`. Значение короче 8 байт — порча, читается как
/// «записи нет»: клиент перезапишет её с версии 0.
fn decode_account_record(raw: &[u8]) -> Option<AccountRecord> {
    let version = u64::from_be_bytes(raw.get(..8)?.try_into().ok()?);
    Some(AccountRecord {
        version,
        record: raw[8..].to_vec(),
    })
}

fn decode_u64(raw: &[u8]) -> u64 {
    raw.try_into().map(u64::from_be_bytes).unwrap_or(0)
}

/// Исход транзакции выделения.
enum AllocateOutcome {
    /// Создана новая живая очередь.
    Created(LiveValue),
    /// Живая очередь уже была — ничего не изменилось.
    Existing(LiveValue),
    /// Записано новое надгробие (`revoked_at`).
    Buried(u64),
    /// Надгробие уже было (`revoked_at`).
    Tombstone(u64),
    Revoked,
    Limit,
}

#[derive(Clone)]
pub struct QueueStore {
    queues: Tree,
    owners: Tree,
    tombstones: Tree,
    tombstone_count: Tree,
    queue_only: Tree,
    account_records: Tree,
    tombstone_cap: usize,
    tombstone_slack: usize,
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
            tombstones: db
                .open_tree("queue_tombstones")
                .context("failed to open `queue_tombstones` tree")?,
            tombstone_count: db
                .open_tree("queue_tombstone_count")
                .context("failed to open `queue_tombstone_count` tree")?,
            queue_only: db
                .open_tree("queue_only")
                .context("failed to open `queue_only` tree")?,
            account_records: db
                .open_tree("account_records")
                .context("failed to open `account_records` tree")?,
            tombstone_cap: MAX_QUEUE_TOMBSTONES_PER_USER,
            tombstone_slack: TOMBSTONE_EVICTION_SLACK,
        })
    }

    /// Включить или снять режим «только по очередям» для аккаунта.
    /// Идемпотентно: повторное включение сохраняет исходное `set_at`, снятие
    /// удаляет ключ.
    pub fn set_queue_only(&self, owner: &UserId, enabled: bool, now_secs: u64) -> Result<()> {
        if enabled {
            // CAS «ключа нет → есть»: момент включения — первое включение,
            // а не последнее подтверждение. Проигранная гонка значит, что
            // флаг уже стоит, и это тот же исход.
            let _ = self
                .queue_only
                .compare_and_swap(&owner[..], None::<&[u8]>, Some(&now_secs.to_be_bytes()[..]))
                .context("failed to set the queue-only flag")?;
        } else {
            self.queue_only
                .remove(&owner[..])
                .context("failed to clear the queue-only flag")?;
        }
        Ok(())
    }

    /// Включён ли у аккаунта режим «только по очередям». Читается на каждом
    /// `ClientSend`, адресованном по `recipientId`.
    pub fn is_queue_only(&self, owner: &UserId) -> Result<bool> {
        self.queue_only
            .contains_key(&owner[..])
            .context("failed to read the queue-only flag")
    }

    /// Запись аккаунта; `None` — записи нет (версия 0).
    pub fn account_record(&self, owner: &UserId) -> Result<Option<AccountRecord>> {
        let raw = self
            .account_records
            .get(&owner[..])
            .context("failed to read the account record")?;
        Ok(raw.as_deref().and_then(decode_account_record))
    }

    /// Заменить запись аккаунта, если её текущая версия равна
    /// `expected_version` (0 — записи ещё нет). Новая версия —
    /// `expected_version + 1`, она и возвращается. Не совпала — `Conflict`,
    /// запись не меняется. Сравнение и запись — одна транзакция: из двух
    /// одновременных замен с одной ожидаемой версией проходит ровно одна.
    /// Длиннее [`MAX_ACCOUNT_RECORD_LEN`] — `Invalid`; пустая запись —
    /// обычное значение.
    pub fn set_account_record(
        &self,
        owner: &UserId,
        record: &[u8],
        expected_version: u64,
    ) -> Result<Result<u64, QueueError>> {
        if record.len() > MAX_ACCOUNT_RECORD_LEN {
            return Ok(Err(QueueError::Invalid));
        }
        // Версии u64::MAX у записи не бывает (каждая замена прибавляет 1 с
        // нуля), так что это обычное несовпадение версии.
        let Some(next_version) = expected_version.checked_add(1) else {
            return Ok(Err(QueueError::Conflict));
        };
        let mut value = Vec::with_capacity(8 + record.len());
        value.extend_from_slice(&next_version.to_be_bytes());
        value.extend_from_slice(record);

        let outcome: Result<bool, TransactionError> = self.account_records.transaction(|tree| {
            let current = tree
                .get(&owner[..])?
                .as_deref()
                .and_then(decode_account_record)
                .map_or(0, |current| current.version);
            if current != expected_version {
                return Ok(false);
            }
            tree.insert(&owner[..], value.as_slice())?;
            Ok(true)
        });
        if outcome.context("failed to write the account record")? {
            Ok(Ok(next_version))
        } else {
            Ok(Err(QueueError::Conflict))
        }
    }

    /// Выделить очередь с id `queue_id` (случайным или выведенным из тега —
    /// решает вызывающий) по таблице состояний контракта (§6.7):
    ///
    /// | id у владельца | `revoked = false` | `revoked = true` |
    /// |---|---|---|
    /// | нет | создать (потолок → `Limit`) | записать надгробие |
    /// | живая | вернуть как есть, срок не меняется | перевести в надгробие |
    /// | надгробие (в т. ч. истёкшая) | `Revoked` | вернуть как есть |
    ///
    /// Живая очередь в потолок повторно не считается: проверка состояния
    /// идёт раньше потолка. `max_per_user = 0` — без ограничения. Потолок
    /// сверяется с числом, посчитанным до транзакции, поэтому параллельные
    /// выделения одного владельца могут его превысить — как и прежде,
    /// best-effort защита ресурса.
    pub fn allocate(
        &self,
        owner: &UserId,
        queue_id: QueueId,
        params: AllocateParams,
        now_secs: u64,
        max_per_user: usize,
    ) -> Result<Result<QueueRecord, QueueError>> {
        let live_count = self.expire_due(owner, now_secs)?;
        let key = compose_key(owner, &queue_id);
        let fresh = LiveValue {
            created_at_secs: now_secs,
            expires_at_secs: params.expires_at_secs,
        };
        let limit_reached = max_per_user > 0 && live_count >= max_per_user;

        let outcome: Result<AllocateOutcome, TransactionError> = (
            &self.queues,
            &self.owners,
            &self.tombstones,
            &self.tombstone_count,
        )
            .transaction(|(queues, owners, tombstones, counts)| {
                if let Some(raw) = tombstones.get(&key[..])? {
                    let revoked_at = decode_u64(&raw);
                    return Ok(if params.revoked {
                        AllocateOutcome::Tombstone(revoked_at)
                    } else {
                        AllocateOutcome::Revoked
                    });
                }
                if let Some(raw) = queues.get(&key[..])? {
                    let live = LiveValue::decode(&raw);
                    // Срок мог наступить после `expire_due`: истёкшая —
                    // это надгробие с `revoked_at = expires_at`.
                    if live.is_expired(now_secs) {
                        bury(
                            queues,
                            owners,
                            tombstones,
                            counts,
                            owner,
                            &queue_id,
                            live.expires_at_secs,
                        )?;
                        return Ok(if params.revoked {
                            AllocateOutcome::Buried(live.expires_at_secs)
                        } else {
                            AllocateOutcome::Revoked
                        });
                    }
                    if params.revoked {
                        bury(
                            queues, owners, tombstones, counts, owner, &queue_id, now_secs,
                        )?;
                        return Ok(AllocateOutcome::Buried(now_secs));
                    }
                    return Ok(AllocateOutcome::Existing(live));
                }
                if params.revoked {
                    insert_tombstone(tombstones, counts, owner, &queue_id, now_secs)?;
                    return Ok(AllocateOutcome::Buried(now_secs));
                }
                if limit_reached {
                    return Ok(AllocateOutcome::Limit);
                }
                queues.insert(&key[..], &fresh.encode()[..])?;
                owners.insert(
                    &queue_id[..],
                    &encode_owner_value(owner, fresh.expires_at_secs)[..],
                )?;
                Ok(AllocateOutcome::Created(fresh))
            });
        let outcome = outcome.context("failed to persist the queue allocation")?;

        let live_record = |live: LiveValue| QueueRecord {
            queue_id,
            created_at_secs: live.created_at_secs,
            revoked_at_secs: 0,
            expires_at_secs: live.expires_at_secs,
        };
        let tombstone_record = |revoked_at_secs| QueueRecord {
            queue_id,
            created_at_secs: 0,
            revoked_at_secs,
            expires_at_secs: 0,
        };
        Ok(match outcome {
            AllocateOutcome::Created(live) | AllocateOutcome::Existing(live) => {
                Ok(live_record(live))
            }
            AllocateOutcome::Buried(revoked_at) => {
                self.enforce_tombstone_cap(owner)?;
                Ok(tombstone_record(revoked_at))
            }
            AllocateOutcome::Tombstone(revoked_at) => Ok(tombstone_record(revoked_at)),
            AllocateOutcome::Revoked => {
                // Надгробие могло появиться из истёкшей очереди прямо в
                // этой транзакции — потолок держится и тогда.
                self.enforce_tombstone_cap(owner)?;
                Err(QueueError::Revoked)
            }
            AllocateOutcome::Limit => Err(QueueError::Limit),
        })
    }

    /// Отозвать очередь: живая переходит в надгробие одной транзакцией
    /// (проверка владения, удаление из `queues` и `queue_owner`, запись
    /// надгробия). Повторный отзыв своего надгробия — успех; неизвестный или
    /// чужой id — `NotFound`. Отзыв истёкшей оставляет `revoked_at =
    /// expires_at`: она уже была отозвана в момент срока.
    pub fn revoke(
        &self,
        owner: &UserId,
        queue_id: &QueueId,
        now_secs: u64,
    ) -> Result<Result<(), QueueError>> {
        let key = compose_key(owner, queue_id);

        // `Some(true)` — записано новое надгробие, `Some(false)` — оно уже
        // было, `None` — очереди нет. Отсутствие записи — флаг, а не abort:
        // до первой записи транзакция ничего не изменила.
        let outcome: Result<Option<bool>, TransactionError> = (
            &self.queues,
            &self.owners,
            &self.tombstones,
            &self.tombstone_count,
        )
            .transaction(|(queues, owners, tombstones, counts)| {
                if let Some(raw) = queues.get(&key[..])? {
                    let live = LiveValue::decode(&raw);
                    let revoked_at = if live.is_expired(now_secs) {
                        live.expires_at_secs
                    } else {
                        now_secs
                    };
                    bury(
                        queues, owners, tombstones, counts, owner, queue_id, revoked_at,
                    )?;
                    return Ok(Some(true));
                }
                Ok(tombstones.get(&key[..])?.map(|_| false))
            });

        match outcome.context("failed to revoke the queue")? {
            Some(true) => {
                self.enforce_tombstone_cap(owner)?;
                Ok(Ok(()))
            }
            Some(false) => Ok(Ok(())),
            None => Ok(Err(QueueError::NotFound)),
        }
    }

    /// Владелец живой очереди — вход маршрутизации депозита. Неизвестная,
    /// отозванная и истёкшая очереди одинаково дают `None`; истёкшая тут же
    /// переводится в надгробие. Значение индекса неверной длины читается как
    /// «очереди нет».
    pub fn owner_of(&self, queue_id: &QueueId, now_secs: u64) -> Result<Option<UserId>> {
        let Some(raw) = self
            .owners
            .get(&queue_id[..])
            .context("failed to read the queue owner index")?
        else {
            return Ok(None);
        };
        let Some((owner, expires_at_secs)) = decode_owner_value(&raw) else {
            return Ok(None);
        };
        if is_expired(expires_at_secs, now_secs) {
            self.expire_due(&owner, now_secs)?;
            return Ok(None);
        }
        Ok(Some(owner))
    }

    /// Очереди пользователя: сначала живые, потом надгробия; внутри — по
    /// `queue_id`. Истёкшие к этому моменту уже надгробия.
    pub fn list(&self, owner: &UserId, now_secs: u64) -> Result<Vec<QueueRecord>> {
        self.expire_due(owner, now_secs)?;
        let mut out = Vec::new();
        for item in self.queues.scan_prefix(&owner[..]) {
            let (key, value) = item.context("failed to scan the queue tree")?;
            let Some(queue_id) = queue_id_of(&key) else {
                continue;
            };
            let live = LiveValue::decode(&value);
            out.push(QueueRecord {
                queue_id,
                created_at_secs: live.created_at_secs,
                revoked_at_secs: 0,
                expires_at_secs: live.expires_at_secs,
            });
        }
        for item in self.tombstones.scan_prefix(&owner[..]) {
            let (key, value) = item.context("failed to scan the tombstone tree")?;
            let Some(queue_id) = queue_id_of(&key) else {
                continue;
            };
            out.push(QueueRecord {
                queue_id,
                created_at_secs: 0,
                revoked_at_secs: decode_u64(&value),
                expires_at_secs: 0,
            });
        }
        Ok(out)
    }

    /// Перевести истёкшие очереди владельца в надгробия. Возвращает число
    /// оставшихся живых — его заодно знает тот же скан, и потолок
    /// выделения сверяется с ним.
    fn expire_due(&self, owner: &UserId, now_secs: u64) -> Result<usize> {
        let mut live = 0usize;
        let mut due = Vec::new();
        for item in self.queues.scan_prefix(&owner[..]) {
            let (key, value) = item.context("failed to scan the queue tree")?;
            let Some(queue_id) = queue_id_of(&key) else {
                continue;
            };
            let value = LiveValue::decode(&value);
            if value.is_expired(now_secs) {
                due.push((queue_id, value));
            } else {
                live += 1;
            }
        }
        if due.is_empty() {
            return Ok(live);
        }

        for (queue_id, expected) in due {
            let key = compose_key(owner, &queue_id);
            let outcome: Result<(), TransactionError> = (
                &self.queues,
                &self.owners,
                &self.tombstones,
                &self.tombstone_count,
            )
                .transaction(|(queues, owners, tombstones, counts)| {
                    // Параллельный отзыв мог успеть раньше: хороним только
                    // то, что всё ещё лежит живым с тем же сроком.
                    if let Some(raw) = queues.get(&key[..])?
                        && LiveValue::decode(&raw) == expected
                    {
                        bury(
                            queues,
                            owners,
                            tombstones,
                            counts,
                            owner,
                            &queue_id,
                            expected.expires_at_secs,
                        )?;
                    }
                    Ok(())
                });
            outcome.context("failed to expire a queue")?;
        }
        self.enforce_tombstone_cap(owner)?;
        Ok(live)
    }

    /// Держать надгробия владельца в пределах потолка: при переполнении
    /// удаляются старейшие (наименьший `revoked_at`, при равенстве — меньший
    /// id) до `потолок − запас`. Число берётся из счётчика, поэтому скан
    /// нужен только при переполнении, а запас делает его редким.
    fn enforce_tombstone_cap(&self, owner: &UserId) -> Result<()> {
        let count = self
            .tombstone_count
            .get(&owner[..])
            .context("failed to read the tombstone counter")?
            .map_or(0, |raw| decode_u64(&raw));
        let cap = self.tombstone_cap as u64;
        if count <= cap {
            return Ok(());
        }

        let mut entries = Vec::new();
        for item in self.tombstones.scan_prefix(&owner[..]) {
            let (key, value) = item.context("failed to scan the tombstone tree")?;
            if let Some(queue_id) = queue_id_of(&key) {
                entries.push((decode_u64(&value), queue_id, value));
            }
        }
        let keep = self.tombstone_cap.saturating_sub(self.tombstone_slack);
        let excess = entries.len().saturating_sub(keep);
        if excess == 0 {
            return Ok(());
        }
        entries.sort_unstable_by_key(|entry| (entry.0, entry.1));
        for (_, queue_id, value) in entries.into_iter().take(excess) {
            let key = compose_key(owner, &queue_id);
            let outcome: Result<(), TransactionError> = (&self.tombstones, &self.tombstone_count)
                .transaction(|(tombstones, counts)| {
                    // Удаляется только то самое надгробие: параллельное
                    // вытеснение могло уже его снять.
                    if tombstones.get(&key[..])?.as_deref() == Some(value.as_ref()) {
                        tombstones.remove(&key[..])?;
                        adjust_count(counts, owner, -1)?;
                    }
                    Ok(())
                });
            outcome.context("failed to evict a queue tombstone")?;
        }
        Ok(())
    }

    /// Потолок надгробий для тестов вытеснения: настоящие 8192 проверяются
    /// отдельно, а мелкий потолок позволяет проверить порядок вытеснения
    /// без тысяч записей.
    #[cfg(test)]
    fn with_tombstone_cap(mut self, cap: usize, slack: usize) -> Self {
        self.tombstone_cap = cap;
        self.tombstone_slack = slack;
        self
    }
}

/// Перевести живую очередь в надгробие: удалить из `queues` и
/// `queue_owner`, записать надгробие и посчитать его. Только внутри
/// транзакции по всем четырём деревьям.
fn bury(
    queues: &TransactionalTree,
    owners: &TransactionalTree,
    tombstones: &TransactionalTree,
    counts: &TransactionalTree,
    owner: &UserId,
    queue_id: &QueueId,
    revoked_at_secs: u64,
) -> Result<(), UnabortableTransactionError> {
    let key = compose_key(owner, queue_id);
    queues.remove(&key[..])?;
    owners.remove(&queue_id[..])?;
    insert_tombstone(tombstones, counts, owner, queue_id, revoked_at_secs)?;
    Ok(())
}

fn insert_tombstone(
    tombstones: &TransactionalTree,
    counts: &TransactionalTree,
    owner: &UserId,
    queue_id: &QueueId,
    revoked_at_secs: u64,
) -> Result<(), UnabortableTransactionError> {
    let key = compose_key(owner, queue_id);
    if tombstones
        .insert(&key[..], &revoked_at_secs.to_be_bytes()[..])?
        .is_none()
    {
        adjust_count(counts, owner, 1)?;
    }
    Ok(())
}

fn adjust_count(
    counts: &TransactionalTree,
    owner: &UserId,
    delta: i64,
) -> Result<(), UnabortableTransactionError> {
    let current = counts.get(&owner[..])?.map_or(0, |raw| decode_u64(&raw));
    let next = current.saturating_add_signed(delta);
    if next == 0 {
        counts.remove(&owner[..])?;
    } else {
        counts.insert(&owner[..], &next.to_be_bytes()[..])?;
    }
    Ok(())
}

fn compose_key(owner: &UserId, queue_id: &QueueId) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..32].copy_from_slice(owner);
    key[32..].copy_from_slice(queue_id);
    key
}

fn queue_id_of(key: &[u8]) -> Option<QueueId> {
    if key.len() != KEY_LEN {
        return None;
    }
    QueueId::try_from(&key[32..]).ok()
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
    const NOW: u64 = 1_000;

    fn live() -> AllocateParams {
        AllocateParams {
            tag: None,
            expires_at_secs: 0,
            revoked: false,
        }
    }

    fn expiring(at: u64) -> AllocateParams {
        AllocateParams {
            expires_at_secs: at,
            ..live()
        }
    }

    fn tombstone() -> AllocateParams {
        AllocateParams {
            tag: Some([0xAA; 32]),
            expires_at_secs: 0,
            revoked: true,
        }
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    // ---- вывод id ----

    /// Векторы общие с клиентом (ТЗ N-2′, контракт §6.7). Не совпали —
    /// клиент и нода разошлись в формуле, и ни одна детерминированная
    /// очередь не найдётся.
    #[test]
    fn derived_ids_match_the_shared_vectors() {
        assert_eq!(
            derive_queue_id(&[0x01; 32], &[0x02; 32]),
            hex32("8fd0706475dca7cdcd48f80507a90a3d670741339e1f20de951e77aa33b8d3d5")
        );
        let owner: [u8; 32] = std::array::from_fn(|i| i as u8);
        let tag: [u8; 32] = std::array::from_fn(|i| 0x20 + i as u8);
        assert_eq!(
            derive_queue_id(&owner, &tag),
            hex32("65ead37b785494ea048c624fa1231a85a8ca0b50938b6ab9659a67e6ab34a2d4")
        );
    }

    #[test]
    fn the_owner_is_part_of_the_derived_id() {
        let tag = [7u8; 32];
        assert_ne!(derive_queue_id(&ALICE, &tag), derive_queue_id(&BOB, &tag));
        assert_ne!(
            derive_queue_id(&ALICE, &tag),
            derive_queue_id(&ALICE, &[8u8; 32])
        );
    }

    #[test]
    fn the_log_fingerprint_is_short_stable_and_not_the_id() {
        let q = [0x42u8; 32];
        let fp = queue_fingerprint(&q);
        assert_eq!(fp.len(), 8);
        assert_eq!(fp, queue_fingerprint(&q));
        assert_ne!(fp, queue_fingerprint(&[0x43u8; 32]));
        assert!(!hex::encode(q).contains(&fp));
        // SHA-256 от 32 байт 0x42, первые 4 байта.
        let digest: [u8; 32] = Sha256::digest(q).into();
        assert_eq!(fp, hex::encode(&digest[..4]));
    }

    // ---- проверка параметров ----

    #[test]
    fn allocate_params_validation() {
        let tag = [3u8; 32];
        assert_eq!(AllocateParams::parse(&[], 0, false, NOW), Ok(live()));
        assert_eq!(
            AllocateParams::parse(&tag, 0, false, NOW).unwrap().tag,
            Some(tag)
        );
        // Длина тега — только 0 или 32.
        for len in [1usize, 31, 33, 64] {
            assert_eq!(
                AllocateParams::parse(&vec![1u8; len], 0, false, NOW),
                Err(QueueError::Invalid)
            );
        }
        // Срок — строго в будущем.
        assert_eq!(
            AllocateParams::parse(&[], NOW, false, NOW),
            Err(QueueError::Invalid)
        );
        assert_eq!(
            AllocateParams::parse(&[], NOW - 1, false, NOW),
            Err(QueueError::Invalid)
        );
        assert_eq!(
            AllocateParams::parse(&[], NOW + 1, false, NOW),
            Ok(expiring(NOW + 1))
        );
        // Надгробие — только с тегом; срок при нём игнорируется.
        assert_eq!(
            AllocateParams::parse(&[], 0, true, NOW),
            Err(QueueError::Invalid)
        );
        assert_eq!(
            AllocateParams::parse(&tag, NOW - 5, true, NOW),
            Ok(AllocateParams {
                tag: Some(tag),
                expires_at_secs: 0,
                revoked: true
            })
        );
    }

    // ---- выделение ----

    #[test]
    fn allocated_queue_is_listed_and_resolvable() {
        let store = store();
        let q = [9u8; 32];
        store.allocate(&ALICE, q, live(), 100, 0).unwrap().unwrap();

        let listed = store.list(&ALICE, 100).unwrap();
        assert_eq!(
            listed,
            vec![QueueRecord {
                queue_id: q,
                created_at_secs: 100,
                revoked_at_secs: 0,
                expires_at_secs: 0,
            }]
        );
        assert_eq!(store.owner_of(&q, 100).unwrap(), Some(ALICE));
    }

    /// Повтор того же id — та же очередь: `ok`, время создания и срок не
    /// перезаписываются, в потолок повторно не считается — даже когда
    /// потолок уже выбран.
    #[test]
    fn repeated_allocation_of_a_live_id_is_idempotent() {
        let store = store();
        let q = derive_queue_id(&ALICE, &[5u8; 32]);
        let first = store
            .allocate(&ALICE, q, expiring(NOW + 100), NOW, 1)
            .unwrap()
            .unwrap();
        let again = store
            .allocate(&ALICE, q, expiring(NOW + 900), NOW + 10, 1)
            .unwrap()
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(again.created_at_secs, NOW);
        assert_eq!(again.expires_at_secs, NOW + 100);
        assert_eq!(store.list(&ALICE, NOW + 10).unwrap().len(), 1);

        // Потолок (1) выбран этой же очередью: новая — отказ, повтор — нет.
        assert_eq!(
            store.allocate(&ALICE, [6u8; 32], live(), NOW, 1).unwrap(),
            Err(QueueError::Limit)
        );
        assert!(store.allocate(&ALICE, q, live(), NOW, 1).unwrap().is_ok());
    }

    #[test]
    fn the_per_user_limit_is_enforced_and_is_per_user() {
        let store = store();
        store
            .allocate(&ALICE, [1u8; 32], live(), 1, 2)
            .unwrap()
            .unwrap();
        store
            .allocate(&ALICE, [2u8; 32], live(), 2, 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            store.allocate(&ALICE, [3u8; 32], live(), 3, 2).unwrap(),
            Err(QueueError::Limit)
        );
        // Потолок чужого пользователя не расходуется.
        store
            .allocate(&BOB, [4u8; 32], live(), 4, 2)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_revoked_slot_frees_room_under_the_limit() {
        let store = store();
        store
            .allocate(&ALICE, [1u8; 32], live(), 1, 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            store.allocate(&ALICE, [2u8; 32], live(), 2, 1).unwrap(),
            Err(QueueError::Limit)
        );
        store.revoke(&ALICE, &[1u8; 32], 2).unwrap().unwrap();
        store
            .allocate(&ALICE, [2u8; 32], live(), 2, 1)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn zero_limit_means_unbounded() {
        let store = store();
        for i in 0..32u8 {
            store
                .allocate(&ALICE, [i; 32], live(), 1, 0)
                .unwrap()
                .unwrap();
        }
        assert_eq!(store.list(&ALICE, 1).unwrap().len(), 32);
    }

    // ---- отзыв и надгробия ----

    /// Отзыв переносит очередь в надгробие одной транзакцией: она пропадает
    /// из маршрутизации и из живых, но остаётся в списке с моментом отзыва.
    #[test]
    fn revoking_turns_the_queue_into_a_tombstone() {
        let store = store();
        let q = [9u8; 32];
        store.allocate(&ALICE, q, live(), 100, 0).unwrap().unwrap();
        store.revoke(&ALICE, &q, 200).unwrap().unwrap();

        assert_eq!(store.owner_of(&q, 200).unwrap(), None);
        assert_eq!(
            store.list(&ALICE, 200).unwrap(),
            vec![QueueRecord {
                queue_id: q,
                created_at_secs: 0,
                revoked_at_secs: 200,
                expires_at_secs: 0,
            }]
        );
        assert!(store.queues.is_empty());
        assert!(store.owners.is_empty());
        // Повторный отзыв своего надгробия — успех, момент не меняется.
        store.revoke(&ALICE, &q, 300).unwrap().unwrap();
        assert_eq!(store.list(&ALICE, 300).unwrap()[0].revoked_at_secs, 200);
    }

    #[test]
    fn a_tombstoned_id_is_not_allocated_again() {
        let store = store();
        let q = derive_queue_id(&ALICE, &[5u8; 32]);
        store.allocate(&ALICE, q, live(), NOW, 0).unwrap().unwrap();
        store.revoke(&ALICE, &q, NOW).unwrap().unwrap();
        assert_eq!(
            store.allocate(&ALICE, q, live(), NOW + 1, 0).unwrap(),
            Err(QueueError::Revoked)
        );
        assert_eq!(store.owner_of(&q, NOW + 1).unwrap(), None);
    }

    /// `revoked = true` по таблице состояний: нет → надгробие сразу; живая →
    /// в надгробие; надгробие → `ok` без изменений.
    #[test]
    fn allocating_as_revoked_follows_the_state_table() {
        let store = store();

        let fresh = [1u8; 32];
        let record = store
            .allocate(&ALICE, fresh, tombstone(), NOW, 0)
            .unwrap()
            .unwrap();
        assert_eq!(record.revoked_at_secs, NOW);
        assert_eq!(store.owner_of(&fresh, NOW).unwrap(), None);

        let live_id = [2u8; 32];
        store
            .allocate(&ALICE, live_id, live(), NOW, 0)
            .unwrap()
            .unwrap();
        let record = store
            .allocate(&ALICE, live_id, tombstone(), NOW + 5, 0)
            .unwrap()
            .unwrap();
        assert_eq!(record.revoked_at_secs, NOW + 5);
        assert_eq!(store.owner_of(&live_id, NOW + 5).unwrap(), None);

        let again = store
            .allocate(&ALICE, live_id, tombstone(), NOW + 9, 0)
            .unwrap()
            .unwrap();
        assert_eq!(again.revoked_at_secs, NOW + 5);

        let listed = store.list(&ALICE, NOW + 9).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(QueueRecord::is_tombstone));
    }

    /// Надгробие не требует места под потолком живых и выделяется даже при
    /// полном потолке.
    #[test]
    fn tombstones_do_not_count_against_the_live_limit() {
        let store = store();
        store
            .allocate(&ALICE, [1u8; 32], live(), NOW, 1)
            .unwrap()
            .unwrap();
        store
            .allocate(&ALICE, [2u8; 32], tombstone(), NOW, 1)
            .unwrap()
            .unwrap();
        store.revoke(&ALICE, &[1u8; 32], NOW).unwrap().unwrap();
        // Два надгробия, ноль живых — место есть.
        store
            .allocate(&ALICE, [3u8; 32], live(), NOW, 1)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_stranger_cannot_revoke_someone_elses_queue() {
        let store = store();
        let q = [9u8; 32];
        store.allocate(&ALICE, q, live(), 100, 0).unwrap().unwrap();

        assert_eq!(
            store.revoke(&BOB, &q, 100).unwrap(),
            Err(QueueError::NotFound)
        );
        // И очередь на месте: неудачный отзыв не должен ничего трогать.
        assert_eq!(store.owner_of(&q, 100).unwrap(), Some(ALICE));
        assert!(store.list(&BOB, 100).unwrap().is_empty());
    }

    #[test]
    fn revoking_a_missing_queue_is_not_found_not_success() {
        let store = store();
        assert_eq!(
            store.revoke(&ALICE, &[7u8; 32], 100).unwrap(),
            Err(QueueError::NotFound)
        );
    }

    /// Надгробие одного владельца не мешает другому: тот же тег у Боба —
    /// другой id, и его очередь живёт своей жизнью.
    #[test]
    fn tombstones_are_per_user() {
        let store = store();
        let tag = [4u8; 32];
        let alice_q = derive_queue_id(&ALICE, &tag);
        let bob_q = derive_queue_id(&BOB, &tag);
        store
            .allocate(&ALICE, alice_q, tombstone(), NOW, 0)
            .unwrap()
            .unwrap();
        store
            .allocate(&BOB, bob_q, live(), NOW, 0)
            .unwrap()
            .unwrap();
        assert_eq!(store.owner_of(&bob_q, NOW).unwrap(), Some(BOB));
        assert_eq!(store.list(&BOB, NOW).unwrap().len(), 1);
        assert!(!store.list(&BOB, NOW).unwrap()[0].is_tombstone());
    }

    // ---- потолок надгробий ----

    /// Порядок вытеснения: сначала наименьший `revoked_at`, при равенстве —
    /// меньший id. Отзыв при этом не отказывает.
    #[test]
    fn tombstone_overflow_evicts_the_oldest_first() {
        let store = store().with_tombstone_cap(3, 0);
        // revoked_at: [1]=10, [2]=5, [3]=5, [4]=20.
        for (id, at) in [(1u8, 10u64), (2, 5), (3, 5)] {
            store
                .allocate(&ALICE, [id; 32], live(), 1, 0)
                .unwrap()
                .unwrap();
            store.revoke(&ALICE, &[id; 32], at).unwrap().unwrap();
        }
        store
            .allocate(&ALICE, [4u8; 32], live(), 1, 0)
            .unwrap()
            .unwrap();
        store.revoke(&ALICE, &[4u8; 32], 20).unwrap().unwrap();

        let ids: Vec<u8> = store
            .list(&ALICE, 30)
            .unwrap()
            .iter()
            .map(|record| record.queue_id[0])
            .collect();
        // Ушёл [2]: revoked_at 5, как у [3], но id меньше.
        assert_eq!(ids, vec![1, 3, 4]);
        // Вытесненный id снова выделяем — это и есть остаточный риск
        // потолка, а не ошибка.
        store
            .allocate(&ALICE, [2u8; 32], live(), 30, 0)
            .unwrap()
            .unwrap();
    }

    /// Гистерезис: переполнение вытесняет до `потолок − запас`, и следующие
    /// `запас` отзывов обходятся без вытеснения.
    #[test]
    fn eviction_leaves_room_for_the_next_revocations() {
        let store = store().with_tombstone_cap(4, 2);
        let tombstone_at = |id: u8, at: u64| {
            store
                .allocate(&ALICE, [id; 32], tombstone_with_tag(id), at, 0)
                .unwrap()
                .unwrap();
        };
        for id in 1..=4u8 {
            tombstone_at(id, u64::from(id));
        }
        assert_eq!(store.list(&ALICE, 10).unwrap().len(), 4);
        // Пятое — переполнение: остаются два самых свежих из пяти.
        tombstone_at(5, 5);
        let ids = |store: &QueueStore| -> Vec<u8> {
            store
                .list(&ALICE, 10)
                .unwrap()
                .iter()
                .map(|record| record.queue_id[0])
                .collect()
        };
        assert_eq!(ids(&store), vec![4, 5]);
        // Ещё два — без вытеснения.
        tombstone_at(6, 6);
        tombstone_at(7, 7);
        assert_eq!(ids(&store), vec![4, 5, 6, 7]);
    }

    fn tombstone_with_tag(id: u8) -> AllocateParams {
        AllocateParams {
            tag: Some([id; 32]),
            expires_at_secs: 0,
            revoked: true,
        }
    }

    /// Настоящий потолок: 8192 надгробия держатся, 8193-е вытесняет
    /// старейшие до 8192 − 256. Надгробия не занимают потолок живых.
    #[test]
    fn the_real_tombstone_cap_holds_8192() {
        let store = store();
        let cap = MAX_QUEUE_TOMBSTONES_PER_USER as u64;
        for i in 0..cap {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_be_bytes());
            store
                .allocate(
                    &ALICE,
                    id,
                    AllocateParams {
                        tag: Some(id),
                        expires_at_secs: 0,
                        revoked: true,
                    },
                    // revoked_at растёт с номером: самое старое — [0].
                    NOW + i,
                    0,
                )
                .unwrap()
                .unwrap();
        }
        assert_eq!(store.list(&ALICE, NOW).unwrap().len(), 8192);

        // Отзыв живой при полном потолке не отказывает.
        store
            .allocate(&ALICE, [0xFF; 32], live(), NOW, 1)
            .unwrap()
            .unwrap();
        store
            .revoke(&ALICE, &[0xFF; 32], NOW + cap)
            .unwrap()
            .unwrap();

        let listed = store.list(&ALICE, NOW + cap).unwrap();
        let kept = MAX_QUEUE_TOMBSTONES_PER_USER - TOMBSTONE_EVICTION_SLACK;
        assert_eq!(listed.len(), kept);
        // Ушли 257 старейших: [0]..[256]; [257] на месте.
        let first_kept = {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&257u64.to_be_bytes());
            id
        };
        let last_gone = {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&256u64.to_be_bytes());
            id
        };
        assert!(!listed.iter().any(|record| record.queue_id == [0u8; 32]));
        assert!(!listed.iter().any(|record| record.queue_id == last_gone));
        assert!(listed.iter().any(|record| record.queue_id == first_kept));
        assert!(listed.iter().any(|record| record.queue_id == [0xFF; 32]));
        // Потолок живых (1) свободен: надгробия в нём не считаются.
        store
            .allocate(&ALICE, [0xFE; 32], live(), NOW, 1)
            .unwrap()
            .unwrap();
    }

    // ---- срок ----

    /// Истёкшая очередь неотличима от отозванной в момент срока: депозит не
    /// проходит, в списке — надгробие с `revoked_at = expires_at`, тот же
    /// id — `Revoked`, в потолок живых не считается.
    #[test]
    fn an_expired_queue_becomes_a_tombstone_at_its_deadline() {
        let store = store();
        let q = derive_queue_id(&ALICE, &[6u8; 32]);
        store
            .allocate(&ALICE, q, expiring(NOW + 60), NOW, 1)
            .unwrap()
            .unwrap();
        assert_eq!(store.owner_of(&q, NOW + 59).unwrap(), Some(ALICE));
        // В самый момент срока — уже нет.
        assert_eq!(store.owner_of(&q, NOW + 60).unwrap(), None);

        assert_eq!(
            store.list(&ALICE, NOW + 61).unwrap(),
            vec![QueueRecord {
                queue_id: q,
                created_at_secs: 0,
                revoked_at_secs: NOW + 60,
                expires_at_secs: 0,
            }]
        );
        assert_eq!(
            store.allocate(&ALICE, q, live(), NOW + 61, 1).unwrap(),
            Err(QueueError::Revoked)
        );
        store
            .allocate(&ALICE, [7u8; 32], live(), NOW + 61, 1)
            .unwrap()
            .unwrap();
    }

    /// Истечение замечается и без депозита: список и выделение переводят
    /// очередь в надгробие сами.
    #[test]
    fn expiry_is_applied_by_listing_and_allocation_too() {
        let store = store();
        let q = [8u8; 32];
        store
            .allocate(&ALICE, q, expiring(NOW + 10), NOW, 1)
            .unwrap()
            .unwrap();
        // Потолок выбран живой очередью, но к `NOW + 10` она истекла.
        store
            .allocate(&ALICE, [9u8; 32], live(), NOW + 10, 1)
            .unwrap()
            .unwrap();
        assert_eq!(store.owners.get(&q[..]).unwrap(), None);
        let listed = store.list(&ALICE, NOW + 10).unwrap();
        assert_eq!(listed.iter().filter(|r| r.is_tombstone()).count(), 1);

        // Отзыв уже истёкшей — успех, момент — срок.
        let r = [10u8; 32];
        store
            .allocate(&ALICE, r, expiring(NOW + 20), NOW, 0)
            .unwrap()
            .unwrap();
        // Обходим ленивый перевод: отзыв видит живую запись с истёкшим
        // сроком.
        store.revoke(&ALICE, &r, NOW + 25).unwrap().unwrap();
        let tomb = store
            .list(&ALICE, NOW + 25)
            .unwrap()
            .into_iter()
            .find(|record| record.queue_id == r)
            .unwrap();
        assert_eq!(tomb.revoked_at_secs, NOW + 20);

        // `revoked = true` на истёкшую — `ok`, надгробие со сроком.
        let s = derive_queue_id(&ALICE, &[0xAA; 32]);
        store
            .allocate(&ALICE, s, expiring(NOW + 30), NOW, 0)
            .unwrap()
            .unwrap();
        let record = store
            .allocate(&ALICE, s, tombstone(), NOW + 40, 0)
            .unwrap()
            .unwrap();
        assert_eq!(record.revoked_at_secs, NOW + 30);
    }

    /// Значения до сроков: 8 байт в `queues` и 32 в `queue_owner` — это
    /// бессрочная живая очередь. Так читаются данные уже развёрнутых нод.
    #[test]
    fn legacy_values_read_as_queues_without_expiry() {
        let store = store();
        let q = [0x42; 32];
        store
            .queues
            .insert(&compose_key(&ALICE, &q)[..], &77u64.to_be_bytes()[..])
            .unwrap();
        store.owners.insert(&q[..], &ALICE[..]).unwrap();

        assert_eq!(store.owner_of(&q, u64::MAX - 1).unwrap(), Some(ALICE));
        assert_eq!(
            store.list(&ALICE, u64::MAX - 1).unwrap(),
            vec![QueueRecord {
                queue_id: q,
                created_at_secs: 77,
                revoked_at_secs: 0,
                expires_at_secs: 0,
            }]
        );
        // Повтор того же id — та же очередь, без перезаписи значения.
        store.allocate(&ALICE, q, live(), 500, 0).unwrap().unwrap();
        assert_eq!(
            store
                .queues
                .get(&compose_key(&ALICE, &q)[..])
                .unwrap()
                .unwrap()
                .as_ref(),
            &77u64.to_be_bytes()[..]
        );
        store.revoke(&ALICE, &q, 600).unwrap().unwrap();
        assert_eq!(store.owner_of(&q, 600).unwrap(), None);
    }

    #[test]
    fn malformed_index_values_read_as_no_queue() {
        let store = store();
        store.owners.insert(&[1u8; 32][..], &[0u8; 7][..]).unwrap();
        assert_eq!(store.owner_of(&[1u8; 32], NOW).unwrap(), None);
        // Мусорный ключ под префиксом владельца в списке не появляется.
        store.queues.insert(&ALICE[..], &[0u8; 8][..]).unwrap();
        assert!(store.list(&ALICE, NOW).unwrap().is_empty());
    }

    // ---- флаг «только по очередям» ----

    #[test]
    fn queue_only_flag_sets_clears_and_is_idempotent() {
        let store = store();
        assert!(!store.is_queue_only(&ALICE).unwrap());

        store.set_queue_only(&ALICE, true, 100).unwrap();
        assert!(store.is_queue_only(&ALICE).unwrap());
        // Повторное включение — не ошибка и не перезапись момента.
        store.set_queue_only(&ALICE, true, 200).unwrap();
        assert!(store.is_queue_only(&ALICE).unwrap());
        assert_eq!(
            store.queue_only.get(&ALICE[..]).unwrap().unwrap().as_ref(),
            &100u64.to_be_bytes()[..]
        );

        store.set_queue_only(&ALICE, false, 300).unwrap();
        assert!(!store.is_queue_only(&ALICE).unwrap());
        // Снятие снятого — тоже не ошибка.
        store.set_queue_only(&ALICE, false, 400).unwrap();
        assert!(!store.is_queue_only(&ALICE).unwrap());
    }

    #[test]
    fn queue_only_flag_is_per_user() {
        let store = store();
        store.set_queue_only(&ALICE, true, 100).unwrap();
        assert!(!store.is_queue_only(&BOB).unwrap());
        store.set_queue_only(&BOB, true, 100).unwrap();
        store.set_queue_only(&ALICE, false, 200).unwrap();
        assert!(store.is_queue_only(&BOB).unwrap());
    }

    // ---- запись аккаунта ----

    #[test]
    fn account_record_cas_bumps_the_version_by_one() {
        let store = store();
        assert_eq!(store.account_record(&ALICE).unwrap(), None);

        assert_eq!(
            store.set_account_record(&ALICE, b"pool-1", 0).unwrap(),
            Ok(1)
        );
        assert_eq!(
            store.account_record(&ALICE).unwrap(),
            Some(AccountRecord {
                version: 1,
                record: b"pool-1".to_vec()
            })
        );
        assert_eq!(
            store.set_account_record(&ALICE, b"pool-2", 1).unwrap(),
            Ok(2)
        );
        // Пустая запись — обычное значение.
        assert_eq!(store.set_account_record(&ALICE, b"", 2).unwrap(), Ok(3));
        assert_eq!(
            store.account_record(&ALICE).unwrap(),
            Some(AccountRecord {
                version: 3,
                record: Vec::new()
            })
        );
    }

    #[test]
    fn a_stale_version_is_a_conflict_and_changes_nothing() {
        let store = store();
        store
            .set_account_record(&ALICE, b"first", 0)
            .unwrap()
            .unwrap();
        for stale in [0u64, 2, 99] {
            assert_eq!(
                store.set_account_record(&ALICE, b"lost", stale).unwrap(),
                Err(QueueError::Conflict)
            );
        }
        assert_eq!(
            store.account_record(&ALICE).unwrap().unwrap().record,
            b"first"
        );
    }

    #[test]
    fn account_record_size_is_capped() {
        let store = store();
        assert_eq!(
            store
                .set_account_record(&ALICE, &[0u8; MAX_ACCOUNT_RECORD_LEN + 1], 0)
                .unwrap(),
            Err(QueueError::Invalid)
        );
        assert_eq!(store.account_record(&ALICE).unwrap(), None);
        assert_eq!(
            store
                .set_account_record(&ALICE, &[0u8; MAX_ACCOUNT_RECORD_LEN], 0)
                .unwrap(),
            Ok(1)
        );
        // Версии, которую нельзя увеличить, у записи не бывает — это
        // несовпадение версии, а не паника.
        assert_eq!(
            store.set_account_record(&ALICE, b"x", u64::MAX).unwrap(),
            Err(QueueError::Conflict)
        );
    }

    #[test]
    fn account_records_are_per_user() {
        let store = store();
        store
            .set_account_record(&ALICE, b"alice", 0)
            .unwrap()
            .unwrap();
        assert_eq!(store.account_record(&BOB).unwrap(), None);
        assert_eq!(store.set_account_record(&BOB, b"bob", 0).unwrap(), Ok(1));
        assert_eq!(
            store.account_record(&ALICE).unwrap().unwrap().record,
            b"alice"
        );
    }

    /// Из двух одновременных замен с одной ожидаемой версией проходит ровно
    /// одна: CAS — одна транзакция, а не чтение и запись порознь.
    #[test]
    fn concurrent_cas_lets_exactly_one_writer_through() {
        let store = store();
        for round in 0..20u64 {
            let wins: usize = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..4u8)
                    .map(|writer| {
                        let store = &store;
                        scope.spawn(move || {
                            store
                                .set_account_record(&ALICE, &[writer], round)
                                .unwrap()
                                .is_ok()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| usize::from(handle.join().unwrap()))
                    .sum()
            });
            assert_eq!(wins, 1, "round {round}");
        }
        assert_eq!(store.account_record(&ALICE).unwrap().unwrap().version, 20);
    }

    #[test]
    fn a_malformed_account_record_reads_as_absent() {
        let store = store();
        store
            .account_records
            .insert(&ALICE[..], &[1u8; 3][..])
            .unwrap();
        assert_eq!(store.account_record(&ALICE).unwrap(), None);
        assert_eq!(
            store.set_account_record(&ALICE, b"fresh", 0).unwrap(),
            Ok(1)
        );
    }

    // ---- переоткрытие БД ----

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
    fn account_state_survives_reopening_the_database() {
        let path = temp_path("account_reopen");
        {
            let db = sled::open(&path).unwrap();
            let store = QueueStore::open(&db).unwrap();
            store.set_queue_only(&ALICE, true, 100).unwrap();
            store
                .set_account_record(&ALICE, b"pool", 0)
                .unwrap()
                .unwrap();
        }
        let db = sled::open(&path).unwrap();
        let store = QueueStore::open(&db).unwrap();
        assert!(store.is_queue_only(&ALICE).unwrap());
        assert!(!store.is_queue_only(&BOB).unwrap());
        assert_eq!(
            store.account_record(&ALICE).unwrap(),
            Some(AccountRecord {
                version: 1,
                record: b"pool".to_vec()
            })
        );
        drop(store);
        drop(db);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Очередь, пережившая рестарт ноды, — это весь смысл её хранения:
    /// контакт держит `queue_id` у себя и после перезапуска обязан
    /// по-прежнему попадать по нему в того же владельца. То же для
    /// надгробий: забытый отзыв вернул бы заблокированному доступ.
    #[test]
    fn queues_and_tombstones_survive_reopening_the_database() {
        let path = temp_path("reopen");
        let q = [9u8; 32];
        let gone = [10u8; 32];
        {
            let db = sled::open(&path).unwrap();
            let store = QueueStore::open(&db).unwrap();
            store
                .allocate(&ALICE, q, expiring(NOW + 100), NOW, 0)
                .unwrap()
                .unwrap();
            store
                .allocate(&ALICE, gone, live(), NOW, 0)
                .unwrap()
                .unwrap();
            store.revoke(&ALICE, &gone, NOW + 1).unwrap().unwrap();
        }
        let db = sled::open(&path).unwrap();
        let store = QueueStore::open(&db).unwrap();
        assert_eq!(store.owner_of(&q, NOW).unwrap(), Some(ALICE));
        assert_eq!(store.owner_of(&gone, NOW).unwrap(), None);
        let listed = store.list(&ALICE, NOW + 2).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].expires_at_secs, NOW + 100);
        assert_eq!(listed[1].revoked_at_secs, NOW + 1);
        assert_eq!(
            store.allocate(&ALICE, gone, live(), NOW + 2, 0).unwrap(),
            Err(QueueError::Revoked)
        );
        drop(store);
        drop(db);
        let _ = std::fs::remove_dir_all(&path);
    }
}
