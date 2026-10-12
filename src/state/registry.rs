use dashmap::DashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{Notify, mpsc};

pub type UserId = [u8; 32];
pub type DeviceId = u16;
pub type ConnectionId = u64;

#[derive(Clone, Debug)]
pub struct OutboundFrame {
    pub bytes: Vec<u8>,
    pub message_id: Option<u64>,
    pub sender_user_id: Option<UserId>,
    pub sender_device_id: Option<DeviceId>,
    /// Записать кадр и закрыть сессию. Единственный способ для ноды
    /// сказать «эта сессия больше не работает» уже после `AuthOk`:
    /// снаружи живое и мёртвое соединение неотличимы, пока нода молчит.
    pub close_after_send: bool,
}

#[derive(Clone)]
pub struct RoutedConnection {
    pub id: ConnectionId,
    pub device_id: Option<DeviceId>,
    pub tx: mpsc::Sender<OutboundFrame>,
    /// `not_before` сертификата делегированной сессии; `None` — сессия
    /// вошла ключом аккаунта, отзыв сертификатов её не касается.
    pub cert_not_before: Option<u64>,
    /// Сигнал «сертификат этой сессии отозван».
    pub revocation: Arc<SessionRevocation>,
}

/// Сигнал отзыва для одной живой сессии. Флаг цикл сессии читает перед
/// каждой записью клиенту — после отзыва сессии не уходит ни одного кадра;
/// `Notify` будит цикл, даже если сессия молчит.
#[derive(Debug, Default)]
pub struct SessionRevocation {
    revoked: AtomicBool,
    notify: Notify,
}

impl SessionRevocation {
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        // Разрешение сохраняется, если цикл сейчас не ждёт: следующий
        // `revoked()` вернётся сразу.
        self.notify.notify_one();
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    /// Дождаться отзыва. Cancel-safe: флаг проверяется на каждом опросе.
    pub async fn revoked(&self) {
        while !self.is_revoked() {
            self.notify.notified().await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct Registration {
    pub connection_id: ConnectionId,
    pub is_first_for_user: bool,
    pub is_first_for_device: bool,
    /// Сигнал отзыва этой сессии (см. [`ConnRegistry::revoke_delegated`]).
    pub revocation: Arc<SessionRevocation>,
}

/// Реестр живых сессий ноды: пользователь → его соединения (с `device_id`,
/// если сессия привязана к устройству). Только в памяти; по нему идёт
/// онлайн-маршрутизация и проверка «получатель в сети».
#[derive(Clone)]
pub struct ConnRegistry {
    inner: Arc<DashMap<UserId, Vec<RoutedConnection>>>,
    next_connection_id: Arc<AtomicU64>,
}

impl Default for ConnRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl ConnRegistry {
    /// Зарегистрировать сессию, вошедшую ключом аккаунта.
    pub fn insert(
        &self,
        user: UserId,
        device_id: Option<DeviceId>,
        tx: mpsc::Sender<OutboundFrame>,
    ) -> Registration {
        self.insert_session(user, device_id, None, tx)
    }

    /// Зарегистрировать сессию. `cert_not_before` — у делегированной
    /// сессии `not_before` её сертификата: по нему её найдёт отзыв.
    pub fn insert_session(
        &self,
        user: UserId,
        device_id: Option<DeviceId>,
        cert_not_before: Option<u64>,
        tx: mpsc::Sender<OutboundFrame>,
    ) -> Registration {
        let revocation = Arc::new(SessionRevocation::default());
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let mut sessions = self.inner.entry(user).or_default();
        let is_first_for_user = sessions.is_empty();
        let is_first_for_device = device_id
            .is_some_and(|device| sessions.iter().all(|entry| entry.device_id != Some(device)));

        sessions.push(RoutedConnection {
            id: connection_id,
            device_id,
            tx,
            cert_not_before,
            revocation: revocation.clone(),
        });

        Registration {
            connection_id,
            is_first_for_user,
            is_first_for_device,
            revocation,
        }
    }

    /// Отзыв сертификатов: делегированные сессии устройства `device_id`
    /// пользователя с `not_before < issued_before` выписываются из реестра
    /// (новые конверты им больше не маршрутизируются) и получают сигнал
    /// закрыться. Сессии, вошедшие ключом аккаунта, не трогаются. Возвращает
    /// число закрытых сессий.
    pub fn revoke_delegated(
        &self,
        user: &UserId,
        device_id: DeviceId,
        issued_before: u64,
    ) -> usize {
        let mut revoked = 0usize;
        self.inner.remove_if_mut(user, |_, sessions| {
            sessions.retain(|entry| {
                let hit = entry.device_id == Some(device_id)
                    && entry
                        .cert_not_before
                        .is_some_and(|not_before| not_before < issued_before);
                if hit {
                    entry.revocation.revoke();
                    revoked += 1;
                }
                !hit
            });
            sessions.is_empty()
        });
        revoked
    }

    pub fn remove(&self, user: &UserId, connection_id: ConnectionId) {
        // Удаление сессии и решение «убрать ключ» — одна операция под
        // блокировкой шарда. Разнесённые по двум блокировкам, они
        // пропускали между собой `insert` того же пользователя: ключ
        // удалялся вместе со свежей сессией, и она пропадала из
        // маршрутизации, оставаясь живой.
        self.inner.remove_if_mut(user, |_, sessions| {
            sessions.retain(|entry| entry.id != connection_id);
            sessions.is_empty()
        });
    }

    pub fn route_targets(
        &self,
        user: &UserId,
        recipient_device_id: Option<DeviceId>,
    ) -> Vec<RoutedConnection> {
        let Some(sessions) = self.inner.get(user) else {
            return Vec::new();
        };

        sessions
            .iter()
            .filter(|entry| match recipient_device_id {
                Some(device_id) => entry.device_id == Some(device_id),
                None => true,
            })
            .cloned()
            .collect()
    }

    pub fn has_user(&self, user: &UserId) -> bool {
        self.inner
            .get(user)
            .is_some_and(|sessions| !sessions.is_empty())
    }

    /// Сколько живых сессий у пользователя сейчас. Гонка «два подключения
    /// одновременно прошли проверку лимита» допустима: лимит — best-effort
    /// защита от исчерпания ресурсов, не бухгалтерия.
    pub fn session_count(&self, user: &UserId) -> usize {
        self.inner
            .get(user)
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }

    pub fn has_device(&self, user: &UserId, device_id: DeviceId) -> bool {
        self.inner.get(user).is_some_and(|sessions| {
            sessions
                .iter()
                .any(|entry| entry.device_id == Some(device_id))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnRegistry, OutboundFrame};
    use tokio::sync::mpsc;

    fn user(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn registry_routes_all_sessions_for_user_when_device_is_absent() {
        let registry = ConnRegistry::default();
        let (tx_a, _rx_a) = mpsc::channel::<OutboundFrame>(1);
        let (tx_b, _rx_b) = mpsc::channel::<OutboundFrame>(1);

        registry.insert(user(1), None, tx_a);
        registry.insert(user(1), Some(7), tx_b);

        let targets = registry.route_targets(&user(1), None);

        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn registry_routes_only_matching_device_when_requested() {
        let registry = ConnRegistry::default();
        let (tx_a, _rx_a) = mpsc::channel::<OutboundFrame>(1);
        let (tx_b, _rx_b) = mpsc::channel::<OutboundFrame>(1);

        registry.insert(user(1), Some(7), tx_a);
        registry.insert(user(1), Some(8), tx_b);

        let targets = registry.route_targets(&user(1), Some(8));

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_id, Some(8));
    }

    #[test]
    fn registration_marks_first_user_and_first_device() {
        let registry = ConnRegistry::default();
        let (tx_a, _rx_a) = mpsc::channel::<OutboundFrame>(1);
        let (tx_b, _rx_b) = mpsc::channel::<OutboundFrame>(1);
        let (tx_c, _rx_c) = mpsc::channel::<OutboundFrame>(1);

        let first = registry.insert(user(1), Some(10), tx_a);
        let second = registry.insert(user(1), Some(10), tx_b);
        let third = registry.insert(user(1), Some(11), tx_c);

        assert!(first.is_first_for_user);
        assert!(first.is_first_for_device);
        assert!(!second.is_first_for_user);
        assert!(!second.is_first_for_device);
        assert!(!third.is_first_for_user);
        assert!(third.is_first_for_device);
    }

    #[test]
    fn revocation_hits_only_older_delegated_sessions_of_that_device() {
        let registry = ConnRegistry::default();
        let (tx, _rx) = mpsc::channel::<OutboundFrame>(1);
        let old_cert = registry.insert_session(user(1), Some(7), Some(100), tx.clone());
        let new_cert = registry.insert_session(user(1), Some(7), Some(200), tx.clone());
        let full = registry.insert(user(1), Some(7), tx.clone());
        let other_device = registry.insert_session(user(1), Some(8), Some(100), tx.clone());
        let other_user = registry.insert_session(user(2), Some(7), Some(100), tx);

        assert_eq!(registry.revoke_delegated(&user(1), 7, 200), 1);
        assert!(old_cert.revocation.is_revoked());
        for untouched in [&new_cert, &full, &other_device, &other_user] {
            assert!(!untouched.revocation.is_revoked());
        }
        // Отозванная выписана из маршрутизации, остальные на месте.
        let ids: Vec<u64> = registry
            .route_targets(&user(1), Some(7))
            .iter()
            .map(|target| target.id)
            .collect();
        assert_eq!(ids, vec![new_cert.connection_id, full.connection_id]);
        // Повтор ничего не находит.
        assert_eq!(registry.revoke_delegated(&user(1), 7, 200), 0);
    }

    #[tokio::test]
    async fn the_revocation_signal_wakes_a_waiting_session() {
        let signal = std::sync::Arc::new(super::SessionRevocation::default());
        let waiter = tokio::spawn({
            let signal = signal.clone();
            async move { signal.revoked().await }
        });
        tokio::task::yield_now().await;
        signal.revoke();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        // И сразу — тому, кто начал ждать после отзыва.
        signal.revoked().await;
    }

    #[test]
    fn remove_drops_only_selected_connection() {
        let registry = ConnRegistry::default();
        let (tx_a, _rx_a) = mpsc::channel::<OutboundFrame>(1);
        let (tx_b, _rx_b) = mpsc::channel::<OutboundFrame>(1);

        let first = registry.insert(user(1), None, tx_a);
        registry.insert(user(1), Some(5), tx_b);

        registry.remove(&user(1), first.connection_id);

        let targets = registry.route_targets(&user(1), None);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_id, Some(5));
    }

    /// `session_count` — вход лимита одновременных сессий.
    #[test]
    fn session_count_tracks_live_sessions() {
        let registry = ConnRegistry::default();
        let (tx_a, _rx_a) = mpsc::channel::<OutboundFrame>(1);
        let (tx_b, _rx_b) = mpsc::channel::<OutboundFrame>(1);

        assert_eq!(registry.session_count(&user(1)), 0);

        let first = registry.insert(user(1), Some(1), tx_a);
        assert_eq!(registry.session_count(&user(1)), 1);

        registry.insert(user(1), Some(2), tx_b);
        assert_eq!(registry.session_count(&user(1)), 2);
        // Чужой ключ не считается.
        assert_eq!(registry.session_count(&user(2)), 0);

        registry.remove(&user(1), first.connection_id);
        assert_eq!(registry.session_count(&user(1)), 1);
    }

    /// `remove` последней сессии пользователя, идущий одновременно с
    /// `insert` новой сессии того же пользователя, не должен её терять.
    /// Окно гонки узкое, поэтому раундов много: каждый раунд стартует оба
    /// потока с барьера.
    #[test]
    fn concurrent_insert_survives_removal_of_last_session() {
        use std::sync::{Arc, Barrier};

        const ROUNDS: usize = 5_000;
        let registry = ConnRegistry::default();
        let barrier = Arc::new(Barrier::new(2));
        let (tx, _rx) = mpsc::channel::<OutboundFrame>(1);

        for round in 0..ROUNDS {
            let leaving = registry.insert(user(1), Some(1), tx.clone());

            let remover = {
                let registry = registry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    registry.remove(&user(1), leaving.connection_id);
                })
            };
            barrier.wait();
            let joining = registry.insert(user(1), Some(2), tx.clone());
            remover.join().unwrap();

            let targets = registry.route_targets(&user(1), None);
            assert_eq!(
                targets.iter().map(|t| t.id).collect::<Vec<_>>(),
                vec![joining.connection_id],
                "round {round}: the fresh session was lost or the old one stayed"
            );
            registry.remove(&user(1), joining.connection_id);
            assert!(!registry.has_user(&user(1)));
        }
    }

    /// Ключ пользователя уходит вместе с последней сессией: иначе карта
    /// росла бы по строке на каждого, кто когда-либо подключался.
    #[test]
    fn removing_last_session_drops_the_user_key() {
        let registry = ConnRegistry::default();
        let (tx_a, _rx_a) = mpsc::channel::<OutboundFrame>(1);
        let (tx_b, _rx_b) = mpsc::channel::<OutboundFrame>(1);

        let first = registry.insert(user(1), Some(1), tx_a);
        let second = registry.insert(user(1), Some(2), tx_b);

        registry.remove(&user(1), first.connection_id);
        assert_eq!(registry.inner.len(), 1);
        // Неизвестный id ничего не трогает.
        registry.remove(&user(1), u64::MAX);
        assert_eq!(registry.session_count(&user(1)), 1);

        registry.remove(&user(1), second.connection_id);
        assert_eq!(registry.inner.len(), 0);
        // Повторное удаление отсутствующего пользователя — не ошибка.
        registry.remove(&user(1), second.connection_id);
    }

    #[test]
    fn registry_reports_user_and_device_presence() {
        let registry = ConnRegistry::default();
        let (tx, _rx) = mpsc::channel::<OutboundFrame>(1);

        registry.insert(user(1), Some(5), tx);

        assert!(registry.has_user(&user(1)));
        assert!(registry.has_device(&user(1), 5));
        assert!(!registry.has_device(&user(1), 7));
    }
}
