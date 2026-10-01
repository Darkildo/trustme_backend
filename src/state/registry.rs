use dashmap::DashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc;

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
}

#[derive(Debug, Clone, Copy)]
pub struct Registration {
    pub connection_id: ConnectionId,
    pub is_first_for_user: bool,
    pub is_first_for_device: bool,
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
    pub fn insert(
        &self,
        user: UserId,
        device_id: Option<DeviceId>,
        tx: mpsc::Sender<OutboundFrame>,
    ) -> Registration {
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let mut sessions = self.inner.entry(user).or_default();
        let is_first_for_user = sessions.is_empty();
        let is_first_for_device = device_id
            .is_some_and(|device| sessions.iter().all(|entry| entry.device_id != Some(device)));

        sessions.push(RoutedConnection {
            id: connection_id,
            device_id,
            tx,
        });

        Registration {
            connection_id,
            is_first_for_user,
            is_first_for_device,
        }
    }

    pub fn remove(&self, user: &UserId, connection_id: ConnectionId) {
        let Some(mut sessions) = self.inner.get_mut(user) else {
            return;
        };

        sessions.retain(|entry| entry.id != connection_id);
        let should_remove_key = sessions.is_empty();
        drop(sessions);

        if should_remove_key {
            self.inner.remove(user);
        }
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
