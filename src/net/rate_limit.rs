use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::LimitsConfig;
use crate::state::registry::UserId;

/// Счётчики одного пользователя: фиксированное секундное окно для msg/s и
/// UTC-суточное окно для байт.
#[derive(Debug)]
struct UserCounters {
    sec_window_start: u64,
    sec_count: u64,
    day_key: u64,
    day_bytes: u64,
}

/// In-memory rate-limiter отправки на пользователя: `msg/s` (фиксированное
/// окно 1 с) и `байт/сутки` (окно = UTC-день).
///
/// Состояние сознательно не персистится: лимиты существуют против активного
/// флуда в моменте, а не как аудит; перезапуск ноды сбрасывает счётчики.
/// Проверка детерминирована относительно переданного времени (`check_at`) —
/// так тестируются окна без реальных пауз.
///
/// Запись заводится на каждого отправителя, а ключ пользователя ничего не
/// стоит, поэтому записи с истёкшими окнами вычищаются: раз в
/// [`SWEEP_INTERVAL_SECS`] это делает один из вызовов `check_at`.
pub struct SendRateLimiter {
    msgs_per_sec: u32,
    bytes_per_day: u64,
    per_user: DashMap<UserId, UserCounters>,
    /// Номер интервала вычистки, в котором она уже прошла.
    last_sweep_slot: AtomicU64,
}

/// Период вычистки, сек. Вычистка — проход по всей карте, поэтому не на
/// каждом вызове; минуты хватает, чтобы карта не росла дольше суточного
/// окна.
const SWEEP_INTERVAL_SECS: u64 = 60;

impl UserCounters {
    /// Запись ничего не помнит сверх свежей: оба окна, которые она
    /// считает, уже сменились, и следующая проверка всё равно обнулила бы
    /// оба счётчика. Удалить её — то же, что оставить. Окно выключенного
    /// лимита не учитывается: его счётчик никто не сравнивает.
    fn is_expired(&self, now_secs: u64, msgs_limited: bool, bytes_limited: bool) -> bool {
        let sec_expired = !msgs_limited || self.sec_window_start != now_secs;
        let day_expired = !bytes_limited || self.day_key != now_secs / SECS_PER_DAY;
        sec_expired && day_expired
    }
}

impl SendRateLimiter {
    pub fn new(msgs_per_sec: u32, bytes_per_day: u64) -> Self {
        Self {
            msgs_per_sec,
            bytes_per_day,
            per_user: DashMap::new(),
            last_sweep_slot: AtomicU64::new(0),
        }
    }

    /// Сколько пользователей сейчас помнит лимитер (для тестов и
    /// диагностики).
    pub fn tracked_users(&self) -> usize {
        self.per_user.len()
    }

    /// Удалить записи с истёкшими окнами, если в текущем интервале этого
    /// ещё никто не сделал. Право на проход достаётся одному вызову через
    /// CAS: остальные не ждут его и не повторяют. Сам проход блокирует
    /// шарды карты по одному, а не всю карту, так что отправители из других
    /// шардов его не замечают.
    ///
    /// Интервал определяется номером, а не ростом: при прыжке часов назад
    /// вычистка не замирает на длину прыжка — так же, как окна в `check_at`.
    fn maybe_sweep(&self, now_secs: u64) {
        let slot = now_secs / SWEEP_INTERVAL_SECS;
        let last = self.last_sweep_slot.load(Ordering::Relaxed);
        if last == slot
            || self
                .last_sweep_slot
                .compare_exchange(last, slot, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let msgs_limited = self.msgs_per_sec > 0;
        let bytes_limited = self.bytes_per_day > 0;
        self.per_user
            .retain(|_, counters| !counters.is_expired(now_secs, msgs_limited, bytes_limited));
    }

    pub fn check(&self, user: &UserId, bytes: usize) -> bool {
        self.check_at(user, bytes, unix_now_secs())
    }

    /// `true` — посылка укладывается в оба лимита и бюджет списан;
    /// `false` — отказ, бюджет не списывается. Лимит 0 = не ограничено.
    pub fn check_at(&self, user: &UserId, bytes: usize, now_secs: u64) -> bool {
        if self.msgs_per_sec == 0 && self.bytes_per_day == 0 {
            return true;
        }
        // До захвата записи пользователя: `retain` берёт шарды на запись, и
        // удерживаемая запись своего шарда заперла бы его навсегда.
        self.maybe_sweep(now_secs);
        let mut counters = self.per_user.entry(*user).or_insert(UserCounters {
            sec_window_start: now_secs,
            sec_count: 0,
            day_key: now_secs / SECS_PER_DAY,
            day_bytes: 0,
        });
        // Ролловер секундного окна. Сравнение на неравенство, а не на
        // «больше»: часы ноды могут прыгнуть назад (коррекция NTP), и
        // тогда окно не сменилось бы вовсе — пользователь, успевший
        // выбрать бюджет, остался бы заблокирован на всю длину прыжка.
        if now_secs != counters.sec_window_start {
            counters.sec_window_start = now_secs;
            counters.sec_count = 0;
        }
        // Ролловер суточного окна (UTC-дни с эпохи).
        let day_key = now_secs / SECS_PER_DAY;
        if day_key != counters.day_key {
            counters.day_key = day_key;
            counters.day_bytes = 0;
        }
        if self.msgs_per_sec > 0 && counters.sec_count >= u64::from(self.msgs_per_sec) {
            return false;
        }
        // Переполнение u64 трактуется как исчерпанный бюджет: `checked_add`,
        // а не `saturating_add` — насыщенное значение прошло бы проверку
        // (`MAX > MAX` ложно) и сорвалось бы на списании ниже.
        let next_day_bytes = counters.day_bytes.checked_add(bytes as u64);
        if self.bytes_per_day > 0
            && !matches!(next_day_bytes, Some(value) if value <= self.bytes_per_day)
        {
            return false;
        }
        counters.sec_count = counters.sec_count.saturating_add(1);
        // При выключенном байтовом лимите счётчик просто насыщается: его
        // никто не сравнивает, а падать из-за него нельзя.
        counters.day_bytes = next_day_bytes.unwrap_or(u64::MAX);
        true
    }
}

/// Пер-соединение ограничитель Ping: фиксированное окно 1 с. Сверх лимита
/// pong не отправляется — соединение не рвётся (keepalive-клиент с честной
/// частотой не страдает, флудер просто не получает ответов).
#[derive(Debug)]
pub struct PingGate {
    window_start: u64,
    count: u64,
    max_per_sec: u32,
}

impl PingGate {
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            window_start: 0,
            count: 0,
            max_per_sec,
        }
    }

    pub fn allow(&mut self, now_secs: u64) -> bool {
        if self.max_per_sec == 0 {
            return true;
        }
        // Как и в лимитере отправки: неравенство, а не «больше», иначе
        // прыжок часов назад замораживает окно.
        if now_secs != self.window_start {
            self.window_start = now_secs;
            self.count = 0;
        }
        if self.count >= u64::from(self.max_per_sec) {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Ограничитель одновременных хендшейков — глобальный и на IP.
///
/// Респондер выполняет DH до того, как узнал, кто к нему пришёл: стоимость
/// хендшейка платится за любого, кто открыл сокет. Таймаут ограничивает
/// длительность одной попытки, но не их количество, поэтому вход считается
/// отдельно — иначе пара тысяч параллельных соединений съедает CPU ноды,
/// не предъявив ни одного ключа.
///
/// Разрешение живёт до подтверждения сессии первым кадром клиента: повтор
/// записанного хендшейка держит место на входе, пока не истечёт таймаут
/// подтверждения. Подтверждённая сессия разрешение освобождает и дальше
/// учитывается лимитом сессий на пользователя.
pub struct HandshakeAdmission {
    global: Arc<Semaphore>,
    per_ip_limit: usize,
    per_ip: Arc<DashMap<IpAddr, usize>>,
}

/// Причина отказа во входе — метка метрики `handshake_admission_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionReject {
    /// Исчерпан глобальный потолок одновременных хендшейков.
    Global,
    /// Исчерпан потолок на конкретный IP.
    PerIp,
}

impl AdmissionReject {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::PerIp => "per_ip",
        }
    }
}

/// Держатель разрешения. Освобождает оба счётчика при drop — в том числе
/// когда хендшейк упал с ошибкой или был отменён.
pub struct AdmissionGuard {
    _global: Option<OwnedSemaphorePermit>,
    per_ip: Option<(IpAddr, Arc<DashMap<IpAddr, usize>>)>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let Some((ip, map)) = self.per_ip.take() else {
            return;
        };
        // Запись удаляется на нуле: иначе карта росла бы по одной строке на
        // каждый IP, который когда-либо подключался.
        map.remove_if_mut(&ip, |_, count| {
            *count = count.saturating_sub(1);
            *count == 0
        });
    }
}

impl HandshakeAdmission {
    /// `0` в любом из лимитов означает «не ограничено».
    pub fn new(max_inflight: usize, max_inflight_per_ip: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(if max_inflight == 0 {
                Semaphore::MAX_PERMITS
            } else {
                max_inflight
            })),
            per_ip_limit: max_inflight_per_ip,
            per_ip: Arc::new(DashMap::new()),
        }
    }

    /// Попытаться занять место под хендшейк. Не ждёт: очередь на вход — это
    /// та же нагрузка, от которой мы защищаемся, поэтому лишнее соединение
    /// закрывается сразу.
    pub fn try_admit(&self, peer: IpAddr) -> Result<AdmissionGuard, AdmissionReject> {
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionReject::Global)?;

        if self.per_ip_limit == 0 {
            return Ok(AdmissionGuard {
                _global: Some(global),
                per_ip: None,
            });
        }

        let mut admitted = false;
        {
            let mut entry = self.per_ip.entry(peer).or_insert(0);
            if *entry < self.per_ip_limit {
                *entry += 1;
                admitted = true;
            }
        }

        if !admitted {
            // Глобальное разрешение вернётся при drop `global`.
            return Err(AdmissionReject::PerIp);
        }

        Ok(AdmissionGuard {
            _global: Some(global),
            per_ip: Some((peer, self.per_ip.clone())),
        })
    }

    /// Сколько хендшейков этого IP сейчас в работе (для тестов и диагностики).
    pub fn inflight_for(&self, peer: IpAddr) -> usize {
        self.per_ip.get(&peer).map(|entry| *entry).unwrap_or(0)
    }
}

/// Всё, что нужно соединению для применения лимитов: конфиг и общий на
/// процесс rate-limiter отправки.
pub struct SessionLimits {
    pub cfg: LimitsConfig,
    pub send: SendRateLimiter,
}

impl SessionLimits {
    pub fn new(cfg: LimitsConfig) -> Self {
        Self {
            send: SendRateLimiter::new(cfg.send_msgs_per_sec, cfg.send_bytes_per_day),
            cfg,
        }
    }
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const SECS_PER_DAY: u64 = 86_400;

#[cfg(test)]
mod tests {
    use super::{AdmissionReject, HandshakeAdmission, PingGate, SendRateLimiter};

    fn user(seed: u8) -> crate::state::registry::UserId {
        [seed; 32]
    }

    #[test]
    fn unlimited_when_both_limits_zero() {
        let limiter = SendRateLimiter::new(0, 0);
        for i in 0..10_000 {
            assert!(limiter.check_at(&user(1), usize::MAX, i));
        }
    }

    #[test]
    fn msgs_per_sec_window_rejects_then_resets() {
        let limiter = SendRateLimiter::new(3, 0);
        assert!(limiter.check_at(&user(1), 10, 100));
        assert!(limiter.check_at(&user(1), 10, 100));
        assert!(limiter.check_at(&user(1), 10, 100));
        // Окно исчерпано; бюджет при отказе не списывается.
        assert!(!limiter.check_at(&user(1), 10, 100));
        assert!(!limiter.check_at(&user(1), 10, 100));
        // Следующая секунда — новое окно.
        assert!(limiter.check_at(&user(1), 10, 101));
        assert!(limiter.check_at(&user(2), 0, 100)); // чужой счётчик независим
    }

    #[test]
    fn bytes_per_day_cap_and_rollover() {
        let limiter = SendRateLimiter::new(0, 100);
        let day_start = 5 * 86_400;
        assert!(limiter.check_at(&user(1), 60, day_start));
        assert!(limiter.check_at(&user(1), 40, day_start));
        // 60+40=100 исчерпано, ещё байт нельзя до конца суток...
        assert!(!limiter.check_at(&user(1), 1, day_start + 86_399));
        // ...а в новый UTC-день бюджет обновился.
        assert!(limiter.check_at(&user(1), 100, day_start + 86_400));
    }

    #[test]
    fn saturating_bytes_do_not_panic() {
        let limiter = SendRateLimiter::new(0, u64::MAX);
        assert!(limiter.check_at(&user(1), usize::MAX, 0));
        assert!(!limiter.check_at(&user(1), usize::MAX, 0));
    }

    /// `check` — обёртка над `check_at` с системными часами; проверяем, что
    /// она действительно списывает бюджет того же пользователя.
    #[test]
    fn check_uses_wall_clock_and_shares_budget() {
        let limiter = SendRateLimiter::new(1, 0);
        assert!(limiter.check(&user(42), 1));
        assert!(!limiter.check(&user(42), 1));
        // Другой пользователь имеет собственный бюджет.
        assert!(limiter.check(&user(43), 1));
    }

    /// Записи с истёкшими окнами вычищаются: карта не растёт по строке на
    /// каждого, кто когда-либо отправлял.
    #[test]
    fn expired_entries_are_evicted() {
        let limiter = SendRateLimiter::new(10, 1_000);
        let day_start = 7 * 86_400;
        for seed in 0..100u8 {
            assert!(limiter.check_at(&user(seed), 1, day_start + 5));
        }
        assert_eq!(limiter.tracked_users(), 100);

        // Следующий UTC-день и следующий интервал вычистки: все прежние
        // окна истекли, остаётся только запись текущего отправителя.
        assert!(limiter.check_at(&user(200), 1, day_start + 86_400));
        assert_eq!(limiter.tracked_users(), 1);
    }

    /// Вычистка не сбрасывает бюджет, который ещё действует: запись с
    /// живым суточным окном переживает проход, и выбравший бюджет
    /// пользователь остаётся заблокирован.
    #[test]
    fn sweep_keeps_entries_with_a_live_window() {
        let limiter = SendRateLimiter::new(0, 100);
        let day_start = 3 * 86_400;
        assert!(limiter.check_at(&user(1), 100, day_start + 10));
        assert!(!limiter.check_at(&user(1), 1, day_start + 10));

        // Тот же день, другой интервал вычистки — проход случился.
        assert!(limiter.check_at(&user(2), 1, day_start + 10 + 2 * 60));
        assert_eq!(limiter.tracked_users(), 2);
        assert!(!limiter.check_at(&user(1), 1, day_start + 10 + 2 * 60));
    }

    /// Только секундный лимит: записи истекают со своей секундой, и
    /// вычистка сводит карту к тем, кто отправлял в текущую.
    #[test]
    fn msgs_only_entries_expire_with_their_second() {
        let limiter = SendRateLimiter::new(1, 0);
        for seed in 0..50u8 {
            assert!(limiter.check_at(&user(seed), 1, 1_000));
        }
        assert!(!limiter.check_at(&user(0), 1, 1_000));
        assert_eq!(limiter.tracked_users(), 50);

        assert!(limiter.check_at(&user(0), 1, 1_000 + 60));
        assert_eq!(limiter.tracked_users(), 1);
    }

    /// Прыжок часов назад не замораживает вычистку: интервал определяется
    /// номером, а не ростом.
    #[test]
    fn sweep_runs_after_backwards_clock_jump() {
        let limiter = SendRateLimiter::new(1, 0);
        assert!(limiter.check_at(&user(1), 1, 100_000));
        assert!(limiter.check_at(&user(2), 1, 100_000 - 3_600));
        assert_eq!(limiter.tracked_users(), 1);
    }

    #[test]
    fn ping_gate_windows_per_second() {
        let mut gate = PingGate::new(2);
        assert!(gate.allow(50));
        assert!(gate.allow(50));
        assert!(!gate.allow(50));
        assert!(!gate.allow(50));
        assert!(gate.allow(51));

        let mut open_gate = PingGate::new(0);
        for i in 0..1_000 {
            assert!(open_gate.allow(i));
        }
    }

    // ---- admission control хендшейков ----

    fn ip(last: u8) -> std::net::IpAddr {
        std::net::IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn admission_enforces_global_ceiling() {
        let admission = HandshakeAdmission::new(2, 0);
        let first = admission.try_admit(ip(1)).unwrap();
        let second = admission.try_admit(ip(2)).unwrap();
        assert_eq!(
            admission.try_admit(ip(3)).err(),
            Some(AdmissionReject::Global)
        );

        // Место освобождается ровно тогда, когда хендшейк закончился —
        // успехом, ошибкой или отменой.
        drop(first);
        let third = admission.try_admit(ip(3)).unwrap();
        drop((second, third));
        assert!(admission.try_admit(ip(4)).is_ok());
    }

    #[test]
    fn admission_enforces_per_ip_ceiling_without_blocking_others() {
        let admission = HandshakeAdmission::new(0, 2);
        let a1 = admission.try_admit(ip(1)).unwrap();
        let a2 = admission.try_admit(ip(1)).unwrap();
        assert_eq!(
            admission.try_admit(ip(1)).err(),
            Some(AdmissionReject::PerIp)
        );

        // Чужой IP не страдает от соседа.
        let b1 = admission.try_admit(ip(2)).unwrap();
        assert_eq!(admission.inflight_for(ip(1)), 2);
        assert_eq!(admission.inflight_for(ip(2)), 1);

        drop(a1);
        assert_eq!(admission.inflight_for(ip(1)), 1);
        assert!(admission.try_admit(ip(1)).is_ok());
        drop((a2, b1));
    }

    /// Отказ по per-IP не должен подтекать глобальным разрешением: иначе
    /// один флудер исчерпал бы глобальный потолок одними отказами.
    #[test]
    fn per_ip_rejection_returns_the_global_permit() {
        let admission = HandshakeAdmission::new(2, 1);
        let held = admission.try_admit(ip(1)).unwrap();
        for _ in 0..10 {
            assert_eq!(
                admission.try_admit(ip(1)).err(),
                Some(AdmissionReject::PerIp)
            );
        }
        // Одно место занято `held`, второе всё ещё свободно.
        assert!(admission.try_admit(ip(2)).is_ok());
        drop(held);
    }

    /// Карта не должна расти по строке на каждый когда-либо подключавшийся
    /// IP — запись уходит на нуле.
    #[test]
    fn per_ip_entries_are_dropped_when_idle() {
        let admission = HandshakeAdmission::new(0, 4);
        for last in 0..50u8 {
            let guard = admission.try_admit(ip(last)).unwrap();
            drop(guard);
            assert_eq!(admission.inflight_for(ip(last)), 0);
        }
    }

    #[test]
    fn zero_limits_admit_everything() {
        let admission = HandshakeAdmission::new(0, 0);
        let mut guards = Vec::new();
        for last in 0..100u8 {
            guards.push(admission.try_admit(ip(last % 3)).unwrap());
        }
    }
    /// Коррекция часов назад не должна замораживать бюджет: окно
    /// определяется значением секунды, а не её ростом. Иначе после прыжка
    /// на час назад пользователь, успевший выбрать лимит, оставался бы
    /// заблокирован весь этот час.
    #[test]
    fn backwards_clock_jump_does_not_freeze_the_send_budget() {
        let limiter = SendRateLimiter::new(2, 0);
        let user = [42u8; 32];

        assert!(limiter.check_at(&user, 1, 10_000));
        assert!(limiter.check_at(&user, 1, 10_000));
        assert!(!limiter.check_at(&user, 1, 10_000));

        // Часы ушли назад на час — это новое окно, а не продолжение старого.
        assert!(limiter.check_at(&user, 1, 6_400));
        assert!(limiter.check_at(&user, 1, 6_400));
        assert!(!limiter.check_at(&user, 1, 6_400));
    }

    #[test]
    fn backwards_clock_jump_does_not_freeze_the_ping_gate() {
        let mut gate = PingGate::new(2);

        assert!(gate.allow(10_000));
        assert!(gate.allow(10_000));
        assert!(!gate.allow(10_000));

        assert!(gate.allow(6_400));
        assert!(gate.allow(6_400));
        assert!(!gate.allow(6_400));
    }
}
