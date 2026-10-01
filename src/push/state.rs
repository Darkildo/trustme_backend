use std::time::Duration;

use crate::domain::priority::MessagePriority;

/// Per-(user, device) throttling state for push notifications.
///
/// Lives in the `PushScheduler`'s in-memory cache and is mirrored to durable
/// storage (`PushStatePersistence`) so a restart does not unleash a burst of
/// pushes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PushState {
    /// Unix seconds of the last send attempt: set by `decide` on `SendNow`
    /// and kept even if the send then fails. `0` means "no push has ever been
    /// attempted for this recipient".
    pub last_push_at_secs: u64,
    /// Count of undelivered messages observed since `last_push_at_secs`. Reset
    /// to zero on `DecisionAction::SendNow`; the scheduler adds the count back
    /// if the send fails.
    pub pending_since_last_push: u32,
    /// Storage-byte encoding of the highest message priority seen in the
    /// current window. `0` = None, `1` = Low, `2` = Medium, `3` = High.
    /// Encoded this way to match `MessagePriority::as_storage_byte` and keep
    /// the type `Copy` for cheap cloning across the worker.
    pub highest_pending_priority: u8,
    /// Unix seconds until which sending is suppressed (set after a failed
    /// send: `Backoff` or `TransientError`). `0` means "no active backoff".
    /// Suppression does not stop the state from accumulating pending
    /// counters — only from sending.
    pub suppressed_until_secs: u64,
    /// Current exponential-backoff step in seconds. Doubles on each consecutive
    /// failure and resets to zero after a successful send or token eviction.
    /// Bounded by `PushConfig::suppress_max`.
    pub current_backoff_secs: u64,
}

impl PushState {
    pub fn highest_priority(&self) -> Option<MessagePriority> {
        // An unknown byte (corrupt persisted row) reads as "no priority".
        MessagePriority::from_storage_byte(self.highest_pending_priority).unwrap_or(None)
    }

    pub fn set_highest_priority(&mut self, priority: Option<MessagePriority>) {
        self.highest_pending_priority = MessagePriority::as_storage_byte(priority);
    }

    /// Состояние больше ни на что не влияет: накопленного нет, backoff
    /// истёк, и отметка последнего пуша старше самого длинного интервала
    /// (`DecisionConfig::longest_gap_secs`). Следующее решение для такой
    /// записи совпадёт с решением для `PushState::default()`, поэтому её
    /// можно не хранить вовсе — иначе карта и дерево `push_state` копят
    /// по строке на каждую пару, которой хоть раз слали пуш.
    ///
    /// Шаг backoff'а (`current_backoff_secs`) при этом теряется намеренно:
    /// после затишья следующая неудача и так должна начинать с начального
    /// шага.
    pub fn is_idle(&self, now_secs: u64, longest_gap_secs: u64) -> bool {
        self.pending_since_last_push == 0
            && self.suppressed_until_secs <= now_secs
            && self.last_push_at_secs.saturating_add(longest_gap_secs) <= now_secs
    }
}

/// Длительность, округлённая вверх до целых секунд.
///
/// Отметки времени в `PushState` — целые unix-секунды, а интервалы в
/// конфиге — миллисекунды. `Duration::as_secs` округляет вниз, и 500 мс
/// превращались в ноль: коалесинг и cooldown молча отключались. Округление
/// вверх, потому что интервал из конфига — нижняя граница: пуш не должен
/// уйти раньше.
pub fn ceil_secs(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

/// Tunable thresholds for the push decision machine. Mirrors `crate::config::PushConfig`
/// but flattened to make `decide` a pure function that can be unit-tested without
/// pulling in HTTP / OAuth config.
#[derive(Clone, Debug)]
pub struct DecisionConfig {
    pub min_gap_high: Duration,
    pub min_gap_medium: Duration,
    pub min_gap_low: Duration,
    pub min_gap_none: Duration,
    /// Будит ли **время** на сообщениях без приоритета. `false` — интервал
    /// для них не истекает никогда: они копятся, пока не придёт сообщение с
    /// приоритетом либо пока их не накопится `burst_none`.
    pub wake_on_unspecified: bool,
    pub burst_high: u32,
    pub burst_medium: u32,
    pub burst_low: u32,
    pub burst_none: u32,
    pub suppress_initial: Duration,
    pub suppress_max: Duration,
}

impl DecisionConfig {
    /// `None` означает «этот приоритет не будит»: не «подождать подольше», а
    /// не отправлять вовсе. Отличать обязательно — нулевой интервал у
    /// `High` значит ровно противоположное.
    pub fn min_gap_for(&self, priority: Option<MessagePriority>) -> Option<Duration> {
        match priority {
            Some(MessagePriority::High) => Some(self.min_gap_high),
            Some(MessagePriority::Medium) => Some(self.min_gap_medium),
            Some(MessagePriority::Low) => Some(self.min_gap_low),
            None if self.wake_on_unspecified => Some(self.min_gap_none),
            None => None,
        }
    }

    pub fn burst_for(&self, priority: Option<MessagePriority>) -> u32 {
        match priority {
            Some(MessagePriority::High) => self.burst_high,
            Some(MessagePriority::Medium) => self.burst_medium,
            Some(MessagePriority::Low) => self.burst_low,
            None => self.burst_none,
        }
    }

    /// Сколько секунд после пуша его отметка ещё может изменить решение.
    /// Приоритет следующего сообщения заранее неизвестен, поэтому берётся
    /// самый длинный из интервалов, которые вообще истекают по времени.
    pub fn longest_gap_secs(&self) -> u64 {
        [
            Some(MessagePriority::High),
            Some(MessagePriority::Medium),
            Some(MessagePriority::Low),
            None,
        ]
        .into_iter()
        .filter_map(|priority| self.min_gap_for(priority))
        .map(ceil_secs)
        .max()
        .unwrap_or(0)
    }
}

/// What caused `decide` to be invoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionInput {
    /// A new undelivered message just arrived for this recipient. Its priority
    /// must be folded into `highest_pending_priority` and `pending_since_last_push`
    /// must be incremented.
    NewMessage(Option<MessagePriority>),
    /// A previously scheduled timer fired. No new message, but pending counters
    /// from earlier `NewMessage` calls may now be eligible to send.
    TimerTick,
}

/// What the scheduler should do after applying the decision. Always paired with
/// the updated `PushState` to write back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionAction {
    /// Send a push now. The embedded counters describe what to put in the
    /// payload (`pending`, `max_priority`). State has already been reset to
    /// reflect the send (pending=0, max=None, last_push_at_secs=now).
    SendNow {
        pending: u32,
        max_priority: Option<MessagePriority>,
    },
    /// Wait until this unix-seconds timestamp, then re-evaluate (timer tick).
    /// Covers both coalescing windows and transport-backoff suppression.
    WaitUntil(u64),
    /// No send and no timer: either nothing is pending, or the pending
    /// messages have no priority and `wake_on_unspecified = false`.
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: DecisionAction,
    pub state: PushState,
}

/// Pure decision function. Given the prior state, the trigger, and `now`, return
/// the next state and the action the scheduler must take. No I/O, no time
/// source — all inputs explicit so this is exhaustively testable.
pub fn decide(
    prior: PushState,
    input: DecisionInput,
    now_secs: u64,
    cfg: &DecisionConfig,
) -> Decision {
    let mut state = prior;

    if let DecisionInput::NewMessage(priority) = input {
        // Saturating: u32::MAX pending messages is unrealistic, but an
        // overflow must not panic in debug builds.
        state.pending_since_last_push = state.pending_since_last_push.saturating_add(1);

        let prior_rank = state.highest_pending_priority;
        let incoming_rank = MessagePriority::as_storage_byte(priority);
        if incoming_rank > prior_rank {
            state.highest_pending_priority = incoming_rank;
        }
    }

    // No pending work → idle. A stale timer tick can land here after a send
    // already drained the counters; treat it as a no-op.
    if state.pending_since_last_push == 0 {
        return Decision {
            action: DecisionAction::Idle,
            state,
        };
    }

    // Honour an active backoff window. Re-evaluate when it expires.
    if now_secs < state.suppressed_until_secs {
        return Decision {
            action: DecisionAction::WaitUntil(state.suppressed_until_secs),
            state,
        };
    }

    let max_priority = state.highest_priority();
    let gap = cfg.min_gap_for(max_priority);
    let burst_threshold = cfg.burst_for(max_priority);

    let gap_satisfied = match gap {
        Some(min_gap) => {
            let elapsed = now_secs.saturating_sub(state.last_push_at_secs);
            state.last_push_at_secs == 0 || elapsed >= ceil_secs(min_gap)
        }
        // Приоритет не будит по времени: сколько ни жди, интервал не
        // истечёт. Окно закрывает только накопление (burst) или сообщение
        // поважнее — счётчики при этом продолжают расти, и первый же пуш
        // унесёт их с собой.
        None => false,
    };
    let burst_satisfied = state.pending_since_last_push >= burst_threshold;

    if gap_satisfied || burst_satisfied {
        let pending = state.pending_since_last_push;
        // Reset window — the caller will pass the embedded counters to the transport.
        state.pending_since_last_push = 0;
        state.set_highest_priority(None);
        state.last_push_at_secs = now_secs;
        Decision {
            action: DecisionAction::SendNow {
                pending,
                max_priority,
            },
            state,
        }
    } else {
        match gap {
            // Wait until the priority's gap elapses. `last_push_at_secs == 0`
            // always takes the SendNow branch above, so the deadline is never
            // computed from the "never sent" sentinel.
            Some(min_gap) => Decision {
                action: DecisionAction::WaitUntil(
                    state.last_push_at_secs.saturating_add(ceil_secs(min_gap)),
                ),
                state,
            },
            // Таймер ставить не на что: время этот приоритет не разбудит.
            None => Decision {
                action: DecisionAction::Idle,
                state,
            },
        }
    }
}

/// Apply a successful send result: clear any backoff state. State must have already
/// been advanced through `decide` returning `SendNow`.
pub fn on_send_success(state: &mut PushState) {
    state.suppressed_until_secs = 0;
    state.current_backoff_secs = 0;
}

/// Apply a transient send failure: exponentially increase backoff and set
/// `suppressed_until_secs`. The next `decide` call will short-circuit until then.
///
/// `retry_after` — пауза, которую назвал сам провайдер (`Retry-After`).
/// Она поднимает только текущее окно подавления, но не шаг экспоненты:
/// провайдер говорит о своём состоянии сейчас, а не о том, как быстро нам
/// наращивать паузу дальше. Ограничена `suppress_max`, чтобы абсурдное
/// значение заголовка не заглушило устройство на сутки.
pub fn on_send_backoff(
    state: &mut PushState,
    now_secs: u64,
    cfg: &DecisionConfig,
    retry_after: Option<Duration>,
) {
    let initial = ceil_secs(cfg.suppress_initial).max(1);
    let max = ceil_secs(cfg.suppress_max).max(initial);
    let next = if state.current_backoff_secs == 0 {
        initial
    } else {
        state.current_backoff_secs.saturating_mul(2).min(max)
    };
    state.current_backoff_secs = next;
    let hinted = retry_after.map(ceil_secs).unwrap_or(0).min(max);
    state.suppressed_until_secs = now_secs.saturating_add(next.max(hinted));
}

/// Когда перепроверить состояние, пережившее рестарт.
///
/// Таймеры живут только в памяти, и без этого накопленное до рестарта
/// ждало бы следующего сообщения тому же устройству — то есть, возможно,
/// никогда. `None` — будить по времени нечего: накопленного нет, либо его
/// приоритет не будит по времени и backoff не активен (такое окно закроет
/// только новое сообщение).
pub fn resume_deadline(state: &PushState, cfg: &DecisionConfig) -> Option<u64> {
    if state.pending_since_last_push == 0 {
        return None;
    }
    match cfg.min_gap_for(state.highest_priority()) {
        Some(gap) => Some(
            state
                .last_push_at_secs
                .saturating_add(ceil_secs(gap))
                .max(state.suppressed_until_secs),
        ),
        // Порог burst мог быть достигнут ещё до рестарта, а отправку
        // отложил backoff: по его истечении `decide` её и выполнит.
        None if state.suppressed_until_secs > 0 => Some(state.suppressed_until_secs),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DecisionConfig {
        DecisionConfig {
            wake_on_unspecified: true,
            min_gap_high: Duration::from_secs(0),
            min_gap_medium: Duration::from_secs(10),
            min_gap_low: Duration::from_secs(60),
            min_gap_none: Duration::from_secs(120),
            burst_high: 1,
            burst_medium: 3,
            burst_low: 8,
            burst_none: 15,
            suppress_initial: Duration::from_secs(30),
            suppress_max: Duration::from_secs(3600),
        }
    }

    #[test]
    fn first_high_priority_message_sends_immediately() {
        let s = PushState::default();
        let d = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::High)),
            100,
            &cfg(),
        );

        assert!(matches!(
            d.action,
            DecisionAction::SendNow {
                pending: 1,
                max_priority: Some(MessagePriority::High)
            }
        ));
        assert_eq!(d.state.last_push_at_secs, 100);
        assert_eq!(d.state.pending_since_last_push, 0);
        assert_eq!(d.state.highest_pending_priority, 0);
    }

    #[test]
    fn medium_priority_within_gap_is_coalesced() {
        let s = PushState {
            last_push_at_secs: 100,
            pending_since_last_push: 0,
            highest_pending_priority: 0,
            ..Default::default()
        };

        // A medium message lands 5s after a prior send — within the 10s gap.
        let d = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::Medium)),
            105,
            &cfg(),
        );

        assert_eq!(d.action, DecisionAction::WaitUntil(110));
        assert_eq!(d.state.pending_since_last_push, 1);
        assert_eq!(
            d.state.highest_pending_priority,
            MessagePriority::as_storage_byte(Some(MessagePriority::Medium))
        );
    }

    #[test]
    fn burst_threshold_overrides_gap() {
        // Medium burst threshold is 3 — three messages back-to-back should send
        // even within the 10s gap window.
        let mut s = PushState {
            last_push_at_secs: 100,
            ..Default::default()
        };

        // First two coalesce.
        let d1 = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::Medium)),
            101,
            &cfg(),
        );
        assert!(matches!(d1.action, DecisionAction::WaitUntil(_)));
        s = d1.state;

        let d2 = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::Medium)),
            102,
            &cfg(),
        );
        assert!(matches!(d2.action, DecisionAction::WaitUntil(_)));
        s = d2.state;

        // Third hits burst_medium=3 → SendNow despite being within gap.
        let d3 = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::Medium)),
            103,
            &cfg(),
        );
        assert!(matches!(
            d3.action,
            DecisionAction::SendNow {
                pending: 3,
                max_priority: Some(MessagePriority::Medium)
            }
        ));
    }

    #[test]
    fn highest_priority_dominates_window() {
        let s = PushState {
            last_push_at_secs: 100,
            ..Default::default()
        };

        // Low message at t=110 (within low's 60s gap) → coalesce, max=Low.
        let d1 = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::Low)),
            110,
            &cfg(),
        );
        let s = d1.state;
        assert!(matches!(d1.action, DecisionAction::WaitUntil(_)));

        // High message arrives next — high's gap is 0s and burst is 1 → SendNow.
        // max_priority must come out as High, not the prior Low.
        let d2 = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::High)),
            111,
            &cfg(),
        );
        assert!(matches!(
            d2.action,
            DecisionAction::SendNow {
                pending: 2,
                max_priority: Some(MessagePriority::High)
            }
        ));
    }

    #[test]
    fn suppression_blocks_send_until_window_expires() {
        let s = PushState {
            last_push_at_secs: 100,
            pending_since_last_push: 0,
            suppressed_until_secs: 200,
            ..Default::default()
        };

        let d = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::High)),
            150,
            &cfg(),
        );
        assert_eq!(d.action, DecisionAction::WaitUntil(200));
        assert_eq!(d.state.pending_since_last_push, 1);
    }

    #[test]
    fn timer_tick_after_gap_drains_pending() {
        let s = PushState {
            last_push_at_secs: 100,
            pending_since_last_push: 2,
            highest_pending_priority: MessagePriority::as_storage_byte(Some(
                MessagePriority::Medium,
            )),
            ..Default::default()
        };

        // Gap for Medium = 10s. Timer fires at t=111 → SendNow.
        let d = decide(s, DecisionInput::TimerTick, 111, &cfg());
        assert!(matches!(
            d.action,
            DecisionAction::SendNow {
                pending: 2,
                max_priority: Some(MessagePriority::Medium)
            }
        ));
    }

    #[test]
    fn timer_tick_with_empty_queue_is_idle() {
        let s = PushState {
            last_push_at_secs: 100,
            pending_since_last_push: 0,
            ..Default::default()
        };
        let d = decide(s, DecisionInput::TimerTick, 1000, &cfg());
        assert_eq!(d.action, DecisionAction::Idle);
    }

    #[test]
    fn no_priority_messages_use_none_thresholds() {
        let s = PushState::default();

        // First-ever None message: last_push_at_secs == 0 → send immediately.
        let d = decide(s, DecisionInput::NewMessage(None), 50, &cfg());
        assert!(matches!(
            d.action,
            DecisionAction::SendNow {
                pending: 1,
                max_priority: None
            }
        ));

        let s = d.state;
        // Next None message 10s later — None gap is 120s → coalesce until t = 50+120 = 170.
        let d2 = decide(s, DecisionInput::NewMessage(None), 60, &cfg());
        assert_eq!(d2.action, DecisionAction::WaitUntil(170));
    }

    /// `wake_on_unspecified = false`: время сообщения без приоритета не
    /// будит — интервал для них не истекает никогда. Не «ждёт дольше»:
    /// таймер вообще не ставится, ждать нечего.
    #[test]
    fn unspecified_priority_is_not_woken_by_time() {
        let mut c = cfg();
        c.wake_on_unspecified = false;
        c.burst_none = 100;

        let mut state = PushState::default();
        for tick in 0..5u64 {
            let d = decide(state, DecisionInput::NewMessage(None), 1000 + tick, &c);
            assert_eq!(
                d.action,
                DecisionAction::Idle,
                "сообщение без приоритета не должно будить по времени"
            );
            state = d.state;
        }

        // Даже спустя сутки: интервала, который бы истёк, у этого приоритета нет.
        assert_eq!(
            decide(state, DecisionInput::TimerTick, 1000 + 86_400, &c).action,
            DecisionAction::Idle
        );
        // Накопленное не потеряно.
        assert_eq!(state.pending_since_last_push, 5);
    }

    /// …но накопление всё же будит: `burst_none` остаётся предохранителем,
    /// иначе беззвучная переписка не дошла бы до устройства вовсе.
    #[test]
    fn unspecified_priority_still_wakes_on_burst() {
        let mut c = cfg();
        c.wake_on_unspecified = false;
        c.burst_none = 3;

        let mut state = PushState::default();
        for tick in 0..2u64 {
            state = decide(state, DecisionInput::NewMessage(None), 1000 + tick, &c).state;
        }

        let d = decide(state, DecisionInput::NewMessage(None), 1002, &c);
        assert_eq!(
            d.action,
            DecisionAction::SendNow {
                pending: 3,
                max_priority: None,
            }
        );
    }

    /// Накопленные «беззвучные» сообщения уходят вместе с первым же
    /// приоритетным: окно одно, и счётчик в нём общий.
    #[test]
    fn pending_unspecified_ride_along_with_the_first_prioritised_message() {
        let mut c = cfg();
        c.wake_on_unspecified = false;

        let mut state = PushState::default();
        for tick in 0..3u64 {
            state = decide(state, DecisionInput::NewMessage(None), 1000 + tick, &c).state;
        }

        let d = decide(
            state,
            DecisionInput::NewMessage(Some(MessagePriority::Medium)),
            1010,
            &c,
        );

        assert_eq!(
            d.action,
            DecisionAction::SendNow {
                pending: 4,
                max_priority: Some(MessagePriority::Medium),
            }
        );
    }

    /// Выключенный будильник для `None` не трогает остальные приоритеты.
    #[test]
    fn disabling_unspecified_leaves_other_priorities_alone() {
        let mut c = cfg();
        c.wake_on_unspecified = false;

        let d = decide(
            PushState::default(),
            DecisionInput::NewMessage(Some(MessagePriority::High)),
            1000,
            &c,
        );

        assert_eq!(
            d.action,
            DecisionAction::SendNow {
                pending: 1,
                max_priority: Some(MessagePriority::High),
            }
        );
    }

    #[test]
    fn on_send_backoff_doubles_until_capped() {
        let mut s = PushState::default();
        let c = cfg();

        on_send_backoff(&mut s, 100, &c, None);
        assert_eq!(s.current_backoff_secs, 30);
        assert_eq!(s.suppressed_until_secs, 130);

        on_send_backoff(&mut s, 200, &c, None);
        assert_eq!(s.current_backoff_secs, 60);
        assert_eq!(s.suppressed_until_secs, 260);

        // Walk it up to the cap.
        for _ in 0..20 {
            on_send_backoff(&mut s, 1000, &c, None);
        }
        assert_eq!(s.current_backoff_secs, 3600);
    }

    /// `Retry-After` провайдера удлиняет текущее окно, но не разгоняет
    /// экспоненту: следующий шаг считается от собственного шага.
    #[test]
    fn retry_after_extends_only_the_current_window() {
        let mut s = PushState::default();
        let c = cfg();

        on_send_backoff(&mut s, 100, &c, Some(Duration::from_secs(300)));
        assert_eq!(s.suppressed_until_secs, 400);
        assert_eq!(s.current_backoff_secs, 30);

        // Подсказка короче собственного шага ничего не сокращает.
        on_send_backoff(&mut s, 1000, &c, Some(Duration::from_secs(5)));
        assert_eq!(s.suppressed_until_secs, 1060);
        assert_eq!(s.current_backoff_secs, 60);
    }

    /// Абсурдный `Retry-After` не глушит устройство дольше `suppress_max`.
    #[test]
    fn retry_after_is_capped_by_suppress_max() {
        let mut s = PushState::default();
        let c = cfg();

        on_send_backoff(&mut s, 100, &c, Some(Duration::from_secs(86_400 * 30)));
        assert_eq!(s.suppressed_until_secs, 100 + 3600);
    }

    /// Миллисекундный backoff не укорачивается округлением вниз.
    #[test]
    fn sub_second_backoff_rounds_up() {
        let mut s = PushState::default();
        let mut c = cfg();
        c.suppress_initial = Duration::from_millis(1500);
        c.suppress_max = Duration::from_millis(1500);

        on_send_backoff(&mut s, 100, &c, None);
        assert_eq!(s.current_backoff_secs, 2);
        assert_eq!(s.suppressed_until_secs, 102);
    }

    #[test]
    fn on_send_success_clears_backoff() {
        let mut s = PushState {
            suppressed_until_secs: 999,
            current_backoff_secs: 240,
            ..Default::default()
        };
        on_send_success(&mut s);
        assert_eq!(s.suppressed_until_secs, 0);
        assert_eq!(s.current_backoff_secs, 0);
    }

    #[test]
    fn ceil_secs_rounds_partial_seconds_up() {
        assert_eq!(ceil_secs(Duration::ZERO), 0);
        assert_eq!(ceil_secs(Duration::from_millis(1)), 1);
        assert_eq!(ceil_secs(Duration::from_millis(500)), 1);
        assert_eq!(ceil_secs(Duration::from_millis(1000)), 1);
        assert_eq!(ceil_secs(Duration::from_millis(1001)), 2);
        assert_eq!(ceil_secs(Duration::from_secs(10)), 10);
    }

    /// Интервал меньше секунды раньше округлялся до нуля через `as_secs()`
    /// и молча отключал коалесинг: второе Medium-сообщение в ту же секунду
    /// уходило отдельным пушем. Теперь оно ждёт ближайшей целой секунды.
    #[test]
    fn sub_second_gap_still_coalesces() {
        let mut c = cfg();
        c.min_gap_medium = Duration::from_millis(500);
        c.burst_medium = 100;

        let s = PushState {
            last_push_at_secs: 100,
            ..Default::default()
        };
        let d = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::Medium)),
            100,
            &c,
        );
        assert_eq!(d.action, DecisionAction::WaitUntil(101));

        let d = decide(d.state, DecisionInput::TimerTick, 101, &c);
        assert_eq!(
            d.action,
            DecisionAction::SendNow {
                pending: 1,
                max_priority: Some(MessagePriority::Medium),
            }
        );
    }

    /// Нулевой интервал по-прежнему значит «сразу».
    #[test]
    fn zero_gap_still_sends_immediately() {
        let s = PushState {
            last_push_at_secs: 100,
            ..Default::default()
        };
        let d = decide(
            s,
            DecisionInput::NewMessage(Some(MessagePriority::High)),
            100,
            &cfg(),
        );
        assert!(matches!(d.action, DecisionAction::SendNow { .. }));
    }

    #[test]
    fn longest_gap_ignores_priorities_that_never_wake_by_time() {
        let mut c = cfg();
        assert_eq!(c.longest_gap_secs(), 120);

        c.wake_on_unspecified = false;
        assert_eq!(c.longest_gap_secs(), 60);

        c.min_gap_low = Duration::from_millis(60_001);
        assert_eq!(c.longest_gap_secs(), 61);
    }

    #[test]
    fn idle_state_is_one_that_no_longer_affects_decisions() {
        let longest = cfg().longest_gap_secs();
        let now = 10_000;

        assert!(PushState::default().is_idle(now, longest));

        let recent_push = PushState {
            last_push_at_secs: now - 10,
            ..Default::default()
        };
        assert!(
            !recent_push.is_idle(now, longest),
            "свежая отметка пуша ещё держит окно коалесинга"
        );

        let old_push = PushState {
            last_push_at_secs: now - longest,
            current_backoff_secs: 60,
            ..Default::default()
        };
        assert!(old_push.is_idle(now, longest));

        let pending = PushState {
            pending_since_last_push: 1,
            ..Default::default()
        };
        assert!(!pending.is_idle(now, longest));

        let suppressed = PushState {
            suppressed_until_secs: now + 1,
            ..Default::default()
        };
        assert!(!suppressed.is_idle(now, longest));
    }

    /// Удалённое «пустое» состояние решает так же, как хранившееся: иначе
    /// вычистка меняла бы поведение коалесинга.
    #[test]
    fn idle_state_decides_like_default() {
        let c = cfg();
        let now = 10_000;
        let idle = PushState {
            last_push_at_secs: now - c.longest_gap_secs(),
            ..Default::default()
        };
        assert!(idle.is_idle(now, c.longest_gap_secs()));

        for priority in [
            Some(MessagePriority::High),
            Some(MessagePriority::Medium),
            Some(MessagePriority::Low),
            None,
        ] {
            let input = DecisionInput::NewMessage(priority);
            assert_eq!(
                decide(idle, input, now, &c).action,
                decide(PushState::default(), input, now, &c).action,
                "priority {priority:?}"
            );
        }
    }

    #[test]
    fn resume_deadline_waits_for_both_gap_and_backoff() {
        let c = cfg();
        let medium = MessagePriority::as_storage_byte(Some(MessagePriority::Medium));

        assert_eq!(resume_deadline(&PushState::default(), &c), None);

        let coalescing = PushState {
            last_push_at_secs: 100,
            pending_since_last_push: 2,
            highest_pending_priority: medium,
            ..Default::default()
        };
        assert_eq!(resume_deadline(&coalescing, &c), Some(110));

        let suppressed = PushState {
            suppressed_until_secs: 500,
            ..coalescing
        };
        assert_eq!(resume_deadline(&suppressed, &c), Some(500));
    }

    #[test]
    fn resume_deadline_for_priorities_that_never_wake_by_time() {
        let mut c = cfg();
        c.wake_on_unspecified = false;

        let silent = PushState {
            last_push_at_secs: 100,
            pending_since_last_push: 3,
            ..Default::default()
        };
        assert_eq!(resume_deadline(&silent, &c), None);

        // Отправку по порогу отложил backoff — проверить по его истечении.
        let deferred_burst = PushState {
            suppressed_until_secs: 700,
            ..silent
        };
        assert_eq!(resume_deadline(&deferred_burst, &c), Some(700));
    }
}
