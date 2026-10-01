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
            state.last_push_at_secs == 0 || elapsed >= min_gap.as_secs()
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
                    state.last_push_at_secs.saturating_add(min_gap.as_secs()),
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
pub fn on_send_backoff(state: &mut PushState, now_secs: u64, cfg: &DecisionConfig) {
    let initial = cfg.suppress_initial.as_secs().max(1);
    let max = cfg.suppress_max.as_secs().max(initial);
    let next = if state.current_backoff_secs == 0 {
        initial
    } else {
        state.current_backoff_secs.saturating_mul(2).min(max)
    };
    state.current_backoff_secs = next;
    state.suppressed_until_secs = now_secs.saturating_add(next);
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

        on_send_backoff(&mut s, 100, &c);
        assert_eq!(s.current_backoff_secs, 30);
        assert_eq!(s.suppressed_until_secs, 130);

        on_send_backoff(&mut s, 200, &c);
        assert_eq!(s.current_backoff_secs, 60);
        assert_eq!(s.suppressed_until_secs, 260);

        // Walk it up to the cap.
        for _ in 0..20 {
            on_send_backoff(&mut s, 1000, &c);
        }
        assert_eq!(s.current_backoff_secs, 3600);
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
}
