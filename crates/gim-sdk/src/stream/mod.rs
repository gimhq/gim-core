//! Connection plumbing of the sync loop: the [`ConnectionState`] it
//! reports, its reconnect [`Backoff`], and the `/v2/stream` WebSocket
//! client ([`ws`]).
//!
//! Reconnect structure follows matrix-rust-sdk's sliding sync loop
//! (Apache-2.0): one long-lived task, exponential backoff with jitter, and a
//! reset once a request succeeds. No code is copied.

pub(crate) mod ws;

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::Duration;

/// Connection of the sync loop to gim-hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Not syncing, or waiting to reconnect after a failure.
    Offline,
    /// (Re)connecting.
    Connecting,
    /// Connected and applying the backlog (after a reconnect or an expired
    /// cursor).
    Syncing,
    /// Caught up; new events arrive over the WebSocket stream or long-poll.
    Connected,
}

/// Exponential reconnect delays from `min` to `max`, each up to 25% shorter
/// at random so that clients do not reconnect in lockstep.
#[derive(Debug, Clone)]
pub(crate) struct Backoff {
    min: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub(crate) fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max: max.max(min),
            attempt: 0,
        }
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let base = self
            .min
            .saturating_mul(1 << self.attempt.min(16))
            .min(self.max);
        self.attempt = self.attempt.saturating_add(1);
        base.mul_f64(1.0 - 0.25 * random_unit())
    }

    pub(crate) fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// A random number in `[0, 1)`. Std's `RandomState` is randomly keyed per
/// instance, which is plenty for jitter.
fn random_unit() -> f64 {
    let bits = RandomState::new().build_hasher().finish();
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_max_with_jitter() {
        let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
        let mut backoff = Backoff::new(min, max);
        for base in [1, 2, 4, 8, 16, 32, 60, 60, 60] {
            let base = Duration::from_secs(base);
            let delay = backoff.next_delay();
            assert!(delay <= base && delay >= base.mul_f64(0.75), "{delay:?}");
        }
        backoff.reset();
        assert!(backoff.next_delay() <= min);
    }
}
