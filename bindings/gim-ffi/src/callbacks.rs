//! Gate for the foreign callbacks of one client.
//!
//! Every call into a platform implementation (listeners, `LocalTimeZone`,
//! keystore hooks from background work) goes through [`Callbacks::call`].
//! Teardown (`sign_out`, client drop) closes the gate, aborts the listener
//! tasks and waits, bounded, for the calls in flight: once it returns no
//! further callback starts, and none is left running on a thread gim-core
//! is about to release.

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::task::AbortHandle;

/// Upper bound teardown waits for callbacks in flight.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct Callbacks {
    state: Mutex<State>,
    idle: Condvar,
}

#[derive(Default)]
struct State {
    closed: bool,
    in_flight: usize,
    /// Listener tasks, aborted on close.
    tasks: Vec<AbortHandle>,
}

impl Callbacks {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` (a foreign call) unless the gate is closed.
    pub(crate) fn call<R>(&self, f: impl FnOnce() -> R) -> Option<R> {
        {
            let mut state = self.state();
            if state.closed {
                return None;
            }
            state.in_flight += 1;
        }
        // Leaves the call counted until it returns, also on unwind.
        struct InFlight<'a>(&'a Callbacks);
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                let mut state = self.0.state();
                state.in_flight -= 1;
                if state.in_flight == 0 {
                    self.0.idle.notify_all();
                }
            }
        }
        let _in_flight = InFlight(self);
        Some(f())
    }

    /// Aborts the listener task `task` on close (at once if already closed).
    pub(crate) fn track(&self, task: AbortHandle) {
        let mut state = self.state();
        if state.closed {
            task.abort();
            return;
        }
        state.tasks.retain(|t| !t.is_finished());
        state.tasks.push(task);
    }

    /// Lets no further callback start and aborts the listener tasks.
    pub(crate) fn close(&self) {
        let tasks = {
            let mut state = self.state();
            state.closed = true;
            std::mem::take(&mut state.tasks)
        };
        for task in tasks {
            task.abort();
        }
    }

    /// Blocks until no callback is in flight or `timeout` passed; returns
    /// whether none is. Never call it on a runtime thread: the callback it
    /// waits for may need that thread.
    pub(crate) fn drain(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        while state.in_flight > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self
                .idle
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;

    #[test]
    fn closed_gate_runs_nothing() {
        let callbacks = Callbacks::default();
        assert_eq!(callbacks.call(|| 1), Some(1));
        callbacks.close();
        assert_eq!(callbacks.call(|| 2), None);
        assert!(callbacks.drain(Duration::ZERO));
    }

    #[test]
    fn drain_waits_for_the_call_in_flight() {
        let callbacks = Arc::new(Callbacks::default());
        let done = Arc::new(AtomicBool::new(false));
        let (started_tx, started) = std::sync::mpsc::channel();
        let worker = std::thread::spawn({
            let callbacks = callbacks.clone();
            let done = done.clone();
            move || {
                callbacks.call(|| {
                    started_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(200));
                    done.store(true, Ordering::SeqCst);
                })
            }
        });
        started.recv().unwrap();
        callbacks.close();
        assert!(!callbacks.drain(Duration::from_millis(10)));
        assert!(callbacks.drain(DRAIN_TIMEOUT));
        assert!(done.load(Ordering::SeqCst));
        worker.join().unwrap();
    }
}
