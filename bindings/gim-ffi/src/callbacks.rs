//! Foreign callbacks: the thread they run on and the per-client gate.
//!
//! Every call into a platform implementation (`PlatformHooks`,
//! `LocalTimeZone`, listeners), and the final release of the platform
//! object, runs on one process-wide, long-lived thread ([`run`]); the
//! calling Rust thread blocks until it returned. Callers may be anywhere:
//! a tokio worker, a blocking-pool thread, or a thread that is itself inside
//! a UniFFI future poll driven from a foreign continuation callback. On
//! Android a foreign call nested in such a frame makes JNA detach the thread
//! from the JVM on return while Java frames are still on it, and ART aborts
//! ("attempting to detach while still running code"). On the callback
//! thread nothing else is on the stack.
//!
//! Every client additionally routes its callbacks through a gate
//! ([`Callbacks::call`]). Teardown (`sign_out`, client drop) closes the gate,
//! aborts the listener tasks and waits, bounded, for the calls in flight:
//! once it returns no further callback starts.

use std::any::Any;
use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use tokio::task::AbortHandle;

/// Name of the thread every foreign callback runs on.
pub(crate) const CALLBACK_THREAD_NAME: &str = "gim-callbacks";

type Job = Box<dyn FnOnce() + Send>;

thread_local! {
    static ON_CALLBACK_THREAD: Cell<bool> = const { Cell::new(false) };
}

fn callback_thread() -> &'static Mutex<Sender<Job>> {
    static SENDER: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
    SENDER.get_or_init(|| {
        let (sender, jobs) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name(CALLBACK_THREAD_NAME.to_string())
            .spawn(move || {
                ON_CALLBACK_THREAD.with(|on| on.set(true));
                for job in jobs {
                    job();
                }
            })
            .expect("cannot start the callback thread");
        Mutex::new(sender)
    })
}

fn submit(job: Job) {
    callback_thread()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send(job)
        .expect("callback thread gone");
}

/// Whether the current thread is the callback thread.
pub(crate) fn on_callback_thread() -> bool {
    ON_CALLBACK_THREAD.with(Cell::get)
}

/// Runs `f` on the callback thread and returns its result; a panic in `f`
/// resumes on the caller. Inline when already on the callback thread (a
/// platform implementation calling back into gim-core).
pub(crate) fn run<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    if on_callback_thread() {
        return f();
    }
    let (sender, result) = mpsc::sync_channel::<Result<R, Box<dyn Any + Send>>>(1);
    submit(Box::new(move || {
        // The caller waits for the result; a send fails only if it unwound.
        let _ = sender.send(panic::catch_unwind(AssertUnwindSafe(f)));
    }));
    match result.recv().expect("callback thread gone") {
        Ok(value) => value,
        Err(payload) => panic::resume_unwind(payload),
    }
}

/// A platform object (UniFFI foreign trait object): called, and finally
/// released, on the callback thread only.
pub(crate) struct Foreign<T: ?Sized + Send + Sync + 'static>(Option<Arc<T>>);

impl<T: ?Sized + Send + Sync + 'static> Foreign<T> {
    pub(crate) fn new(inner: Arc<T>) -> Self {
        Self(Some(inner))
    }

    /// Runs `f` with the object on the callback thread.
    pub(crate) fn call<R: Send + 'static>(&self, f: impl FnOnce(&T) -> R + Send + 'static) -> R {
        let inner = self.0.clone().expect("present until dropped");
        run(move || f(&*inner))
    }
}

impl<T: ?Sized + Send + Sync + 'static> Drop for Foreign<T> {
    fn drop(&mut self) {
        let Some(inner) = self.0.take() else { return };
        if on_callback_thread() {
            drop(inner);
        } else {
            // Not awaited: releasing only drops gim-core's reference.
            submit(Box::new(move || drop(inner)));
        }
    }
}

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

    use super::*;

    #[test]
    fn runs_on_the_callback_thread() {
        let name = || std::thread::current().name().map(str::to_string);
        assert_eq!(run(name).as_deref(), Some(CALLBACK_THREAD_NAME));
        // Nested calls run inline instead of waiting for themselves.
        assert_eq!(
            run(move || run(name)).as_deref(),
            Some(CALLBACK_THREAD_NAME)
        );
        let panicked = panic::catch_unwind(|| run(|| panic!("hook failed")));
        assert!(panicked.is_err());
        assert_eq!(run(|| 7), 7);
    }

    #[test]
    fn foreign_objects_are_released_on_the_callback_thread() {
        struct Probe(Sender<Option<String>>);
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = self
                    .0
                    .send(std::thread::current().name().map(str::to_string));
            }
        }
        let (sender, released) = mpsc::channel();
        let foreign = Foreign::new(Arc::new(Probe(sender)));
        foreign.call(|_| ());
        drop(foreign);
        let thread = released.recv_timeout(DRAIN_TIMEOUT).unwrap();
        assert_eq!(thread.as_deref(), Some(CALLBACK_THREAD_NAME));
    }

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
