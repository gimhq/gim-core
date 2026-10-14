// Modelled on matrix-rust-sdk `bindings/matrix-sdk-ffi/src/task_handle.rs`
// (Apache-2.0).

use std::future::Future;
use std::sync::Arc;

use tokio::task::JoinHandle;

/// Keeps a listener subscription alive. Dropping or cancelling the handle
/// stops the subscription; native code must hold on to it.
#[derive(uniffi::Object)]
pub struct TaskHandle {
    handle: JoinHandle<()>,
}

impl TaskHandle {
    /// Spawns `future` on the current tokio runtime.
    pub(crate) fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            handle: tokio::spawn(future),
        }
    }

    /// A subscription that keeps `listener` alive until cancelled but never
    /// calls it. Used by API calls that are not wired to a backend yet.
    pub(crate) fn idle<T: Send + Sync + ?Sized + 'static>(listener: Arc<T>) -> Self {
        Self::spawn(async move {
            let _listener = listener;
            std::future::pending::<()>().await;
        })
    }
}

#[uniffi::export]
impl TaskHandle {
    /// Stops the subscription; no callback is delivered once the task has
    /// observed the cancellation. Calling it twice is harmless.
    pub fn cancel(&self) {
        self.handle.abort();
    }

    /// Whether the subscription has ended (cancelled or finished on its own).
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
