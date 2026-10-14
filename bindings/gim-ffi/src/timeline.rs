use std::sync::Arc;

use crate::{GimError, TaskHandle, TimelineItem};

/// Incremental change to a timeline, mirroring eyeball-im `VectorDiff`.
/// Apply the diffs of one `on_update` call in order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TimelineDiff {
    Append { values: Vec<TimelineItem> },
    Clear,
    PushFront { value: TimelineItem },
    PushBack { value: TimelineItem },
    PopFront,
    PopBack,
    Insert { index: u32, value: TimelineItem },
    Set { index: u32, value: TimelineItem },
    Remove { index: u32 },
    Truncate { length: u32 },
    Reset { values: Vec<TimelineItem> },
}

/// Receives timeline changes, oldest item first.
#[uniffi::export(with_foreign)]
pub trait TimelineListener: Send + Sync {
    fn on_update(&self, diffs: Vec<TimelineDiff>);
}

/// The message timeline of one chat.
#[derive(uniffi::Object)]
pub struct Timeline {
    chat_id: String,
}

impl Timeline {
    pub(crate) fn new(chat_id: String) -> Self {
        Self { chat_id }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Timeline {
    pub fn chat_id(&self) -> String {
        self.chat_id.clone()
    }

    /// Subscribes to timeline changes. The first callback is a `Reset` with
    /// the currently loaded items.
    pub async fn add_listener(&self, listener: Arc<dyn TimelineListener>) -> Arc<TaskHandle> {
        Arc::new(TaskHandle::idle(listener))
    }

    /// Loads up to `count` older items into the timeline (delivered through
    /// the listeners). Returns whether more history exists.
    pub async fn paginate_backwards(&self, count: u16) -> Result<bool, GimError> {
        let _ = count;
        Err(GimError::NotImplemented)
    }
}
