use std::sync::Arc;

use futures_util::StreamExt;

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
    inner: Arc<gim_ui::Timeline>,
}

impl Timeline {
    pub(crate) fn new(inner: gim_ui::Timeline) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Timeline {
    pub fn chat_id(&self) -> String {
        self.inner.group_id().to_string()
    }

    /// Subscribes to timeline changes. The first callback is a `Reset` with
    /// the currently loaded items.
    pub async fn add_listener(&self, listener: Arc<dyn TimelineListener>) -> Arc<TaskHandle> {
        let inner = self.inner.clone();
        let (values, stream) = inner.items();
        Arc::new(TaskHandle::spawn(async move {
            // Keeps the timeline following the client.
            let _inner = inner;
            listener.on_update(vec![TimelineDiff::Reset {
                values: values.into_iter().map(Into::into).collect(),
            }]);
            let mut stream = std::pin::pin!(stream);
            while let Some(diffs) = stream.next().await {
                listener.on_update(diffs.into_iter().map(Into::into).collect());
            }
        }))
    }

    /// Loads up to `count` older items into the timeline (delivered through
    /// the listeners). Returns whether more history exists.
    pub async fn paginate_backwards(&self, count: u16) -> Result<bool, GimError> {
        Ok(self.inner.paginate_backwards(count).await?)
    }
}
