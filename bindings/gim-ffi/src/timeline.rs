use std::sync::Arc;

use futures_util::StreamExt;

use crate::callbacks::{Callbacks, Foreign};
use crate::{ChatState, GimError, TaskHandle, TimelineItem};

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

/// Receives timeline changes, oldest item first. Called on gim-core's
/// callback thread.
#[uniffi::export(with_foreign)]
pub trait TimelineListener: Send + Sync {
    fn on_update(&self, diffs: Vec<TimelineDiff>);
}

/// The local time zone date separators split calendar days in. Implemented
/// in Kotlin/Swift and set with `GimClient::set_local_time_zone`. Called on
/// gim-core's callback thread; do not call back into gim-core from it.
#[uniffi::export(with_foreign)]
pub trait LocalTimeZone: Send + Sync {
    /// Offset from UTC in seconds in effect at `at_ms` (Unix milliseconds),
    /// DST included.
    fn utc_offset_secs(&self, at_ms: i64) -> i32;
}

/// gim-ui [`gim_ui::TimeZone`] over the platform time zone; UTC once the
/// client's callbacks are closed.
pub(crate) struct PlatformTimeZone {
    pub(crate) zone: Foreign<dyn LocalTimeZone>,
    pub(crate) callbacks: Arc<Callbacks>,
}

impl gim_ui::TimeZone for PlatformTimeZone {
    fn utc_offset_secs(&self, at_ms: i64) -> i32 {
        self.callbacks
            .call(|| self.zone.call(move |zone| zone.utc_offset_secs(at_ms)))
            .unwrap_or(0)
    }
}

/// The message timeline of one chat.
#[derive(uniffi::Object)]
pub struct Timeline {
    inner: Arc<gim_ui::Timeline>,
    callbacks: Arc<Callbacks>,
}

impl Timeline {
    pub(crate) fn new(inner: Arc<gim_ui::Timeline>, callbacks: Arc<Callbacks>) -> Self {
        Self { inner, callbacks }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Timeline {
    pub fn chat_id(&self) -> String {
        self.inner.group_id().to_string()
    }

    /// The chat's current state, from local state; `None` while the chat
    /// is not known locally.
    pub fn chat_state(&self) -> Option<ChatState> {
        self.inner.chat_state().map(Into::into)
    }

    /// Subscribes to timeline changes. The first callback is a `Reset` with
    /// the currently loaded items.
    pub async fn add_listener(&self, listener: Arc<dyn TimelineListener>) -> Arc<TaskHandle> {
        let listener = Foreign::new(listener);
        let inner = self.inner.clone();
        let (values, stream) = inner.items();
        let callbacks = self.callbacks.clone();
        Arc::new(TaskHandle::spawn(&self.callbacks, async move {
            // Keeps the timeline following the client.
            let _inner = inner;
            let reset = vec![TimelineDiff::Reset {
                values: values.into_iter().map(Into::into).collect(),
            }];
            if callbacks
                .call(|| listener.call(move |l| l.on_update(reset)))
                .is_none()
            {
                return;
            }
            let mut stream = std::pin::pin!(stream);
            while let Some(diffs) = stream.next().await {
                let diffs = diffs.into_iter().map(Into::into).collect();
                if callbacks
                    .call(|| listener.call(move |l| l.on_update(diffs)))
                    .is_none()
                {
                    return;
                }
            }
        }))
    }

    /// Loads up to `count` older items into the timeline (delivered through
    /// the listeners). Returns whether more history exists.
    pub async fn paginate_backwards(&self, count: u16) -> Result<bool, GimError> {
        Ok(self.inner.paginate_backwards(count).await?)
    }
}
