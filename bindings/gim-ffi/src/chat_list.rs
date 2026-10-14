use crate::ChatSummary;

/// Incremental change to the chat list, mirroring eyeball-im `VectorDiff`.
/// Apply the diffs of one `on_update` call in order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ChatListDiff {
    Append { values: Vec<ChatSummary> },
    Clear,
    PushFront { value: ChatSummary },
    PushBack { value: ChatSummary },
    PopFront,
    PopBack,
    Insert { index: u32, value: ChatSummary },
    Set { index: u32, value: ChatSummary },
    Remove { index: u32 },
    Truncate { length: u32 },
    Reset { values: Vec<ChatSummary> },
}

/// Receives chat list changes, most recently updated chat first. The first
/// callback is a `Reset` with the current list.
#[uniffi::export(with_foreign)]
pub trait ChatListListener: Send + Sync {
    fn on_update(&self, diffs: Vec<ChatListDiff>);
}
