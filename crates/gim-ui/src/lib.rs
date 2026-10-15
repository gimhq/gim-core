//! Chat list service and per-chat timeline producing `VectorDiff` streams
//! (eyeball-im), typing aggregation.
//!
//! Every service subscribes to the [`gim_sdk::Client`] state changes, reads
//! the store for what it shows (local-first: the UI never waits on the
//! network) and keeps an `ObservableVector` whose batched diffs it hands out.
//!
//! The service-over-observable-vector shape follows matrix-rust-sdk's
//! `matrix-sdk-ui` room list service and timeline (Apache-2.0). No code is
//! copied.

#![forbid(unsafe_code)]

mod chat_list;
mod diff;
mod error;
mod items;
mod listener;
mod timeline;
mod typing;

pub use chat_list::ChatListService;
pub use error::{Result, UiError};
pub use eyeball_im::{Vector, VectorDiff};
pub use items::{
    ChatKind, ChatListItem, MediaRef, MembershipChangeKind, MessageContent, MessageItem,
    MessagePreview, ReactionGroup, ReplyPreview, SendState, TimelineItem, UserProfile,
};
pub use timeline::{Timeline, TimelineOptions, DEFAULT_PAGE_SIZE};
pub use typing::{TypingNotifications, TYPING_TIMEOUT};
