//! Ids, shared error helpers and time helpers used by every gim crate.
//! No I/O, no async runtime.

#![forbid(unsafe_code)]

mod error;
mod ids;
mod time;

pub use error::GimCommonError;
pub use ids::{ClientId, DeviceId, DeviceRef, GroupId, MessageId, UserId, MAX_ID_LEN};
pub use time::now_ms;
