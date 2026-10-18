//! CBOR `data` blobs: serde mirrors of the gim-base model fields that are
//! not stored as columns. New fields must be `#[serde(default)]` so older
//! rows still decode.

use std::collections::{BTreeMap, BTreeSet};

use gim_base::model::{
    ChatKind, ChatMember, Membership, MessageContent, MessageKind, OutboxKind, PendingCommit,
    PendingLeave, PendingMedia, PendingWelcome, PreparedPayload, SendFailure, SendState,
};
use gim_base::StoreError;
use gim_common::{ClientId, DeviceRef, GroupId, MessageId, UserId};
use gim_proto::envelope::{self, MediaInfo, ReceiptKind, MEDIA_KEY_LEN};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(StoreError::new)?;
    Ok(out)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    ciborium::from_reader(bytes).map_err(StoreError::new)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ChatData {
    pub kind: ChatKindRow,
    pub name: Option<String>,
    pub avatar: Option<MediaRow>,
    pub members: Vec<MemberRow>,
    pub unread_count: u32,
    pub last_message_id: Option<MessageId>,
    pub last_seq: u64,
    pub last_read_seq: u64,
    pub membership: MembershipRow,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MemberRow {
    pub device: DeviceRef,
    pub display_name: Option<String>,
}

impl From<&ChatMember> for MemberRow {
    fn from(m: &ChatMember) -> Self {
        Self {
            device: m.device.clone(),
            display_name: m.display_name.clone(),
        }
    }
}

impl From<MemberRow> for ChatMember {
    fn from(m: MemberRow) -> Self {
        Self {
            device: m.device,
            display_name: m.display_name,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChatKindRow {
    Direct,
    Group,
}

impl From<ChatKind> for ChatKindRow {
    fn from(kind: ChatKind) -> Self {
        match kind {
            ChatKind::Direct => Self::Direct,
            ChatKind::Group => Self::Group,
        }
    }
}

impl From<ChatKindRow> for ChatKind {
    fn from(kind: ChatKindRow) -> Self {
        match kind {
            ChatKindRow::Direct => Self::Direct,
            ChatKindRow::Group => Self::Group,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MembershipRow {
    Joined,
    Leaving,
    Left,
}

impl From<Membership> for MembershipRow {
    fn from(membership: Membership) -> Self {
        match membership {
            Membership::Joined => Self::Joined,
            Membership::Leaving => Self::Leaving,
            Membership::Left => Self::Left,
        }
    }
}

impl From<MembershipRow> for Membership {
    fn from(membership: MembershipRow) -> Self {
        match membership {
            MembershipRow::Joined => Self::Joined,
            MembershipRow::Leaving => Self::Leaving,
            MembershipRow::Left => Self::Left,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MediaRow {
    pub blob_id: String,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
    pub mime: String,
    pub size: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub file_name: Option<String>,
    pub thumbnail: Option<serde_bytes::ByteBuf>,
}

impl From<&MediaInfo> for MediaRow {
    fn from(m: &MediaInfo) -> Self {
        Self {
            blob_id: m.blob_id.clone(),
            key: m.key.to_vec(),
            sha256: m.sha256.to_vec(),
            mime: m.mime.clone(),
            size: m.size,
            width: m.width,
            height: m.height,
            file_name: m.file_name.clone(),
            thumbnail: m.thumbnail.clone().map(serde_bytes::ByteBuf::from),
        }
    }
}

impl TryFrom<MediaRow> for MediaInfo {
    type Error = StoreError;

    fn try_from(m: MediaRow) -> Result<Self, StoreError> {
        let fixed = |bytes: Vec<u8>| {
            <[u8; MEDIA_KEY_LEN]>::try_from(bytes)
                .map_err(|_| StoreError::new("stored media key or digest has a wrong length"))
        };
        Ok(Self {
            blob_id: m.blob_id,
            key: fixed(m.key)?,
            sha256: fixed(m.sha256)?,
            mime: m.mime,
            size: m.size,
            width: m.width,
            height: m.height,
            file_name: m.file_name,
            thumbnail: m.thumbnail.map(serde_bytes::ByteBuf::into_vec),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MessageData {
    pub sender: DeviceRef,
    pub content: ContentRow,
    pub reply_to: Option<MessageId>,
    pub edited: bool,
    pub deleted: bool,
    pub reactions: BTreeMap<UserId, BTreeSet<String>>,
    pub send_state: Option<SendStateRow>,
    pub receipts: Vec<(DeviceRef, ReceiptKind)>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContentRow {
    Text {
        body: String,
    },
    Media {
        media: MediaRow,
        caption: Option<String>,
    },
    PendingMedia(PendingMediaRow),
}

impl From<&MessageContent> for ContentRow {
    fn from(content: &MessageContent) -> Self {
        match content {
            MessageContent::Text { body } => Self::Text { body: body.clone() },
            MessageContent::Media { media, caption } => Self::Media {
                media: media.into(),
                caption: caption.clone(),
            },
            MessageContent::PendingMedia(pending) => Self::PendingMedia(pending.into()),
        }
    }
}

impl TryFrom<ContentRow> for MessageContent {
    type Error = StoreError;

    fn try_from(content: ContentRow) -> Result<Self, StoreError> {
        Ok(match content {
            ContentRow::Text { body } => Self::Text { body },
            ContentRow::Media { media, caption } => Self::Media {
                media: media.try_into()?,
                caption,
            },
            ContentRow::PendingMedia(pending) => Self::PendingMedia(pending.into()),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingMediaRow {
    pub local_path: String,
    pub mime: String,
    pub caption: Option<String>,
}

impl From<&PendingMedia> for PendingMediaRow {
    fn from(p: &PendingMedia) -> Self {
        Self {
            local_path: p.local_path.clone(),
            mime: p.mime.clone(),
            caption: p.caption.clone(),
        }
    }
}

impl From<PendingMediaRow> for PendingMedia {
    fn from(p: PendingMediaRow) -> Self {
        Self {
            local_path: p.local_path,
            mime: p.mime,
            caption: p.caption,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SendStateRow {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed,
}

impl From<SendState> for SendStateRow {
    fn from(state: SendState) -> Self {
        match state {
            SendState::Pending => Self::Pending,
            SendState::Sent => Self::Sent,
            SendState::Delivered => Self::Delivered,
            SendState::Read => Self::Read,
            SendState::Failed => Self::Failed,
        }
    }
}

impl From<SendStateRow> for SendState {
    fn from(state: SendStateRow) -> Self {
        match state {
            SendStateRow::Pending => Self::Pending,
            SendStateRow::Sent => Self::Sent,
            SendStateRow::Delivered => Self::Delivered,
            SendStateRow::Read => Self::Read,
            SendStateRow::Failed => Self::Failed,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct OutboxData {
    pub kind: OutboxKindRow,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub prepared: Option<PreparedRow>,
    /// Absent from rows written before the cause was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<SendFailureRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SendFailureRow {
    UserSuspended,
    UserNotAdmitted,
    NotAdmittedByPeer,
    Rejected,
    Other,
}

impl From<SendFailure> for SendFailureRow {
    fn from(failure: SendFailure) -> Self {
        match failure {
            SendFailure::UserSuspended => Self::UserSuspended,
            SendFailure::UserNotAdmitted => Self::UserNotAdmitted,
            SendFailure::NotAdmittedByPeer => Self::NotAdmittedByPeer,
            SendFailure::Rejected => Self::Rejected,
            SendFailure::Other => Self::Other,
        }
    }
}

impl From<SendFailureRow> for SendFailure {
    fn from(failure: SendFailureRow) -> Self {
        match failure {
            SendFailureRow::UserSuspended => Self::UserSuspended,
            SendFailureRow::UserNotAdmitted => Self::UserNotAdmitted,
            SendFailureRow::NotAdmittedByPeer => Self::NotAdmittedByPeer,
            SendFailureRow::Rejected => Self::Rejected,
            SendFailureRow::Other => Self::Other,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutboxKindRow {
    /// gim-proto CBOR envelope encoding.
    Envelope(serde_bytes::ByteBuf),
    MediaUpload(PendingMediaRow),
}

impl TryFrom<&OutboxKind> for OutboxKindRow {
    type Error = StoreError;

    fn try_from(kind: &OutboxKind) -> Result<Self, StoreError> {
        Ok(match kind {
            OutboxKind::Envelope(env) => Self::Envelope(serde_bytes::ByteBuf::from(
                envelope::encode(env).map_err(StoreError::new)?,
            )),
            OutboxKind::MediaUpload(pending) => Self::MediaUpload(pending.into()),
        })
    }
}

impl TryFrom<OutboxKindRow> for OutboxKind {
    type Error = StoreError;

    fn try_from(kind: OutboxKindRow) -> Result<Self, StoreError> {
        Ok(match kind {
            OutboxKindRow::Envelope(bytes) => {
                Self::Envelope(envelope::decode(&bytes).map_err(StoreError::new)?)
            }
            OutboxKindRow::MediaUpload(pending) => Self::MediaUpload(pending.into()),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PreparedRow {
    pub epoch: u64,
    pub payload: serde_bytes::ByteBuf,
}

impl From<&PreparedPayload> for PreparedRow {
    fn from(p: &PreparedPayload) -> Self {
        Self {
            epoch: p.epoch,
            payload: serde_bytes::ByteBuf::from(p.payload.clone()),
        }
    }
}

impl From<PreparedRow> for PreparedPayload {
    fn from(p: PreparedRow) -> Self {
        Self {
            epoch: p.epoch,
            payload: p.payload.into_vec(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ParkedData {
    pub sender: DeviceRef,
    pub kind: MessageKindRow,
    pub payload: serde_bytes::ByteBuf,
    pub client_id: Option<ClientId>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MessageKindRow {
    Commit,
    Welcome,
    Application,
}

impl From<MessageKind> for MessageKindRow {
    fn from(kind: MessageKind) -> Self {
        match kind {
            MessageKind::Commit => Self::Commit,
            MessageKind::Welcome => Self::Welcome,
            MessageKind::Application => Self::Application,
        }
    }
}

impl From<MessageKindRow> for MessageKind {
    fn from(kind: MessageKindRow) -> Self {
        match kind {
            MessageKindRow::Commit => Self::Commit,
            MessageKindRow::Welcome => Self::Welcome,
            MessageKindRow::Application => Self::Application,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingCommitData {
    pub client_id: ClientId,
    pub epoch: u64,
    pub payload: serde_bytes::ByteBuf,
    pub welcome: Option<PendingWelcomeRow>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingWelcomeRow {
    pub payload: serde_bytes::ByteBuf,
    pub recipients: Vec<DeviceRef>,
}

impl From<&PendingCommit> for PendingCommitData {
    fn from(p: &PendingCommit) -> Self {
        Self {
            client_id: p.client_id.clone(),
            epoch: p.epoch,
            payload: serde_bytes::ByteBuf::from(p.payload.clone()),
            welcome: p.welcome.as_ref().map(|w| PendingWelcomeRow {
                payload: serde_bytes::ByteBuf::from(w.payload.clone()),
                recipients: w.recipients.clone(),
            }),
        }
    }
}

impl PendingCommitData {
    pub(crate) fn into_model(self, group_id: GroupId) -> PendingCommit {
        PendingCommit {
            group_id,
            client_id: self.client_id,
            epoch: self.epoch,
            payload: self.payload.into_vec(),
            welcome: self.welcome.map(|w| PendingWelcome {
                payload: w.payload.into_vec(),
                recipients: w.recipients,
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingLeaveData {
    pub client_id: ClientId,
    pub epoch: u64,
    pub payload: serde_bytes::ByteBuf,
    pub attempts: u32,
    pub accepted: bool,
}

impl From<&PendingLeave> for PendingLeaveData {
    fn from(p: &PendingLeave) -> Self {
        Self {
            client_id: p.client_id.clone(),
            epoch: p.epoch,
            payload: serde_bytes::ByteBuf::from(p.payload.clone()),
            attempts: p.attempts,
            accepted: p.accepted,
        }
    }
}

impl PendingLeaveData {
    pub(crate) fn into_model(self, group_id: GroupId) -> PendingLeave {
        PendingLeave {
            group_id,
            client_id: self.client_id,
            epoch: self.epoch,
            payload: self.payload.into_vec(),
            attempts: self.attempts,
            accepted: self.accepted,
        }
    }
}
