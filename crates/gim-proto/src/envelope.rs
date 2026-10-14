//! The message envelope carried inside MLS application messages.
//!
//! # Wire format (version 1)
//!
//! An envelope is one CBOR map with short text keys. Optional fields are
//! omitted when absent; decoders ignore keys they do not know, so later
//! minor additions stay readable by older clients. A breaking change bumps
//! the version, and decoders reject versions they do not understand.
//!
//! | Key | Type | Field |
//! |---|---|---|
//! | `v` | uint | version, `1` |
//! | `id` | text | message id |
//! | `ts` | uint | sent time, Unix milliseconds |
//! | `re` | text, optional | message id replied to (text and media only) |
//! | `c` | map | content |
//!
//! The content map is tagged by `t`:
//!
//! | `t` | Other keys |
//! |---|---|
//! | `"text"` | `b` body |
//! | `"media"` | `m` media map, `cap` caption (optional) |
//! | `"edit"` | `tg` target id, `b` new body |
//! | `"delete"` | `tg` target id |
//! | `"reaction"` | `tg` target id, `e` emoji, `rm` bool (true removes it) |
//! | `"receipt"` | `k` `"delivered"` or `"read"`, `ids` array of message ids |
//! | `"typing"` | `a` bool (active) |
//! | `"group_info"` | `n` name (optional), `av` media map (optional) |
//!
//! A media map has `id` blob id (text), `k` AES-256 key (32-byte bstr),
//! `d` SHA-256 of the encrypted blob (32-byte bstr), `mt` MIME type (text),
//! `sz` plaintext size (uint), and optional `w`/`h` dimensions (uint),
//! `fn` file name (text) and `th` thumbnail (bstr).

use std::fmt;

use ciborium::Value;
use gim_common::MessageId;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::ProtoError;

/// Envelope version written by this build; also the newest it decodes.
pub const ENVELOPE_VERSION: u32 = 1;

/// Length of [`MediaInfo::key`] and [`MediaInfo::sha256`].
pub const MEDIA_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u32,
    pub message_id: MessageId,
    pub sent_at_ms: u64,
    /// Only allowed on [`Content::Text`] and [`Content::Media`].
    pub reply_to: Option<MessageId>,
    pub content: Content,
}

impl Envelope {
    /// An envelope at [`ENVELOPE_VERSION`] without `reply_to`.
    pub fn new(message_id: MessageId, sent_at_ms: u64, content: Content) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            message_id,
            sent_at_ms,
            reply_to: None,
            content,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Text {
        body: String,
    },
    Media {
        media: MediaInfo,
        caption: Option<String>,
    },
    Edit {
        target: MessageId,
        new_body: String,
    },
    Delete {
        target: MessageId,
    },
    Reaction {
        target: MessageId,
        emoji: String,
        remove: bool,
    },
    Receipt {
        kind: ReceiptKind,
        message_ids: Vec<MessageId>,
    },
    Typing {
        active: bool,
    },
    GroupInfo {
        name: Option<String>,
        avatar: Option<MediaInfo>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Delivered,
    Read,
}

/// An encrypted blob on gim-server and what is needed to fetch and decrypt it.
#[derive(Clone, PartialEq, Eq)]
pub struct MediaInfo {
    pub blob_id: String,
    /// AES-256 media key.
    pub key: [u8; MEDIA_KEY_LEN],
    /// SHA-256 of the encrypted blob as uploaded.
    pub sha256: [u8; MEDIA_KEY_LEN],
    pub mime: String,
    /// Plaintext size in bytes.
    pub size: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub file_name: Option<String>,
    pub thumbnail: Option<Vec<u8>>,
}

impl fmt::Debug for MediaInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaInfo")
            .field("blob_id", &self.blob_id)
            .field("sha256", &self.sha256)
            .field("mime", &self.mime)
            .field("size", &self.size)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("file_name", &self.file_name)
            .field("thumbnail_len", &self.thumbnail.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// Encodes an envelope to CBOR after validating it.
pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, ProtoError> {
    check_version(envelope.version.into())?;
    check_reply_to(envelope.reply_to.as_ref(), &envelope.content)?;
    let wire = WireEnvelope {
        v: envelope.version,
        id: envelope.message_id.clone(),
        ts: envelope.sent_at_ms,
        re: envelope.reply_to.clone(),
        c: WireContent::from(&envelope.content),
    };
    let mut out = Vec::new();
    ciborium::into_writer(&wire, &mut out).map_err(ProtoError::malformed)?;
    Ok(out)
}

/// Decodes and validates a CBOR envelope.
pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtoError> {
    let value: Value = ciborium::from_reader(bytes).map_err(ProtoError::malformed)?;
    // Check the version before the schema, which may differ in other versions.
    let version = value
        .as_map()
        .ok_or_else(|| ProtoError::malformed("not a map"))?
        .iter()
        .find(|(key, _)| key.as_text() == Some("v"))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| ProtoError::malformed("missing or invalid version"))?;
    check_version(version)?;
    let wire: WireEnvelope = value.deserialized().map_err(ProtoError::malformed)?;
    let content = Content::try_from(wire.c)?;
    check_reply_to(wire.re.as_ref(), &content)?;
    Ok(Envelope {
        version: wire.v,
        message_id: wire.id,
        sent_at_ms: wire.ts,
        reply_to: wire.re,
        content,
    })
}

fn check_version(version: u64) -> Result<(), ProtoError> {
    if version == 0 || version > u64::from(ENVELOPE_VERSION) {
        return Err(ProtoError::UnsupportedVersion { version });
    }
    Ok(())
}

fn check_reply_to(reply_to: Option<&MessageId>, content: &Content) -> Result<(), ProtoError> {
    match (reply_to, content) {
        (None, _) | (Some(_), Content::Text { .. } | Content::Media { .. }) => Ok(()),
        (Some(_), _) => Err(ProtoError::invalid(
            "reply_to is only allowed on text and media",
        )),
    }
}

#[derive(Serialize, Deserialize)]
struct WireEnvelope {
    v: u32,
    id: MessageId,
    ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    re: Option<MessageId>,
    c: WireContent,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WireContent {
    Text {
        b: String,
    },
    Media {
        m: WireMedia,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cap: Option<String>,
    },
    Edit {
        tg: MessageId,
        b: String,
    },
    Delete {
        tg: MessageId,
    },
    Reaction {
        tg: MessageId,
        e: String,
        rm: bool,
    },
    Receipt {
        k: ReceiptKind,
        ids: Vec<MessageId>,
    },
    Typing {
        a: bool,
    },
    GroupInfo {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        n: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        av: Option<WireMedia>,
    },
}

#[derive(Serialize, Deserialize)]
struct WireMedia {
    id: String,
    k: ByteBuf,
    d: ByteBuf,
    mt: String,
    sz: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    h: Option<u32>,
    #[serde(default, rename = "fn", skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    th: Option<ByteBuf>,
}

impl From<&Content> for WireContent {
    fn from(content: &Content) -> Self {
        match content.clone() {
            Content::Text { body } => Self::Text { b: body },
            Content::Media { media, caption } => Self::Media {
                m: WireMedia::from(media),
                cap: caption,
            },
            Content::Edit { target, new_body } => Self::Edit {
                tg: target,
                b: new_body,
            },
            Content::Delete { target } => Self::Delete { tg: target },
            Content::Reaction {
                target,
                emoji,
                remove,
            } => Self::Reaction {
                tg: target,
                e: emoji,
                rm: remove,
            },
            Content::Receipt { kind, message_ids } => Self::Receipt {
                k: kind,
                ids: message_ids,
            },
            Content::Typing { active } => Self::Typing { a: active },
            Content::GroupInfo { name, avatar } => Self::GroupInfo {
                n: name,
                av: avatar.map(WireMedia::from),
            },
        }
    }
}

impl TryFrom<WireContent> for Content {
    type Error = ProtoError;

    fn try_from(wire: WireContent) -> Result<Self, ProtoError> {
        Ok(match wire {
            WireContent::Text { b } => Self::Text { body: b },
            WireContent::Media { m, cap } => Self::Media {
                media: m.try_into()?,
                caption: cap,
            },
            WireContent::Edit { tg, b } => Self::Edit {
                target: tg,
                new_body: b,
            },
            WireContent::Delete { tg } => Self::Delete { target: tg },
            WireContent::Reaction { tg, e, rm } => Self::Reaction {
                target: tg,
                emoji: e,
                remove: rm,
            },
            WireContent::Receipt { k, ids } => Self::Receipt {
                kind: k,
                message_ids: ids,
            },
            WireContent::Typing { a } => Self::Typing { active: a },
            WireContent::GroupInfo { n, av } => Self::GroupInfo {
                name: n,
                avatar: av.map(MediaInfo::try_from).transpose()?,
            },
        })
    }
}

impl From<MediaInfo> for WireMedia {
    fn from(media: MediaInfo) -> Self {
        Self {
            id: media.blob_id,
            k: ByteBuf::from(media.key.to_vec()),
            d: ByteBuf::from(media.sha256.to_vec()),
            mt: media.mime,
            sz: media.size,
            w: media.width,
            h: media.height,
            file_name: media.file_name,
            th: media.thumbnail.map(ByteBuf::from),
        }
    }
}

impl TryFrom<WireMedia> for MediaInfo {
    type Error = ProtoError;

    fn try_from(wire: WireMedia) -> Result<Self, ProtoError> {
        let fixed = |bytes: ByteBuf, field: &str| {
            <[u8; MEDIA_KEY_LEN]>::try_from(bytes.into_vec()).map_err(|_| {
                ProtoError::invalid(format!("media {field} must be {MEDIA_KEY_LEN} bytes"))
            })
        };
        Ok(Self {
            blob_id: wire.id,
            key: fixed(wire.k, "key")?,
            sha256: fixed(wire.d, "sha256")?,
            mime: wire.mt,
            size: wire.sz,
            width: wire.w,
            height: wire.h,
            file_name: wire.file_name,
            thumbnail: wire.th.map(ByteBuf::into_vec),
        })
    }
}
