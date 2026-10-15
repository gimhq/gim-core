//! Media upload and download. Blobs are encrypted with gim-crypto's chunked
//! AES-256-GCM format; the key and the blob digest travel in the message.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use gim_base::model::{MediaCacheEntry, MessageContent, PendingMedia};
use gim_base::{BaseError, StateStore, StoreTxn};
use gim_common::{now_ms, GroupId, MessageId};
use gim_crypto::{
    MediaDecryptor, MediaEncryptor, MediaError, MAX_CHUNK_SIZE, MEDIA_HEADER_LEN, MEDIA_MAGIC,
};
use gim_proto::envelope::MediaInfo;

use crate::client::Session;
use crate::transport::TransportError;
use crate::{Client, ClientError, Result};

/// Bytes requested per ranged download; the partial file grows by this much
/// per request, so an interrupted download resumes where it stopped.
pub const DOWNLOAD_PIECE: u64 = 256 * 1024;

/// AES-GCM tag per chunk.
const TAG_LEN: u64 = 16;

impl<S: StateStore + 'static> Client<S> {
    /// Encrypts the file to a temporary file under the data directory and
    /// uploads it.
    pub(crate) async fn upload_media(
        &self,
        session: &Session,
        message_id: &MessageId,
        pending: PendingMedia,
    ) -> Result<MediaInfo> {
        let encrypted = self.tmp_dir().join(format!("upload-{message_id}"));
        let source = PathBuf::from(&pending.local_path);
        let tmp = encrypted.clone();
        let (encryption, dimensions) = blocking(move || {
            fs::create_dir_all(tmp.parent().expect("temp files have a parent"))?;
            let dimensions = image_dimensions(&source)?;
            let input = BufReader::new(File::open(&source)?);
            let encrypted = (|| {
                let mut output = BufWriter::new(File::create(&tmp)?);
                let encryption = MediaEncryptor::new()?.encrypt(input, &mut output)?;
                output.flush()?;
                Ok::<_, ClientError>(encryption)
            })();
            if encrypted.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            Ok((encrypted?, dimensions))
        })
        .await?;
        let uploaded = self
            .inner
            .transport
            .upload_blob(&session.token, &encrypted)
            .await;
        let _ = fs::remove_file(&encrypted);
        let blob_id = uploaded?;
        Ok(MediaInfo {
            blob_id,
            key: encryption.key,
            sha256: encryption.sha256,
            mime: pending.mime,
            size: encryption.plaintext_size,
            width: dimensions.map(|(w, _)| w),
            height: dimensions.map(|(_, h)| h),
            file_name: Path::new(&pending.local_path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string),
            thumbnail: None,
        })
    }

    /// Downloads, verifies and decrypts the media of a message to `dest`,
    /// and records it in the media cache. A download interrupted earlier
    /// resumes from its partial file; a blob that fails verification is
    /// discarded and nothing is written to `dest`.
    pub async fn fetch_media(
        &self,
        group_id: &GroupId,
        message_id: &MessageId,
        dest: impl AsRef<Path>,
    ) -> Result<()> {
        let session = self.require_session()?;
        let media = self.media_of(group_id, message_id).await?;
        let dest = dest.as_ref().to_path_buf();
        let dest_str = dest
            .to_str()
            .ok_or_else(|| ClientError::InvalidInput("path is not UTF-8".into()))?
            .to_string();
        let blob_id = media.blob_id.clone();
        let cached = self
            .run(move |store, _| Ok(store.media(&blob_id)?))
            .await?
            .filter(|entry| Path::new(&entry.local_path).is_file());
        if let Some(entry) = cached {
            if entry.local_path != dest_str {
                let (from, to) = (PathBuf::from(&entry.local_path), dest.clone());
                blocking(move || Ok(fs::copy(from, to).map(drop)?)).await?;
            }
        } else {
            self.download(&session, &media, &dest).await?;
        }
        let entry = MediaCacheEntry {
            blob_id: media.blob_id.clone(),
            local_path: dest_str,
            size: media.size,
            last_access_ms: now_ms(),
        };
        self.run(move |store, _| store.transaction(|txn| Ok(txn.upsert_media(&entry)?)))
            .await
    }

    /// Writes the inline thumbnail of a media message to `dest`.
    pub async fn fetch_thumbnail(
        &self,
        group_id: &GroupId,
        message_id: &MessageId,
        dest: impl AsRef<Path>,
    ) -> Result<()> {
        let media = self.media_of(group_id, message_id).await?;
        let thumbnail = media
            .thumbnail
            .ok_or_else(|| ClientError::InvalidInput(format!("{message_id} has no thumbnail")))?;
        let dest = dest.as_ref().to_path_buf();
        blocking(move || Ok(fs::write(dest, thumbnail)?)).await
    }

    async fn download(&self, session: &Session, media: &MediaInfo, dest: &Path) -> Result<()> {
        let hex: String = media.sha256.iter().map(|b| format!("{b:02x}")).collect();
        let partial = self.tmp_dir().join(format!("download-{hex}.part"));
        let (part, size) = (partial.clone(), media.size);
        let (mut have, mut total) = blocking(move || {
            fs::create_dir_all(part.parent().expect("temp files have a parent"))?;
            let mut header = Vec::new();
            if let Ok(file) = File::open(&part) {
                file.take(MEDIA_HEADER_LEN as u64)
                    .read_to_end(&mut header)?;
            }
            if header.len() < MEDIA_HEADER_LEN {
                File::create(&part)?;
                return Ok((0, None));
            }
            let total = match blob_len(&header, size) {
                Ok(total) => total,
                Err(err) => {
                    let _ = fs::remove_file(&part);
                    return Err(err.into());
                }
            };
            Ok((fs::metadata(&part)?.len().min(total), Some(total)))
        })
        .await?;
        loop {
            let end = match total {
                Some(total) if have >= total => break,
                Some(total) => (have + DOWNLOAD_PIECE).min(total),
                None => MEDIA_HEADER_LEN as u64,
            };
            let bytes = self
                .inner
                .transport
                .download_blob(&session.token, &media.blob_id, Some(have..end))
                .await?;
            if bytes.len() as u64 != end - have {
                return Err(TransportError::Server(format!(
                    "blob range {have}..{end} returned {} bytes",
                    bytes.len()
                ))
                .into());
            }
            if total.is_none() {
                match blob_len(&bytes, media.size) {
                    Ok(len) => total = Some(len),
                    Err(err) => {
                        let _ = fs::remove_file(&partial);
                        return Err(err.into());
                    }
                }
            }
            let (part, offset) = (partial.clone(), have);
            blocking(move || {
                let mut file = OpenOptions::new().write(true).open(&part)?;
                // Drops anything past `offset` from an earlier run.
                file.set_len(offset)?;
                std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset))?;
                file.write_all(&bytes)?;
                Ok(file.sync_data()?)
            })
            .await?;
            have = end;
        }
        let (key, sha256, dest) = (media.key, media.sha256, dest.to_path_buf());
        blocking(move || {
            let tmp = sibling_tmp(&dest);
            let decrypted = (|| {
                let input = BufReader::new(File::open(&partial)?);
                let output = BufWriter::new(File::create(&tmp)?);
                MediaDecryptor::new(key, sha256).decrypt(input, output)?;
                Ok::<_, ClientError>(fs::rename(&tmp, &dest)?)
            })();
            if decrypted.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            // Corrupt data is not worth resuming.
            let _ = fs::remove_file(&partial);
            decrypted
        })
        .await
    }

    async fn media_of(&self, group_id: &GroupId, message_id: &MessageId) -> Result<MediaInfo> {
        let (gid, id) = (group_id.clone(), message_id.clone());
        let message = self
            .run(move |store, _| {
                store
                    .message(&id)?
                    .filter(|m| m.group_id == gid)
                    .ok_or_else(|| BaseError::NotFound(format!("message {id} in chat {gid}")))
            })
            .await?;
        match message.content {
            MessageContent::Media { media, .. } => Ok(media),
            _ => Err(ClientError::InvalidInput(format!(
                "{message_id} has no downloadable media"
            ))),
        }
    }

    fn tmp_dir(&self) -> PathBuf {
        self.inner.data_dir.join("tmp")
    }
}

/// Encrypted blob length for `size` plaintext bytes, from the blob header.
fn blob_len(header: &[u8], size: u64) -> Result<u64, MediaError> {
    let malformed = |reason: &str| MediaError::Malformed {
        reason: reason.into(),
    };
    if header.len() < MEDIA_HEADER_LEN || header[..4] != MEDIA_MAGIC {
        return Err(malformed("bad header"));
    }
    let chunk_size = u32::from_be_bytes(header[4..8].try_into().expect("4 bytes"));
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(malformed("bad chunk size"));
    }
    let chunks = size.div_ceil(u64::from(chunk_size)).max(1);
    Ok(MEDIA_HEADER_LEN as u64 + size + chunks * TAG_LEN)
}

/// Width and height from a PNG or GIF header; `None` for anything else.
fn image_dimensions(path: &Path) -> std::io::Result<Option<(u32, u32)>> {
    let mut header = Vec::with_capacity(24);
    File::open(path)?.take(24).read_to_end(&mut header)?;
    let be = |i: usize| u32::from_be_bytes(header[i..i + 4].try_into().expect("4 bytes"));
    let le16 = |i: usize| u32::from(u16::from_le_bytes([header[i], header[i + 1]]));
    Ok(
        if header.len() >= 24
            && header.starts_with(b"\x89PNG\r\n\x1a\n")
            && &header[12..16] == b"IHDR"
        {
            Some((be(16), be(20)))
        } else if header.len() >= 10
            && (header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a"))
        {
            Some((le16(6), le16(8)))
        } else {
            None
        },
    )
}

/// A temporary path next to `dest`, so the final rename stays on one
/// file system.
fn sibling_tmp(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".gim-tmp");
    dest.with_file_name(name)
}

/// Runs blocking file work off the async runtime.
async fn blocking<R, F>(f: F) -> Result<R>
where
    R: Send + 'static,
    F: FnOnce() -> Result<R> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ClientError::Task(e.to_string()))?
}
