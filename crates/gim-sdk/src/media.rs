//! Media upload and download. Blobs are encrypted with gim-crypto's chunked
//! AES-256-GCM format; the key and the blob digest travel in the message.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use gim_base::model::{MediaCacheEntry, MessageContent, OutboxKind, PendingMedia};
use gim_base::{BaseError, StateStore, StoreTxn};
use gim_common::{now_ms, GroupId, MessageId};
use gim_crypto::{
    MediaDecryptor, MediaEncryptor, MediaError, MAX_CHUNK_SIZE, MEDIA_HEADER_LEN, MEDIA_MAGIC,
};
use gim_proto::envelope::MediaInfo;

use crate::transport::TransportError;
use crate::{Client, ClientError, Result};

/// Bytes requested per ranged download; the partial file grows by this much
/// per request, so an interrupted download resumes where it stopped.
pub const DOWNLOAD_PIECE: u64 = 256 * 1024;

/// AES-GCM tag per chunk.
const TAG_LEN: u64 = 16;

/// Subdirectory of the data directory for private copies of files to send,
/// one directory per file: `outgoing/<dir>/<file name>`. The client deletes
/// such a copy with its directory once uploaded or cancelled.
pub const OUTGOING_DIR: &str = "outgoing";

impl<S: StateStore + 'static> Client<S> {
    /// Encrypts the file to a temporary file under the data directory and
    /// uploads it.
    pub(crate) async fn upload_media(
        &self,
        message_id: &MessageId,
        pending: PendingMedia,
    ) -> Result<MediaInfo> {
        let encrypted = self.tmp_dir().join(format!("upload-{message_id}"));
        let source = PathBuf::from(&pending.local_path);
        let tmp = encrypted.clone();
        let (encryption, dimensions) = blocking(move || {
            let dimensions = image_dimensions(&source)?;
            let input = BufReader::new(File::open(&source)?);
            // Left over from an interrupted attempt.
            let _ = fs::remove_file(&tmp);
            let encrypted = (|| {
                let mut output = BufWriter::new(create_private(&tmp)?);
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
            .authed(|t| {
                let encrypted = &encrypted;
                async move { self.inner.transport.upload_blob(&t, encrypted).await }
            })
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
        self.require_session()?;
        let media = self.media_of(group_id, message_id).await?;
        let dest = dest.as_ref().to_path_buf();
        let dest_str = dest
            .to_str()
            .ok_or_else(|| ClientError::InvalidInput("path is not UTF-8".into()))?
            .to_string();
        let blob_id = media.blob_id.clone();
        let cached = self
            .read(move |store, _| Ok(store.media(&blob_id)?))
            .await?
            .filter(|entry| Path::new(&entry.local_path).is_file());
        if let Some(entry) = cached {
            if entry.local_path != dest_str {
                let (from, to) = (PathBuf::from(&entry.local_path), dest.clone());
                blocking(move || Ok(fs::copy(from, to).map(drop)?)).await?;
            }
        } else {
            self.download(&media, &dest).await?;
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

    async fn download(&self, media: &MediaInfo, dest: &Path) -> Result<()> {
        let hex: String = media.sha256.iter().map(|b| format!("{b:02x}")).collect();
        let partial = self.tmp_dir().join(format!("download-{hex}.part"));
        let (part, size) = (partial.clone(), media.size);
        let (mut have, mut total) = blocking(move || {
            let mut header = Vec::new();
            if let Some(file) = open_partial(&part, false)? {
                file.take(MEDIA_HEADER_LEN as u64)
                    .read_to_end(&mut header)?;
            }
            if header.len() < MEDIA_HEADER_LEN {
                let _ = fs::remove_file(&part);
                create_private(&part)?;
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
                .authed(|t| {
                    let blob_id = &media.blob_id;
                    async move {
                        self.inner
                            .transport
                            .download_blob(&t, blob_id, Some(have..end))
                            .await
                    }
                })
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
                let mut file = open_partial(&part, true)?.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "partial file vanished")
                })?;
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
                let input = open_partial(&partial, false)?.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "partial file vanished")
                })?;
                let input = BufReader::new(input);
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

    /// `<data_dir>/outgoing`; see [`OUTGOING_DIR`].
    pub fn outgoing_dir(&self) -> PathBuf {
        self.inner.data_dir.join(OUTGOING_DIR)
    }

    /// Deletes the copy of a sent or cancelled file with its directory, if
    /// it lives under [`Client::outgoing_dir`]; other files are the app's.
    pub(crate) async fn remove_outgoing(&self, local_path: &str) {
        let outgoing = self.outgoing_dir();
        let path = PathBuf::from(local_path);
        // Best effort: leftovers are removed on the next start.
        let _ = blocking(move || {
            if let Some(dir) = path.parent().filter(|d| d.parent() == Some(&outgoing)) {
                fs::remove_dir_all(dir)?;
            }
            Ok(())
        })
        .await;
    }

    /// Deletes the entries of [`Client::outgoing_dir`] that no queued media
    /// upload refers to (left by a crash or by a removed chat).
    pub(crate) async fn clean_outgoing(&self) -> Result<()> {
        let entries = self.read(|store, _| Ok(store.outbox_entries()?)).await?;
        let outgoing = self.outgoing_dir();
        let keep: Vec<PathBuf> = entries
            .into_iter()
            .filter_map(|entry| match entry.kind {
                OutboxKind::MediaUpload(pending) => Path::new(&pending.local_path)
                    .parent()
                    .map(Path::to_path_buf),
                OutboxKind::Envelope(_) => None,
            })
            .collect();
        blocking(move || {
            let dir = match fs::read_dir(&outgoing) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                dir => dir?,
            };
            for entry in dir {
                let path = entry?.path();
                if keep.contains(&path) {
                    continue;
                }
                if path.is_dir() {
                    fs::remove_dir_all(&path)?;
                } else {
                    fs::remove_file(&path)?;
                }
            }
            Ok(())
        })
        .await
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

/// Creates a new file readable and writable by the owner only (0600 on
/// Unix); fails if anything exists at `path`.
fn create_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Opens an existing partial file without following symlinks: anything
/// but a regular file is removed and treated as missing.
fn open_partial(path: &Path, write: bool) -> std::io::Result<Option<File>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            fs::remove_file(path)?;
            return Ok(None);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    }
    OpenOptions::new()
        .read(!write)
        .write(write)
        .open(path)
        .map(Some)
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
