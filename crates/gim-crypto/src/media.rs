//! Chunked AES-256-GCM media encryption.
//!
//! # Format
//!
//! ```text
//! header = "GIM1" || chunk_size (u32 BE) || nonce_prefix (8 random bytes)
//! blob   = header || chunk_0 || chunk_1 || ... || chunk_n
//! chunk_i = AES-256-GCM(key, nonce = nonce_prefix || i (u32 BE),
//!                       aad = header || last, plaintext_i) // ciphertext || 16-byte tag
//! ```
//!
//! Every chunk but the last holds exactly `chunk_size` plaintext bytes; the
//! last holds 1..=`chunk_size` bytes, or 0 bytes when the whole plaintext is
//! empty. `last` is `1` for the final chunk and `0` otherwise, so truncating
//! the blob at a chunk boundary fails authentication; the chunk index in the
//! nonce rejects reordered chunks. The SHA-256 of the whole blob travels in
//! the envelope ([`gim_proto::envelope::MediaInfo::sha256`]) and binds the
//! blob to the message.

use std::io::{self, Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Magic bytes starting every encrypted blob.
pub const MEDIA_MAGIC: [u8; 4] = *b"GIM1";
/// Plaintext bytes per chunk written by [`MediaEncryptor::new`].
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
/// Largest chunk size accepted, bounding per-chunk memory when decrypting.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
/// Length of the media key and of the blob digest.
pub const MEDIA_KEY_LEN: usize = 32;
/// Length of the blob header.
pub const MEDIA_HEADER_LEN: usize = 16;

const NONCE_PREFIX_LEN: usize = 8;
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    /// Header, chunk layout or authentication tag is wrong.
    #[error("malformed or tampered media blob: {reason}")]
    Malformed { reason: String },
    #[error("media blob digest mismatch")]
    DigestMismatch,
    #[error("random number generator failed: {0}")]
    Random(String),
}

fn malformed(reason: impl Into<String>) -> MediaError {
    MediaError::Malformed {
        reason: reason.into(),
    }
}

/// A whole encrypted blob plus what the envelope needs to decrypt it.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedMedia {
    pub ciphertext: Vec<u8>,
    pub key: [u8; MEDIA_KEY_LEN],
    /// SHA-256 of `ciphertext`.
    pub sha256: [u8; MEDIA_KEY_LEN],
    pub plaintext_size: u64,
}

impl std::fmt::Debug for EncryptedMedia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMedia")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("sha256", &self.sha256)
            .field("plaintext_size", &self.plaintext_size)
            .finish_non_exhaustive()
    }
}

/// Result of a streaming encryption.
#[derive(Clone, PartialEq, Eq)]
pub struct MediaEncryption {
    pub key: [u8; MEDIA_KEY_LEN],
    /// SHA-256 of everything written.
    pub sha256: [u8; MEDIA_KEY_LEN],
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
}

impl std::fmt::Debug for MediaEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaEncryption")
            .field("sha256", &self.sha256)
            .field("plaintext_size", &self.plaintext_size)
            .field("ciphertext_size", &self.ciphertext_size)
            .finish_non_exhaustive()
    }
}

/// Encrypts `plaintext` under a fresh random key.
pub fn encrypt_media(plaintext: &[u8]) -> Result<EncryptedMedia, MediaError> {
    let mut ciphertext = Vec::new();
    let out = MediaEncryptor::new()?.encrypt(plaintext, &mut ciphertext)?;
    Ok(EncryptedMedia {
        ciphertext,
        key: out.key,
        sha256: out.sha256,
        plaintext_size: out.plaintext_size,
    })
}

/// Checks the blob digest (constant time), then decrypts it.
pub fn decrypt_media(
    ciphertext: &[u8],
    key: &[u8; MEDIA_KEY_LEN],
    sha256: &[u8; MEDIA_KEY_LEN],
) -> Result<Vec<u8>, MediaError> {
    let digest: [u8; MEDIA_KEY_LEN] = Sha256::digest(ciphertext).into();
    if !bool::from(digest.ct_eq(sha256)) {
        return Err(MediaError::DigestMismatch);
    }
    let mut plaintext = Vec::new();
    MediaDecryptor::new(*key, *sha256).decrypt(ciphertext, &mut plaintext)?;
    Ok(plaintext)
}

/// Streaming encryptor; holds at most two chunks in memory.
pub struct MediaEncryptor {
    key: [u8; MEDIA_KEY_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: u32,
}

impl MediaEncryptor {
    /// Fresh random key and nonce prefix, [`DEFAULT_CHUNK_SIZE`].
    pub fn new() -> Result<Self, MediaError> {
        Self::with_chunk_size(DEFAULT_CHUNK_SIZE)
    }

    /// Fresh random key and nonce prefix with the given chunk size.
    pub fn with_chunk_size(chunk_size: u32) -> Result<Self, MediaError> {
        let mut key = [0; MEDIA_KEY_LEN];
        let mut nonce_prefix = [0; NONCE_PREFIX_LEN];
        getrandom::getrandom(&mut key).map_err(|e| MediaError::Random(e.to_string()))?;
        getrandom::getrandom(&mut nonce_prefix).map_err(|e| MediaError::Random(e.to_string()))?;
        Self::deterministic(key, nonce_prefix, chunk_size)
    }

    /// Fixed key and nonce prefix, for test vectors only. Never reuse a key
    /// and prefix pair for two plaintexts.
    #[doc(hidden)]
    pub fn deterministic(
        key: [u8; MEDIA_KEY_LEN],
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        chunk_size: u32,
    ) -> Result<Self, MediaError> {
        check_chunk_size(chunk_size).map_err(|reason| MediaError::InvalidInput { reason })?;
        Ok(Self {
            key,
            nonce_prefix,
            chunk_size,
        })
    }

    pub fn key(&self) -> &[u8; MEDIA_KEY_LEN] {
        &self.key
    }

    /// Reads all of `reader` and writes the encrypted blob to `writer`.
    pub fn encrypt<R: Read, W: Write>(
        self,
        mut reader: R,
        writer: W,
    ) -> Result<MediaEncryption, MediaError> {
        let header = header(self.chunk_size, &self.nonce_prefix);
        let cipher = Aes256Gcm::new(&self.key.into());
        let mut writer = HashingWriter::new(writer);
        writer.write_all(&header)?;
        let chunk_size = self.chunk_size as usize;
        let mut current = read_up_to(&mut reader, chunk_size)?;
        let mut plaintext_size = 0u64;
        let mut index = 0u32;
        loop {
            // Look ahead one chunk to know whether the current one is last.
            let next = if current.len() == chunk_size {
                read_up_to(&mut reader, chunk_size)?
            } else {
                Vec::new()
            };
            let last = next.is_empty();
            let sealed = cipher
                .encrypt(
                    Nonce::from_slice(&nonce(&self.nonce_prefix, index)),
                    Payload {
                        msg: &current,
                        aad: &aad(&header, last),
                    },
                )
                .map_err(|_| MediaError::InvalidInput {
                    reason: "chunk encryption failed".into(),
                })?;
            writer.write_all(&sealed)?;
            plaintext_size += current.len() as u64;
            if last {
                break;
            }
            index = index
                .checked_add(1)
                .ok_or_else(|| MediaError::InvalidInput {
                    reason: "too many chunks".into(),
                })?;
            current = next;
        }
        writer.inner.flush()?;
        Ok(MediaEncryption {
            key: self.key,
            sha256: writer.hasher.finalize().into(),
            plaintext_size,
            ciphertext_size: writer.written,
        })
    }
}

/// Streaming decryptor; holds at most two chunks in memory.
///
/// Every chunk is authenticated before its plaintext is written, but the
/// blob digest can only be checked at the end: on any error, discard what
/// was written.
pub struct MediaDecryptor {
    key: [u8; MEDIA_KEY_LEN],
    sha256: [u8; MEDIA_KEY_LEN],
}

impl MediaDecryptor {
    pub fn new(key: [u8; MEDIA_KEY_LEN], sha256: [u8; MEDIA_KEY_LEN]) -> Self {
        Self { key, sha256 }
    }

    /// Decrypts the blob read from `reader` into `writer`; returns the
    /// plaintext size.
    pub fn decrypt<R: Read, W: Write>(self, reader: R, mut writer: W) -> Result<u64, MediaError> {
        let mut reader = HashingReader::new(reader);
        let header = read_up_to(&mut reader, MEDIA_HEADER_LEN)?;
        if header.len() != MEDIA_HEADER_LEN || header[..4] != MEDIA_MAGIC {
            return Err(malformed("bad header"));
        }
        let chunk_size = u32::from_be_bytes(header[4..8].try_into().expect("4 bytes"));
        check_chunk_size(chunk_size).map_err(malformed)?;
        let nonce_prefix: [u8; NONCE_PREFIX_LEN] = header[8..].try_into().expect("8 bytes");
        let cipher = Aes256Gcm::new(&self.key.into());
        let sealed_size = chunk_size as usize + TAG_LEN;
        let mut current = read_up_to(&mut reader, sealed_size)?;
        let mut plaintext_size = 0u64;
        let mut index = 0u32;
        loop {
            let next = if current.len() == sealed_size {
                read_up_to(&mut reader, sealed_size)?
            } else {
                Vec::new()
            };
            let last = next.is_empty();
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&nonce(&nonce_prefix, index)),
                    Payload {
                        msg: &current,
                        aad: &aad(&header, last),
                    },
                )
                .map_err(|_| malformed(format!("chunk {index} failed authentication")))?;
            writer.write_all(&plaintext)?;
            plaintext_size += plaintext.len() as u64;
            if last {
                break;
            }
            index = index
                .checked_add(1)
                .ok_or_else(|| malformed("too many chunks"))?;
            current = next;
        }
        let digest: [u8; MEDIA_KEY_LEN] = reader.hasher.finalize().into();
        if !bool::from(digest.ct_eq(&self.sha256)) {
            return Err(MediaError::DigestMismatch);
        }
        writer.flush()?;
        Ok(plaintext_size)
    }
}

fn check_chunk_size(chunk_size: u32) -> Result<(), String> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(format!("chunk size must be 1..={MAX_CHUNK_SIZE}"));
    }
    Ok(())
}

fn header(chunk_size: u32, nonce_prefix: &[u8; NONCE_PREFIX_LEN]) -> [u8; MEDIA_HEADER_LEN] {
    let mut header = [0; MEDIA_HEADER_LEN];
    header[..4].copy_from_slice(&MEDIA_MAGIC);
    header[4..8].copy_from_slice(&chunk_size.to_be_bytes());
    header[8..].copy_from_slice(nonce_prefix);
    header
}

fn nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn aad(header: &[u8], last: bool) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.push(u8::from(last));
    aad
}

/// Reads until `len` bytes or end of input.
fn read_up_to(reader: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    reader.take(len as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}
