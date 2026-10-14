use std::io::{self, Read};

use gim_crypto::{
    decrypt_media, encrypt_media, MediaDecryptor, MediaEncryptor, MediaError, DEFAULT_CHUNK_SIZE,
    MEDIA_HEADER_LEN,
};
use sha2::{Digest, Sha256};

const CS: usize = 16;
const TAG: usize = 16;

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn sizes(cs: usize) -> [usize; 6] {
    [0, 1, cs - 1, cs, cs + 1, 3 * cs + 7]
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A reader returning at most 3 bytes per call.
struct Trickle<'a>(&'a [u8]);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(3).min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

fn seal(data: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let encryptor = MediaEncryptor::deterministic([1; 32], [2; 8], CS as u32).unwrap();
    let mut ct = Vec::new();
    let out = encryptor.encrypt(data, &mut ct).unwrap();
    (ct, out.key)
}

/// Decrypts with the digest of the given bytes, so only chunk
/// authentication can reject them.
fn open(ct: &[u8], key: [u8; 32]) -> Result<Vec<u8>, MediaError> {
    let mut out = Vec::new();
    MediaDecryptor::new(key, sha256(ct)).decrypt(ct, &mut out)?;
    Ok(out)
}

#[test]
fn whole_buffer_round_trip() {
    for len in sizes(DEFAULT_CHUNK_SIZE as usize) {
        let data = plaintext(len);
        let enc = encrypt_media(&data).unwrap();
        assert_eq!(enc.plaintext_size, len as u64);
        assert_eq!(enc.sha256, sha256(&enc.ciphertext));
        let chunks = len.div_ceil(DEFAULT_CHUNK_SIZE as usize).max(1);
        assert_eq!(enc.ciphertext.len(), MEDIA_HEADER_LEN + len + chunks * TAG);
        assert_eq!(&enc.ciphertext[..4], b"GIM1");
        assert_eq!(
            decrypt_media(&enc.ciphertext, &enc.key, &enc.sha256).unwrap(),
            data
        );
    }
}

#[test]
fn streaming_round_trip() {
    for cs in [CS, DEFAULT_CHUNK_SIZE as usize] {
        for len in sizes(cs) {
            let data = plaintext(len);
            let mut ct = Vec::new();
            let out = MediaEncryptor::with_chunk_size(cs as u32)
                .unwrap()
                .encrypt(Trickle(&data), &mut ct)
                .unwrap();
            assert_eq!(out.plaintext_size, len as u64);
            assert_eq!(out.ciphertext_size, ct.len() as u64);
            assert_eq!(out.sha256, sha256(&ct));

            let mut pt = Vec::new();
            let size = MediaDecryptor::new(out.key, out.sha256)
                .decrypt(Trickle(&ct), &mut pt)
                .unwrap();
            assert_eq!(size, len as u64);
            assert_eq!(pt, data);
            // Streaming output is readable by the whole-buffer API.
            assert_eq!(decrypt_media(&ct, &out.key, &out.sha256).unwrap(), data);
        }
    }
}

#[test]
fn deterministic_constructor_is_deterministic() {
    let data = plaintext(3 * CS + 7);
    assert_eq!(seal(&data), seal(&data));
    assert_eq!(&seal(&data).0[4..8], &(CS as u32).to_be_bytes());
    assert_eq!(&seal(&data).0[8..16], &[2; 8]);
}

#[test]
fn fresh_key_and_ciphertext_per_call() {
    let data = plaintext(100);
    let a = encrypt_media(&data).unwrap();
    let b = encrypt_media(&data).unwrap();
    assert_ne!(a.key, b.key);
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_ne!(a.ciphertext[8..16], b.ciphertext[8..16]);
    assert_ne!(a.sha256, b.sha256);
}

#[test]
fn flipped_byte_fails() {
    let data = plaintext(3 * CS + 7);
    let (ct, key) = seal(&data);
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(open(&bad, key).is_err(), "flip at {i} accepted");
        assert!(matches!(
            decrypt_media(&bad, &key, &sha256(&ct)),
            Err(MediaError::DigestMismatch)
        ));
    }
}

#[test]
fn truncation_fails() {
    for len in sizes(CS) {
        let (ct, key) = seal(&plaintext(len));
        for cut in 0..ct.len() {
            assert!(
                open(&ct[..cut], key).is_err(),
                "len {len} cut {cut} accepted"
            );
        }
    }
}

#[test]
fn dropping_last_chunk_fails() {
    // Plaintext of exactly 3 chunks: dropping the last leaves whole chunks.
    let (ct, key) = seal(&plaintext(3 * CS));
    let sealed = CS + TAG;
    assert_eq!(ct.len(), MEDIA_HEADER_LEN + 3 * sealed);
    assert!(open(&ct[..ct.len() - sealed], key).is_err());
}

#[test]
fn swapped_chunks_fail() {
    let (ct, key) = seal(&plaintext(3 * CS + 7));
    let sealed = CS + TAG;
    let mut bad = ct.clone();
    let (first, second) = (MEDIA_HEADER_LEN, MEDIA_HEADER_LEN + sealed);
    let chunk0 = ct[first..first + sealed].to_vec();
    bad.copy_within(second..second + sealed, first);
    bad[second..second + sealed].copy_from_slice(&chunk0);
    assert!(open(&bad, key).is_err());
}

#[test]
fn appended_bytes_fail() {
    let (mut ct, key) = seal(&plaintext(2 * CS));
    ct.extend_from_slice(&[0; TAG]);
    assert!(open(&ct, key).is_err());
}

#[test]
fn wrong_key_fails() {
    let enc = encrypt_media(&plaintext(10)).unwrap();
    let mut key = enc.key;
    key[0] ^= 1;
    assert!(matches!(
        decrypt_media(&enc.ciphertext, &key, &enc.sha256),
        Err(MediaError::Malformed { .. })
    ));
}

#[test]
fn wrong_sha256_fails() {
    let data = plaintext(10);
    let enc = encrypt_media(&data).unwrap();
    let mut digest = enc.sha256;
    digest[31] ^= 1;
    assert!(matches!(
        decrypt_media(&enc.ciphertext, &enc.key, &digest),
        Err(MediaError::DigestMismatch)
    ));
    let mut out = Vec::new();
    assert!(matches!(
        MediaDecryptor::new(enc.key, digest).decrypt(&enc.ciphertext[..], &mut out),
        Err(MediaError::DigestMismatch)
    ));
}

#[test]
fn rejects_bad_header_and_chunk_size() {
    assert!(MediaEncryptor::with_chunk_size(0).is_err());
    assert!(MediaEncryptor::with_chunk_size(u32::MAX).is_err());
    let (ct, key) = seal(&plaintext(5));
    let mut bad = ct.clone();
    bad[0] = b'X';
    assert!(open(&bad, key).is_err());
    let mut bad = ct.clone();
    bad[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(open(&bad, key).is_err());
    assert!(open(&[], key).is_err());
}
