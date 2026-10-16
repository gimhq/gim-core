//! Cross-process lock of the local store, for an app and its extensions
//! (the iOS Notification Service Extension) that run on the same data
//! directory at the same time.
//!
//! `<data_dir>/gim.lock` carries an exclusive advisory lock (`flock` on
//! Unix) around every store mutation, and a generation counter: the first
//! 8 bytes, little-endian, incremented by every holder that may have
//! written. A process that takes the lock and finds a generation it did
//! not write itself knows that another process changed the store and
//! reloads what it keeps in memory (see `Client::run`).
//!
//! MLS group state is never cached: every MLS operation loads the group
//! from the store inside its transaction, so a stale epoch or ratchet
//! cannot be used once the lock is held.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::{ClientError, Result};

/// File name of the lock inside the data directory.
pub const LOCK_FILE_NAME: &str = "gim.lock";
/// Default of [`crate::ClientBuilder::store_lock_timeout`].
pub const DEFAULT_STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest sleep between two attempts to take the lock.
const MAX_POLL: Duration = Duration::from_millis(50);

/// The lock file of one data directory, opened once per client.
pub struct StoreLock {
    /// In-process serialization; always taken before the file lock.
    file: Mutex<File>,
    timeout: Duration,
    /// The generation this process last saw or wrote.
    seen: AtomicU64,
}

impl std::fmt::Debug for StoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreLock")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl StoreLock {
    /// Opens (creating it owner-only if needed) `data_dir`'s lock file.
    /// [`StoreLock::acquire`] waits up to `timeout` for another process.
    pub fn open(data_dir: &Path, timeout: Duration) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(data_dir.join(LOCK_FILE_NAME))?;
        Ok(Self {
            file: Mutex::new(file),
            timeout,
            seen: AtomicU64::new(0),
        })
    }

    /// Takes the lock: first in-process, then the file lock, waiting up to
    /// the timeout for another process to release it. Blocking. Fails with
    /// [`ClientError::StoreBusy`] after the timeout; the caller defers its
    /// mutation, it never goes ahead without the lock.
    pub fn acquire(&self) -> Result<StoreLockGuard<'_>> {
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let started = Instant::now();
        let mut poll = Duration::from_millis(2);
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    let left = self.timeout.saturating_sub(started.elapsed());
                    if left.is_zero() {
                        return Err(ClientError::StoreBusy(self.timeout));
                    }
                    std::thread::sleep(poll.min(left));
                    poll = (poll * 2).min(MAX_POLL);
                }
                Err(TryLockError::Error(err)) => return Err(err.into()),
            }
        }
        let mut guard = StoreLockGuard {
            file,
            lock: self,
            generation: 0,
        };
        guard.generation = guard.read_generation()?;
        Ok(guard)
    }
}

/// The held lock; released when dropped.
pub struct StoreLockGuard<'a> {
    file: MutexGuard<'a, File>,
    lock: &'a StoreLock,
    generation: u64,
}

impl std::fmt::Debug for StoreLockGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreLockGuard")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl StoreLockGuard<'_> {
    /// Whether another process changed the store since this process last
    /// held the lock.
    pub fn changed_elsewhere(&self) -> bool {
        self.generation != self.lock.seen.load(Ordering::SeqCst)
    }

    /// Records that the store may have changed under this lock, for the
    /// other processes.
    pub fn mark_written(&mut self) -> Result<()> {
        let next = self.generation.wrapping_add(1);
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&next.to_le_bytes())?;
        self.generation = next;
        Ok(())
    }

    /// A missing or short counter (a new file) reads as 0.
    fn read_generation(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.file.seek(SeekFrom::Start(0))?;
        let mut read = 0;
        while read < bytes.len() {
            match self.file.read(&mut bytes[read..])? {
                0 => return Ok(0),
                n => read += n,
            }
        }
        Ok(u64::from_le_bytes(bytes))
    }
}

impl Drop for StoreLockGuard<'_> {
    fn drop(&mut self) {
        self.lock.seen.store(self.generation, Ordering::SeqCst);
        // Closing the file or ending the process releases it as well.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_shared_between_holders() {
        let dir = tempfile::tempdir().unwrap();
        let a = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        let b = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        drop(a.acquire().unwrap());
        let mut held = b.acquire().unwrap();
        // Separate open files conflict, also within one process.
        assert!(matches!(a.acquire(), Err(ClientError::StoreBusy(_))));
        held.mark_written().unwrap();
        drop(held);
        let guard = a.acquire().unwrap();
        assert!(guard.changed_elsewhere());
        drop(guard);
        assert!(!a.acquire().unwrap().changed_elsewhere());
        assert!(!b.acquire().unwrap().changed_elsewhere());
    }
}
