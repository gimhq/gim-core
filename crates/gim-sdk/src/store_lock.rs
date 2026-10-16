//! Cross-process lock of the local store, for an app and its extensions
//! (the iOS Notification Service Extension) that run on the same data
//! directory at the same time.
//!
//! `<data_dir>/gim.lock` carries an exclusive advisory lock (`flock` on
//! Unix) around every store mutation, and a generation counter: the first
//! 8 bytes, little-endian, incremented by every holder that may have
//! written. A process that takes the lock and finds a generation it did
//! not write itself knows that another process changed the store and
//! reloads what it keeps in memory (see `Client::run`). The next 8 bytes
//! count the wipes of the store (sign-out, see [`StoreLock::wipe`]): a
//! lock that took its first hold before a wipe fails every later hold with
//! [`ClientError::StoreWiped`], so a process still holding the deleted
//! database open never writes through it again.
//!
//! The lock file itself is never deleted, also not by a wipe: a process
//! that still has it open would keep locking the unlinked file while a new
//! one locked a fresh file at the same path, and the two would no longer
//! exclude each other.
//!
//! MLS group state is never cached: every MLS operation loads the group
//! from the store inside its transaction, so a stale epoch or ratchet
//! cannot be used once the lock is held.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
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
    /// The wipe count at the first hold: the store this lock belongs to.
    wipes: OnceLock<u64>,
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
            wipes: OnceLock::new(),
        })
    }

    /// Takes the lock: first in-process, then the file lock, waiting up to
    /// the timeout for another process to release it. Blocking. Fails with
    /// [`ClientError::StoreBusy`] after the timeout; the caller defers its
    /// mutation, it never goes ahead without the lock. Fails with
    /// [`ClientError::StoreWiped`] once the store was wiped after this
    /// lock's first hold.
    pub fn acquire(&self) -> Result<StoreLockGuard<'_>> {
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        self.lock_file(&file)?;
        let mut guard = StoreLockGuard {
            file,
            lock: self,
            generation: 0,
        };
        let (generation, wipes) = read_counters(&mut guard.file)?;
        guard.generation = generation;
        if *self.wipes.get_or_init(|| wipes) != wipes {
            return Err(ClientError::StoreWiped);
        }
        Ok(guard)
    }

    /// Runs `wipe`, which deletes the store and its secrets (sign-out),
    /// under the lock, then fails every hold of a lock that took its
    /// first hold before (in this or another process) with
    /// [`ClientError::StoreWiped`]. Blocking.
    ///
    /// If another process holds the lock past the timeout, `wipe` runs
    /// anyway (logged): a stuck extension must not keep the user signed
    /// in. The holder's next hold fails; until then it writes to the
    /// unlinked database, which SQLite refuses (`SQLITE_READONLY_DBMOVED`)
    /// or which goes nowhere.
    pub fn wipe(&self, wipe: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let locked = match self.lock_file(&file) {
            Ok(()) => true,
            Err(ClientError::StoreBusy(waited)) => {
                tracing::warn!(?waited, "wiping the store without its lock");
                false
            }
            Err(err) => return Err(err),
        };
        // First: a holder waiting for the lock fails instead of going on
        // with a store that is being deleted.
        let result = read_counters(&mut file)
            .and_then(|(_, wipes)| write_counter(&mut file, 8, wipes.wrapping_add(1)))
            .and_then(|()| wipe());
        if locked {
            let _ = file.unlock();
        }
        result
    }

    /// Takes the file lock, waiting up to the timeout.
    fn lock_file(&self, file: &File) -> Result<()> {
        let started = Instant::now();
        let mut poll = Duration::from_millis(2);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(()),
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
    }
}

/// The generation and the wipe count; each reads as 0 while missing or
/// short (a new file).
fn read_counters(file: &mut File) -> Result<(u64, u64)> {
    let mut bytes = [0u8; 16];
    file.seek(SeekFrom::Start(0))?;
    let mut read = 0;
    while read < bytes.len() {
        match file.read(&mut bytes[read..])? {
            0 => break,
            n => read += n,
        }
    }
    let counter = |at: usize| match bytes.get(at..at + 8) {
        Some(b) if read >= at + 8 => u64::from_le_bytes(b.try_into().expect("8 bytes")),
        _ => 0,
    };
    Ok((counter(0), counter(8)))
}

fn write_counter(file: &mut File, at: u64, value: u64) -> Result<()> {
    file.seek(SeekFrom::Start(at))?;
    file.write_all(&value.to_le_bytes())?;
    Ok(())
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
        write_counter(&mut self.file, 0, next)?;
        self.generation = next;
        Ok(())
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

    #[test]
    fn a_wipe_fails_the_locks_held_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let a = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        let b = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        a.acquire().unwrap().mark_written().unwrap();
        drop(b.acquire().unwrap());
        let mut wiped = false;
        a.wipe(|| {
            wiped = true;
            Ok(())
        })
        .unwrap();
        assert!(wiped);
        assert!(matches!(a.acquire(), Err(ClientError::StoreWiped)));
        assert!(matches!(b.acquire(), Err(ClientError::StoreWiped)));
        // A lock opened afterwards belongs to the new store; the
        // generation is kept.
        let c = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        let guard = c.acquire().unwrap();
        assert!(guard.changed_elsewhere());
        drop(guard);
        // A failed hold released the file lock.
        drop(c.acquire().unwrap());
    }

    #[test]
    fn a_wipe_goes_ahead_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let a = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        let b = StoreLock::open(dir.path(), Duration::from_millis(50)).unwrap();
        let held = b.acquire().unwrap();
        let started = Instant::now();
        a.wipe(|| Ok(())).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(50));
        drop(held);
        assert!(matches!(b.acquire(), Err(ClientError::StoreWiped)));
    }
}
