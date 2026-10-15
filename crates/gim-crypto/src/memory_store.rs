//! In-memory [`CryptoStore`] for tests, with a versioned byte export.
//!
//! Export layout: one format version byte, then length-prefixed fields
//! (`u32` big-endian lengths and counts).

use std::collections::BTreeSet;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use gim_common::{DeviceRef, GroupId};
use openmls_memory_storage::MemoryStorage;

use crate::{CryptoStore, StoredIdentity};

const EXPORT_FORMAT_VERSION: u8 = 2;

#[derive(Debug, thiserror::Error)]
#[error("memory store: {0}")]
pub struct MemoryStoreError(String);

fn corrupt(reason: impl Into<String>) -> MemoryStoreError {
    MemoryStoreError(reason.into())
}

#[derive(Debug, Default)]
pub struct MemoryCryptoStore {
    mls: MemoryStorage,
    identity: RwLock<Option<StoredIdentity>>,
    group_ids: RwLock<BTreeSet<GroupId>>,
}

impl MemoryCryptoStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes the whole store.
    pub fn export(&self) -> Result<Vec<u8>, MemoryStoreError> {
        let mut out = vec![EXPORT_FORMAT_VERSION];
        match &*read(&self.identity)? {
            None => out.push(0),
            Some(identity) => {
                out.push(1);
                put_bytes(&mut out, identity.device.user_id.as_str().as_bytes())?;
                put_bytes(&mut out, identity.device.device_id.as_str().as_bytes())?;
                put_bytes(&mut out, &identity.signature_private_key)?;
                put_bytes(&mut out, &identity.signature_public_key)?;
                match &identity.credential {
                    None => out.push(0),
                    Some(credential) => {
                        out.push(1);
                        put_bytes(&mut out, credential)?;
                    }
                }
            }
        }
        let group_ids = read(&self.group_ids)?;
        put_len(&mut out, group_ids.len())?;
        for group_id in group_ids.iter() {
            put_bytes(&mut out, group_id.as_str().as_bytes())?;
        }
        let values = read(&self.mls.values)?;
        put_len(&mut out, values.len())?;
        for (key, value) in values.iter() {
            put_bytes(&mut out, key)?;
            put_bytes(&mut out, value)?;
        }
        Ok(out)
    }

    /// Rebuilds a store from [`MemoryCryptoStore::export`] output.
    pub fn import(bytes: &[u8]) -> Result<Self, MemoryStoreError> {
        let (&version, rest) = bytes.split_first().ok_or_else(|| corrupt("empty export"))?;
        if version != EXPORT_FORMAT_VERSION {
            return Err(corrupt(format!("unsupported export version {version}")));
        }
        let mut reader = Reader(rest);
        let identity = match reader.take(1)?[0] {
            0 => None,
            1 => Some(StoredIdentity {
                device: DeviceRef::parse(&reader.string()?, &reader.string()?)
                    .map_err(|e| corrupt(e.to_string()))?,
                signature_private_key: reader.bytes()?.to_vec(),
                signature_public_key: reader.bytes()?.to_vec(),
                credential: match reader.take(1)?[0] {
                    0 => None,
                    1 => Some(reader.bytes()?.to_vec()),
                    _ => return Err(corrupt("bad credential flag")),
                },
            }),
            _ => return Err(corrupt("bad identity flag")),
        };
        let group_ids = (0..reader.len()?)
            .map(|_| GroupId::new(reader.string()?).map_err(|e| corrupt(e.to_string())))
            .collect::<Result<_, _>>()?;
        let values = (0..reader.len()?)
            .map(|_| Ok((reader.bytes()?.to_vec(), reader.bytes()?.to_vec())))
            .collect::<Result<_, MemoryStoreError>>()?;
        if !reader.0.is_empty() {
            return Err(corrupt("trailing bytes"));
        }
        Ok(Self {
            mls: MemoryStorage {
                values: RwLock::new(values),
            },
            identity: RwLock::new(identity),
            group_ids: RwLock::new(group_ids),
        })
    }
}

impl CryptoStore for MemoryCryptoStore {
    type MlsStorage = MemoryStorage;
    type Error = MemoryStoreError;

    fn mls_storage(&self) -> &MemoryStorage {
        &self.mls
    }

    fn load_identity(&self) -> Result<Option<StoredIdentity>, MemoryStoreError> {
        Ok(read(&self.identity)?.clone())
    }

    fn save_identity(&self, identity: &StoredIdentity) -> Result<(), MemoryStoreError> {
        *write(&self.identity)? = Some(identity.clone());
        Ok(())
    }

    fn group_ids(&self) -> Result<BTreeSet<GroupId>, MemoryStoreError> {
        Ok(read(&self.group_ids)?.clone())
    }

    fn add_group_id(&self, group_id: &GroupId) -> Result<(), MemoryStoreError> {
        write(&self.group_ids)?.insert(group_id.clone());
        Ok(())
    }

    fn remove_group_id(&self, group_id: &GroupId) -> Result<(), MemoryStoreError> {
        write(&self.group_ids)?.remove(group_id);
        Ok(())
    }
}

fn read<T>(lock: &RwLock<T>) -> Result<RwLockReadGuard<'_, T>, MemoryStoreError> {
    lock.read().map_err(|_| corrupt("lock poisoned"))
}

fn write<T>(lock: &RwLock<T>) -> Result<RwLockWriteGuard<'_, T>, MemoryStoreError> {
    lock.write().map_err(|_| corrupt("lock poisoned"))
}

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), MemoryStoreError> {
    let len = u32::try_from(len).map_err(|_| corrupt("field too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MemoryStoreError> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MemoryStoreError> {
        if self.0.len() < n {
            return Err(corrupt("truncated export"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn len(&mut self) -> Result<usize, MemoryStoreError> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(buf) as usize)
    }

    fn bytes(&mut self) -> Result<&'a [u8], MemoryStoreError> {
        let len = self.len()?;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, MemoryStoreError> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| corrupt("string is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MemoryCryptoStore {
        sample_with(Some(vec![3; 40]))
    }

    fn sample_with(credential: Option<Vec<u8>>) -> MemoryCryptoStore {
        let store = MemoryCryptoStore::new();
        store
            .save_identity(&StoredIdentity {
                device: DeviceRef::parse("alice", "phone").unwrap(),
                signature_private_key: vec![1; 32],
                signature_public_key: vec![2; 32],
                credential,
            })
            .unwrap();
        store.add_group_id(&GroupId::new("g1").unwrap()).unwrap();
        store.add_group_id(&GroupId::new("g2").unwrap()).unwrap();
        store.remove_group_id(&GroupId::new("g2").unwrap()).unwrap();
        store
            .mls_storage()
            .values
            .write()
            .unwrap()
            .insert(vec![9], vec![8, 7]);
        store
    }

    #[test]
    fn export_import_round_trip() {
        let store = sample();
        let bytes = store.export().unwrap();
        assert_eq!(bytes[0], EXPORT_FORMAT_VERSION);
        let imported = MemoryCryptoStore::import(&bytes).unwrap();
        assert_eq!(
            imported.load_identity().unwrap(),
            store.load_identity().unwrap()
        );
        assert_eq!(imported.group_ids().unwrap(), store.group_ids().unwrap());
        assert_eq!(imported.group_ids().unwrap().len(), 1);
        assert_eq!(
            *imported.mls_storage().values.read().unwrap(),
            *store.mls_storage().values.read().unwrap()
        );
        assert_eq!(imported.export().unwrap(), bytes);
    }

    #[test]
    fn legacy_identity_round_trip() {
        let store = sample_with(None);
        let imported = MemoryCryptoStore::import(&store.export().unwrap()).unwrap();
        let identity = imported.load_identity().unwrap().unwrap();
        assert_eq!(identity.credential, None);
        assert_eq!(Some(identity), store.load_identity().unwrap());
    }

    #[test]
    fn empty_store_round_trip() {
        let bytes = MemoryCryptoStore::new().export().unwrap();
        let imported = MemoryCryptoStore::import(&bytes).unwrap();
        assert!(imported.load_identity().unwrap().is_none());
        assert!(imported.group_ids().unwrap().is_empty());
    }

    #[test]
    fn import_rejects_bad_input() {
        let bytes = sample().export().unwrap();
        assert!(MemoryCryptoStore::import(&[]).is_err());
        assert!(MemoryCryptoStore::import(&[EXPORT_FORMAT_VERSION + 1]).is_err());
        assert!(MemoryCryptoStore::import(&[EXPORT_FORMAT_VERSION, 2]).is_err());
        for cut in 1..bytes.len() {
            assert!(MemoryCryptoStore::import(&bytes[..cut]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(MemoryCryptoStore::import(&trailing).is_err());
    }
}
