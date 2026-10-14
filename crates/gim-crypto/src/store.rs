use std::collections::BTreeSet;

use gim_common::{DeviceRef, GroupId};
use openmls_traits::storage::{StorageProvider, CURRENT_VERSION};

/// The device's MLS identity: who it is and its signature key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    pub device: DeviceRef,
    pub signature_private_key: Vec<u8>,
    pub signature_public_key: Vec<u8>,
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredIdentity")
            .field("device", &self.device)
            .field("signature_public_key", &self.signature_public_key)
            .finish_non_exhaustive()
    }
}

/// Persistence boundary of gim-crypto.
///
/// An implementation may be scoped to a database transaction: every
/// [`crate::MlsEngine`] call borrows the store only for its duration, so MLS
/// state written through [`CryptoStore::mls_storage`] and the caller's own rows
/// can commit together.
pub trait CryptoStore {
    type MlsStorage: StorageProvider<CURRENT_VERSION>;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Storage backing OpenMLS (groups, KeyPackages, secrets).
    fn mls_storage(&self) -> &Self::MlsStorage;

    fn load_identity(&self) -> Result<Option<StoredIdentity>, Self::Error>;
    fn save_identity(&self, identity: &StoredIdentity) -> Result<(), Self::Error>;

    /// Ids of the groups this device is a member of.
    fn group_ids(&self) -> Result<BTreeSet<GroupId>, Self::Error>;
    fn add_group_id(&self, group_id: &GroupId) -> Result<(), Self::Error>;
    fn remove_group_id(&self, group_id: &GroupId) -> Result<(), Self::Error>;
}
