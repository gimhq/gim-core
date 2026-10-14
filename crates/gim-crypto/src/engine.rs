use std::collections::BTreeSet;

use gim_common::{DeviceRef, GroupId};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{GroupId as MlsGroupId, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::storage::{StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;

use crate::config::{group_create_config, group_join_config, leaf_capabilities, CIPHERSUITE};
use crate::{CryptoError, CryptoStore, StoredIdentity};

type Result<T> = std::result::Result<T, CryptoError>;

/// Upper bound for one [`MlsEngine::generate_key_packages`] call.
pub const MAX_KEY_PACKAGES_PER_CALL: u32 = 1000;

/// A commit created locally and not yet merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutput {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    /// Epoch the commit was created in; sent to gim-server as `epoch`.
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupJoined {
    pub group_id: GroupId,
    pub epoch: u64,
    pub members: Vec<DeviceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessedMessage {
    Application {
        sender: DeviceRef,
        plaintext: Vec<u8>,
        epoch: u64,
    },
    Commit {
        sender: DeviceRef,
        /// Epoch after the commit was merged.
        epoch: u64,
        added: Vec<DeviceRef>,
        removed: Vec<DeviceRef>,
        self_removed: bool,
    },
    Proposal {
        sender: DeviceRef,
    },
}

/// Stateless MLS operations. Every call borrows a [`CryptoStore`] for its
/// duration; the engine itself holds only the crypto backend.
#[derive(Debug, Default)]
pub struct MlsEngine {
    crypto: RustCrypto,
}

/// OpenMLS provider assembled per call from the engine and a borrowed store.
struct Provider<'a, S> {
    crypto: &'a RustCrypto,
    storage: &'a S,
}

impl<S: StorageProvider<CURRENT_VERSION>> OpenMlsProvider for Provider<'_, S> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = S;

    fn storage(&self) -> &S {
        self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        self.crypto
    }
}

/// The device identity loaded from the store for one operation.
struct Account {
    device: DeviceRef,
    signer: SignatureKeyPair,
}

impl Account {
    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.device.credential_identity()).into(),
            signature_key: self.signer.to_public_vec().into(),
        }
    }
}

impl MlsEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates the device identity (fresh Ed25519 signature key) in `store`.
    pub fn create_identity(&self, store: &impl CryptoStore, device: DeviceRef) -> Result<()> {
        if store.load_identity().map_err(CryptoError::store)?.is_some() {
            return Err(CryptoError::invalid("identity already exists"));
        }
        let (signature_private_key, signature_public_key) = self
            .crypto
            .signature_key_gen(CIPHERSUITE.signature_algorithm())
            .map_err(CryptoError::mls)?;
        store
            .save_identity(&StoredIdentity {
                device,
                signature_private_key,
                signature_public_key,
            })
            .map_err(CryptoError::store)
    }

    pub fn identity(&self, store: &impl CryptoStore) -> Result<DeviceRef> {
        Ok(account(store)?.device)
    }

    pub fn signature_public_key(&self, store: &impl CryptoStore) -> Result<Vec<u8>> {
        Ok(account(store)?.signer.to_public_vec())
    }

    /// Generates one-time KeyPackages, each a TLS-serialized `MlsMessage`.
    pub fn generate_key_packages(
        &self,
        store: &impl CryptoStore,
        count: u32,
    ) -> Result<Vec<Vec<u8>>> {
        if count > MAX_KEY_PACKAGES_PER_CALL {
            return Err(CryptoError::invalid(format!(
                "count must be at most {MAX_KEY_PACKAGES_PER_CALL}"
            )));
        }
        let account = account(store)?;
        (0..count)
            .map(|_| self.key_package(store, &account, false))
            .collect()
    }

    /// Generates a reusable KeyPackage carrying the LastResort extension.
    pub fn generate_last_resort_key_package(&self, store: &impl CryptoStore) -> Result<Vec<u8>> {
        self.key_package(store, &account(store)?, true)
    }

    /// Creates a group whose MLS GroupId is the UTF-8 bytes of `group_id`.
    pub fn create_group(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<()> {
        let account = account(store)?;
        if group_ids(store)?.contains(group_id) {
            return Err(CryptoError::invalid(format!(
                "group {group_id} already exists"
            )));
        }
        MlsGroup::new_with_group_id(
            &self.provider(store),
            &account.signer,
            &group_create_config(),
            mls_group_id(group_id),
            account.credential_with_key(),
        )
        .map_err(CryptoError::mls)?;
        store.add_group_id(group_id).map_err(CryptoError::store)
    }

    /// Validates the KeyPackages and creates a pending commit adding them,
    /// plus a self-contained Welcome.
    pub fn add_members(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
        key_packages: &[Vec<u8>],
    ) -> Result<CommitOutput> {
        if key_packages.is_empty() {
            return Err(CryptoError::invalid("no key packages"));
        }
        let key_packages = key_packages
            .iter()
            .map(|bytes| self.validate_key_package(bytes))
            .collect::<Result<Vec<_>>>()?;
        let account = account(store)?;
        let mut group = load_group(store, group_id)?;
        let epoch = group.epoch().as_u64();
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider(store), &account.signer, &key_packages)
            .map_err(CryptoError::mls)?;
        Ok(CommitOutput {
            commit: serialize(&commit)?,
            welcome: Some(serialize(&welcome)?),
            epoch,
        })
    }

    /// Creates a pending commit removing the given devices.
    pub fn remove_members(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
        members: &[DeviceRef],
    ) -> Result<CommitOutput> {
        if members.is_empty() {
            return Err(CryptoError::invalid("no members to remove"));
        }
        let account = account(store)?;
        let mut group = load_group(store, group_id)?;
        let indices = members
            .iter()
            .map(|device| {
                let identity = device.credential_identity();
                group
                    .members()
                    .find(|m| m.credential.serialized_content() == identity.as_slice())
                    .map(|m| m.index)
                    .ok_or_else(|| CryptoError::invalid(format!("{device} is not a member")))
            })
            .collect::<Result<Vec<_>>>()?;
        let epoch = group.epoch().as_u64();
        let (commit, welcome, _group_info) = group
            .remove_members(&self.provider(store), &account.signer, &indices)
            .map_err(CryptoError::mls)?;
        Ok(CommitOutput {
            commit: serialize(&commit)?,
            welcome: welcome.as_ref().map(serialize).transpose()?,
            epoch,
        })
    }

    /// Merges the pending commit after the server accepted it; returns the
    /// new epoch.
    pub fn merge_pending_commit(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
    ) -> Result<u64> {
        let mut group = load_group(store, group_id)?;
        if group.pending_commit().is_none() {
            return Err(CryptoError::NoPendingCommit);
        }
        group
            .merge_pending_commit(&self.provider(store))
            .map_err(CryptoError::mls)?;
        Ok(group.epoch().as_u64())
    }

    /// Drops the pending commit after the server rejected it (409).
    pub fn clear_pending_commit(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<()> {
        let mut group = load_group(store, group_id)?;
        if group.pending_commit().is_none() {
            return Err(CryptoError::NoPendingCommit);
        }
        group
            .clear_pending_commit(store.mls_storage())
            .map_err(CryptoError::mls)
    }

    /// Joins a group from a Welcome; the group id is recovered from the MLS
    /// GroupId bytes.
    pub fn join_from_welcome(
        &self,
        store: &impl CryptoStore,
        welcome: &[u8],
    ) -> Result<GroupJoined> {
        let welcome = match deserialize(welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(CryptoError::invalid("message is not a Welcome")),
        };
        let provider = self.provider(store);
        let staged =
            StagedWelcome::new_from_welcome(&provider, &group_join_config(), welcome, None)
                .map_err(CryptoError::mls)?;
        let group_id = String::from_utf8(staged.group_context().group_id().to_vec())
            .map_err(|_| CryptoError::invalid("group id is not UTF-8"))
            .and_then(|id| GroupId::new(id).map_err(CryptoError::from))?;
        if group_ids(store)?.contains(&group_id) {
            return Err(CryptoError::invalid(format!(
                "group {group_id} already exists"
            )));
        }
        let group = staged.into_group(&provider).map_err(CryptoError::mls)?;
        store.add_group_id(&group_id).map_err(CryptoError::store)?;
        Ok(GroupJoined {
            group_id,
            epoch: group.epoch().as_u64(),
            members: members_of(&group)?,
        })
    }

    /// Processes an incoming group message. Commits are merged immediately;
    /// if the commit removed this device the group is deleted locally.
    ///
    /// Messages sent by this device must not be fed back: they return
    /// `InvalidInput` (own commits are applied with `merge_pending_commit`).
    pub fn process_message(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
        message: &[u8],
    ) -> Result<ProcessedMessage> {
        let mut group = load_group(store, group_id)?;
        let message = deserialize(message)?
            .try_into_protocol_message()
            .map_err(|_| CryptoError::invalid("message is not a group message"))?;
        let current_epoch = group.epoch().as_u64();
        let message_epoch = message.epoch().as_u64();
        if message_epoch > current_epoch {
            return Err(wrong_epoch(message_epoch, current_epoch));
        }
        let provider = self.provider(store);
        let processed = group.process_message(&provider, message).map_err(|e| {
            if message_epoch != current_epoch {
                wrong_epoch(message_epoch, current_epoch)
            } else {
                CryptoError::mls(e)
            }
        })?;
        let sender = device_of(processed.credential())?;
        let epoch = processed.epoch().as_u64();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(ProcessedMessage::Application {
                    sender,
                    plaintext: message.into_bytes(),
                    epoch,
                })
            }
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                group
                    .store_pending_proposal(store.mls_storage(), *proposal)
                    .map_err(CryptoError::mls)?;
                Ok(ProcessedMessage::Proposal { sender })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                let added = commit
                    .add_proposals()
                    .map(|p| device_of(p.add_proposal().key_package().leaf_node().credential()))
                    .collect::<Result<Vec<_>>>()?;
                let removed = commit
                    .remove_proposals()
                    .map(|p| {
                        group
                            .member(p.remove_proposal().removed())
                            .ok_or_else(|| CryptoError::mls("removed leaf is not a member"))
                            .and_then(device_of)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let self_removed = commit.self_removed();
                let epoch = commit.group_context().epoch().as_u64();
                group
                    .merge_staged_commit(&provider, *commit)
                    .map_err(CryptoError::mls)?;
                if self_removed {
                    delete(store, &mut group, group_id)?;
                }
                Ok(ProcessedMessage::Commit {
                    sender,
                    epoch,
                    added,
                    removed,
                    self_removed,
                })
            }
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => {
                Err(CryptoError::invalid("message was sent by this device"))
            }
        }
    }

    /// Encrypts an application message for the group.
    pub fn encrypt(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let account = account(store)?;
        let mut group = load_group(store, group_id)?;
        let message = group
            .create_message(&self.provider(store), &account.signer, plaintext)
            .map_err(CryptoError::mls)?;
        serialize(&message)
    }

    pub fn group_epoch(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<u64> {
        Ok(load_group(store, group_id)?.epoch().as_u64())
    }

    pub fn group_members(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
    ) -> Result<Vec<DeviceRef>> {
        members_of(&load_group(store, group_id)?)
    }

    pub fn group_ids(&self, store: &impl CryptoStore) -> Result<BTreeSet<GroupId>> {
        group_ids(store)
    }

    pub fn has_group(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<bool> {
        Ok(group_ids(store)?.contains(group_id))
    }

    /// Deletes the group's local state.
    pub fn delete_group(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<()> {
        let mut group = load_group(store, group_id)?;
        delete(store, &mut group, group_id)
    }

    fn provider<'a, S: CryptoStore>(&'a self, store: &'a S) -> Provider<'a, S::MlsStorage> {
        Provider {
            crypto: &self.crypto,
            storage: store.mls_storage(),
        }
    }

    fn key_package(
        &self,
        store: &impl CryptoStore,
        account: &Account,
        last_resort: bool,
    ) -> Result<Vec<u8>> {
        let mut builder = KeyPackage::builder().leaf_node_capabilities(leaf_capabilities());
        if last_resort {
            builder = builder.mark_as_last_resort();
        }
        let bundle = builder
            .build(
                CIPHERSUITE,
                &self.provider(store),
                &account.signer,
                account.credential_with_key(),
            )
            .map_err(CryptoError::mls)?;
        serialize(&MlsMessageOut::from(bundle.key_package().clone()))
    }

    fn validate_key_package(&self, bytes: &[u8]) -> Result<KeyPackage> {
        let key_package = match deserialize(bytes)?.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => return Err(CryptoError::invalid("message is not a KeyPackage")),
        };
        let key_package = key_package
            .validate(&self.crypto, ProtocolVersion::Mls10)
            .map_err(|e| CryptoError::invalid(format!("invalid KeyPackage: {e}")))?;
        if key_package.ciphersuite() != CIPHERSUITE {
            return Err(CryptoError::invalid("KeyPackage has the wrong ciphersuite"));
        }
        device_of(key_package.leaf_node().credential())?;
        Ok(key_package)
    }
}

fn account(store: &impl CryptoStore) -> Result<Account> {
    let identity = store
        .load_identity()
        .map_err(CryptoError::store)?
        .ok_or_else(|| CryptoError::store("no identity; call create_identity first"))?;
    Ok(Account {
        device: identity.device,
        signer: SignatureKeyPair::from_raw(
            CIPHERSUITE.signature_algorithm(),
            identity.signature_private_key,
            identity.signature_public_key,
        ),
    })
}

fn group_ids(store: &impl CryptoStore) -> Result<BTreeSet<GroupId>> {
    store.group_ids().map_err(CryptoError::store)
}

fn mls_group_id(group_id: &GroupId) -> MlsGroupId {
    MlsGroupId::from_slice(group_id.as_str().as_bytes())
}

fn load_group(store: &impl CryptoStore, group_id: &GroupId) -> Result<MlsGroup> {
    let unknown = || CryptoError::UnknownGroup {
        group_id: group_id.to_string(),
    };
    if !group_ids(store)?.contains(group_id) {
        return Err(unknown());
    }
    MlsGroup::load(store.mls_storage(), &mls_group_id(group_id))
        .map_err(CryptoError::store)?
        .ok_or_else(unknown)
}

fn delete(store: &impl CryptoStore, group: &mut MlsGroup, group_id: &GroupId) -> Result<()> {
    group
        .delete(store.mls_storage())
        .map_err(CryptoError::store)?;
    store.remove_group_id(group_id).map_err(CryptoError::store)
}

fn device_of(credential: &Credential) -> Result<DeviceRef> {
    Ok(DeviceRef::from_credential_identity(
        credential.serialized_content(),
    )?)
}

fn members_of(group: &MlsGroup) -> Result<Vec<DeviceRef>> {
    group.members().map(|m| device_of(&m.credential)).collect()
}

fn serialize(message: &MlsMessageOut) -> Result<Vec<u8>> {
    message.tls_serialize_detached().map_err(CryptoError::mls)
}

fn deserialize(bytes: &[u8]) -> Result<MlsMessageIn> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|e| CryptoError::invalid(format!("malformed MLS message: {e}")))
}

fn wrong_epoch(message_epoch: u64, current_epoch: u64) -> CryptoError {
    CryptoError::WrongEpoch {
        reason: format!("message epoch {message_epoch}, group epoch {current_epoch}"),
    }
}

#[cfg(test)]
mod tests;
