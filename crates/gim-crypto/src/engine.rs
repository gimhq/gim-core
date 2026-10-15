use std::collections::BTreeSet;
use std::sync::Arc;

use gim_common::{DeviceRef, GroupId};
use gim_identity::{DeviceSigningKey, RootPublicKey, SignedDeviceCert};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{GroupId as MlsGroupId, *};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::storage::{StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;

use crate::config::{group_create_config, group_join_config, leaf_capabilities, CIPHERSUITE};
use crate::credential::{self, DeviceListLookup, GimCredential, NoDeviceLists};
use crate::{CryptoError, CryptoStore, StoredIdentity, GIM_CREDENTIAL_TYPE};

type Result<T> = std::result::Result<T, CryptoError>;

/// Upper bound for one [`MlsEngine::generate_key_packages`] call.
pub const MAX_KEY_PACKAGES_PER_CALL: u32 = 1000;

/// A commit created locally and not yet merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutput {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    /// Epoch the commit was created in; sent to the hub as `epoch`.
    pub epoch: u64,
    /// Devices whose leaves the commit adds.
    pub added: Vec<DeviceRef>,
    /// Devices whose leaves the commit removes.
    pub removed: Vec<DeviceRef>,
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
        /// The device a Remove proposal removes; the sender itself when it
        /// leaves the group.
        removed: Option<DeviceRef>,
    },
}

/// Stateless MLS operations. Every call borrows a [`CryptoStore`] for its
/// duration; the engine itself holds only the crypto backend and the
/// [`DeviceListLookup`] used to validate gim credentials.
///
/// Every leaf carries a [`GimCredential`]: every incoming or added leaf must
/// pass [`credential::validate`] against the engine's lookup, and
/// application messages from a device revoked in the latest known
/// DeviceList are rejected.
pub struct MlsEngine {
    crypto: RustCrypto,
    device_lists: Arc<dyn DeviceListLookup + Send + Sync>,
}

impl Default for MlsEngine {
    fn default() -> Self {
        Self::with_device_list_lookup(Arc::new(NoDeviceLists))
    }
}

impl std::fmt::Debug for MlsEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsEngine").finish_non_exhaustive()
    }
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
struct Account<'a> {
    device: DeviceRef,
    signer: DeviceSigner<'a>,
    /// Encoded [`GimCredential`].
    credential: Vec<u8>,
}

impl Account<'_> {
    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: Credential::new(
                CredentialType::Other(GIM_CREDENTIAL_TYPE),
                self.credential.clone(),
            ),
            signature_key: self.signer.public.clone().into(),
        }
    }

    fn capabilities(&self) -> Capabilities {
        leaf_capabilities()
    }
}

/// Ed25519 signer over the stored device key seed.
struct DeviceSigner<'a> {
    crypto: &'a RustCrypto,
    seed: Vec<u8>,
    public: Vec<u8>,
}

impl Drop for DeviceSigner<'_> {
    fn drop(&mut self) {
        self.seed.fill(0);
    }
}

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(self.signature_scheme(), payload, &self.seed)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        CIPHERSUITE.signature_algorithm()
    }
}

impl MlsEngine {
    /// An engine that knows no device lists (no revocations).
    pub fn new() -> Self {
        Self::default()
    }

    /// An engine validating gim credentials against `device_lists`.
    pub fn with_device_list_lookup(device_lists: Arc<dyn DeviceListLookup + Send + Sync>) -> Self {
        Self {
            crypto: RustCrypto::default(),
            device_lists,
        }
    }

    /// Creates a device identity with a self-certifying [`GimCredential`]:
    /// `signed_cert` must verify under `root_public_key` and certify the
    /// public half of `device_key`.
    pub fn create_identity_v2(
        &self,
        store: &impl CryptoStore,
        device_key: &DeviceSigningKey,
        root_public_key: RootPublicKey,
        signed_cert: SignedDeviceCert,
    ) -> Result<()> {
        if store.load_identity().map_err(CryptoError::store)?.is_some() {
            return Err(CryptoError::invalid("identity already exists"));
        }
        let credential = GimCredential::new(root_public_key, signed_cert);
        let cert = credential.verify()?;
        if cert.device_public_key != device_key.public() {
            return Err(CryptoError::InvalidCredential {
                reason: "device key does not match the certified device key".into(),
            });
        }
        store
            .save_identity(&StoredIdentity {
                device: DeviceRef::new(cert.user_id, cert.device_id),
                signature_private_key: device_key.to_seed().to_vec(),
                signature_public_key: device_key.public().as_bytes().to_vec(),
                credential: credential.encode(),
            })
            .map_err(CryptoError::store)
    }

    pub fn identity(&self, store: &impl CryptoStore) -> Result<DeviceRef> {
        Ok(self.account(store)?.device)
    }

    pub fn signature_public_key(&self, store: &impl CryptoStore) -> Result<Vec<u8>> {
        Ok(self.account(store)?.signer.public.clone())
    }

    /// Whether `device` is revoked in the latest DeviceList the engine's
    /// lookup knows for its user.
    pub fn is_revoked(&self, device: &DeviceRef) -> bool {
        self.device_lists
            .device_list(&device.user_id)
            .is_some_and(|list| list.is_revoked(&device.device_id))
    }

    /// Validates a KeyPackage as a hub does on upload (signature,
    /// ciphersuite, gim credential against the engine's lookup) and returns
    /// the device its credential certifies.
    pub fn key_package_device(&self, key_package: &[u8]) -> Result<DeviceRef> {
        let key_package = self.validate_key_package(key_package)?;
        self.validate_leaf(key_package.leaf_node())
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
        let account = self.account(store)?;
        (0..count)
            .map(|_| self.key_package(store, &account, false))
            .collect()
    }

    /// Generates a reusable KeyPackage carrying the LastResort extension.
    pub fn generate_last_resort_key_package(&self, store: &impl CryptoStore) -> Result<Vec<u8>> {
        self.key_package(store, &self.account(store)?, true)
    }

    /// Creates a group whose MLS GroupId is the UTF-8 bytes of `group_id`.
    pub fn create_group(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<()> {
        let account = self.account(store)?;
        if group_ids(store)?.contains(group_id) {
            return Err(CryptoError::invalid(format!(
                "group {group_id} already exists"
            )));
        }
        MlsGroup::new_with_group_id(
            &self.provider(store),
            &account.signer,
            &group_create_config(account.capabilities()),
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
        let account = self.account(store)?;
        let key_packages = key_packages
            .iter()
            .map(|bytes| {
                let key_package = self.validate_key_package(bytes)?;
                self.validate_leaf(key_package.leaf_node())?;
                Ok(key_package)
            })
            .collect::<Result<Vec<_>>>()?;
        let added = key_packages
            .iter()
            .map(|kp| device_of(kp.leaf_node().credential()))
            .collect::<Result<Vec<_>>>()?;
        let mut group = load_group(store, group_id)?;
        // Own commits carry their proposals inline only.
        group
            .clear_pending_proposals(store.mls_storage())
            .map_err(CryptoError::store)?;
        let epoch = group.epoch().as_u64();
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider(store), &account.signer, &key_packages)
            .map_err(CryptoError::mls)?;
        Ok(CommitOutput {
            commit: serialize(&commit)?,
            welcome: Some(serialize(&welcome)?),
            epoch,
            added,
            removed: Vec::new(),
        })
    }

    /// Creates a pending commit removing every leaf of the given devices
    /// (e.g. all leaves of a revoked device). Each device must have at least
    /// one leaf in the group.
    pub fn remove_members(
        &self,
        store: &impl CryptoStore,
        group_id: &GroupId,
        members: &[DeviceRef],
    ) -> Result<CommitOutput> {
        if members.is_empty() {
            return Err(CryptoError::invalid("no members to remove"));
        }
        let account = self.account(store)?;
        let mut group = load_group(store, group_id)?;
        let mut removed = Vec::new();
        let mut indices = Vec::new();
        for device in members {
            if removed.contains(device) {
                continue;
            }
            let leaves = group
                .members()
                .filter(|m| device_of(&m.credential).is_ok_and(|d| &d == device))
                .map(|m| m.index)
                .collect::<Vec<_>>();
            if leaves.is_empty() {
                return Err(CryptoError::invalid(format!("{device} is not a member")));
            }
            indices.extend(leaves);
            removed.push(device.clone());
        }
        group
            .clear_pending_proposals(store.mls_storage())
            .map_err(CryptoError::store)?;
        let epoch = group.epoch().as_u64();
        let (commit, welcome, _group_info) = group
            .remove_members(&self.provider(store), &account.signer, &indices)
            .map_err(CryptoError::mls)?;
        Ok(CommitOutput {
            commit: serialize(&commit)?,
            welcome: welcome.as_ref().map(serialize).transpose()?,
            epoch,
            added: Vec::new(),
            removed,
        })
    }

    /// Creates a Remove proposal for this device's own leaf, to be committed
    /// by another member. The local group is left untouched; callers delete
    /// it once the proposal was delivered.
    pub fn leave_group(&self, store: &impl CryptoStore, group_id: &GroupId) -> Result<Vec<u8>> {
        let account = self.account(store)?;
        let mut group = load_group(store, group_id)?;
        let proposal = group
            .leave_group(&self.provider(store), &account.signer)
            .map_err(CryptoError::mls)?;
        serialize(&proposal)
    }

    /// Merges the pending commit after the hub accepted it; returns the
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
        for member in staged.members() {
            credential::validate(
                &member.credential,
                &member.signature_key,
                &*self.device_lists,
            )?;
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
        if message.wire_format() == WireFormat::PrivateMessage && message.is_handshake_message() {
            return Err(CryptoError::invalid(
                "handshake messages must be sent as PublicMessage",
            ));
        }
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
        let sender_leaf = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                if self.is_revoked(&sender) {
                    return Err(credential::CredentialError::RevokedDevice {
                        user: sender.user_id,
                        device: sender.device_id,
                    }
                    .into());
                }
                Ok(ProcessedMessage::Application {
                    sender,
                    plaintext: message.into_bytes(),
                    epoch,
                })
            }
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let removed = match proposal.proposal() {
                    Proposal::Add(add) => {
                        self.validate_leaf(add.key_package().leaf_node())?;
                        None
                    }
                    Proposal::Update(update) => {
                        self.validate_leaf(update.leaf_node())?;
                        None
                    }
                    Proposal::Remove(remove) => Some(
                        group
                            .member(remove.removed())
                            .ok_or_else(|| CryptoError::mls("removed leaf is not a member"))
                            .and_then(device_of)?,
                    ),
                    Proposal::SelfRemove => Some(sender.clone()),
                    _ => None,
                };
                group
                    .store_pending_proposal(store.mls_storage(), *proposal)
                    .map_err(CryptoError::mls)?;
                Ok(ProcessedMessage::Proposal { sender, removed })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.validate_commit(&group, sender_leaf, &commit)?;
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
        let account = self.account(store)?;
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

    fn account(&self, store: &impl CryptoStore) -> Result<Account<'_>> {
        let identity = store
            .load_identity()
            .map_err(CryptoError::store)?
            .ok_or_else(|| CryptoError::store("no identity; call create_identity_v2 first"))?;
        Ok(Account {
            device: identity.device.clone(),
            signer: DeviceSigner {
                crypto: &self.crypto,
                seed: identity.signature_private_key.clone(),
                public: identity.signature_public_key.clone(),
            },
            credential: identity.credential.clone(),
        })
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
        account: &Account<'_>,
        last_resort: bool,
    ) -> Result<Vec<u8>> {
        let mut builder = KeyPackage::builder().leaf_node_capabilities(account.capabilities());
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

    /// Validates a leaf's gim credential against the engine's lookup.
    fn validate_leaf(&self, leaf: &LeafNode) -> Result<DeviceRef> {
        credential::validate(
            leaf.credential(),
            leaf.signature_key().as_slice(),
            &*self.device_lists,
        )
    }

    /// Validates every new or changed leaf of an incoming commit, and the
    /// committer's leaf (so commits from revoked devices are rejected).
    fn validate_commit(
        &self,
        group: &MlsGroup,
        sender_leaf: Option<LeafNodeIndex>,
        commit: &StagedCommit,
    ) -> Result<()> {
        match commit.update_path_leaf_node() {
            Some(leaf) => {
                self.validate_leaf(leaf)?;
            }
            None => {
                let sender = sender_leaf
                    .and_then(|index| group.members().find(|m| m.index == index))
                    .ok_or_else(|| CryptoError::mls("commit sender is not a member"))?;
                credential::validate(
                    &sender.credential,
                    &sender.signature_key,
                    &*self.device_lists,
                )?;
            }
        }
        for add in commit.add_proposals() {
            self.validate_leaf(add.add_proposal().key_package().leaf_node())?;
        }
        for update in commit.update_proposals() {
            self.validate_leaf(update.update_proposal().leaf_node())?;
        }
        Ok(())
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

/// Maps a leaf credential to its certified device.
pub(crate) fn device_of(credential: &Credential) -> Result<DeviceRef> {
    let cert = GimCredential::from_mls(credential)?.verify()?;
    Ok(DeviceRef::new(cert.user_id, cert.device_id))
}

fn members_of(group: &MlsGroup) -> Result<Vec<DeviceRef>> {
    group.members().map(|m| device_of(&m.credential)).collect()
}

fn serialize(message: &MlsMessageOut) -> Result<Vec<u8>> {
    message.tls_serialize_detached().map_err(CryptoError::mls)
}

pub(crate) fn deserialize(bytes: &[u8]) -> Result<MlsMessageIn> {
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
