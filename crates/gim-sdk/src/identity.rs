//! Identity: creating the user's root key and this device's certified key,
//! the handle directory, and the DeviceList cache that MLS credential
//! validation and revocation checks use.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use gim_base::model::UserInfo;
use gim_base::{BaseClient, StateReader, StateStore, StoreError, StoreTxn};
use gim_common::{now_ms, DeviceId, DeviceRef, UserId};
use gim_crypto::CryptoStore;
use gim_identity::recovery::{seal_root_key_backup, RecoveryCode};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList};
use zeroize::Zeroizing;

use crate::client::{
    Session, DEVICE_KEY_SECRET_KEY, ENROLLMENT_SECRET_KEY, KEY_PACKAGE_BATCH, ROOT_KEY_SECRET_KEY,
    SESSION_SECRET_KEY,
};
use crate::hosting::Publish;
use crate::routing::hub_unreachable;
use crate::transport::{AccessToken, Transport, TransportError, UserRecord};
use crate::{Client, ClientError, Result};

/// A new device of a user, ready to be enrolled with the hub.
pub(crate) struct Enrollment {
    pub(crate) root_seed: Zeroizing<[u8; 32]>,
    pub(crate) device_seed: Zeroizing<[u8; 32]>,
    pub(crate) cert: SignedDeviceCert,
    pub(crate) device_list: SignedDeviceList,
    /// Sealed root key backup to upload (new identities only).
    pub(crate) backup: Option<Vec<u8>>,
    pub(crate) me: UserInfo,
}

pub(crate) fn random_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut *seed)
        .map_err(|_| gim_base::BaseError::Random("identity key".into()))?;
    Ok(seed)
}

impl<S: StateStore + 'static> Client<S> {
    /// Creates a new user: a root key, this device's signing key certified
    /// by it, and the user's first DeviceList. Uploads the DeviceList, signs
    /// in, uploads the root key backup sealed with a new recovery code,
    /// uploads [`KEY_PACKAGE_BATCH`] KeyPackages plus a last-resort one, and
    /// creates the self group (the MLS group of the user's devices). The
    /// keys stay in [`crate::SecretStorage`]; the display name is kept
    /// locally and shared through the self group and with chats (the hub
    /// has no profiles). Publishes the user's hosting record; a failure
    /// there is only logged (the sync loop retries).
    ///
    /// Returns the recovery code. It is stored nowhere: show it to the user
    /// once.
    ///
    /// On failure everything the call stored is discarded (or, if that
    /// fails too, by the next onboarding call or [`Client::restore_session`],
    /// see [`crate::ENROLLMENT_SECRET_KEY`]): calling it again creates
    /// another user from scratch. What the failed attempt uploaded belongs
    /// to a user id nobody holds the root key of. Fails with
    /// [`ClientError::AlreadyLoggedIn`] once an identity was completed on
    /// this client (its session restored or not).
    pub async fn create_identity(&self, display_name: &str) -> Result<RecoveryCode> {
        self.create_user(display_name, None).await
    }

    /// [`Client::create_identity`] and [`Client::claim_handle`]: returns the
    /// recovery code. A failed claim discards the new identity like any
    /// other failed step.
    pub async fn register(&self, handle: &str, display_name: &str) -> Result<RecoveryCode> {
        self.create_user(display_name, Some(handle)).await
    }

    async fn create_user(&self, display_name: &str, handle: Option<&str>) -> Result<RecoveryCode> {
        self.check_onboarding()?;
        let root_seed = random_seed()?;
        let root = RootKey::from_seed(&root_seed);
        let user_id = root.public().user_id();
        let device_seed = random_seed()?;
        let device = DeviceSigningKey::from_seed(&device_seed).public();
        let cert = SignedDeviceCert::issue(&root, &device, now_ms(), 1);
        let device_list = DeviceList::new(root.public(), 1, vec![cert.clone()], vec![])
            .and_then(|list| list.sign(&root))
            .map_err(ClientError::identity)?;
        let code = RecoveryCode::generate().map_err(ClientError::identity)?;
        let sealing = code.clone();
        // Argon2id with 64 MiB: off the async runtime.
        let backup = tokio::task::spawn_blocking(move || seal_root_key_backup(&root, &sealing))
            .await
            .map_err(|e| ClientError::Task(e.to_string()))?
            .map_err(ClientError::identity)?;
        self.begin_enrollment(&DeviceRef::new(user_id.clone(), device.device_id()))
            .await?;
        let enrolled = async {
            self.enroll(Enrollment {
                root_seed,
                device_seed,
                cert,
                device_list,
                backup: Some(backup),
                me: UserInfo {
                    user_id,
                    handle: String::new(),
                    display_name: display_name.to_string(),
                },
            })
            .await?;
            self.publish_hosting_record_logged(Publish::Now).await;
            self.create_self_group().await?;
            if let Some(handle) = handle {
                self.claim_handle(handle).await?;
            }
            Ok(())
        }
        .await;
        self.end_enrollment(enrolled).await?;
        Ok(code)
    }

    /// Fails with [`ClientError::AlreadyLoggedIn`] if the client holds a
    /// session, in memory or in [`crate::SecretStorage`], not of an
    /// unfinished enrollment; an unfinished enrollment may be replaced.
    /// Keys left without a session (the store was reset) are overwritten.
    pub(crate) fn check_onboarding(&self) -> Result<()> {
        let secrets = &self.inner.secrets;
        if secrets.get(ENROLLMENT_SECRET_KEY)?.is_some() {
            return Ok(());
        }
        if self.session().is_some() || secrets.get(SESSION_SECRET_KEY)?.is_some() {
            return Err(ClientError::AlreadyLoggedIn);
        }
        Ok(())
    }

    /// The device of the unfinished enrollment, if any (and readable).
    pub(crate) fn enrolling_device(&self) -> Result<Option<DeviceRef>> {
        let Some(marker) = self.inner.secrets.get(ENROLLMENT_SECRET_KEY)? else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&marker)
            .inspect_err(|err| tracing::warn!(error = %err, "unreadable enrollment marker"))
            .ok())
    }

    /// Discards an unfinished enrollment, then records a new one of
    /// `device`, before anything else of it is stored or uploaded. Fails
    /// like [`Self::check_onboarding`], and with
    /// [`ClientError::AlreadyLoggedIn`] if the store holds a device identity
    /// not of an unfinished enrollment: that is never discarded.
    pub(crate) async fn begin_enrollment(&self, device: &DeviceRef) -> Result<()> {
        self.check_onboarding()?;
        if !self.discard_enrollment().await? {
            let identity = self
                .run(|store, _| {
                    store.transaction(|txn| {
                        Ok(txn.load_identity().map_err(StoreError::new)?.is_some())
                    })
                })
                .await?;
            if identity {
                return Err(ClientError::AlreadyLoggedIn);
            }
        }
        let marker = serde_json::to_vec(device).expect("a device ref serializes");
        Ok(self.inner.secrets.set(ENROLLMENT_SECRET_KEY, &marker)?)
    }

    /// Completes the enrollment if `enrolled` succeeded. Otherwise, or if
    /// completing fails, discards it (a failure there is only logged: the
    /// next onboarding call or [`Client::restore_session`] discards it
    /// again) and returns the error.
    pub(crate) async fn end_enrollment(&self, enrolled: Result<()>) -> Result<()> {
        let ended = enrolled.and_then(|()| Ok(self.inner.secrets.delete(ENROLLMENT_SECRET_KEY)?));
        if let Err(err) = &ended {
            tracing::warn!(error = %err, "enrollment failed; discarding it");
            if let Err(err) = self.discard_enrollment().await {
                tracing::warn!(error = %err, "cannot discard the failed enrollment");
            }
        }
        ended
    }

    /// Deletes the keys, the session and all local state of an unfinished
    /// enrollment. Keeps the marker, so a retried restore can revoke the
    /// device. Returns whether there was one.
    pub(crate) async fn discard_enrollment(&self) -> Result<bool> {
        if self.inner.secrets.get(ENROLLMENT_SECRET_KEY)?.is_none() {
            return Ok(false);
        }
        self.clear_session()?;
        self.inner.secrets.delete(ROOT_KEY_SECRET_KEY)?;
        self.inner.secrets.delete(DEVICE_KEY_SECRET_KEY)?;
        self.run(|store, _| store.transaction(|txn| Ok(txn.clear()?)))
            .await?;
        self.inner.link_pending.store(false, Ordering::SeqCst);
        Ok(true)
    }

    /// Stores the device's keys and MLS identity, uploads the DeviceList,
    /// signs in, uploads the recovery backup (if any) and KeyPackages.
    pub(crate) async fn enroll(&self, enrollment: Enrollment) -> Result<()> {
        let Enrollment {
            root_seed,
            device_seed,
            cert,
            device_list,
            backup,
            me,
        } = enrollment;
        let root = RootKey::from_seed(&root_seed);
        let key = DeviceSigningKey::from_seed(&device_seed);
        let device = DeviceRef::new(me.user_id.clone(), key.public().device_id());
        let list_bytes = device_list.to_bytes();
        self.inner.secrets.set(ROOT_KEY_SECRET_KEY, &*root_seed)?;
        self.inner
            .secrets
            .set(DEVICE_KEY_SECRET_KEY, &*device_seed)?;
        self.inner
            .device_lists
            .insert(&me.user_id, &device_list)
            .map_err(ClientError::identity)?;
        let (user_id, bytes, root_public) = (me.user_id.clone(), list_bytes.clone(), root.public());
        let (key_packages, last_resort) = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    engine.create_identity_v2(&*txn, &key, root_public, cert)?;
                    txn.upsert_user(&me)?;
                    txn.upsert_device_list(&user_id, &bytes)?;
                    Ok((
                        engine.generate_key_packages(&*txn, KEY_PACKAGE_BATCH)?,
                        engine.generate_last_resort_key_package(&*txn)?,
                    ))
                })
            })
            .await?;
        self.inner
            .transport
            .put_device_list(&device.user_id, list_bytes)
            .await?;
        let key = DeviceSigningKey::from_seed(&device_seed);
        let (token, hub_id) = self.sign_in(&device, &key, None).await?;
        let session = Session {
            device: device.clone(),
            token: token.token,
            expires_at_ms: token.expires_at_ms,
            hub_id,
        };
        // The KeyPackages belong to the hub signed in to, ever.
        let ledger = key_packages
            .iter()
            .map(|k| (k.clone(), false))
            .chain([(last_resort.clone(), true)])
            .collect();
        self.record_key_packages(&session.hub_id, ledger).await?;
        self.persist_session(&session)?;
        self.set_session(session);
        if let Some(backup) = backup {
            let user_id = &device.user_id;
            self.authed(|t| {
                let backup = backup.clone();
                async move {
                    self.inner
                        .transport
                        .put_recovery_backup(&t, user_id, backup)
                        .await
                }
            })
            .await?;
        }
        self.authed(|t| {
            let key_packages = key_packages.clone();
            async move {
                self.inner
                    .transport
                    .upload_key_packages(&t, key_packages, false)
                    .await
            }
        })
        .await?;
        self.authed(|t| {
            let last_resort = vec![last_resort.clone()];
            async move {
                self.inner
                    .transport
                    .upload_key_packages(&t, last_resort, true)
                    .await
            }
        })
        .await?;
        let name = self.own_user().await?.map(|u| u.display_name);
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            self.authed(|t| {
                let name = name.clone();
                async move { self.inner.transport.publish_display_name(&t, &name).await }
            })
            .await?;
        }
        Ok(())
    }

    /// Claims `handle` in the hub directory for this user, so others can
    /// find it with [`Client::find_user`].
    pub async fn claim_handle(&self, handle: &str) -> Result<()> {
        self.require_session()?;
        self.authed(|t| async move { self.inner.transport.claim_handle(&t, handle).await })
            .await?;
        self.set_own_handle(handle.to_string()).await
    }

    /// Releases this user's `handle`.
    pub async fn release_handle(&self, handle: &str) -> Result<()> {
        self.require_session()?;
        self.authed(|t| async move { self.inner.transport.release_handle(&t, handle).await })
            .await?;
        self.set_own_handle(String::new()).await
    }

    async fn set_own_handle(&self, handle: String) -> Result<()> {
        let Some(mut me) = self.own_user().await? else {
            return Ok(());
        };
        me.handle = handle;
        self.run(move |store, _| store.transaction(|txn| Ok(txn.upsert_user(&me)?)))
            .await
    }

    pub(crate) async fn own_user(&self) -> Result<Option<UserInfo>> {
        let user_id = self.require_session()?.device.user_id;
        self.read(move |store, _| Ok(store.user(&user_id)?)).await
    }

    /// Looks a user up by handle in the hub directories (the home hub,
    /// then the other listed hubs), caches the profile and the user's
    /// DeviceList.
    pub async fn find_user(&self, handle: &str) -> Result<Option<UserInfo>> {
        self.require_session()?;
        let Some((user_id, hub)) = self.find_handle_routed(handle).await? else {
            return Ok(None);
        };
        let read = |transport: Arc<dyn Transport>, t: AccessToken| {
            let user_id = user_id.clone();
            async move { transport.user(Some(&t), &user_id).await }
        };
        // The hub that knows the handle first.
        let record = match self.authed_on(&hub, read).await {
            Err(err) if hub_unreachable(&err) => self.read_routed(read).await?,
            record => record?,
        };
        let Some(record) = record else {
            return Ok(None);
        };
        let mut user = self.accept_user(record).await?;
        user.handle = handle.to_string();
        let fetched = user.clone();
        let (user, new) = self
            .run(move |store, _| {
                store.transaction(|txn| {
                    let stored = txn.user(&fetched.user_id)?;
                    let user = merge_directory_user(stored.as_ref(), fetched);
                    txn.upsert_user(&user)?;
                    Ok((user, stored.is_none()))
                })
            })
            .await?;
        if new {
            self.share_contact(&user).await;
        }
        Ok(Some(user))
    }

    /// Takes the DeviceList of a directory record and returns the profile;
    /// the display name is empty unless the directory has one (see
    /// [`merge_directory_user`]).
    pub(crate) async fn accept_user(&self, record: UserRecord) -> Result<UserInfo> {
        if let Err(err) = self
            .accept_device_list(&record.user_id, &record.device_list)
            .await
        {
            tracing::warn!(user_id = %record.user_id, error = %err, "ignoring a device list");
        }
        Ok(UserInfo {
            user_id: record.user_id,
            display_name: record.display_name.unwrap_or_default(),
            handle: record.handle.unwrap_or_default(),
        })
    }

    /// Verifies a user's signed DeviceList and keeps it if it supersedes the
    /// known one. Returns the devices it newly revokes, or newly drops (a
    /// restore from the recovery code cannot name the lost devices).
    pub(crate) async fn accept_device_list(
        &self,
        user_id: &UserId,
        bytes: &[u8],
    ) -> Result<Vec<DeviceRef>> {
        let signed = SignedDeviceList::from_bytes(bytes).map_err(ClientError::identity)?;
        let before = self.inner.device_lists.get(user_id);
        let stored = self
            .inner
            .device_lists
            .insert(user_id, &signed)
            .map_err(ClientError::identity)?;
        if !stored {
            return Ok(vec![]);
        }
        let (uid, bytes) = (user_id.clone(), bytes.to_vec());
        self.run(move |store, _| {
            store.transaction(|txn| Ok(txn.upsert_device_list(&uid, &bytes)?))
        })
        .await?;
        let list = self
            .inner
            .device_lists
            .get(user_id)
            .expect("the list was just stored");
        let mut gone: Vec<DeviceId> = list
            .revoked()
            .iter()
            .filter(|d| before.as_ref().is_none_or(|b| !b.is_revoked(d)))
            .cloned()
            .collect();
        if let Some(before) = &before {
            gone.extend(
                before
                    .certs()
                    .map(|c| c.device_id.clone())
                    .filter(|d| !list.contains(d) && !list.is_revoked(d)),
            );
        }
        Ok(gone
            .into_iter()
            .map(|d| DeviceRef::new(user_id.clone(), d))
            .collect())
    }

    /// Fetches and keeps the user's current DeviceList; returns the devices
    /// it newly revokes. Unknown users and lists that do not verify are
    /// skipped; network and auth errors are returned.
    pub(crate) async fn refresh_device_list(&self, user_id: &UserId) -> Result<Vec<DeviceRef>> {
        self.refresh_device_list_with(user_id, false).await
    }

    /// [`Client::refresh_device_list`] for a caller that cannot go on
    /// without the list: a read whose outcome is unknown (5xx, 429, the
    /// user's hub down) is returned as an error too, so the caller retries
    /// later instead of deciding on the cached list.
    pub(crate) async fn refresh_device_list_strict(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<DeviceRef>> {
        self.refresh_device_list_with(user_id, true).await
    }

    async fn refresh_device_list_with(
        &self,
        user_id: &UserId,
        strict: bool,
    ) -> Result<Vec<DeviceRef>> {
        let fetched = self
            .read_routed(
                |transport, t| async move { transport.device_list(Some(&t), user_id).await },
            )
            .await;
        let bytes = match fetched {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(vec![]),
            Err(err @ (TransportError::Network(_) | TransportError::Unauthorized)) => {
                return Err(err.into())
            }
            Err(err) if strict && err.outcome_unknown() => return Err(err.into()),
            Err(err) => {
                tracing::debug!(%user_id, error = %err, "cannot fetch a device list");
                return Ok(vec![]);
            }
        };
        match self.accept_device_list(user_id, &bytes).await {
            Ok(revoked) => Ok(revoked),
            Err(ClientError::Identity(reason)) => {
                tracing::warn!(%user_id, %reason, "ignoring a device list");
                Ok(vec![])
            }
            Err(err) => Err(err),
        }
    }

    /// Fetches the DeviceList of every user with a device in `devices` that
    /// the cached list neither certifies nor revokes (an unknown user, or a
    /// device added since): credential checks are fail-closed against the
    /// cached lists. Returns the devices the fetched lists newly revoke.
    pub(crate) async fn fetch_device_lists(
        &self,
        devices: impl IntoIterator<Item = DeviceRef>,
    ) -> Result<Vec<DeviceRef>> {
        let stale: BTreeSet<UserId> = devices
            .into_iter()
            .filter(|device| {
                !self
                    .inner
                    .device_lists
                    .get(&device.user_id)
                    .is_some_and(|list| {
                        list.contains(&device.device_id) || list.is_revoked(&device.device_id)
                    })
            })
            .map(|device| device.user_id)
            .collect();
        let mut revoked = Vec::new();
        for user_id in stale {
            revoked.extend(self.refresh_device_list(&user_id).await?);
        }
        Ok(revoked)
    }

    /// Records joined-group members revoked by a DeviceList as departed,
    /// so the next committer removes their leaves.
    pub(crate) async fn record_revoked(
        &self,
        session: &Session,
        revoked: Vec<DeviceRef>,
    ) -> Result<()> {
        if revoked.is_empty() {
            return Ok(());
        }
        tracing::info!(devices = ?revoked, "devices revoked");
        let base = BaseClient::new(session.device.clone());
        self.run(move |store, engine| base.record_revoked(store, engine, &revoked))
            .await
    }
}

/// Characters of a user id shown when a user has neither a display name nor
/// a handle.
const SHORT_USER_ID_LEN: usize = 12;

/// The name shown for a user without a display name: the handle, else the
/// start of the user id.
pub(crate) fn fallback_name(user: &UserInfo) -> String {
    if user.handle.is_empty() {
        user.user_id
            .as_str()
            .chars()
            .take(SHORT_USER_ID_LEN)
            .collect()
    } else {
        user.handle.clone()
    }
}

/// A directory profile merged into the cached one: the handle is updated,
/// a display name the user announced (`profile` content) is kept over the
/// fallback; without either, the fallback name is stored.
pub(crate) fn merge_directory_user(stored: Option<&UserInfo>, mut fetched: UserInfo) -> UserInfo {
    if !fetched.display_name.is_empty() {
        return fetched;
    }
    if let Some(stored) = stored {
        if fetched.handle.is_empty() {
            fetched.handle = stored.handle.clone();
        }
        let announced = !stored.display_name.is_empty()
            && stored.display_name != fallback_name(stored)
            && stored.display_name != stored.handle;
        if announced {
            fetched.display_name = stored.display_name.clone();
            return fetched;
        }
    }
    fetched.display_name = fallback_name(&fetched);
    fetched
}
