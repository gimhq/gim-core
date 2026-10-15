//! Identity: creating the user's root key and this device's certified key,
//! the handle directory, and the DeviceList cache that MLS credential
//! validation and revocation checks use.

use std::collections::BTreeSet;

use gim_base::model::UserInfo;
use gim_base::{BaseClient, StateStore, StoreTxn};
use gim_common::{now_ms, DeviceRef, UserId};
use gim_identity::recovery::{seal_root_key_backup, RecoveryCode};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList};
use zeroize::Zeroizing;

use crate::client::{Session, DEVICE_KEY_SECRET_KEY, KEY_PACKAGE_BATCH, ROOT_KEY_SECRET_KEY};
use crate::transport::{TransportError, UserRecord};
use crate::{Client, ClientError, Result};

/// A new device of a user, ready to be enrolled with the hub.
struct Enrollment {
    root_seed: Zeroizing<[u8; 32]>,
    device_seed: Zeroizing<[u8; 32]>,
    cert: SignedDeviceCert,
    device_list: SignedDeviceList,
    /// Sealed root key backup to upload (new identities only).
    backup: Option<Vec<u8>>,
    me: UserInfo,
}

fn random_seed() -> Result<Zeroizing<[u8; 32]>> {
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
    /// in, uploads the root key backup sealed with a new recovery code, and
    /// uploads [`KEY_PACKAGE_BATCH`] KeyPackages plus a last-resort one. The
    /// keys stay in [`crate::SecretStorage`]; the display name is kept
    /// locally (the hub has no profiles).
    ///
    /// Returns the recovery code. It is stored nowhere: show it to the user
    /// once.
    pub async fn create_identity(&self, display_name: &str) -> Result<RecoveryCode> {
        if self.session().is_some() {
            return Err(ClientError::AlreadyLoggedIn);
        }
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
        Ok(code)
    }

    /// [`Client::create_identity`] and [`Client::claim_handle`]: returns the
    /// recovery code.
    ///
    /// With a test transport, a handle registered before through it gets
    /// another device of the same user instead (a stand-in for device
    /// linking), and there is no recovery code.
    pub async fn register(&self, handle: &str, display_name: &str) -> Result<Option<RecoveryCode>> {
        #[cfg(any(test, feature = "testing"))]
        if let Some(linking) = self.inner.transport.test_linking() {
            if let Some(root_seed) = linking.root_seed(handle) {
                self.link_test_device(linking, root_seed, handle, display_name)
                    .await?;
                return Ok(None);
            }
        }
        let code = self.create_identity(display_name).await?;
        self.claim_handle(handle).await?;
        #[cfg(any(test, feature = "testing"))]
        if let Some(linking) = self.inner.transport.test_linking() {
            if let Some(seed) = self.inner.secrets.get(ROOT_KEY_SECRET_KEY)? {
                if let Ok(seed) = <[u8; 32]>::try_from(seed.as_slice()) {
                    linking.remember(handle, &seed);
                }
            }
        }
        Ok(Some(code))
    }

    /// Adds this device to the user owning `handle` with that user's root
    /// key, as a link would.
    #[cfg(any(test, feature = "testing"))]
    async fn link_test_device(
        &self,
        linking: &crate::testing::TestLinking,
        root_seed: Zeroizing<[u8; 32]>,
        handle: &str,
        display_name: &str,
    ) -> Result<()> {
        if self.session().is_some() {
            return Err(ClientError::AlreadyLoggedIn);
        }
        let root = RootKey::from_seed(&root_seed);
        let user_id = root.public().user_id();
        let current = linking
            .device_list(&user_id)
            .ok_or_else(|| ClientError::InvalidInput(format!("no device list of {user_id}")))?;
        let current = SignedDeviceList::from_bytes(&current)
            .and_then(|list| list.verify(&user_id))
            .map_err(ClientError::identity)?;
        let device_seed = random_seed()?;
        let device = DeviceSigningKey::from_seed(&device_seed).public();
        let cert = SignedDeviceCert::issue(&root, &device, now_ms(), current.seq() + 1);
        let device_list = current
            .add_cert(cert.clone())
            .and_then(|list| list.sign(&root))
            .map_err(ClientError::identity)?;
        self.enroll(Enrollment {
            root_seed,
            device_seed,
            cert,
            device_list,
            backup: None,
            me: UserInfo {
                user_id,
                handle: handle.to_string(),
                display_name: display_name.to_string(),
            },
        })
        .await
    }

    async fn enroll(&self, enrollment: Enrollment) -> Result<()> {
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

    async fn own_user(&self) -> Result<Option<UserInfo>> {
        let user_id = self.require_session()?.device.user_id;
        self.run(move |store, _| Ok(store.user(&user_id)?)).await
    }

    /// Looks a user up by handle in the hub directory, caches the profile
    /// and the user's DeviceList.
    pub async fn find_user(&self, handle: &str) -> Result<Option<UserInfo>> {
        self.require_session()?;
        let user_id = self
            .authed(|t| async move { self.inner.transport.find_handle(&t, handle).await })
            .await?;
        let Some(user_id) = user_id else {
            return Ok(None);
        };
        let record = self
            .authed(|t| {
                let user_id = user_id.clone();
                async move { self.inner.transport.user(&t, &user_id).await }
            })
            .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let mut user = self.accept_user(record).await?;
        user.handle = handle.to_string();
        if user.display_name.is_empty() {
            user.display_name = handle.to_string();
        }
        let stored = user.clone();
        self.run(move |store, _| store.transaction(|txn| Ok(txn.upsert_user(&stored)?)))
            .await?;
        Ok(Some(user))
    }

    /// Takes the DeviceList of a directory record and returns the profile.
    pub(crate) async fn accept_user(&self, record: UserRecord) -> Result<UserInfo> {
        if let Err(err) = self
            .accept_device_list(&record.user_id, &record.device_list)
            .await
        {
            tracing::warn!(user_id = %record.user_id, error = %err, "ignoring a device list");
        }
        Ok(UserInfo {
            user_id: record.user_id,
            display_name: record
                .display_name
                .or_else(|| record.handle.clone())
                .unwrap_or_default(),
            handle: record.handle.unwrap_or_default(),
        })
    }

    /// Verifies a user's signed DeviceList and keeps it if it supersedes the
    /// known one. Returns the devices it newly revokes.
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
        Ok(list
            .revoked()
            .iter()
            .filter(|d| before.as_ref().is_none_or(|b| !b.is_revoked(d)))
            .map(|d| DeviceRef::new(user_id.clone(), d.clone()))
            .collect())
    }

    /// Fetches and keeps the user's current DeviceList; returns the devices
    /// it newly revokes. Unknown users and lists that do not verify are
    /// skipped; network and auth errors are returned.
    pub(crate) async fn refresh_device_list(&self, user_id: &UserId) -> Result<Vec<DeviceRef>> {
        let fetched = self
            .authed(|t| async move { self.inner.transport.device_list(&t, user_id).await })
            .await;
        let bytes = match fetched {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(vec![]),
            Err(err @ (TransportError::Network(_) | TransportError::Unauthorized)) => {
                return Err(err.into())
            }
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
