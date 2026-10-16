//! The self group (arch §9.4): the MLS group of the user's own devices. It
//! carries the signed DeviceList (on change), the display name, contacts,
//! read markers and the hub URLs as `self.*` envelope contents, which gim-base applies
//! on receipt; it is hidden from the chat list. A device adopts a group as
//! its self group when the first `self.*` content of another own device
//! arrives in it.
//!
//! Also: the display name announced to chats (`profile` content, on join
//! and on change) and device management (list, revoke).

use gim_base::model::ChatKind;
use gim_base::model::{Membership, UserInfo};
use gim_base::{BaseClient, StateReader, StateStore, StoreTxn};
use gim_common::{now_ms, DeviceId, DeviceRef, GroupId, UserId};
use gim_identity::{DeviceList, RootKey, SignedDeviceList};
use gim_proto::envelope::{Contact, Content};
use zeroize::Zeroize;

use crate::client::{CommitOp, Session, ROOT_KEY_SECRET_KEY};
use crate::{Client, ClientError, Result};

/// A device of a user, from the user's DeviceList.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    /// When the device was certified (Unix milliseconds); 0 for revoked
    /// devices, whose certificate is gone from the list.
    pub created_at: u64,
    /// This client's device.
    pub is_current: bool,
    pub revoked: bool,
}

fn device_infos(list: &DeviceList, current: &DeviceRef) -> Vec<DeviceInfo> {
    let is_current = |device_id: &DeviceId| {
        list.user_id() == &current.user_id && device_id == &current.device_id
    };
    list.certs()
        .map(|cert| DeviceInfo {
            device_id: cert.device_id.clone(),
            created_at: cert.created_at,
            is_current: is_current(&cert.device_id),
            revoked: false,
        })
        .chain(list.revoked().iter().map(|device_id| DeviceInfo {
            device_id: device_id.clone(),
            created_at: 0,
            is_current: is_current(device_id),
            revoked: true,
        }))
        .collect()
}

impl<S: StateStore + 'static> Client<S> {
    /// Sets the user's display name: stored locally, synced to the other
    /// own devices through the self group and announced to every joined
    /// chat.
    pub async fn set_display_name(&self, display_name: &str) -> Result<()> {
        let session = self.require_session()?;
        if display_name.is_empty() {
            return Err(ClientError::InvalidInput("empty display name".into()));
        }
        let name = display_name.to_string();
        let own = session.device.user_id.clone();
        self.run(move |store, _| {
            store.transaction(|txn| {
                let mut user = txn.user(&own)?.unwrap_or_else(|| UserInfo {
                    user_id: own.clone(),
                    handle: String::new(),
                    display_name: String::new(),
                });
                user.display_name = name;
                Ok(txn.upsert_user(&user)?)
            })
        })
        .await?;
        self.authed(|t| async move {
            self.inner
                .transport
                .publish_display_name(&t, display_name)
                .await
        })
        .await?;
        self.send_to_self_group(Content::SelfProfile {
            display_name: display_name.to_string(),
        })
        .await?;
        let chats = self.read(|store, _| Ok(store.chats()?)).await?;
        for chat in chats {
            if chat.membership == Membership::Joined {
                self.announce_profile(&chat.group_id).await;
            }
        }
        Ok(())
    }

    /// The devices of this user, from its DeviceList.
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        let session = self.require_session()?;
        let list = self.own_device_list(&session).await?;
        Ok(device_infos(&list, &session.device))
    }

    /// The devices of any user, from the user's current DeviceList; empty
    /// for an unknown user.
    pub async fn user_devices(&self, user_id: &UserId) -> Result<Vec<DeviceInfo>> {
        let session = self.require_session()?;
        let revoked = self.refresh_device_list(user_id).await?;
        self.record_revoked(&session, revoked).await?;
        Ok(self
            .inner
            .device_lists
            .get(user_id)
            .map(|list| device_infos(&list, &session.device))
            .unwrap_or_default())
    }

    /// Revokes another device of this user: uploads a DeviceList (seq + 1)
    /// revoking it, shares the list in the self group, and removes the
    /// device's leaves from every joined group and the self group. The hub
    /// drops the device's sessions; peers reject its credential.
    pub async fn revoke_device(&self, device_id: &DeviceId) -> Result<()> {
        let session = self.require_session()?;
        if device_id == &session.device.device_id {
            return Err(ClientError::InvalidInput(
                "this device cannot revoke itself".into(),
            ));
        }
        let root = self.root_key()?;
        let current = self.own_device_list(&session).await?;
        let list = current
            .revoke(device_id)
            .and_then(|list| list.sign(&root))
            .map_err(ClientError::identity)?;
        self.publish_own_device_list(&list).await?;
        self.send_to_self_group(Content::SelfDeviceList {
            device_list: list.to_bytes(),
        })
        .await?;
        let device = DeviceRef::new(session.device.user_id.clone(), device_id.clone());
        let _guard = self.inner.group_lock.lock().await;
        let removed = device.clone();
        let groups = self
            .run(move |store, engine| {
                store.transaction(|txn| {
                    let mut groups = Vec::new();
                    let joined = txn
                        .chats()?
                        .into_iter()
                        .filter(|c| c.membership == Membership::Joined)
                        .map(|c| c.group_id)
                        .chain(txn.self_groups()?);
                    for group_id in joined {
                        if engine.has_group(&*txn, &group_id)?
                            && engine.group_members(&*txn, &group_id)?.contains(&removed)
                        {
                            groups.push(group_id);
                        }
                    }
                    Ok(groups)
                })
            })
            .await?;
        for group_id in groups {
            self.commit(&session, &group_id, CommitOp::Remove(vec![device.clone()]))
                .await?;
        }
        Ok(())
    }

    /// Creates a self group on the primary hub and locally, as the
    /// current one.
    pub(crate) async fn create_self_group(&self) -> Result<GroupId> {
        let session = self.require_session()?;
        let _guard = self.inner.group_lock.lock().await;
        let group_id = self.create_group_routed(ChatKind::Group, None).await?;
        let (gid, base) = (group_id.clone(), BaseClient::new(session.device));
        self.run(move |store, engine| base.create_self_group(store, engine, &gid, now_ms()))
            .await?;
        Ok(group_id)
    }

    /// The current self group, if any.
    pub(crate) async fn self_group(&self) -> Result<Option<GroupId>> {
        self.read(|store, _| Ok(store.self_groups()?.pop())).await
    }

    /// Sends `content` to the current self group, if another own device is
    /// in it.
    pub(crate) async fn send_to_self_group(&self, content: Content) -> Result<()> {
        let session = self.require_session()?;
        let Some(group_id) = self.self_group().await? else {
            return Ok(());
        };
        let gid = group_id.clone();
        let chat = self.read(move |store, _| Ok(store.chat(&gid)?)).await?;
        let shared = chat.is_some_and(|c| {
            c.membership == Membership::Joined
                && c.members.iter().any(|m| m.device != session.device)
        });
        if shared {
            self.send(&group_id, content).await?;
        }
        Ok(())
    }

    /// Shares a newly found user with the other own devices. Best effort.
    pub(crate) async fn share_contact(&self, user: &UserInfo) {
        let contact = Contact {
            user_id: user.user_id.clone(),
            handle: Some(user.handle.clone()).filter(|h| !h.is_empty()),
            display_name: Some(user.display_name.clone()).filter(|n| !n.is_empty()),
        };
        let content = Content::SelfContacts {
            contacts: vec![contact],
        };
        if let Err(err) = self.send_to_self_group(content).await {
            tracing::debug!(error = %err, "cannot share a contact");
        }
    }

    /// Shares that the chat was read up to `seq` with the other own
    /// devices. Best effort.
    pub(crate) async fn share_read_marker(&self, group_id: &GroupId, seq: u64) {
        let content = Content::SelfReadMarker {
            group_id: group_id.clone(),
            seq,
        };
        if let Err(err) = self.send_to_self_group(content).await {
            tracing::debug!(error = %err, "cannot share a read marker");
        }
    }

    /// Announces the own display name to a chat, if there is one. Best
    /// effort.
    pub(crate) async fn announce_profile(&self, group_id: &GroupId) {
        let name = match self.own_user().await {
            Ok(user) => user.map(|u| u.display_name).unwrap_or_default(),
            Err(err) => {
                tracing::debug!(error = %err, "cannot read the own profile");
                return;
            }
        };
        if name.is_empty() {
            return;
        }
        let content = Content::Profile { display_name: name };
        if let Err(err) = self.send(group_id, content).await {
            tracing::debug!(%group_id, error = %err, "cannot announce the profile");
        }
    }

    /// Adds a newly linked own device to the self group (creating one if
    /// there is none), shares the DeviceList and the display name there,
    /// then adds it to every joined chat (best effort per chat).
    pub(crate) async fn add_own_device(&self, device: &DeviceRef) -> Result<()> {
        let session = self.require_session()?;
        let self_group = match self.self_group().await? {
            Some(group_id) => group_id,
            None => self.create_self_group().await?,
        };
        let added = {
            let _guard = self.inner.group_lock.lock().await;
            self.add_device_to_group(&session, &self_group, device)
                .await?
        };
        if !added {
            return Err(ClientError::InvalidInput(format!(
                "device {device} has no KeyPackage yet; finish linking on it first"
            )));
        }
        let own = session.device.user_id.clone();
        let list = self
            .run(move |store, _| {
                Ok(store
                    .device_lists()?
                    .into_iter()
                    .find(|(user_id, _)| *user_id == own)
                    .map(|(_, bytes)| bytes))
            })
            .await?;
        if let Some(device_list) = list {
            self.send_to_self_group(Content::SelfDeviceList { device_list })
                .await?;
        }
        let name = self.own_user().await?.map(|u| u.display_name);
        if let Some(display_name) = name.filter(|n| !n.is_empty()) {
            self.send_to_self_group(Content::SelfProfile { display_name })
                .await?;
        }
        self.share_hub_locations().await;
        let chats = self.read(|store, _| Ok(store.chats()?)).await?;
        for chat in chats {
            if chat.membership != Membership::Joined
                || chat.members.iter().any(|m| &m.device == device)
            {
                continue;
            }
            let added = {
                let _guard = self.inner.group_lock.lock().await;
                self.add_device_to_group(&session, &chat.group_id, device)
                    .await
            };
            match added {
                Ok(true) => {
                    if let Err(err) = self.share_group_info(&chat.group_id).await {
                        tracing::debug!(group_id = %chat.group_id, error = %err, "cannot share group info");
                    }
                }
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(group_id = %chat.group_id, error = %err, "cannot add the linked device");
                }
            }
        }
        Ok(())
    }

    /// Claims a KeyPackage of the own `device` and commits adding it to the
    /// group; `false` if it has none. The caller holds the group lock.
    async fn add_device_to_group(
        &self,
        session: &Session,
        group_id: &GroupId,
        device: &DeviceRef,
    ) -> Result<bool> {
        let claim = self.claim_key_packages(session, &[], &[]).await?;
        let Some(key_package) = claim.key_packages.into_iter().find(|k| &k.device == device) else {
            return Ok(false);
        };
        self.commit(
            session,
            group_id,
            CommitOp::Add(vec![key_package], claim.hub),
        )
        .await?;
        Ok(true)
    }

    /// The user's root key from secure storage; only devices of a user
    /// hold it (every linked or restored device does).
    pub(crate) fn root_key(&self) -> Result<RootKey> {
        let mut stored = self
            .inner
            .secrets
            .get(ROOT_KEY_SECRET_KEY)?
            .ok_or_else(|| ClientError::Identity("no root key on this device".into()))?;
        let seed = <[u8; 32]>::try_from(stored.as_slice()).map(zeroize::Zeroizing::new);
        stored.zeroize();
        let seed = seed.map_err(|_| ClientError::Identity("malformed root key".into()))?;
        Ok(RootKey::from_seed(&seed))
    }

    /// The own user's current DeviceList, fetched from the hub.
    pub(crate) async fn own_device_list(&self, session: &Session) -> Result<DeviceList> {
        let own = &session.device.user_id;
        let revoked = self.refresh_device_list(own).await?;
        self.record_revoked(session, revoked).await?;
        self.inner
            .device_lists
            .get(own)
            .ok_or_else(|| ClientError::Identity("own device list is unknown".into()))
    }

    /// Uploads a new own DeviceList and keeps it.
    pub(crate) async fn publish_own_device_list(&self, list: &SignedDeviceList) -> Result<()> {
        let session = self.require_session()?;
        let own = &session.device.user_id;
        self.inner
            .transport
            .put_device_list(own, list.to_bytes())
            .await?;
        self.accept_device_list(own, &list.to_bytes()).await?;
        Ok(())
    }
}
