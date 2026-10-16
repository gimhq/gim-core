//! Adding a device to a user: the QR link flow (new and old device sides)
//! and the restore from the recovery code after losing every device.
//!
//! Linking (`docs/identity.md`, "Device link"):
//!
//! 1. New device: [`Client::start_link`] shows [`LinkSession::qr_string`].
//! 2. Old device: [`Client::approve_link`] scans it, certifies the new
//!    device in a new DeviceList, uploads the list, seals the root key, the
//!    certificate and the list to the offer, posts the bundle through the
//!    hub and shows the SAS.
//! 3. New device: [`Client::wait_link`] long-polls for the bundle, opens it,
//!    stores the root and device keys, signs in, uploads KeyPackages and
//!    shows the SAS.
//! 4. The user compares the SAS on both screens and confirms on both:
//!    [`Client::confirm_link`] on the new device (a mismatch wipes it) and
//!    [`Client::confirm_approval`] on the old one, which adds the new device
//!    to the self group and to every joined chat (a mismatch revokes it).
//!
//! The bundle never carries a self-group Welcome: a Welcome needs a
//! KeyPackage of the new device, which can only exist once the device holds
//! its certificate, i.e. after it opened the bundle. The new device joins
//! the self group from the Welcome the hub delivers after step 4.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gim_base::model::UserInfo;
use gim_base::StateStore;
use gim_common::{now_ms, DeviceRef, UserId};
use gim_identity::link::{open_link_bundle, seal_link_bundle, LinkBundle, LinkOffer, LinkSecret};
use gim_identity::recovery::{open_root_key_backup, RecoveryCode};
use gim_identity::{DeviceList, DeviceSigningKey, RootKey, SignedDeviceCert, SignedDeviceList};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::client::{DEVICE_KEY_SECRET_KEY, ROOT_KEY_SECRET_KEY};
use crate::hosting::Publish;
use crate::hubs::Listed;
use crate::identity::{random_seed, Enrollment};
use crate::transport::TransportError;
use crate::{Client, ClientError, Result};

pub use gim_identity::link::Sas;

/// How long the hub keeps a posted link bundle (its maximum).
pub const LINK_BUNDLE_LIFETIME: Duration = Duration::from_secs(600);
/// How long [`Client::wait_link`] waits for the bundle.
pub const LINK_TIMEOUT: Duration = Duration::from_secs(600);
/// `wait` of one link-bundle long-poll (the hub's maximum).
const LINK_POLL_WAIT: Duration = Duration::from_secs(30);
/// Shortest interval between two link-bundle polls that found nothing.
const MIN_LINK_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// A link offer of a new device: show [`Self::qr_string`] as a QR code and
/// call [`Client::wait_link`]. Holds the device key and the offer's X25519
/// secret; a session accepts a single bundle.
pub struct LinkSession {
    pub qr_string: String,
    offer: LinkOffer,
    secret: LinkSecret,
    device_seed: Zeroizing<[u8; 32]>,
    used: AtomicBool,
}

impl fmt::Debug for LinkSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkSession")
            .field("qr_string", &self.qr_string)
            .finish_non_exhaustive()
    }
}

/// The opened link on the new device: show the SAS, then call
/// [`Client::confirm_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkResult {
    pub sas: Sas,
}

/// A link approved on the old device: show the SAS, then call
/// [`Client::confirm_approval`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub sas: Sas,
    /// The new device, certified in the user's DeviceList.
    pub device: DeviceRef,
}

/// The `link_id` the hub relays the bundle under: the offer's 16 random
/// bytes in lowercase hex.
fn link_id(offer: &LinkOffer) -> String {
    offer
        .link_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl<S: StateStore + 'static> Client<S> {
    /// New device: creates this device's signing key and a link offer
    /// naming `hubs` (where the old device may post the bundle).
    pub fn start_link(&self, hubs: Vec<String>) -> Result<LinkSession> {
        self.check_onboarding()?;
        let device_seed = random_seed()?;
        let device = DeviceSigningKey::from_seed(&device_seed).public();
        let (offer, secret) = LinkOffer::new(device, hubs).map_err(ClientError::identity)?;
        Ok(LinkSession {
            qr_string: offer.to_qr_string(),
            offer,
            secret,
            device_seed,
            used: AtomicBool::new(false),
        })
    }

    /// New device: long-polls the hub for the bundle (up to
    /// [`LINK_TIMEOUT`]), opens and verifies it, stores the user's root key
    /// and this device's key, signs in and uploads KeyPackages. Returns the
    /// SAS to compare with the old device's; confirm it with
    /// [`Client::confirm_link`]. Publishes the user's hosting record only if
    /// the hub has no valid one or it is due for renewal (failures are only
    /// logged).
    ///
    /// If no bundle arrived (network error, timeout), call it again with
    /// the same session. A bundle that does not open or verify is rejected
    /// and nothing is stored; the session cannot be reused then. A failure
    /// after the bundle opened discards everything the call stored (see
    /// [`crate::ENROLLMENT_SECRET_KEY`]) and uses the session up: start a
    /// new link and approve it on the old device again. The device of the
    /// failed attempt stays in the user's DeviceList until the old device
    /// revokes it ([`Client::confirm_approval`] with `false` on the first
    /// approval, or [`Client::revoke_device`]).
    pub async fn wait_link(&self, link: &LinkSession) -> Result<LinkResult> {
        self.check_onboarding()?;
        if link.used.swap(true, Ordering::SeqCst) {
            return Err(ClientError::InvalidInput(
                "the link session was used; start a new one".into(),
            ));
        }
        let sealed = match self.poll_link_bundle(&link_id(&link.offer)).await {
            Ok(sealed) => sealed,
            Err(err) => {
                link.used.store(false, Ordering::SeqCst);
                return Err(err);
            }
        };
        let (opened, sas) =
            open_link_bundle(&link.offer, &link.secret, &sealed).map_err(ClientError::identity)?;
        if opened.self_group_welcome.is_some() {
            tracing::debug!("ignoring the link bundle's self-group Welcome");
        }
        let root = opened.root;
        // Ed25519 signatures are deterministic: re-signing reproduces the
        // certificate and list the old device signed.
        let cert = SignedDeviceCert::issue(
            &root,
            &opened.cert.device_public_key,
            opened.cert.created_at,
            opened.cert.seq,
        );
        let device_list = opened
            .device_list
            .sign(&root)
            .map_err(ClientError::identity)?;
        let user_id = opened.cert.user_id;
        self.begin_enrollment(&DeviceRef::new(
            user_id.clone(),
            opened.cert.device_public_key.device_id(),
        ))
        .await?;
        let enrolled = async {
            self.enroll(Enrollment {
                root_seed: root.to_seed(),
                device_seed: link.device_seed.clone(),
                cert,
                device_list,
                backup: None,
                me: UserInfo {
                    user_id,
                    handle: String::new(),
                    display_name: String::new(),
                },
            })
            .await?;
            // The other devices keep the user's record; publish only if it
            // is missing or due.
            self.publish_hosting_record_logged(Publish::IfDue).await;
            Ok(())
        }
        .await;
        self.end_enrollment(enrolled).await?;
        self.inner.link_pending.store(true, Ordering::SeqCst);
        Ok(LinkResult { sas })
    }

    /// Long-polls the hub for the bundle of `link_id`, up to
    /// [`LINK_TIMEOUT`].
    async fn poll_link_bundle(&self, link_id: &str) -> Result<Vec<u8>> {
        let deadline = Instant::now() + LINK_TIMEOUT;
        loop {
            let started = Instant::now();
            let fetched = self
                .inner
                .transport
                .fetch_link_bundle(link_id, LINK_POLL_WAIT)
                .await?;
            if let Some(sealed) = fetched {
                return Ok(sealed);
            }
            if Instant::now() >= deadline {
                return Err(ClientError::InvalidInput("no link bundle arrived".into()));
            }
            tokio::time::sleep_until(started + MIN_LINK_POLL_INTERVAL).await;
        }
    }

    /// New device: the user compared the SAS. On a mismatch the bundle came
    /// from someone else: the keys and the session are deleted (discard the
    /// local database too) and the link is aborted.
    pub async fn confirm_link(&self, sas_ok: bool) -> Result<()> {
        if !self.inner.link_pending.swap(false, Ordering::SeqCst) {
            return Err(ClientError::InvalidInput("no link to confirm".into()));
        }
        if !sas_ok {
            tracing::warn!("link SAS mismatch; wiping the linked identity");
            self.clear_session()?;
            self.inner.secrets.delete(ROOT_KEY_SECRET_KEY)?;
            self.inner.secrets.delete(DEVICE_KEY_SECRET_KEY)?;
        }
        Ok(())
    }

    /// Old device: certifies the device of the scanned offer in a new
    /// DeviceList (seq + 1), uploads it, and posts the sealed bundle (root
    /// key, certificate, list) through the hub. Returns the SAS to compare
    /// with the new device's; confirm it with [`Client::confirm_approval`].
    pub async fn approve_link(&self, qr_string: &str) -> Result<PendingApproval> {
        let session = self.require_session()?;
        let root = self.root_key()?;
        let offer = LinkOffer::from_qr_string(qr_string).map_err(ClientError::identity)?;
        let device_key = *offer.device_public_key();
        let device = DeviceRef::new(session.device.user_id.clone(), device_key.device_id());
        let current = self.own_device_list(&session).await?;
        if current.contains(&device.device_id) || current.is_revoked(&device.device_id) {
            return Err(ClientError::InvalidInput(format!(
                "device {} is already listed",
                device.device_id
            )));
        }
        let seq = current.seq() + 1;
        let cert = SignedDeviceCert::issue(&root, &device_key, now_ms(), seq);
        let list = current
            .add_cert(cert.clone())
            .and_then(|list| list.sign(&root))
            .map_err(ClientError::identity)?;
        self.publish_own_device_list(&list).await?;
        let bundle = LinkBundle::new(&root, &cert, &list, None);
        let (sealed, sas) = seal_link_bundle(&offer, &bundle).map_err(ClientError::identity)?;
        let link_id = link_id(&offer);
        self.authed(|t| {
            let (link_id, sealed) = (link_id.clone(), sealed.clone());
            async move {
                self.inner
                    .transport
                    .post_link_bundle(&t, &link_id, sealed, LINK_BUNDLE_LIFETIME)
                    .await
            }
        })
        .await?;
        Ok(PendingApproval { sas, device })
    }

    /// Old device: the user compared the SAS. On a match the new device is
    /// added to the self group (with the DeviceList and the profile) and to
    /// every joined chat; it must have finished [`Client::wait_link`]. On a
    /// mismatch the device is revoked.
    pub async fn confirm_approval(&self, approval: &PendingApproval, sas_ok: bool) -> Result<()> {
        if sas_ok {
            self.add_own_device(&approval.device).await
        } else {
            tracing::warn!(device = %approval.device, "link SAS mismatch; revoking the device");
            self.revoke_device(&approval.device.device_id).await
        }
    }

    /// Restores the user from the recovery code after losing every device:
    /// opens the user's recovery backup, and makes this (fresh) client a new
    /// device of the user, signed in with KeyPackages and a new self group.
    ///
    /// The user's current DeviceList is always read from the hub (a public
    /// read, no session needed; the local cache is not used) and verified
    /// against the recovered root key. The new list is its seq + 1 with this
    /// device's certificate: with `revoke_others` every previously listed
    /// device moves to the revoked set, otherwise they all stay listed. If a
    /// newer list lands concurrently (409), the list is read and rebuilt
    /// once more. Fails with [`TransportError::NotFound`] if the hub has no
    /// DeviceList of the user. Publishes a new hosting record (seq + 1);
    /// a failure there is only logged (the sync loop retries).
    ///
    /// On failure everything the call stored is discarded (see
    /// [`crate::ENROLLMENT_SECRET_KEY`]); calling it again restores with a
    /// new device key. If the hub's list certifies the device of the
    /// discarded attempt, the new list revokes it (one more seq).
    ///
    /// Chats are not rejoined automatically: their members (or another own
    /// device) have to add this device again.
    pub async fn restore_from_recovery(
        &self,
        user_id: &UserId,
        code: &RecoveryCode,
        revoke_others: bool,
    ) -> Result<()> {
        self.check_onboarding()?;
        let backup = self
            .inner
            .transport
            .recovery_backup(user_id)
            .await?
            .ok_or_else(|| ClientError::InvalidInput(format!("no recovery backup of {user_id}")))?;
        let (code, uid) = (code.clone(), user_id.clone());
        // Argon2id with up to 256 MiB: off the async runtime.
        let root = tokio::task::spawn_blocking(move || open_root_key_backup(&backup, &code, &uid))
            .await
            .map_err(|e| ClientError::Task(e.to_string()))?
            .map_err(ClientError::identity)?;
        let device_seed = random_seed()?;
        let device = DeviceSigningKey::from_seed(&device_seed).public();
        let discarded = self
            .enrolling_device()?
            .filter(|d| d.user_id == *user_id)
            .map(|d| d.device_id);
        self.begin_enrollment(&DeviceRef::new(user_id.clone(), device.device_id()))
            .await?;
        let enrolled = async {
            let mut rebuilt = false;
            let (cert, device_list) = loop {
                let mut current = self.hub_device_list(user_id, &root).await?;
                if let Some(discarded) = discarded.as_ref().filter(|d| current.contains(d)) {
                    current = current.revoke(discarded).map_err(ClientError::identity)?;
                }
                let seq = current
                    .seq()
                    .checked_add(1)
                    .ok_or_else(|| ClientError::Identity("device list seq overflow".into()))?;
                let cert = SignedDeviceCert::issue(&root, &device, now_ms(), seq);
                let list = if revoke_others {
                    let revoked = current
                        .revoked()
                        .iter()
                        .cloned()
                        .chain(current.certs().map(|c| c.device_id.clone()))
                        .collect();
                    DeviceList::new(root.public(), seq, vec![cert.clone()], revoked)
                } else {
                    current.add_cert(cert.clone())
                }
                .and_then(|list| list.sign(&root))
                .map_err(ClientError::identity)?;
                match self
                    .inner
                    .transport
                    .put_device_list(user_id, list.to_bytes())
                    .await
                {
                    Ok(()) => break (cert, list),
                    Err(TransportError::Conflict(reason)) if !rebuilt => {
                        tracing::info!(%reason, "a newer device list landed; rebuilding");
                        rebuilt = true;
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            self.enroll(Enrollment {
                root_seed: root.to_seed(),
                device_seed,
                cert,
                device_list,
                backup: None,
                me: UserInfo {
                    user_id: user_id.clone(),
                    handle: String::new(),
                    display_name: String::new(),
                },
            })
            .await?;
            self.publish_hosting_record_logged(Publish::Now).await;
            self.create_self_group().await?;
            // The hub map goes to the new self group, for the devices
            // linked from here on.
            self.refresh_hubs_logged(Listed::Fetch).await;
            self.share_hub_locations().await;
            Ok(())
        }
        .await;
        self.end_enrollment(enrolled).await
    }

    /// The user's current DeviceList read from the hub without a session,
    /// verified against the recovered root key.
    async fn hub_device_list(&self, user_id: &UserId, root: &RootKey) -> Result<DeviceList> {
        let bytes = self
            .inner
            .transport
            .device_list(None, user_id)
            .await?
            .ok_or_else(|| {
                TransportError::NotFound(format!("the hub has no device list of {user_id}"))
            })?;
        let list = SignedDeviceList::from_bytes(&bytes)
            .and_then(|signed| signed.verify(user_id))
            .map_err(ClientError::identity)?;
        if *list.root_public_key() != root.public() {
            return Err(ClientError::Identity(
                "the hub's device list is not signed by the recovered root key".into(),
            ));
        }
        Ok(list)
    }
}
