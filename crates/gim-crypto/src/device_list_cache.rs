//! In-memory [`DeviceListLookup`] fed with signed device lists from hub
//! responses and events.

use std::collections::HashMap;
use std::sync::RwLock;

use gim_common::UserId;
use gim_identity::{DeviceList, IdentityError, SignedDeviceList};

use crate::DeviceListLookup;

/// The latest verified [`DeviceList`] per user. Updates follow the
/// supersedes rules of `docs/identity.md` ("Update and seq rules"), so a
/// stored list is never rolled back or forked.
#[derive(Debug, Default)]
pub struct DeviceListCache {
    lists: RwLock<HashMap<UserId, DeviceList>>,
}

impl DeviceListCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `signed` as the list of `user_id` and stores it. Returns
    /// `Ok(true)` if it was stored (first list for the user, or a higher
    /// seq), `Ok(false)` for an identical copy of the stored list (no-op).
    /// A stale seq or a different list with the same seq is rejected and
    /// leaves the cache unchanged.
    pub fn insert(
        &self,
        user_id: &UserId,
        signed: &SignedDeviceList,
    ) -> Result<bool, IdentityError> {
        let list = signed.verify(user_id)?;
        let mut lists = self.lists.write().unwrap_or_else(|e| e.into_inner());
        if let Some(stored) = lists.get(user_id) {
            if !list.supersedes(stored)? {
                return Ok(false);
            }
        }
        lists.insert(user_id.clone(), list);
        Ok(true)
    }

    /// The stored list of `user_id`, if any.
    pub fn get(&self, user_id: &UserId) -> Option<DeviceList> {
        self.lists
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(user_id)
            .cloned()
    }
}

impl DeviceListLookup for DeviceListCache {
    fn device_list(&self, user_id: &UserId) -> Option<DeviceList> {
        self.get(user_id)
    }
}

#[cfg(test)]
mod tests {
    use gim_identity::{DeviceSigningKey, RootKey, SignedDeviceCert};

    use super::*;

    fn lists() -> (RootKey, DeviceList) {
        let root = RootKey::from_seed(&[1; 32]);
        let device = DeviceSigningKey::from_seed(&[2; 32]).public();
        let cert = SignedDeviceCert::issue(&root, &device, 0, 1);
        let list = DeviceList::new(root.public(), 1, vec![cert], vec![]).unwrap();
        (root, list)
    }

    #[test]
    fn newer_replaces_and_same_is_noop() {
        let (root, v1) = lists();
        let user = v1.user_id().clone();
        let device = v1.certs().next().unwrap().device_id.clone();
        let cache = DeviceListCache::new();
        assert!(cache.device_list(&user).is_none());
        assert!(cache.insert(&user, &v1.sign(&root).unwrap()).unwrap());
        assert!(!cache.insert(&user, &v1.sign(&root).unwrap()).unwrap());
        assert_eq!(cache.device_list(&user), Some(v1.clone()));

        let v2 = v1.revoke(&device).unwrap();
        assert!(cache.insert(&user, &v2.sign(&root).unwrap()).unwrap());
        assert!(cache.device_list(&user).unwrap().is_revoked(&device));
        // Older lists cannot roll the revocation back.
        assert!(matches!(
            cache.insert(&user, &v1.sign(&root).unwrap()),
            Err(IdentityError::StaleSeq(1))
        ));
        assert_eq!(cache.get(&user), Some(v2));
    }

    #[test]
    fn same_seq_conflict_is_rejected() {
        let (root, v1) = lists();
        let user = v1.user_id().clone();
        let cache = DeviceListCache::new();
        cache.insert(&user, &v1.sign(&root).unwrap()).unwrap();
        let other = DeviceSigningKey::from_seed(&[3; 32]).public();
        let fork = DeviceList::new(
            root.public(),
            1,
            vec![SignedDeviceCert::issue(&root, &other, 0, 1)],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            cache.insert(&user, &fork.sign(&root).unwrap()),
            Err(IdentityError::SeqConflict(1))
        ));
        assert_eq!(cache.get(&user), Some(v1));
    }

    #[test]
    fn list_of_another_user_is_rejected() {
        let (root, v1) = lists();
        let other = RootKey::from_seed(&[9; 32]).public().user_id();
        let cache = DeviceListCache::new();
        assert!(cache.insert(&other, &v1.sign(&root).unwrap()).is_err());
        assert!(cache.get(&other).is_none());
        assert!(cache.get(v1.user_id()).is_none());
    }
}
