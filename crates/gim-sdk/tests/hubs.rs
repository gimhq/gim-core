//! The hub registry (multi-homing, contract `multihoming.md` §4.1, §4.5,
//! Q2): the home hub is bootstrapped with `GET /v2/hub`, listed hubs come
//! from the hosting record, their URLs from `set_hub_url` or the self
//! group, every URL is checked against the listed `hub_id` before the
//! device signs in there, and the registry and the per-hub sessions
//! survive a restart.

mod common;
mod mock_server;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::FlakyTransport;
use gim_base::model::HubState;
use gim_base::MemoryStore;
use gim_common::{now_ms, UserId};
use gim_identity::{HostingEntry, RootKey, UserHostingRecord};
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::transport::{HubEvent, Transport, TransportError};
use gim_sdk::{
    Client, ClientBuilder, ClientError, HttpTransport, HubConnector, HubStatus, SecretStorage,
    HOSTING_RECORD_LIFETIME, ROOT_KEY_SECRET_KEY,
};
use mock_server::{fast_settings, MockServer};
use tempfile::TempDir;

const SEED_B: [u8; 32] = [0x62; 32];
const SEED_C: [u8; 32] = [0x63; 32];

struct Account {
    client: Client<MemoryStore>,
    store: Arc<MemoryStore>,
    secrets: Arc<MemorySecretStorage>,
    transport: Arc<dyn Transport>,
    connector: Option<HubConnector>,
    data_dir: TempDir,
}

impl Account {
    fn new(transport: Arc<dyn Transport>, connector: Option<HubConnector>) -> Self {
        let store = Arc::new(MemoryStore::new());
        let secrets = Arc::new(MemorySecretStorage::new());
        let data_dir = tempfile::tempdir().unwrap();
        let client = build(&store, &secrets, &transport, &connector, &data_dir);
        Self {
            client,
            store,
            secrets,
            transport,
            connector,
            data_dir,
        }
    }

    async fn register(transport: Arc<dyn Transport>, connector: Option<HubConnector>) -> Self {
        let account = Self::new(transport, connector);
        account.client.register("alice", "Alice").await.unwrap();
        account
    }

    /// A new client over the same store, secrets and transport.
    async fn restart(&self) -> Client<MemoryStore> {
        let client = build(
            &self.store,
            &self.secrets,
            &self.transport,
            &self.connector,
            &self.data_dir,
        );
        assert!(client.restore_session().await.unwrap());
        client
    }

    fn user_id(&self) -> UserId {
        self.client.session().unwrap().device.user_id
    }

    fn root(&self) -> RootKey {
        let seed = self.secrets.get(ROOT_KEY_SECRET_KEY).unwrap().unwrap();
        RootKey::from_seed(&seed.try_into().unwrap())
    }

    /// A record of this user listing `hubs` (hub, priority).
    fn record(&self, seq: u64, hubs: &[(&FakeTransport, u8)]) -> Vec<u8> {
        let root = self.root();
        let entries = hubs
            .iter()
            .map(|(hub, priority)| {
                HostingEntry::sign(hub.hub_root_key(), &self.user_id(), *priority)
            })
            .collect();
        let expires_at = now_ms() + HOSTING_RECORD_LIFETIME.as_millis() as u64;
        UserHostingRecord::new(root.public(), seq, expires_at, entries)
            .and_then(|record| record.sign(&root))
            .unwrap()
            .to_bytes()
    }

    /// Copies the user's DeviceList from `from` to `to`, as the add-hub
    /// procedure does before signing in there.
    async fn copy_device_list(&self, from: &FakeTransport, to: &FakeTransport) {
        let user_id = self.user_id();
        let list = from.service().device_list(&user_id).unwrap();
        to.put_device_list(&user_id, list).await.unwrap();
    }
}

fn build(
    store: &Arc<MemoryStore>,
    secrets: &Arc<MemorySecretStorage>,
    transport: &Arc<dyn Transport>,
    connector: &Option<HubConnector>,
    data_dir: &TempDir,
) -> Client<MemoryStore> {
    let builder = ClientBuilder::new(
        store.clone(),
        transport.clone(),
        secrets.clone() as Arc<dyn SecretStorage>,
    )
    .data_dir(data_dir.path())
    .sync_settings(fast_settings());
    match connector {
        Some(connector) => builder.hub_connector(connector.clone()),
        None => builder,
    }
    .build()
    .unwrap()
}

fn hub_id(hub: &FakeTransport) -> String {
    hub.service().hub_id().to_string()
}

fn status<'a>(hubs: &'a [HubStatus], hub: &FakeTransport) -> &'a HubStatus {
    let hub_id = hub_id(hub);
    hubs.iter()
        .find(|h| h.hub.hub_id == hub_id)
        .unwrap_or_else(|| panic!("{hub_id} not in {hubs:?}"))
}

/// A connector over fake hubs by URL.
fn connector(hubs: &[(&str, &FlakyTransport)]) -> HubConnector {
    let hubs: HashMap<String, FlakyTransport> = hubs
        .iter()
        .map(|(url, hub)| ((*url).to_string(), (*hub).clone()))
        .collect();
    Arc::new(move |url: &str| {
        hubs.get(url)
            .map(|hub| Arc::new(hub.clone()) as Arc<dyn Transport>)
            .ok_or_else(|| TransportError::Network(format!("no hub at {url}")))
    })
}

#[tokio::test]
async fn second_hub_over_http_is_verified_signed_in_and_restored() {
    let hub_a = FakeTransport::new();
    let hub_b = FakeTransport::with_hub_seed(SEED_B);
    let hub_c = FakeTransport::with_hub_seed(SEED_C);
    let server_a = MockServer::start(hub_a.clone()).await;
    let server_b = MockServer::start(hub_b.clone()).await;
    let server_c = MockServer::start(hub_c.clone()).await;
    let transport = Arc::new(HttpTransport::new(server_a.url.parse().unwrap()).unwrap());
    let alice = Account::register(transport, None).await;
    let user_id = alice.user_id();

    // Onboarding bootstrapped the home hub: verified, with the client's URL.
    let hubs = alice.client.hubs().await.unwrap();
    assert_eq!(hubs.len(), 1, "{hubs:?}");
    let a = status(&hubs, &hub_a);
    assert!(a.home && a.signed_in);
    assert_eq!(a.hub.state, HubState::Verified);
    assert_eq!(
        a.hub.url.as_deref(),
        Some(server_a.url.trim_end_matches('/'))
    );
    assert_eq!(
        a.hub.verified_root_pubkey.as_deref(),
        Some(hub_a.hub_root_key().public().as_bytes().as_slice())
    );
    assert_eq!(a.hub.priority, 0);

    // The record now lists B too; its URL is not known yet.
    alice.copy_device_list(&hub_a, &hub_b).await;
    let record = alice.record(2, &[(&hub_a, 0), (&hub_b, 1)]);
    hub_a.set_hosting_record(&user_id, Some(record));
    alice.client.refresh_hubs().await.unwrap();
    let hubs = alice.client.hubs().await.unwrap();
    assert_eq!(hubs.len(), 2);
    let b = status(&hubs, &hub_b);
    assert_eq!(b.hub.state, HubState::Unverified);
    assert_eq!(b.hub.url, None);
    assert!(!b.home && !b.signed_in);

    // A URL serving another hub is refused; nothing is sent there.
    let result = alice
        .client
        .set_hub_url(&hub_id(&hub_b), &server_c.url)
        .await;
    assert!(
        matches!(result, Err(ClientError::InvalidInput(_))),
        "{result:?}"
    );
    let hubs = alice.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b);
    assert_eq!(b.hub.state, HubState::Unverified);
    assert_eq!(b.hub.url, None);
    assert!(!b.signed_in);
    assert_eq!(server_c.controls.challenges.load(Ordering::SeqCst), 0);

    // B's own URL: verified, and the device signs in there with audience B.
    alice
        .client
        .set_hub_url(&hub_id(&hub_b), &server_b.url)
        .await
        .unwrap();
    let hubs = alice.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b);
    assert_eq!(b.hub.state, HubState::Verified);
    assert_eq!(b.hub.url.as_deref(), Some(server_b.url.as_str()));
    assert_eq!(b.hub.priority, 1);
    assert!(b.signed_in);
    assert_eq!(server_b.controls.challenges.load(Ordering::SeqCst), 1);
    // Registry order: (priority, hub_id).
    let order: Vec<String> = hubs.iter().map(|h| h.hub.hub_id.clone()).collect();
    assert_eq!(order, [hub_id(&hub_a), hub_id(&hub_b)]);

    // A restart restores the registry and the session on B; the next
    // refresh checks B's URL again but needs no new sign-in.
    let restarted = alice.restart().await;
    let before_restart = hubs;
    assert_eq!(restarted.hubs().await.unwrap(), before_restart);
    restarted.refresh_hubs().await.unwrap();
    assert_eq!(server_b.controls.challenges.load(Ordering::SeqCst), 1);
    let hubs = restarted.hubs().await.unwrap();
    assert!(status(&hubs, &hub_b).signed_in);
    assert_eq!(status(&hubs, &hub_b).hub.state, HubState::Verified);
}

#[tokio::test]
async fn hosting_record_updates_and_the_self_group_spread_the_hubs() {
    let hub_a = FlakyTransport::new();
    let hub_b = FlakyTransport::over(FakeTransport::with_hub_seed(SEED_B));
    let urls = connector(&[("fake://a", &hub_a), ("fake://b", &hub_b)]);
    let alice = Account::register(Arc::new(hub_a.clone()), Some(urls.clone())).await;
    let user_id = alice.user_id();
    let tablet = link(&alice).await;

    // Without a URL, the home hub is verified but has none to share.
    let hubs = alice.client.hubs().await.unwrap();
    assert_eq!(hubs.len(), 1, "{hubs:?}");
    let a = status(&hubs, &hub_a.inner);
    assert!(a.home && a.signed_in);
    assert_eq!(a.hub.state, HubState::Verified);
    assert_eq!(a.hub.url, None);

    // hosting_record.updated: the record read again lists B.
    alice.copy_device_list(&hub_a.inner, &hub_b.inner).await;
    let record = alice.record(2, &[(&hub_a.inner, 0), (&hub_b.inner, 1)]);
    hub_a.inner.set_hosting_record(&user_id, Some(record));
    inject_update(&hub_a, &user_id, 2);
    alice.client.sync_once().await.unwrap();
    let hubs = alice.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b.inner);
    assert_eq!(b.hub.state, HubState::Unverified);
    assert_eq!(b.hub.priority, 1);
    assert_eq!(hub_b.faults.challenges.load(Ordering::SeqCst), 0);

    // Alice learns B's URL; the tablet gets it through the self group,
    // checks it and signs in on B too.
    alice
        .client
        .set_hub_url(&hub_id(&hub_b.inner), "fake://b")
        .await
        .unwrap();
    assert!(status(&alice.client.hubs().await.unwrap(), &hub_b.inner).signed_in);
    assert_eq!(hub_b.faults.challenges.load(Ordering::SeqCst), 1);
    tablet.client.sync_once().await.unwrap();
    let hubs = tablet.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b.inner);
    assert_eq!(b.hub.state, HubState::Verified);
    assert_eq!(b.hub.url.as_deref(), Some("fake://b"));
    assert!(b.signed_in);
    assert_eq!(hub_b.faults.challenges.load(Ordering::SeqCst), 2);

    // A record without B: B is marked removed.
    let record = alice.record(3, &[(&hub_a.inner, 0)]);
    hub_a.inner.set_hosting_record(&user_id, Some(record));
    inject_update(&hub_a, &user_id, 3);
    alice.client.sync_once().await.unwrap();
    let hubs = alice.client.hubs().await.unwrap();
    assert_eq!(status(&hubs, &hub_b.inner).hub.state, HubState::Removed);
    assert_eq!(status(&hubs, &hub_a.inner).hub.state, HubState::Verified);
}

#[tokio::test]
async fn a_shared_url_serving_another_hub_stays_unverified() {
    let hub_a = FlakyTransport::new();
    let hub_b = FlakyTransport::over(FakeTransport::with_hub_seed(SEED_B));
    let hub_c = FlakyTransport::over(FakeTransport::with_hub_seed(SEED_C));
    let urls = connector(&[("fake://b", &hub_b), ("fake://c", &hub_c)]);
    let alice = Account::register(Arc::new(hub_a.clone()), Some(urls)).await;
    let user_id = alice.user_id();
    let tablet = link(&alice).await;
    let record = alice.record(2, &[(&hub_a.inner, 0), (&hub_b.inner, 1)]);
    hub_a.inner.set_hosting_record(&user_id, Some(record));
    tablet.client.refresh_hubs().await.unwrap();

    // Another own device shares a wrong URL for B.
    let wrong = gim_proto::envelope::Content::SelfHubs {
        hubs: vec![gim_proto::envelope::HubLocation {
            hub_id: hub_id(&hub_b.inner),
            url: "fake://c".into(),
            priority: 1,
        }],
    };
    let self_group = gim_base::StateReader::self_groups(&*alice.store)
        .unwrap()
        .pop()
        .unwrap();
    alice.client.send(&self_group, wrong).await.unwrap();
    tablet.client.sync_once().await.unwrap();
    let hubs = tablet.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b.inner);
    assert_eq!(b.hub.state, HubState::Unverified);
    assert_eq!(b.hub.url.as_deref(), Some("fake://c"));
    assert!(!b.signed_in);
    assert_eq!(hub_c.faults.challenges.load(Ordering::SeqCst), 0);
}

fn inject_update(hub: &FlakyTransport, user_id: &UserId, seq: u64) {
    hub.faults
        .injected_events
        .lock()
        .unwrap()
        .push(HubEvent::HostingRecordUpdated {
            user_id: user_id.clone(),
            seq,
        });
}

/// A new device of `old`'s user, linked and confirmed on both, in the self
/// group.
async fn link(old: &Account) -> Account {
    let new = Account::new(old.transport.clone(), old.connector.clone());
    let session = new.client.start_link(vec!["hub.example".into()]).unwrap();
    let approval = old.client.approve_link(&session.qr_string).await.unwrap();
    let linked = new.client.wait_link(&session).await.unwrap();
    assert_eq!(linked.sas, approval.sas);
    new.client.confirm_link(true).await.unwrap();
    old.client.confirm_approval(&approval, true).await.unwrap();
    new.client.sync_once().await.unwrap();
    new
}
