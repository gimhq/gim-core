//! The hub registry (multi-homing, contract `multihoming.md` §4.1, §4.5,
//! Q2): the home hub is bootstrapped with `GET /v2/hub`, listed hubs come
//! from the hosting record, their URLs from `set_hub_url` or the self
//! group, every URL must prove the listed `hub_id` at that URL (hub proof
//! of possession) before the device signs in there with a challenge bound
//! to it, and the registry and the per-hub sessions survive a restart.

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
const B_URL: &str = "https://hub-b.example.eu";
const C_URL: &str = "https://hub-c.example.eu";
const RELAY_URL: &str = "https://relay.example.eu";

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
    let hub_b = FlakyTransport::over(FakeTransport::with_hub_seed(SEED_B).with_public_url(B_URL));
    let urls = connector(&[(B_URL, &hub_b)]);
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
    // checks it with the hub proof and then uses B: it signs in there and
    // uploads KeyPackages.
    alice
        .client
        .set_hub_url(&hub_id(&hub_b.inner), B_URL)
        .await
        .unwrap();
    assert!(status(&alice.client.hubs().await.unwrap(), &hub_b.inner).signed_in);
    assert_eq!(hub_b.faults.challenges.load(Ordering::SeqCst), 1);
    tablet.client.sync_once().await.unwrap();
    let hubs = tablet.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b.inner);
    assert_eq!(b.hub.state, HubState::Verified);
    assert_eq!(b.hub.url.as_deref(), Some(B_URL));
    assert!(b.hub.url_shared);
    assert!(b.signed_in);
    assert_eq!(
        b.hub.verified_root_pubkey.as_deref(),
        Some(hub_b.inner.hub_root_key().public().as_bytes().as_slice())
    );
    let tablet_device = tablet.client.session().unwrap().device;
    assert_eq!(hub_b.faults.challenges.load(Ordering::SeqCst), 2);
    assert_eq!(
        hub_b.inner.service().key_package_count(&tablet_device),
        gim_sdk::KEY_PACKAGE_BATCH as usize
    );
    // The same URL set on the tablet: checked again, no new sign-in.
    tablet
        .client
        .set_hub_url(&hub_id(&hub_b.inner), B_URL)
        .await
        .unwrap();
    let hubs = tablet.client.hubs().await.unwrap();
    let b = status(&hubs, &hub_b.inner);
    assert_eq!(b.hub.state, HubState::Verified);
    assert!(!b.hub.url_shared);
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
async fn shared_urls_that_do_not_prove_the_hub_get_one_request_only() {
    let hub_a = FlakyTransport::new();
    let fake_b = FakeTransport::with_hub_seed(SEED_B).with_public_url(B_URL);
    let hub_b = FlakyTransport::over(fake_b.clone());
    let hub_c = FlakyTransport::over(FakeTransport::with_hub_seed(SEED_C).with_public_url(C_URL));
    // A relay in front of B: B's identity and proofs, for B's URL.
    let relay = FlakyTransport::over(fake_b);
    let urls = connector(&[(B_URL, &hub_b), (C_URL, &hub_c), (RELAY_URL, &relay)]);
    let alice = Account::register(Arc::new(hub_a.clone()), Some(urls)).await;
    let user_id = alice.user_id();
    let tablet = link(&alice).await;
    let record = alice.record(2, &[(&hub_a.inner, 0), (&hub_b.inner, 1)]);
    hub_a.inner.set_hosting_record(&user_id, Some(record));
    tablet.client.refresh_hubs().await.unwrap();
    let self_group = gim_base::StateReader::self_groups(&*alice.store)
        .unwrap()
        .pop()
        .unwrap();
    let tablet_device = tablet.client.session().unwrap().device;

    // Another own device shares a wrong URL for B, then a relay's.
    for (url, wrong) in [(C_URL, &hub_c), (RELAY_URL, &relay)] {
        let shared = gim_proto::envelope::Content::SelfHubs {
            hubs: vec![gim_proto::envelope::HubLocation {
                hub_id: hub_id(&hub_b.inner),
                url: url.into(),
                priority: 1,
            }],
        };
        alice.client.send(&self_group, shared).await.unwrap();
        tablet.client.sync_once().await.unwrap();
        tablet.client.refresh_hubs().await.unwrap();
        tablet.client.replenish_key_packages().await.unwrap();
        let note = gim_proto::envelope::Content::Text {
            body: "ahoy".into(),
        };
        let self_group = gim_base::StateReader::self_groups(&*tablet.store)
            .unwrap()
            .pop()
            .unwrap();
        tablet.client.send(&self_group, note).await.unwrap();
        let hubs = tablet.client.hubs().await.unwrap();
        let b = status(&hubs, &hub_b.inner);
        assert_eq!(b.hub.state, HubState::Unverified, "{url}");
        assert_eq!(b.hub.url.as_deref(), Some(url));
        assert!(b.hub.url_shared);
        assert!(!b.signed_in);
        // The hub proof only, once: no sign-in, KeyPackages or posts.
        assert_eq!(wrong.faults.hub_infos.load(Ordering::SeqCst), 1, "{url}");
        assert_eq!(wrong.faults.challenges.load(Ordering::SeqCst), 0);
        assert!(wrong.faults.message_posts.lock().unwrap().is_empty());
        assert!(wrong.faults.commit_posts.lock().unwrap().is_empty());
    }
    assert_eq!(hub_b.inner.service().key_package_count(&tablet_device), 0);
    assert_eq!(hub_b.faults.hub_infos.load(Ordering::SeqCst), 0);
    assert_eq!(hub_b.faults.challenges.load(Ordering::SeqCst), 0);
}

/// Registers a new device at `url`; the client's own transport is the home
/// hub.
async fn register_at(url: &str) -> (Client<MemoryStore>, Result<(), ClientError>) {
    let transport = Arc::new(HttpTransport::new(url.parse().unwrap()).unwrap());
    let account = Account::new(transport, None);
    let result = account.client.register("alice", "Alice").await.map(drop);
    (account.client, result)
}

fn not_verified(result: &Result<(), ClientError>) -> bool {
    matches!(
        result,
        Err(ClientError::Transport(TransportError::HubNotVerified(_)))
    )
}

#[tokio::test]
async fn a_relay_gets_no_session() {
    let hub_a = FakeTransport::new();
    let server_a = MockServer::start(hub_a.clone()).await;
    let relay = MockServer::relay(hub_a.clone()).await;

    // The home hub behind a relay: the proof names the hub's URL.
    let (client, result) = register_at(&relay.url).await;
    assert!(not_verified(&result), "{result:?}");
    assert!(client.session().is_none());
    assert_eq!(relay.controls.hub_infos.load(Ordering::SeqCst), 1);
    for controls in [&relay.controls, &server_a.controls] {
        assert_eq!(controls.challenges.load(Ordering::SeqCst), 0);
        assert_eq!(controls.sessions.load(Ordering::SeqCst), 0);
    }

    // A listed hub behind a relay.
    let hub_b = FakeTransport::with_hub_seed(SEED_B);
    let server_b = MockServer::start(hub_b.clone()).await;
    let relay_b = MockServer::relay(hub_b.clone()).await;
    let transport = Arc::new(HttpTransport::new(server_a.url.parse().unwrap()).unwrap());
    let alice = Account::register(transport, None).await;
    alice.copy_device_list(&hub_a, &hub_b).await;
    let record = alice.record(2, &[(&hub_a, 0), (&hub_b, 1)]);
    hub_a.set_hosting_record(&alice.user_id(), Some(record));
    alice.client.refresh_hubs().await.unwrap();
    let result = alice
        .client
        .set_hub_url(&hub_id(&hub_b), &relay_b.url)
        .await;
    assert!(
        matches!(result, Err(ClientError::InvalidInput(_))),
        "{result:?}"
    );
    let b = status(&alice.client.hubs().await.unwrap(), &hub_b).clone();
    assert_eq!(b.hub.state, HubState::Unverified);
    assert!(!b.signed_in);
    for controls in [&relay_b.controls, &server_b.controls] {
        assert_eq!(controls.challenges.load(Ordering::SeqCst), 0);
        assert_eq!(controls.sessions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn the_home_hub_must_prove_itself_at_the_typed_url() {
    let hub = FakeTransport::new();
    let server = MockServer::start(hub.clone()).await;
    let controls = &server.controls;
    let refused = |result: &Result<(), ClientError>| {
        assert!(not_verified(result), "{result:?}");
        assert_eq!(controls.challenges.load(Ordering::SeqCst), 0);
        assert_eq!(controls.sessions.load(Ordering::SeqCst), 0);
    };

    // The hub signs another public URL than the one contacted.
    hub.set_public_url(Some("https://elsewhere.example.eu"));
    refused(&register_at(&server.url).await.1);
    hub.set_public_url(Some(&server.url));

    // A bad signature.
    controls.corrupt_proof.store(true, Ordering::SeqCst);
    refused(&register_at(&server.url).await.1);
    controls.corrupt_proof.store(false, Ordering::SeqCst);

    // A proof replayed for an old nonce.
    *controls.replay_nonce.lock().unwrap() = Some([9; 32]);
    refused(&register_at(&server.url).await.1);
    *controls.replay_nonce.lock().unwrap() = None;

    let (client, result) = register_at(&server.url).await;
    result.unwrap();
    assert!(client.session().is_some());
    assert_eq!(controls.sessions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn challenges_must_be_bound_to_the_proven_url() {
    let hub = FakeTransport::new();
    let server = MockServer::start(hub.clone()).await;
    let controls = &server.controls;

    // A v1 challenge from a hub that proved a public URL.
    controls.challenge_v1.store(true, Ordering::SeqCst);
    let (client, result) = register_at(&server.url).await;
    assert!(not_verified(&result), "{result:?}");
    assert!(client.session().is_none());
    controls.challenge_v1.store(false, Ordering::SeqCst);

    // A v2 challenge for another URL.
    *controls.challenge_url.lock().unwrap() = Some(RELAY_URL.into());
    let (client, result) = register_at(&server.url).await;
    assert!(not_verified(&result), "{result:?}");
    assert!(client.session().is_none());
    assert_eq!(controls.sessions.load(Ordering::SeqCst), 0);
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
