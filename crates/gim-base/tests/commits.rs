//! Persisted pending-commit records and departed-member candidates.

mod common;

use common::{group, new_client_id, setup, Device};
use gim_base::model::{DepartedMember, IncomingEvent, PendingCommit};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_test::FakeDeliveryService;

fn removed(device: &Device, g: &gim_common::GroupId) -> IncomingEvent {
    IncomingEvent::MemberRemoved {
        group_id: g.clone(),
        device: device.me.clone(),
    }
}

#[test]
fn departed_members_are_recorded_until_out_of_the_tree() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob, &carol]);
    let departed = DepartedMember {
        group_id: g.clone(),
        device: carol.me.clone(),
    };

    // Recording is idempotent; the own device is never a candidate.
    for device in [&alice, &bob] {
        device.apply(removed(&carol, &g));
        device.apply(removed(&carol, &g));
        assert_eq!(
            device.store.departed_members().unwrap(),
            vec![departed.clone()]
        );
    }
    bob.apply(removed(&bob, &g));
    assert_eq!(bob.store.departed_members().unwrap(), vec![departed]);

    // Merging the own removal commit drops the candidate...
    alice.remove(&ds, &g, &[&carol]);
    assert!(alice.store.departed_members().unwrap().is_empty());
    // ...and so does applying someone else's.
    bob.sync(&ds);
    assert!(bob.store.departed_members().unwrap().is_empty());
}

#[test]
fn merging_removes_the_pending_commit_record() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob]);
    alice
        .store
        .transaction(|txn| {
            let out = alice
                .engine
                .add_members(&*txn, &g, &[carol.key_package()])?;
            txn.upsert_pending_commit(&PendingCommit {
                group_id: g.clone(),
                client_id: new_client_id(),
                epoch: out.epoch,
                payload: out.commit,
                welcome: None,
            })?;
            Ok(())
        })
        .unwrap();
    alice
        .client
        .merge_own_commit(&alice.store, &alice.engine, &g, 10)
        .unwrap();
    assert_eq!(alice.store.pending_commit(&g).unwrap(), None);
    assert!(alice.store.pending_commits().unwrap().is_empty());
}

/// Whether the MLS group has a pending commit; clears it if so.
fn take_mls_pending_commit(device: &Device, g: &gim_common::GroupId) -> bool {
    device
        .store
        .transaction(|txn| match device.engine.clear_pending_commit(&*txn, g) {
            Ok(()) => Ok(true),
            Err(gim_crypto::CryptoError::NoPendingCommit) => Ok(false),
            Err(err) => Err(err.into()),
        })
        .unwrap()
}

fn record(g: &gim_common::GroupId, epoch: u64) -> PendingCommit {
    PendingCommit {
        group_id: g.clone(),
        client_id: new_client_id(),
        epoch,
        payload: vec![1],
        welcome: None,
    }
}

#[test]
fn startup_reconciles_dangling_pending_commits() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    setup(&ds, &g, &[&alice, &bob]);
    let reconcile = || {
        alice
            .client
            .reconcile_pending_commits(&alice.store, &alice.engine)
            .unwrap()
    };
    let upsert = |commit: PendingCommit| {
        alice
            .store
            .transaction(|txn| Ok(txn.upsert_pending_commit(&commit)?))
            .unwrap()
    };
    let mls_commit = || {
        alice
            .store
            .transaction(|txn| {
                Ok(alice
                    .engine
                    .remove_members(&*txn, &g, std::slice::from_ref(&bob.me))?)
            })
            .unwrap()
    };
    let epoch = alice.epoch(&g);
    assert!(reconcile().is_empty());

    // An MLS pending commit without a record is cleared, once.
    mls_commit();
    assert_eq!(reconcile(), vec![g.clone()]);
    assert!(reconcile().is_empty());
    assert!(!take_mls_pending_commit(&alice, &g));
    assert_eq!(alice.epoch(&g), epoch);

    // A record without an MLS pending commit is dropped, also for a group
    // that is gone.
    let gone = group("gone");
    upsert(record(&g, epoch));
    upsert(record(&gone, 1));
    assert_eq!(reconcile(), vec![g.clone(), gone]);
    assert!(alice.store.pending_commits().unwrap().is_empty());

    // A matching pair is left alone and can still be merged.
    let out = mls_commit();
    upsert(record(&g, out.epoch));
    assert!(reconcile().is_empty());
    alice
        .client
        .merge_own_commit(&alice.store, &alice.engine, &g, 100)
        .unwrap();
    assert_eq!(alice.epoch(&g), epoch + 1);
    assert!(alice.store.pending_commits().unwrap().is_empty());
}
