//! Persisted pending-commit records and departed-member candidates.

mod common;

use common::{group, new_client_id, setup, Device};
use gim_base::model::{AfterCommit, DepartedMember, IncomingEvent, PendingCommit};
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
fn merging_settles_the_pending_commit_record() {
    let ds = FakeDeliveryService::new();
    let g = group("crew");
    let (alice, bob, carol) = (
        Device::new("alice"),
        Device::new("bob"),
        Device::new("carol"),
    );
    setup(&ds, &g, &[&alice, &bob]);

    let commit = |then: AfterCommit, devices: Vec<gim_common::DeviceRef>| {
        alice
            .store
            .transaction(|txn| {
                let out = if devices.is_empty() {
                    alice
                        .engine
                        .add_members(&*txn, &g, &[carol.key_package()])?
                } else {
                    alice.engine.remove_members(&*txn, &g, &devices)?
                };
                txn.upsert_pending_commit(&PendingCommit {
                    group_id: g.clone(),
                    client_id: new_client_id(),
                    epoch: out.epoch,
                    payload: out.commit,
                    merged: false,
                    then: then.clone(),
                })?;
                Ok(())
            })
            .unwrap();
    };

    // A follow-up is left: the record is kept, marked merged.
    commit(
        AfterCommit::RemoveFromFanOut(vec![bob.me.clone()]),
        vec![bob.me.clone()],
    );
    alice
        .client
        .merge_own_commit(&alice.store, &alice.engine, &g, 10)
        .unwrap();
    let pending = alice.store.pending_commit(&g).unwrap().unwrap();
    assert!(pending.merged);
    alice
        .store
        .transaction(|txn| Ok(txn.remove_pending_commit(&g)?))
        .unwrap();

    // Nothing follows: the record goes with the merge.
    commit(AfterCommit::Nothing, vec![]);
    alice
        .client
        .merge_own_commit(&alice.store, &alice.engine, &g, 11)
        .unwrap();
    assert_eq!(alice.store.pending_commit(&g).unwrap(), None);
    assert!(alice.store.pending_commits().unwrap().is_empty());
}
