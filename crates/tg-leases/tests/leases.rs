use std::collections::BTreeSet;

use tg_leases::{LeaseError, LeaseManager, LeaseOwner, ResourceKey, ResourceKind};
use uuid::Uuid;

fn set<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn owner(worker: &str) -> LeaseOwner {
    LeaseOwner {
        session_id: Uuid::new_v4(),
        worker_id: worker.to_owned(),
        run_id: Uuid::new_v4(),
    }
}

fn resource(kind: ResourceKind, id: &str) -> ResourceKey {
    ResourceKey {
        kind,
        stable_id: id.to_owned(),
    }
}

#[test]
fn multi_resource_acquire_is_atomic() {
    let mut manager = LeaseManager::default();
    let usb = resource(ResourceKind::Usb, "port-1");
    let device = resource(ResourceKind::Device, "device-1");
    let first_owner = owner("worker-a");
    manager
        .acquire(set([usb.clone()]), first_owner, 0, 10)
        .unwrap();

    let second_owner = owner("worker-b");
    let result = manager.acquire(
        set([usb.clone(), device.clone()]),
        second_owner,
        0,
        10,
    );

    assert_eq!(result, Err(LeaseError::ResourceConflict(vec![usb])));
    assert!(manager.active_for(&device).is_none());
    assert_eq!(manager.active_resource_count(), 1);
}

#[test]
fn same_lease_owns_all_requested_resources() {
    let mut manager = LeaseManager::default();
    let usb = resource(ResourceKind::Usb, "port-1");
    let device = resource(ResourceKind::Device, "device-1");
    let primary_owner = owner("worker-a");
    let grant = manager
        .acquire(
            set([usb.clone(), device.clone()]),
            primary_owner,
            4,
            6,
        )
        .unwrap();

    assert_eq!(manager.active_for(&usb).unwrap().lease_id, grant.lease_id);
    assert_eq!(
        manager.active_for(&device).unwrap().lease_id,
        grant.lease_id
    );
    assert_eq!(grant.expires_at_tick, 10);
}

#[test]
fn wrong_owner_cannot_release_lease() {
    let mut manager = LeaseManager::default();
    let usb = resource(ResourceKind::Usb, "port-1");
    let primary_owner = owner("worker-a");
    let grant = manager
        .acquire(set([usb.clone()]), primary_owner.clone(), 0, 10)
        .unwrap();

    assert_eq!(
        manager.release(grant.lease_id, &owner("worker-b")),
        Err(LeaseError::OwnerMismatch)
    );
    assert!(manager.active_for(&usb).is_some());
    manager.release(grant.lease_id, &primary_owner).unwrap();
    assert!(manager.active_for(&usb).is_none());
}

#[test]
fn expired_lease_releases_every_resource() {
    let mut manager = LeaseManager::default();
    let resources = set([
        resource(ResourceKind::Usb, "port-1"),
        resource(ResourceKind::Device, "device-1"),
    ]);
    let grant = manager
        .acquire(resources, owner("worker-a"), 5, 5)
        .unwrap();

    assert!(manager.expire(9).is_empty());
    let expired = manager.expire(10);
    assert_eq!(expired, vec![grant]);
    assert_eq!(manager.active_resource_count(), 0);
}

#[test]
fn lease_renewal_requires_same_owner() {
    let mut manager = LeaseManager::default();
    let primary_owner = owner("worker-a");
    let grant = manager
        .acquire(
            set([resource(ResourceKind::Session, "session-1")]),
            primary_owner.clone(),
            1,
            4,
        )
        .unwrap();

    assert_eq!(
        manager.renew(grant.lease_id, &owner("worker-b"), 3, 10),
        Err(LeaseError::OwnerMismatch)
    );
    let renewed = manager
        .renew(grant.lease_id, &primary_owner, 3, 10)
        .unwrap();
    assert_eq!(renewed.expires_at_tick, 13);
}
