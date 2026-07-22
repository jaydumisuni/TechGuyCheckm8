use std::collections::BTreeSet;

use tg_contracts::Permission;
use tg_policy::{evaluate_permissions, PolicyContext, PolicyProfile};

fn set(values: impl IntoIterator<Item = Permission>) -> BTreeSet<Permission> {
    values.into_iter().collect()
}

#[test]
fn worker_cannot_expand_beyond_route_requirements() {
    let decision = evaluate_permissions(
        &PolicyContext {
            profile: PolicyProfile::Stable,
            offline_required: true,
            destructive_authorized: false,
            recovery_ready: false,
        },
        &set([Permission::UsbRead, Permission::UsbWrite]),
        &set([Permission::UsbRead]),
        &set([Permission::UsbRead, Permission::UsbWrite]),
    );

    assert!(decision.approved);
    assert_eq!(decision.granted, set([Permission::UsbRead]));
    assert!(!decision.granted.contains(&Permission::UsbWrite));
}

#[test]
fn destructive_permission_needs_authorization_and_recovery() {
    let needed = set([Permission::FirmwareRestore]);
    let denied = evaluate_permissions(
        &PolicyContext {
            profile: PolicyProfile::Stable,
            offline_required: true,
            destructive_authorized: true,
            recovery_ready: false,
        },
        &needed,
        &needed,
        &needed,
    );
    assert!(!denied.approved);
    assert!(denied
        .denied_by_policy
        .contains(&Permission::FirmwareRestore));

    let approved = evaluate_permissions(
        &PolicyContext {
            profile: PolicyProfile::Stable,
            offline_required: true,
            destructive_authorized: true,
            recovery_ready: true,
        },
        &needed,
        &needed,
        &needed,
    );
    assert!(approved.approved);
}

#[test]
fn offline_session_denies_network_access() {
    let needed = set([Permission::NetworkApprovedSource]);
    let decision = evaluate_permissions(
        &PolicyContext {
            profile: PolicyProfile::Beta,
            offline_required: true,
            destructive_authorized: false,
            recovery_ready: false,
        },
        &needed,
        &needed,
        &needed,
    );

    assert!(!decision.approved);
    assert!(decision
        .denied_by_policy
        .contains(&Permission::NetworkApprovedSource));
}

#[test]
fn missing_human_authorization_fails_closed() {
    let needed = set([Permission::UsbWrite]);
    let decision = evaluate_permissions(
        &PolicyContext {
            profile: PolicyProfile::Beta,
            offline_required: true,
            destructive_authorized: false,
            recovery_ready: false,
        },
        &needed,
        &needed,
        &BTreeSet::new(),
    );

    assert!(!decision.approved);
    assert!(decision
        .missing_human_authorization
        .contains(&Permission::UsbWrite));
}
