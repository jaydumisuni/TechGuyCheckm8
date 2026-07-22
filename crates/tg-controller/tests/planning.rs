use std::collections::BTreeSet;

use tg_contracts::{
    DeviceIdentity, DeviceMode, FirmwareIdentity, HostIdentity, Maturity, OperationKind, Permission,
    SessionRequest, SessionState,
};
use tg_controller::{prepare_session, PlanOutcome};
use tg_policy::{PolicyContext, PolicyProfile};
use tg_router::{AvailableResources, RouteManifest};

fn set<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn request() -> SessionRequest {
    let mut request = SessionRequest::new(
        OperationKind::Jailbreak,
        DeviceIdentity {
            product_type: "iPhone10,6".to_owned(),
            board_config: Some("d221ap".to_owned()),
            chip: Some("A11".to_owned()),
            cpid: Some("0x8015".to_owned()),
            ecid_hash: None,
            udid_hash: None,
            serial_hash: None,
        },
        HostIdentity {
            os: "linux".to_owned(),
            version: None,
            architecture: "x86_64".to_owned(),
        },
        DeviceMode::Dfu,
    );
    request.firmware = Some(FirmwareIdentity {
        version: "16.7.12".to_owned(),
        build: None,
        architecture: Some("arm64".to_owned()),
    });
    request.policy_profile = "beta".to_owned();
    request
}

fn route() -> RouteManifest {
    RouteManifest {
        route_id: "fixture-route".to_owned(),
        engine_ids: vec!["fixture-engine".to_owned()],
        maturity: Maturity::Beta,
        operations: set([OperationKind::Jailbreak]),
        product_types: set(["iPhone10,6".to_owned()]),
        chips: set(["A11".to_owned()]),
        firmware_versions: set(["16.7.12".to_owned()]),
        host_platforms: set(["linux".to_owned()]),
        allowed_entry_modes: set([DeviceMode::Dfu]),
        required_permissions: set([Permission::UsbWrite]),
        hardware_requirements: BTreeSet::new(),
        exact_hardware_proof: true,
    }
}

fn beta_policy() -> PolicyContext {
    PolicyContext {
        profile: PolicyProfile::Beta,
        offline_required: true,
        destructive_authorized: false,
        recovery_ready: false,
    }
}

#[test]
fn approved_plan_reaches_preparing_only_after_both_gates() {
    let permissions = set([Permission::UsbWrite]);
    let outcome = prepare_session(
        &request(),
        &[route()],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
        &beta_policy(),
        &permissions,
        &permissions,
    )
    .unwrap();

    let PlanOutcome::Ready(prepared) = outcome else {
        panic!("expected ready plan");
    };
    assert_eq!(prepared.machine.state(), &SessionState::Preparing);
    assert_eq!(prepared.machine.transition_count(), 5);
}

#[test]
fn unsupported_route_fails_before_authorization() {
    let mut request = request();
    request.firmware.as_mut().unwrap().version = "99.0".to_owned();
    let permissions = set([Permission::UsbWrite]);

    let outcome = prepare_session(
        &request,
        &[route()],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
        &beta_policy(),
        &permissions,
        &permissions,
    )
    .unwrap();

    let PlanOutcome::RouteBlocked(decision) = outcome else {
        panic!("expected route block");
    };
    assert!(!decision.approved);
}

#[test]
fn missing_human_authorization_blocks_preparation() {
    let permissions = set([Permission::UsbWrite]);
    let outcome = prepare_session(
        &request(),
        &[route()],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
        &beta_policy(),
        &permissions,
        &BTreeSet::new(),
    )
    .unwrap();

    let PlanOutcome::PermissionBlocked { permissions, .. } = outcome else {
        panic!("expected permission block");
    };
    assert!(!permissions.approved);
}
