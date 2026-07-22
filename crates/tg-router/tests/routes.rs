use std::collections::BTreeSet;

use tg_contracts::{
    DeviceIdentity, DeviceMode, FirmwareIdentity, HostIdentity, Maturity, OperationKind, Permission,
    SessionRequest,
};
use tg_router::{select_route, AvailableResources, RouteManifest};

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
    request
}

fn stable_route(id: &str) -> RouteManifest {
    RouteManifest {
        route_id: id.to_owned(),
        engine_ids: vec!["fixture-engine".to_owned()],
        maturity: Maturity::Stable,
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

#[test]
fn exact_route_is_selected() {
    let decision = select_route(
        &request(),
        &[stable_route("a11-fixture")],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
    );

    assert!(decision.approved);
    assert_eq!(decision.route_id.as_deref(), Some("a11-fixture"));
}

#[test]
fn unknown_firmware_is_blocked() {
    let mut request = request();
    request.firmware.as_mut().unwrap().version = "99.0".to_owned();

    let decision = select_route(
        &request,
        &[stable_route("a11-fixture")],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
    );

    assert!(!decision.approved);
    assert_eq!(decision.rationale_codes, ["no_exact_route"]);
}

#[test]
fn ambiguous_exact_matches_are_blocked() {
    let decision = select_route(
        &request(),
        &[stable_route("route-one"), stable_route("route-two")],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
    );

    assert!(!decision.approved);
    assert_eq!(decision.rationale_codes, ["ambiguous_route"]);
}

#[test]
fn beta_route_cannot_enter_stable_session() {
    let mut route = stable_route("beta-route");
    route.maturity = Maturity::Beta;

    let decision = select_route(
        &request(),
        &[route],
        &AvailableResources {
            hardware: BTreeSet::new(),
        },
    );

    assert!(!decision.approved);
}
