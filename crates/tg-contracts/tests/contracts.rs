use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{
    validate_engine_for_policy, DeviceIdentity, DeviceMode, EngineManifest, FailureBehavior,
    HostIdentity, Maturity, OperationKind, Provenance, RouteDecision, SessionRequest,
    CONTRACT_VERSION,
};

fn provenance() -> Provenance {
    Provenance {
        source_repository: "owner/repo".to_owned(),
        source_commit: "0123456789abcdef".to_owned(),
        source_release: None,
        licence: "MIT".to_owned(),
        local_patch_hash: None,
        build_recipe_hash: None,
        artifact_hashes: BTreeMap::new(),
    }
}

fn manifest(maturity: Maturity) -> EngineManifest {
    EngineManifest {
        schema_version: CONTRACT_VERSION.to_owned(),
        engine_id: "fixture-engine".to_owned(),
        version: "0.1.0".to_owned(),
        maturity,
        capabilities: BTreeSet::new(),
        requested_permissions: BTreeSet::new(),
        supported_hosts: BTreeSet::new(),
        executes_external_code: false,
        requires_network: false,
        modifies_device: false,
        provenance: provenance(),
        proof_requirements: BTreeSet::new(),
        failure_behavior: FailureBehavior::FailClosed,
    }
}

#[test]
fn stable_policy_accepts_only_stable_engine_maturity() {
    assert!(validate_engine_for_policy(&manifest(Maturity::Stable), "stable").is_ok());
    assert!(validate_engine_for_policy(&manifest(Maturity::Beta), "stable").is_err());
    assert!(validate_engine_for_policy(&manifest(Maturity::HardwareTested), "stable").is_err());
}

#[test]
fn blocked_route_cannot_smuggle_engines_or_permissions() {
    let decision = RouteDecision::blocked("unknown_device", "No approved route");

    assert!(!decision.approved);
    assert!(decision.route_id.is_none());
    assert!(decision.engine_ids.is_empty());
    assert!(decision.granted_permissions.is_empty());
    assert_eq!(decision.rationale_codes, ["unknown_device"]);
}

#[test]
fn new_sessions_are_offline_and_stable_by_default() {
    let session = SessionRequest::new(
        OperationKind::Diagnose,
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
            version: Some("fixture".to_owned()),
            architecture: "x86_64".to_owned(),
        },
        DeviceMode::Recovery,
    );

    assert_eq!(session.schema_version, CONTRACT_VERSION);
    assert_eq!(session.policy_profile, "stable");
    assert!(session.offline_required);
    assert!(session.requested_permissions.is_empty());
}

#[test]
fn session_contract_round_trips_without_losing_policy_fields() {
    let session = SessionRequest::new(
        OperationKind::PreserveDevice,
        DeviceIdentity {
            product_type: "iPhone8,1".to_owned(),
            board_config: None,
            chip: Some("A9".to_owned()),
            cpid: None,
            ecid_hash: Some("redacted-hash".to_owned()),
            udid_hash: None,
            serial_hash: None,
        },
        HostIdentity {
            os: "macos".to_owned(),
            version: None,
            architecture: "arm64".to_owned(),
        },
        DeviceMode::Normal,
    );

    let encoded = serde_json::to_string(&session).expect("session should serialize");
    let decoded: SessionRequest =
        serde_json::from_str(&encoded).expect("session should deserialize");

    assert_eq!(decoded, session);
}
