use tg_contracts::Maturity;
use tg_purple_boot::{
    build_purple_boot_plan, required_permissions, validate_route_manifest,
    BootEnvironmentBackupReceipt, PurpleBootError, PurpleBootRequest, PurpleBootRouteManifest,
};
use tg_usbliter8::PwnDfuFinalProof;
use uuid::Uuid;

#[test]
fn research_route_tracks_public_evidence_without_claiming_asset_readiness() {
    let route: PurpleBootRouteManifest = serde_json::from_str(include_str!(
        "../../../manifests/purple/routes/a12-iphone11,6-d331pap-usbliter8.research.json"
    ))
    .unwrap();

    assert_eq!(route.maturity, Maturity::Discovered);
    assert!(route.raw_ibss.sha256.is_none());
    assert!(route.diag_image.sha256.is_none());
    assert!(!route.raw_ibss.redistribution_allowed);
    assert!(!route.diag_image.redistribution_allowed);
    assert_eq!(route.requested_permissions, required_permissions());
    assert!(validate_route_manifest(&route, "development").is_ok());

    let session_id = Uuid::new_v4();
    let pwn_observation = tg_apple_observe::ObservedAppleDevice {
        schema_version: tg_apple_observe::OBSERVATION_SCHEMA_VERSION.to_owned(),
        rule_id: Some("synthetic.pwnd".to_owned()),
        mode: tg_contracts::DeviceMode::PwnedDfu,
        cpid: Some("8020".to_owned()),
        ecid_hash: Some("synthetic-ecid-hash".to_owned()),
        serial_hash: Some("synthetic-serial-hash".to_owned()),
        pwn_provider: Some("usbliter8".to_owned()),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        device_identity_hash: Some("synthetic-identity-hash".to_owned()),
        source: tg_apple_observe::ObservationSource::RecordedFixture,
        evidence_complete: true,
    };
    let request = PurpleBootRequest {
        session_id,
        route_id: route.route_id.clone(),
        locked_identity: tg_apple_observe::LockedDeviceIdentity {
            cpid: "8020".to_owned(),
            ecid_hash: "synthetic-ecid-hash".to_owned(),
            product_type: Some("iPhone11,6".to_owned()),
            board_config: Some("d331pap".to_owned()),
            identity_hash: "synthetic-identity-hash".to_owned(),
        },
        pwn_proof: PwnDfuFinalProof {
            session_id,
            verified: true,
            node_id: "usbliter8.research".to_owned(),
            expected_cpid: "8020".to_owned(),
            firmware_sha256: "11".repeat(32),
            board_log_sha256: "22".repeat(32),
            host_mode: tg_contracts::DeviceMode::PwnedDfu,
            host_pwn_provider: Some("usbliter8".to_owned()),
            failures: Vec::new(),
        },
        pwn_observation,
        environment_backup: BootEnvironmentBackupReceipt {
            session_id,
            route_id: route.route_id.clone(),
            device_identity_hash: "synthetic-identity-hash".to_owned(),
            snapshot_sha256: "55".repeat(32),
            rollback_ready: true,
        },
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
        policy_profile: "development".to_owned(),
    };

    assert_eq!(
        build_purple_boot_plan(&route, &request),
        Err(PurpleBootError::UnpinnedBootArtifacts)
    );
}
