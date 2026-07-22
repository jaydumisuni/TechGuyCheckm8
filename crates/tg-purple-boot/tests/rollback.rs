use tg_contracts::{DeviceMode, Maturity};
use tg_purple_boot::{
    build_purple_boot_plan, finalize_purple_boot, required_permissions, ArtifactTransferReceipt,
    BootArtifactKind, BootEnvironmentBackupReceipt, PurpleBootError, PurpleBootRequest,
    PurpleBootRouteManifest, PurpleBootRunEvidence, PurpleStepReceipt,
};
use tg_usbliter8::PwnDfuFinalProof;
use uuid::Uuid;

fn pinned_route() -> PurpleBootRouteManifest {
    let mut route: PurpleBootRouteManifest = serde_json::from_str(include_str!(
        "../../../manifests/purple/routes/a12-iphone11,6-d331pap-usbliter8.research.json"
    ))
    .unwrap();
    route.version = "0.1.0-synthetic".to_owned();
    route.maturity = Maturity::SimulationTested;
    route.declared_route_licence = Some("route-metadata-test-only".to_owned());
    route.raw_ibss.sha256 = Some("11".repeat(32));
    route.raw_ibss.size_bytes = Some(2_271_600);
    route.diag_image.sha256 = Some("22".repeat(32));
    route.diag_image.size_bytes = Some(8_429_529);
    route
}

fn pwn_observation() -> tg_apple_observe::ObservedAppleDevice {
    tg_apple_observe::ObservedAppleDevice {
        schema_version: tg_apple_observe::OBSERVATION_SCHEMA_VERSION.to_owned(),
        rule_id: Some("synthetic.pwnd".to_owned()),
        mode: DeviceMode::PwnedDfu,
        cpid: Some("8020".to_owned()),
        ecid_hash: Some("synthetic-ecid-hash".to_owned()),
        serial_hash: Some("synthetic-serial-hash".to_owned()),
        pwn_provider: Some("usbliter8".to_owned()),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        device_identity_hash: Some("synthetic-identity-hash".to_owned()),
        source: tg_apple_observe::ObservationSource::RecordedFixture,
        evidence_complete: true,
    }
}

fn transition(mode: DeviceMode) -> tg_apple_observe::ObservedAppleDevice {
    let mut observation = pwn_observation();
    observation.mode = mode;
    observation.pwn_provider = None;
    observation
}

fn request(route: &PurpleBootRouteManifest) -> PurpleBootRequest {
    let session_id = Uuid::new_v4();
    let locked_identity = tg_apple_observe::LockedDeviceIdentity {
        cpid: "8020".to_owned(),
        ecid_hash: "synthetic-ecid-hash".to_owned(),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        identity_hash: "synthetic-identity-hash".to_owned(),
    };
    PurpleBootRequest {
        session_id,
        route_id: route.route_id.clone(),
        locked_identity: locked_identity.clone(),
        pwn_proof: PwnDfuFinalProof {
            session_id,
            verified: true,
            node_id: "usbliter8.synthetic".to_owned(),
            expected_cpid: "8020".to_owned(),
            firmware_sha256: "33".repeat(32),
            board_log_sha256: "44".repeat(32),
            host_mode: DeviceMode::PwnedDfu,
            host_pwn_provider: Some("usbliter8".to_owned()),
            failures: Vec::new(),
        },
        pwn_observation: pwn_observation(),
        environment_backup: BootEnvironmentBackupReceipt {
            session_id,
            route_id: route.route_id.clone(),
            device_identity_hash: locked_identity.identity_hash,
            snapshot_sha256: "55".repeat(32),
            rollback_ready: true,
        },
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
        policy_profile: "development".to_owned(),
    }
}

#[test]
fn environment_backup_must_match_device_scope_and_be_rollback_ready() {
    let route = pinned_route();

    let mut wrong_device = request(&route);
    wrong_device.environment_backup.device_identity_hash = "another-device".to_owned();
    assert_eq!(
        build_purple_boot_plan(&route, &wrong_device),
        Err(PurpleBootError::EnvironmentBackupDeviceMismatch)
    );

    let mut wrong_session = request(&route);
    wrong_session.environment_backup.session_id = Uuid::new_v4();
    assert_eq!(
        build_purple_boot_plan(&route, &wrong_session),
        Err(PurpleBootError::EnvironmentBackupScopeMismatch)
    );

    let mut not_ready = request(&route);
    not_ready.environment_backup.rollback_ready = false;
    assert_eq!(
        build_purple_boot_plan(&route, &not_ready),
        Err(PurpleBootError::EnvironmentRollbackNotReady)
    );
}

#[test]
fn internally_inconsistent_pwn_proof_is_rejected() {
    let route = pinned_route();
    let mut request = request(&route);
    request.pwn_proof.host_pwn_provider = Some("other-provider".to_owned());
    assert_eq!(
        build_purple_boot_plan(&route, &request),
        Err(PurpleBootError::InconsistentPwnProof)
    );
}

#[test]
fn verified_purple_checkpoint_keeps_cleanup_obligation() {
    let route = pinned_route();
    let request = request(&route);
    let plan = build_purple_boot_plan(&route, &request).unwrap();
    let evidence = PurpleBootRunEvidence {
        session_id: plan.session_id,
        route_id: plan.route_id.clone(),
        step_receipts: plan
            .steps
            .iter()
            .cloned()
            .map(|step| PurpleStepReceipt {
                step,
                acknowledged: true,
            })
            .collect(),
        artifact_receipts: plan
            .artifacts
            .iter()
            .map(|artifact| ArtifactTransferReceipt {
                kind: artifact.kind.clone(),
                observed_sha256: artifact.sha256.clone(),
                observed_size_bytes: artifact.size_bytes,
                transfer_acknowledged: true,
            })
            .collect(),
        recovery_observation: transition(DeviceMode::Recovery),
        purple_observation: transition(DeviceMode::PurpleDiagnostic),
    };

    let proof = finalize_purple_boot(&plan, &request.locked_identity, &evidence);
    assert!(proof.verified);
    assert!(proof.cleanup_required);
    assert_eq!(
        proof.environment_backup_sha256,
        request.environment_backup.snapshot_sha256
    );
    assert!(plan
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == BootArtifactKind::DiagImg4));
}
