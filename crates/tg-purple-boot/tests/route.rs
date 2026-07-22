use std::collections::BTreeSet;

use tg_apple_observe::{
    lock_identity, observe, ModeRule, ObservationCatalog, ObservationSource, RawUsbObservation,
};
use tg_contracts::{DeviceMode, Maturity};
use tg_purple_boot::{
    build_purple_boot_plan, finalize_purple_boot, required_permissions, validate_route_manifest,
    ArtifactTransferReceipt, AssetAcquisition, BootArtifactDescriptor, BootArtifactKind,
    BootEnvironmentBackupReceipt, PurpleBootError, PurpleBootRequest, PurpleBootRouteManifest,
    PurpleBootRunEvidence, PurpleStepReceipt, PurpleTransport, PURPLE_BOOT_VERSION,
};
use tg_usbliter8::PwnDfuFinalProof;
use uuid::Uuid;

const ECID_A: &str = "DEADBEEF00000001";
const ECID_B: &str = "DEADBEEF00000002";

fn catalog() -> ObservationCatalog {
    ObservationCatalog {
        rules: vec![
            ModeRule {
                rule_id: "synthetic.dfu".to_owned(),
                vendor_id: 0x05ac,
                product_id: 0x1227,
                mode: DeviceMode::Dfu,
                serial_must_contain: Some("CPID:".to_owned()),
            },
            ModeRule {
                rule_id: "synthetic.recovery".to_owned(),
                vendor_id: 0x05ac,
                product_id: 0x1281,
                mode: DeviceMode::Recovery,
                serial_must_contain: Some("CPID:".to_owned()),
            },
            ModeRule {
                rule_id: "synthetic.purple".to_owned(),
                vendor_id: 0x05ac,
                product_id: 0x1337,
                mode: DeviceMode::PurpleDiagnostic,
                serial_must_contain: Some("CPID:".to_owned()),
            },
        ],
    }
}

fn raw(product_id: u16, serial: String) -> RawUsbObservation {
    RawUsbObservation {
        vendor_id: 0x05ac,
        product_id,
        serial: Some(serial),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        source: ObservationSource::RecordedFixture,
    }
}

fn serial(ecid: &str, pwnd: bool) -> String {
    if pwnd {
        format!("CPID:8020 ECID:{ecid} PWND:[usbliter8]")
    } else {
        format!("CPID:8020 ECID:{ecid}")
    }
}

fn pwn_observation() -> tg_apple_observe::ObservedAppleDevice {
    observe(&catalog(), &raw(0x1227, serial(ECID_A, true))).unwrap()
}

fn recovery_observation(ecid: &str) -> tg_apple_observe::ObservedAppleDevice {
    observe(&catalog(), &raw(0x1281, serial(ecid, false))).unwrap()
}

fn purple_observation(ecid: &str) -> tg_apple_observe::ObservedAppleDevice {
    observe(&catalog(), &raw(0x1337, serial(ecid, false))).unwrap()
}

fn route(pinned: bool) -> PurpleBootRouteManifest {
    let artifact = |kind: BootArtifactKind, byte: &str, size| BootArtifactDescriptor {
        kind,
        sha256: pinned.then(|| byte.repeat(32)),
        size_bytes: pinned.then_some(size),
        acquisition: AssetAcquisition::UserSuppliedLocal,
        redistribution_allowed: false,
        source_description: "synthetic local test asset".to_owned(),
    };

    PurpleBootRouteManifest {
        schema_version: PURPLE_BOOT_VERSION.to_owned(),
        route_id: "purple.a12.iphone11,6.d331pap.usbliter8".to_owned(),
        version: "0.1.0-test".to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        cpid: "8020".to_owned(),
        pwn_provider: "usbliter8".to_owned(),
        raw_ibss: artifact(BootArtifactKind::RawIbss, "11", 2_271_600),
        diag_image: artifact(BootArtifactKind::DiagImg4, "22", 8_429_529),
        requires_power_button_hold_seconds: Some(2),
        recovery_settle_millis: 2_000,
        transports: BTreeSet::from([PurpleTransport::UsbSerial, PurpleTransport::DcsdSerial]),
        maturity: Maturity::SimulationTested,
        route_source_evidence: BTreeSet::from([
            "https://haiyuidesu.github.io/posts/diags/".to_owned(),
            "https://www.gsmzone.com/experience-reports/boot-diag-apple-a2098-eft-pro".to_owned(),
        ]),
        declared_route_licence: Some("route-metadata-test-only".to_owned()),
        requested_permissions: required_permissions(),
        proof_requirements: [
            "pwned_dfu_same_device",
            "boot_environment_backup_verified",
            "raw_ibss_hash_verified",
            "custom_boot_acknowledged",
            "recovery_same_device",
            "diag_image_hash_verified",
            "fixed_boot_commands_acknowledged",
            "purple_mode_same_device",
            "post_service_environment_rollback_required",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

fn request(route: &PurpleBootRouteManifest) -> PurpleBootRequest {
    let pwn_observation = pwn_observation();
    let locked_identity = lock_identity(&pwn_observation).unwrap();
    let session_id = Uuid::new_v4();
    PurpleBootRequest {
        session_id,
        route_id: route.route_id.clone(),
        locked_identity: locked_identity.clone(),
        pwn_proof: PwnDfuFinalProof {
            session_id,
            verified: true,
            node_id: "usbliter8.waveshare-rp2350-usb-a".to_owned(),
            expected_cpid: "8020".to_owned(),
            firmware_sha256: "33".repeat(32),
            board_log_sha256: "44".repeat(32),
            host_mode: DeviceMode::PwnedDfu,
            host_pwn_provider: Some("usbliter8".to_owned()),
            failures: Vec::new(),
        },
        pwn_observation,
        environment_backup: BootEnvironmentBackupReceipt {
            session_id,
            route_id: route.route_id.clone(),
            device_identity_hash: locked_identity.identity_hash.clone(),
            snapshot_sha256: "55".repeat(32),
            rollback_ready: true,
        },
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
        policy_profile: "development".to_owned(),
    }
}

fn successful_evidence(
    plan: &tg_purple_boot::PurpleBootPlan,
    purple_ecid: &str,
) -> PurpleBootRunEvidence {
    PurpleBootRunEvidence {
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
        recovery_observation: recovery_observation(ECID_A),
        purple_observation: purple_observation(purple_ecid),
    }
}

#[test]
fn research_route_validates_but_cannot_build_without_local_asset_pins() {
    let unpinned = route(false);
    assert!(validate_route_manifest(&unpinned, "development").is_ok());
    let request = request(&unpinned);
    assert_eq!(
        build_purple_boot_plan(&unpinned, &request),
        Err(PurpleBootError::UnpinnedBootArtifacts)
    );
}

#[test]
fn pinned_route_builds_only_the_fixed_command_sequence() {
    let route = route(true);
    let request = request(&route);
    let plan = build_purple_boot_plan(&route, &request).unwrap();

    assert_eq!(plan.artifacts.len(), 2);
    assert_eq!(plan.granted_permissions, required_permissions());
    assert!(plan.cleanup_required);
    assert_eq!(plan.environment_backup_sha256, "55".repeat(32));
    assert!(plan
        .steps
        .contains(&tg_purple_boot::PurpleBootStep::SendCustomBoot));
    assert!(plan
        .steps
        .contains(&tg_purple_boot::PurpleBootStep::SetUsbSerialBootArgs));
    assert!(plan
        .steps
        .contains(&tg_purple_boot::PurpleBootStep::SaveEnvironment));
    assert!(plan.steps.contains(&tg_purple_boot::PurpleBootStep::Go));
}

#[test]
fn free_redistribution_of_apple_assets_is_rejected() {
    let mut route = route(false);
    route.diag_image.redistribution_allowed = true;
    assert_eq!(
        validate_route_manifest(&route, "development"),
        Err(PurpleBootError::AppleAssetRedistributionForbidden)
    );
}

#[test]
fn unverified_pwn_stage_cannot_enter_purple_plan() {
    let route = route(true);
    let mut request = request(&route);
    request.pwn_proof.verified = false;
    assert_eq!(
        build_purple_boot_plan(&route, &request),
        Err(PurpleBootError::UnverifiedPwnProof)
    );
}

#[test]
fn broad_or_incomplete_permission_grants_are_rejected() {
    let route = route(true);
    let mut request = request(&route);
    request
        .granted_permissions
        .remove(&tg_contracts::Permission::SerialRead);
    assert_eq!(
        build_purple_boot_plan(&route, &request),
        Err(PurpleBootError::PermissionGrantMismatch)
    );

    let mut request = request(&route);
    request
        .granted_permissions
        .insert(tg_contracts::Permission::SysCfgRestoreSameBoard);
    assert_eq!(
        build_purple_boot_plan(&route, &request),
        Err(PurpleBootError::PermissionGrantMismatch)
    );
}

#[test]
fn exact_artifacts_commands_and_same_device_transitions_verify() {
    let route = route(true);
    let request = request(&route);
    let plan = build_purple_boot_plan(&route, &request).unwrap();
    let evidence = successful_evidence(&plan, ECID_A);

    let proof = finalize_purple_boot(&plan, &request.locked_identity, &evidence);
    assert!(proof.verified);
    assert!(proof.failures.is_empty());
    assert_eq!(proof.final_mode, DeviceMode::PurpleDiagnostic);
}

#[test]
fn altered_diag_hash_blocks_final_proof() {
    let route = route(true);
    let request = request(&route);
    let plan = build_purple_boot_plan(&route, &request).unwrap();
    let mut evidence = successful_evidence(&plan, ECID_A);
    let diag = evidence
        .artifact_receipts
        .iter_mut()
        .find(|receipt| receipt.kind == BootArtifactKind::DiagImg4)
        .unwrap();
    diag.observed_sha256 = "99".repeat(32);

    let proof = finalize_purple_boot(&plan, &request.locked_identity, &evidence);
    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("DiagImg4")));
}

#[test]
fn missing_or_reordered_fixed_command_blocks_final_proof() {
    let route = route(true);
    let request = request(&route);
    let plan = build_purple_boot_plan(&route, &request).unwrap();
    let mut evidence = successful_evidence(&plan, ECID_A);
    evidence.step_receipts.swap(2, 3);

    let proof = finalize_purple_boot(&plan, &request.locked_identity, &evidence);
    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("step sequence")));
}

#[test]
fn different_device_in_purple_mode_blocks_success() {
    let route = route(true);
    let request = request(&route);
    let plan = build_purple_boot_plan(&route, &request).unwrap();
    let evidence = successful_evidence(&plan, ECID_B);

    let proof = finalize_purple_boot(&plan, &request.locked_identity, &evidence);
    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("ECID mismatch")));
}
