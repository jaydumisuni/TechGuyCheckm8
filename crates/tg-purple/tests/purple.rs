use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{Maturity, Permission};
use tg_purple::{
    build_boot_plan, evaluate_write_request, validate_provider, verify_write_readback,
    ChipGeneration, PurpleBootStage, PurpleError, PurpleProviderManifest, PurpleTransport,
    PwnProvider, SysCfgBackupReceipt, SysCfgChange, SysCfgFieldClass, SysCfgFieldRecord,
    SysCfgReadbackProof, SysCfgSnapshot, SysCfgWriteIntent, SysCfgWriteRequest,
    PURPLE_CONTRACT_VERSION,
};
use uuid::Uuid;

fn proofs() -> BTreeSet<String> {
    [
        "device_identity_locked",
        "pwned_dfu_verified",
        "bootchain_integrity_verified",
        "purple_mode_verified",
        "purple_identity_match",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn a12_provider(maturity: Maturity, declared_licence: Option<&str>) -> PurpleProviderManifest {
    PurpleProviderManifest {
        schema_version: PURPLE_CONTRACT_VERSION.to_owned(),
        provider_id: "purple.a12-a13.usbliter8-rp2350".to_owned(),
        version: "0.1.0-research".to_owned(),
        generation: ChipGeneration::A12A13,
        pwn_provider: PwnProvider::Usbliter8Rp2350,
        supported_product_types: BTreeSet::from([
            "iPhone11,2".to_owned(),
            "iPhone11,4".to_owned(),
            "iPhone11,6".to_owned(),
            "iPhone12,1".to_owned(),
            "iPhone12,3".to_owned(),
            "iPhone12,5".to_owned(),
        ]),
        transports: BTreeSet::from([
            PurpleTransport::UsbSerial,
            PurpleTransport::DcsdSerial,
        ]),
        required_hardware: BTreeSet::from([
            "rp2350_usb_host".to_owned(),
            "lightning_usb_a_cable".to_owned(),
        ]),
        maturity,
        source_repository: "https://github.com/prdgmshift/usbliter8".to_owned(),
        source_commit: "afe8b5c8998fce63e76c0b2a88c606c61e2950c7".to_owned(),
        declared_licence: declared_licence.map(str::to_owned),
        proof_requirements: proofs(),
        supports_syscfg_read: true,
        supports_syscfg_write: true,
        allowed_write_classes: BTreeSet::from([
            SysCfgFieldClass::Diagnostic,
            SysCfgFieldClass::Calibration,
        ]),
    }
}

fn snapshot(session_id: Uuid) -> SysCfgSnapshot {
    let diagnostic = SysCfgFieldRecord {
        key: "DiagFlag".to_owned(),
        class: SysCfgFieldClass::Diagnostic,
        encoded_value_hash: "before-diag".to_owned(),
        checksum_valid: true,
        writable: true,
    };
    let identity = SysCfgFieldRecord {
        key: "SerialNumber".to_owned(),
        class: SysCfgFieldClass::IdentityCritical,
        encoded_value_hash: "before-serial".to_owned(),
        checksum_valid: true,
        writable: true,
    };

    SysCfgSnapshot {
        snapshot_id: Uuid::new_v4(),
        session_id,
        provider_id: "purple.a12-a13.usbliter8-rp2350".to_owned(),
        device_identity_hash: "device-a".to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        blob_sha256: "syscfg-blob".to_owned(),
        fields: BTreeMap::from([
            (diagnostic.key.clone(), diagnostic),
            (identity.key.clone(), identity),
        ]),
        verified: true,
    }
}

fn request(snapshot: &SysCfgSnapshot, change: SysCfgChange) -> SysCfgWriteRequest {
    SysCfgWriteRequest {
        session_id: snapshot.session_id,
        provider_id: snapshot.provider_id.clone(),
        current_device_identity_hash: snapshot.device_identity_hash.clone(),
        current_board_config: snapshot.board_config.clone(),
        intent: SysCfgWriteIntent::RepairSelectedFields,
        backup: SysCfgBackupReceipt {
            snapshot_id: snapshot.snapshot_id,
            device_identity_hash: snapshot.device_identity_hash.clone(),
            board_config: snapshot.board_config.clone(),
            source_blob_sha256: snapshot.blob_sha256.clone(),
            backup_sha256: "backup-hash".to_owned(),
            verified: true,
            rollback_ready: true,
        },
        changes: vec![change],
        requested_permissions: BTreeSet::from([
            Permission::SerialWrite,
            Permission::SysCfgRestoreSameBoard,
            Permission::VaultRead,
            Permission::VaultWrite,
        ]),
        explicit_authorization: true,
        policy_profile: "development".to_owned(),
    }
}

fn diagnostic_change() -> SysCfgChange {
    SysCfgChange {
        field_key: "DiagFlag".to_owned(),
        class: SysCfgFieldClass::Diagnostic,
        expected_before_hash: "before-diag".to_owned(),
        requested_after_hash: "after-diag".to_owned(),
    }
}

#[test]
fn usbliter8_provider_is_research_only_without_declared_licence() {
    let provider = a12_provider(Maturity::Discovered, None);
    assert_eq!(
        validate_provider(&provider, "stable"),
        Err(PurpleError::ImmatureStableProvider)
    );
    assert!(validate_provider(&provider, "development").is_ok());
}

#[test]
fn stable_provider_requires_declared_licence() {
    let provider = a12_provider(Maturity::Stable, None);
    assert_eq!(
        validate_provider(&provider, "stable"),
        Err(PurpleError::MissingDeclaredLicence)
    );
}

#[test]
fn a12_plan_requires_usbliter8_hardware_and_full_transition_proof() {
    let provider = a12_provider(Maturity::Discovered, None);
    let plan = build_boot_plan(&provider, "development").unwrap();

    assert!(plan.required_hardware.contains("rp2350_usb_host"));
    assert_eq!(plan.stages.first(), Some(&PurpleBootStage::LockDeviceIdentity));
    assert_eq!(plan.stages.last(), Some(&PurpleBootStage::VerifyPurpleIdentity));
    assert!(plan.required_permissions.contains(&Permission::UsbWrite));
    assert!(plan.required_permissions.contains(&Permission::SerialRead));
}

#[test]
fn wrong_generation_provider_pair_is_rejected() {
    let mut provider = a12_provider(Maturity::Discovered, None);
    provider.pwn_provider = PwnProvider::SoftwareCheckm8;
    assert_eq!(
        validate_provider(&provider, "development"),
        Err(PurpleError::GenerationProviderMismatch)
    );
}

#[test]
fn selected_diagnostic_write_requires_verified_backup_and_authorization() {
    let provider = a12_provider(Maturity::Discovered, None);
    let snapshot = snapshot(Uuid::new_v4());
    let mut request = request(&snapshot, diagnostic_change());
    request.backup.verified = false;
    request.explicit_authorization = false;

    let decision = evaluate_write_request(&provider, &snapshot, &request);
    assert!(!decision.approved);
    assert!(decision
        .blockers
        .iter()
        .any(|blocker| blocker.contains("rollback-ready backup")));
    assert!(decision
        .blockers
        .iter()
        .any(|blocker| blocker.contains("authorization")));
}

#[test]
fn cross_device_backup_is_blocked() {
    let provider = a12_provider(Maturity::Discovered, None);
    let snapshot = snapshot(Uuid::new_v4());
    let mut request = request(&snapshot, diagnostic_change());
    request.backup.device_identity_hash = "device-b".to_owned();

    let decision = evaluate_write_request(&provider, &snapshot, &request);
    assert!(!decision.approved);
    assert!(decision
        .blockers
        .iter()
        .any(|blocker| blocker.contains("device identity mismatch")));
}

#[test]
fn identity_fields_are_blocked_even_in_development() {
    let provider = a12_provider(Maturity::Discovered, None);
    let snapshot = snapshot(Uuid::new_v4());
    let change = SysCfgChange {
        field_key: "SerialNumber".to_owned(),
        class: SysCfgFieldClass::IdentityCritical,
        expected_before_hash: "before-serial".to_owned(),
        requested_after_hash: "after-serial".to_owned(),
    };
    let request = request(&snapshot, change);

    let decision = evaluate_write_request(&provider, &snapshot, &request);
    assert!(!decision.approved);
    assert!(decision
        .blockers
        .iter()
        .any(|blocker| blocker.contains("field class is blocked")));
}

#[test]
fn valid_development_repair_is_approved_but_not_yet_execution_proof() {
    let provider = a12_provider(Maturity::Discovered, None);
    let snapshot = snapshot(Uuid::new_v4());
    let request = request(&snapshot, diagnostic_change());

    let decision = evaluate_write_request(&provider, &snapshot, &request);
    assert!(decision.approved);
    assert!(decision
        .required_post_write_proofs
        .contains("exact_readback_match"));
    assert_eq!(decision.granted_permissions.len(), 4);
}

#[test]
fn mismatched_readback_never_verifies_success() {
    let snapshot = snapshot(Uuid::new_v4());
    let request = request(&snapshot, diagnostic_change());
    let proof = SysCfgReadbackProof {
        session_id: request.session_id,
        device_identity_hash: request.current_device_identity_hash.clone(),
        board_config: request.current_board_config.clone(),
        observed_field_hashes: BTreeMap::from([(
            "DiagFlag".to_owned(),
            "unexpected".to_owned(),
        )]),
        transport_write_acknowledged: true,
        rollback_package_sha256: "rollback-hash".to_owned(),
        valid: true,
    };

    let verification = verify_write_readback(&request, &proof);
    assert!(!verification.verified);
    assert!(verification
        .failures
        .iter()
        .any(|failure| failure.contains("read-back mismatch")));
}

#[test]
fn exact_same_device_readback_verifies() {
    let snapshot = snapshot(Uuid::new_v4());
    let request = request(&snapshot, diagnostic_change());
    let proof = SysCfgReadbackProof {
        session_id: request.session_id,
        device_identity_hash: request.current_device_identity_hash.clone(),
        board_config: request.current_board_config.clone(),
        observed_field_hashes: BTreeMap::from([(
            "DiagFlag".to_owned(),
            "after-diag".to_owned(),
        )]),
        transport_write_acknowledged: true,
        rollback_package_sha256: "rollback-hash".to_owned(),
        valid: true,
    };

    let verification = verify_write_readback(&request, &proof);
    assert!(verification.verified);
    assert!(verification.failures.is_empty());
}
