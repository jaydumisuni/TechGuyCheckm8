use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_purple::{
    ChipGeneration, PurpleProviderManifest, PurpleTransport, PwnProvider, SysCfgChange,
    SysCfgFieldClass, SysCfgWriteIntent, SysCfgWriteRequest, PURPLE_CONTRACT_VERSION,
};
use tg_purple_boot::PurpleBootFinalProof;
use tg_syscfg_serial::{
    build_backup_receipt, build_write_transaction_plan, capture_snapshot, encode_command,
    hash_value, parse_print_response, parse_syscfg_list, read_full_snapshot,
    required_read_permissions, required_write_permissions, validate_provider_manifest,
    SerialLink, SerialTransport, SerialTransportError, SelectedFieldMutation, SysCfgCommand,
    SysCfgFieldPolicy, SysCfgSerialContext, SysCfgSerialError, SysCfgSerialProviderManifest,
    TransactionStatus, VaultWriteReceipt, SYSCFG_SERIAL_VERSION,
};
use uuid::Uuid;

fn proofs() -> BTreeSet<String> {
    [
        "purple_mode_same_device",
        "full_syscfg_list_captured",
        "backup_vault_verified",
        "field_precondition_verified",
        "typed_write_only",
        "exact_readback_match",
        "rollback_verified_or_recovery_required",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn field_policy(class: SysCfgFieldClass, writable: bool) -> SysCfgFieldPolicy {
    SysCfgFieldPolicy {
        class,
        writable,
        max_value_bytes: 128,
        response_labels: BTreeSet::from(["DiagFlag".to_owned()]),
    }
}

fn serial_manifest(supports_write: bool) -> SysCfgSerialProviderManifest {
    let mut field_catalog = BTreeMap::new();
    field_catalog.insert(
        "DiagFlag".to_owned(),
        field_policy(SysCfgFieldClass::Calibration, supports_write),
    );
    field_catalog.insert(
        "Regn".to_owned(),
        SysCfgFieldPolicy {
            class: SysCfgFieldClass::Manufacturing,
            writable: false,
            max_value_bytes: 64,
            response_labels: BTreeSet::from(["Regn".to_owned()]),
        },
    );
    field_catalog.insert(
        "SrNm".to_owned(),
        SysCfgFieldPolicy {
            class: SysCfgFieldClass::IdentityCritical,
            writable: false,
            max_value_bytes: 128,
            response_labels: BTreeSet::from(["SrNm".to_owned(), "Serial".to_owned()]),
        },
    );

    SysCfgSerialProviderManifest {
        schema_version: SYSCFG_SERIAL_VERSION.to_owned(),
        provider_id: "syscfg.synthetic.serial".to_owned(),
        version: "0.1.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        supported_board_configs: BTreeSet::from(["d331pap".to_owned()]),
        links: BTreeSet::from([SerialLink::UsbSerial]),
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "11".repeat(20),
        declared_licence: Some("test-only".to_owned()),
        supports_write,
        max_response_bytes: 64 * 1024,
        field_catalog,
        required_backup_keys: BTreeSet::from(["DiagFlag".to_owned(), "Regn".to_owned()]),
        requested_read_permissions: required_read_permissions(),
        requested_write_permissions: required_write_permissions(),
        proof_requirements: proofs(),
    }
}

fn policy_manifest() -> PurpleProviderManifest {
    PurpleProviderManifest {
        schema_version: PURPLE_CONTRACT_VERSION.to_owned(),
        provider_id: "syscfg.synthetic.serial".to_owned(),
        version: "0.1.0-test".to_owned(),
        generation: ChipGeneration::A12A13,
        pwn_provider: PwnProvider::Usbliter8Rp2350,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        transports: BTreeSet::from([PurpleTransport::UsbSerial]),
        required_hardware: BTreeSet::from(["synthetic serial link".to_owned()]),
        maturity: Maturity::SimulationTested,
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "22".repeat(20),
        declared_licence: Some("test-only".to_owned()),
        proof_requirements: [
            "device_identity_locked",
            "pwned_dfu_verified",
            "bootchain_integrity_verified",
            "purple_mode_verified",
            "purple_identity_match",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        supports_syscfg_read: true,
        supports_syscfg_write: true,
        allowed_write_classes: BTreeSet::from([SysCfgFieldClass::Calibration]),
    }
}

fn context(session_id: Uuid, permissions: BTreeSet<Permission>) -> SysCfgSerialContext {
    SysCfgSerialContext {
        session_id,
        provider_id: "syscfg.synthetic.serial".to_owned(),
        device_identity_hash: "device-identity-hash".to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        purple_proof: PurpleBootFinalProof {
            session_id,
            route_id: "purple.a12.synthetic".to_owned(),
            verified: true,
            final_mode: DeviceMode::PurpleDiagnostic,
            cleanup_required: true,
            environment_backup_sha256: "33".repeat(32),
            failures: Vec::new(),
        },
        granted_permissions: permissions,
        policy_profile: "development".to_owned(),
    }
}

fn raw_dump(manifest: &SysCfgSerialProviderManifest) -> tg_syscfg_serial::RawSysCfgDump {
    parse_syscfg_list(
        manifest,
        b"syscfg list\nDiagFlag: old\nRegn: LL/A\nSrNm: SECRET-SERIAL\n>\n",
    )
    .unwrap()
}

fn prepared_plan() -> (
    SysCfgSerialProviderManifest,
    tg_syscfg_serial::WriteTransactionPlan,
) {
    let manifest = serial_manifest(true);
    let session_id = Uuid::new_v4();
    let read_context = context(session_id, required_read_permissions());
    let dump = raw_dump(&manifest);
    let snapshot = capture_snapshot(&manifest, &read_context, &dump).unwrap();
    let vault = VaultWriteReceipt {
        session_id,
        device_identity_hash: read_context.device_identity_hash.clone(),
        board_config: read_context.board_config.clone(),
        plaintext_sha256: snapshot.blob_sha256.clone(),
        stored_package_sha256: "44".repeat(32),
        plaintext_bytes: dump.byte_len(),
        encrypted: true,
        durable: true,
        rollback_ready: true,
    };
    let backup = build_backup_receipt(&read_context, &snapshot, &dump, &vault).unwrap();
    let write_context = context(session_id, required_write_permissions());
    let request = SysCfgWriteRequest {
        session_id,
        provider_id: manifest.provider_id.clone(),
        current_device_identity_hash: write_context.device_identity_hash.clone(),
        current_board_config: write_context.board_config.clone(),
        intent: SysCfgWriteIntent::RepairSelectedFields,
        backup,
        changes: vec![SysCfgChange {
            field_key: "DiagFlag".to_owned(),
            class: SysCfgFieldClass::Calibration,
            expected_before_hash: hash_value("old"),
            requested_after_hash: hash_value("new"),
        }],
        requested_permissions: required_write_permissions(),
        explicit_authorization: true,
        policy_profile: "development".to_owned(),
    };
    let plan = build_write_transaction_plan(
        &manifest,
        &policy_manifest(),
        &write_context,
        &snapshot,
        &dump,
        &request,
        vec![SelectedFieldMutation {
            key: "DiagFlag".to_owned(),
            requested_value: "new".to_owned(),
        }],
    )
    .unwrap();
    (manifest, plan)
}

struct ScriptedTransport {
    exchanges: VecDeque<(Vec<u8>, Result<Vec<u8>, SerialTransportError>)>,
}

impl ScriptedTransport {
    fn new(entries: Vec<(&str, Result<&str, &str>)>) -> Self {
        Self {
            exchanges: entries
                .into_iter()
                .map(|(command, response)| {
                    (
                        command.as_bytes().to_vec(),
                        response
                            .map(|text| text.as_bytes().to_vec())
                            .map_err(|message| SerialTransportError {
                                message: message.to_owned(),
                            }),
                    )
                })
                .collect(),
        }
    }

    fn assert_drained(&self) {
        assert!(self.exchanges.is_empty());
    }
}

impl SerialTransport for ScriptedTransport {
    fn exchange(
        &mut self,
        command: &[u8],
        _max_response_bytes: usize,
    ) -> Result<Vec<u8>, SerialTransportError> {
        let (expected, response) = self.exchanges.pop_front().expect("unexpected command");
        assert_eq!(command, expected);
        response
    }
}

#[test]
fn research_manifest_is_read_only_and_unpromoted() {
    let manifest: SysCfgSerialProviderManifest = serde_json::from_str(include_str!(
        "../../../providers/syscfg-serial/magiccfg-research.json"
    ))
    .unwrap();
    assert!(validate_provider_manifest(&manifest, "development").is_ok());
    assert!(!manifest.supports_write);
    assert!(manifest.field_catalog.values().all(|field| !field.writable));
    assert!(matches!(
        validate_provider_manifest(&manifest, "stable"),
        Err(SysCfgSerialError::ImmatureStableProvider)
    ));
}

#[test]
fn command_encoder_rejects_terminal_injection_and_identity_writes() {
    let manifest = serial_manifest(true);
    assert!(matches!(
        encode_command(
            &manifest,
            &SysCfgCommand::Add {
                key: "DiagFlag".to_owned(),
                value: "new\nsyscfg add SrNm forged".to_owned(),
            }
        ),
        Err(SysCfgSerialError::InvalidFieldValue(_))
            | Err(SysCfgSerialError::UnsafeFieldValue(_))
    ));
    assert!(matches!(
        encode_command(
            &manifest,
            &SysCfgCommand::Add {
                key: "SrNm".to_owned(),
                value: "forged".to_owned(),
            }
        ),
        Err(SysCfgSerialError::FieldNotWritable(key)) if key == "SrNm"
    ));
}

#[test]
fn full_list_snapshot_and_vault_backup_bind_to_same_device() {
    let manifest = serial_manifest(true);
    let session_id = Uuid::new_v4();
    let read_context = context(session_id, required_read_permissions());
    let dump = raw_dump(&manifest);
    let snapshot = capture_snapshot(&manifest, &read_context, &dump).unwrap();
    assert!(snapshot.verified);
    assert_eq!(snapshot.fields["SrNm"].class, SysCfgFieldClass::IdentityCritical);
    assert!(!snapshot.fields["SrNm"].writable);
    assert!(!format!("{dump:?}").contains("SECRET-SERIAL"));

    let receipt = build_backup_receipt(
        &read_context,
        &snapshot,
        &dump,
        &VaultWriteReceipt {
            session_id,
            device_identity_hash: read_context.device_identity_hash.clone(),
            board_config: read_context.board_config.clone(),
            plaintext_sha256: snapshot.blob_sha256.clone(),
            stored_package_sha256: "55".repeat(32),
            plaintext_bytes: dump.byte_len(),
            encrypted: true,
            durable: true,
            rollback_ready: true,
        },
    )
    .unwrap();
    assert!(receipt.verified);
    assert!(receipt.rollback_ready);
}

#[test]
fn read_full_snapshot_uses_only_syscfg_list() {
    let manifest = serial_manifest(true);
    let session_id = Uuid::new_v4();
    let read_context = context(session_id, required_read_permissions());
    let mut transport = ScriptedTransport::new(vec![(
        "syscfg list\n",
        Ok("DiagFlag: old\nRegn: LL/A\nSrNm: SECRET-SERIAL\n"),
    )]);
    let (dump, snapshot) = read_full_snapshot(&manifest, &read_context, &mut transport).unwrap();
    assert_eq!(dump.field_count(), 3);
    assert!(snapshot.verified);
    transport.assert_drained();
}

#[test]
fn print_parser_accepts_declared_alias_but_not_ambiguous_values() {
    let manifest = serial_manifest(true);
    let serial = parse_print_response(&manifest, "SrNm", b"Serial: SECRET-SERIAL\n").unwrap();
    assert_eq!(serial.key(), "SrNm");
    assert_eq!(serial.value(), "SECRET-SERIAL");
    assert!(matches!(
        parse_print_response(
            &manifest,
            "SrNm",
            b"SrNm: FIRST\nSerial: SECOND\n"
        ),
        Err(SysCfgSerialError::AmbiguousFieldResponse(key)) if key == "SrNm"
    ));
}

#[test]
fn exact_readback_commits_selected_calibration_write() {
    let (manifest, plan) = prepared_plan();
    assert_eq!(plan.field_keys(), vec!["DiagFlag"]);
    assert!(!format!("{plan:?}").contains("old"));
    assert!(!format!("{plan:?}").contains("new"));
    let mut transport = ScriptedTransport::new(vec![
        ("syscfg print DiagFlag\n", Ok("DiagFlag: old\n")),
        ("syscfg add DiagFlag new\n", Ok("OK\n")),
        ("syscfg print DiagFlag\n", Ok("DiagFlag: new\n")),
    ]);
    let outcome = tg_syscfg_serial::execute_write_transaction(&manifest, &plan, &mut transport);
    assert_eq!(outcome.status, TransactionStatus::VerifiedCommitted);
    assert!(outcome.verification.verified);
    assert!(!outcome.recovery_required);
    assert!(outcome.fields[0].readback_matched);
    transport.assert_drained();
}

#[test]
fn readback_mismatch_rolls_back_and_verifies_previous_value() {
    let (manifest, plan) = prepared_plan();
    let mut transport = ScriptedTransport::new(vec![
        ("syscfg print DiagFlag\n", Ok("DiagFlag: old\n")),
        ("syscfg add DiagFlag new\n", Ok("OK\n")),
        ("syscfg print DiagFlag\n", Ok("DiagFlag: wrong\n")),
        ("syscfg add DiagFlag old\n", Ok("OK\n")),
        ("syscfg print DiagFlag\n", Ok("DiagFlag: old\n")),
    ]);
    let outcome = tg_syscfg_serial::execute_write_transaction(&manifest, &plan, &mut transport);
    assert_eq!(outcome.status, TransactionStatus::RolledBackVerified);
    assert!(!outcome.recovery_required);
    assert!(outcome.fields[0].rollback_attempted);
    assert!(outcome.fields[0].rollback_verified);
    transport.assert_drained();
}

#[test]
fn failed_rollback_requires_recovery() {
    let (manifest, plan) = prepared_plan();
    let mut transport = ScriptedTransport::new(vec![
        ("syscfg print DiagFlag\n", Ok("DiagFlag: old\n")),
        ("syscfg add DiagFlag new\n", Ok("OK\n")),
        ("syscfg print DiagFlag\n", Ok("DiagFlag: wrong\n")),
        ("syscfg add DiagFlag old\n", Ok("OK\n")),
        ("syscfg print DiagFlag\n", Ok("DiagFlag: still-wrong\n")),
    ]);
    let outcome = tg_syscfg_serial::execute_write_transaction(&manifest, &plan, &mut transport);
    assert_eq!(outcome.status, TransactionStatus::RecoveryRequired);
    assert!(outcome.recovery_required);
    assert!(!outcome.fields[0].rollback_verified);
    transport.assert_drained();
}

#[test]
fn changed_precondition_blocks_before_any_write() {
    let (manifest, plan) = prepared_plan();
    let mut transport = ScriptedTransport::new(vec![(
        "syscfg print DiagFlag\n",
        Ok("DiagFlag: changed-after-backup\n"),
    )]);
    let outcome = tg_syscfg_serial::execute_write_transaction(&manifest, &plan, &mut transport);
    assert_eq!(outcome.status, TransactionStatus::FailedNoWrite);
    assert!(!outcome.fields[0].write_exchange_completed);
    assert!(!outcome.fields[0].rollback_attempted);
    transport.assert_drained();
}

#[test]
fn broad_permissions_are_rejected_even_when_policy_subset_is_present() {
    let manifest = serial_manifest(true);
    let session_id = Uuid::new_v4();
    let read_context = context(session_id, required_read_permissions());
    let dump = raw_dump(&manifest);
    let snapshot = capture_snapshot(&manifest, &read_context, &dump).unwrap();
    let backup = build_backup_receipt(
        &read_context,
        &snapshot,
        &dump,
        &VaultWriteReceipt {
            session_id,
            device_identity_hash: read_context.device_identity_hash.clone(),
            board_config: read_context.board_config.clone(),
            plaintext_sha256: snapshot.blob_sha256.clone(),
            stored_package_sha256: "66".repeat(32),
            plaintext_bytes: dump.byte_len(),
            encrypted: true,
            durable: true,
            rollback_ready: true,
        },
    )
    .unwrap();
    let mut broad = required_write_permissions();
    broad.insert(Permission::ActivationArtifactRestoreSameDevice);
    let broad_context = context(session_id, broad.clone());
    let request = SysCfgWriteRequest {
        session_id,
        provider_id: manifest.provider_id.clone(),
        current_device_identity_hash: broad_context.device_identity_hash.clone(),
        current_board_config: broad_context.board_config.clone(),
        intent: SysCfgWriteIntent::RepairSelectedFields,
        backup,
        changes: vec![SysCfgChange {
            field_key: "DiagFlag".to_owned(),
            class: SysCfgFieldClass::Calibration,
            expected_before_hash: hash_value("old"),
            requested_after_hash: hash_value("new"),
        }],
        requested_permissions: broad,
        explicit_authorization: true,
        policy_profile: "development".to_owned(),
    };
    assert!(matches!(
        build_write_transaction_plan(
            &manifest,
            &policy_manifest(),
            &broad_context,
            &snapshot,
            &dump,
            &request,
            vec![SelectedFieldMutation {
                key: "DiagFlag".to_owned(),
                requested_value: "new".to_owned(),
            }],
        ),
        Err(SysCfgSerialError::PermissionGrantMismatch)
    ));
}
