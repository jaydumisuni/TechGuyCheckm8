use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_leases::{LeaseManager, LeaseOwner};
use tg_purple::{
    ChipGeneration, PurpleProviderManifest, PurpleTransport, PwnProvider, SysCfgFieldClass,
    PURPLE_CONTRACT_VERSION,
};
use tg_purple_boot::PurpleBootFinalProof;
use tg_serial_doctor::{
    required_permissions as doctor_permissions, select_candidate, HostPlatform,
    RawSerialPortObservation, SerialDoctorContext, SerialDoctorManifest, SerialMatchRule,
    SerialOpenProbe, SerialParity, SerialProbeObservation, SerialSettings, SerialStopBits,
    SERIAL_DOCTOR_VERSION,
};
use tg_serial_platform::{reserve_and_run_doctor, PlatformDoctorReservation};
use tg_syscfg_backup_vault::{
    capture_encrypt_verify_backup, required_backup_permissions, BackupAuthorization,
    BackupPipelineEvidence, BackupVaultRequest, CapturedSysCfgList, FileBackupVault, VaultKey,
};
use tg_syscfg_read_transport::{
    bind_read_endpoint, required_transport_permissions, BoundReadEndpoint, ReadExchangeReceipt,
    ReadTransportAuthorization, SysCfgReadOperation, SYSCFG_READ_TRANSPORT_VERSION,
};
use tg_syscfg_serial::{
    required_read_permissions, required_write_permissions, SerialLink, SerialTransport,
    SerialTransportError, SysCfgFieldPolicy, SysCfgSerialContext, SysCfgSerialProviderManifest,
    TransactionStatus, SYSCFG_SERIAL_VERSION,
};
use tg_syscfg_write_transport::{
    execute_selected_write_with_transport, required_write_transport_permissions,
    SelectedNonIdentityFieldWrite, SelectedWriteRequest, WriteTransportAuthorization,
};
use uuid::Uuid;

const PROVIDER_ID: &str = "synthetic.syscfg-selected-write";
const RAW_BACKUP: &[u8] =
    b"syscfg list\r\nSrNm: PRIVATE-SERIAL\r\nRegn: LL/A\r\nDiagFlag: OLD\r\n>\r\n";

fn settings() -> SerialSettings {
    SerialSettings {
        baud_rate: 115_200,
        data_bits: 8,
        parity: SerialParity::None,
        stop_bits: SerialStopBits::One,
        timeout_millis: 100,
    }
}

fn doctor_manifest() -> SerialDoctorManifest {
    SerialDoctorManifest {
        schema_version: SERIAL_DOCTOR_VERSION.to_owned(),
        provider_id: "synthetic.serial-doctor".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        rules: vec![SerialMatchRule {
            rule_id: "synthetic-adapter".to_owned(),
            link: SerialLink::UsbSerial,
            host: None,
            vid: Some(0x1209),
            pid: Some(0x0001),
            manufacturer_contains: Some("Synthetic Lab".to_owned()),
            product_contains: Some("Diags Adapter".to_owned()),
            settings: settings(),
            priority: 100,
        }],
        requested_permissions: doctor_permissions(),
        proof_requirements: BTreeSet::from([
            "purple_mode_same_session".to_owned(),
            "unique_serial_candidate".to_owned(),
            "stable_hardware_fingerprint".to_owned(),
            "exclusive_open_verified".to_owned(),
            "serial_settings_verified".to_owned(),
            "zero_bytes_written".to_owned(),
            "serial_lease_acquired".to_owned(),
        ]),
    }
}

fn serial_manifest() -> SysCfgSerialProviderManifest {
    SysCfgSerialProviderManifest {
        schema_version: SYSCFG_SERIAL_VERSION.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        supported_board_configs: BTreeSet::from(["d331pap".to_owned()]),
        links: BTreeSet::from([SerialLink::UsbSerial]),
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "a".repeat(40),
        declared_licence: Some("MIT".to_owned()),
        supports_write: true,
        max_response_bytes: 4096,
        field_catalog: BTreeMap::from([
            (
                "SrNm".to_owned(),
                SysCfgFieldPolicy {
                    class: SysCfgFieldClass::IdentityCritical,
                    writable: false,
                    max_value_bytes: 64,
                    response_labels: BTreeSet::from(["SrNm".to_owned()]),
                },
            ),
            (
                "Regn".to_owned(),
                SysCfgFieldPolicy {
                    class: SysCfgFieldClass::Manufacturing,
                    writable: false,
                    max_value_bytes: 16,
                    response_labels: BTreeSet::from(["Regn".to_owned()]),
                },
            ),
            (
                "DiagFlag".to_owned(),
                SysCfgFieldPolicy {
                    class: SysCfgFieldClass::Diagnostic,
                    writable: true,
                    max_value_bytes: 16,
                    response_labels: BTreeSet::from(["DiagFlag".to_owned()]),
                },
            ),
        ]),
        required_backup_keys: BTreeSet::from([
            "SrNm".to_owned(),
            "Regn".to_owned(),
            "DiagFlag".to_owned(),
        ]),
        requested_read_permissions: required_read_permissions(),
        requested_write_permissions: required_write_permissions(),
        proof_requirements: BTreeSet::from([
            "purple_mode_same_device".to_owned(),
            "full_syscfg_list_captured".to_owned(),
            "backup_vault_verified".to_owned(),
            "field_precondition_verified".to_owned(),
            "typed_write_only".to_owned(),
            "exact_readback_match".to_owned(),
            "rollback_verified_or_recovery_required".to_owned(),
        ]),
    }
}

fn purple_manifest() -> PurpleProviderManifest {
    PurpleProviderManifest {
        schema_version: PURPLE_CONTRACT_VERSION.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        version: "1.0.0-test".to_owned(),
        generation: ChipGeneration::A12A13,
        pwn_provider: PwnProvider::Usbliter8Rp2350,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        transports: BTreeSet::from([PurpleTransport::UsbSerial]),
        required_hardware: BTreeSet::from(["synthetic-adapter".to_owned()]),
        maturity: Maturity::SimulationTested,
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "b".repeat(40),
        declared_licence: Some("MIT".to_owned()),
        proof_requirements: BTreeSet::from([
            "device_identity_locked".to_owned(),
            "pwned_dfu_verified".to_owned(),
            "bootchain_integrity_verified".to_owned(),
            "purple_mode_verified".to_owned(),
            "purple_identity_match".to_owned(),
        ]),
        supports_syscfg_read: true,
        supports_syscfg_write: true,
        allowed_write_classes: BTreeSet::from([SysCfgFieldClass::Diagnostic]),
    }
}

fn purple_proof(session_id: Uuid) -> PurpleBootFinalProof {
    PurpleBootFinalProof {
        session_id,
        route_id: "synthetic-purple".to_owned(),
        verified: true,
        final_mode: DeviceMode::PurpleDiagnostic,
        cleanup_required: true,
        environment_backup_sha256: "b".repeat(64),
        failures: Vec::new(),
    }
}

fn doctor_context(session_id: Uuid, device_hash: &str) -> SerialDoctorContext {
    SerialDoctorContext {
        session_id,
        device_identity_hash: device_hash.to_owned(),
        purple_proof: purple_proof(session_id),
        granted_permissions: doctor_permissions(),
        policy_profile: "development".to_owned(),
    }
}

fn syscfg_context(
    session_id: Uuid,
    device_hash: &str,
    permissions: BTreeSet<Permission>,
) -> SysCfgSerialContext {
    SysCfgSerialContext {
        session_id,
        provider_id: PROVIDER_ID.to_owned(),
        device_identity_hash: device_hash.to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        purple_proof: purple_proof(session_id),
        granted_permissions: permissions,
        policy_profile: "development".to_owned(),
    }
}

fn observation() -> RawSerialPortObservation {
    RawSerialPortObservation {
        port_name: "COM77".to_owned(),
        vid: Some(0x1209),
        pid: Some(0x0001),
        serial_number: Some("SYNTHETIC-WRITE-ADAPTER".to_owned()),
        manufacturer: Some("Synthetic Lab".to_owned()),
        product: Some("Diags Adapter".to_owned()),
        physical_location: Some("usb-root-1-port-4".to_owned()),
    }
}

#[derive(Debug, Clone)]
struct ReadyProbe;

impl SerialOpenProbe for ReadyProbe {
    fn probe(
        &mut self,
        _port_name: &str,
        _settings: &SerialSettings,
    ) -> Result<SerialProbeObservation, String> {
        Ok(SerialProbeObservation {
            opened: true,
            exclusive: true,
            settings_applied: true,
            bytes_written: 0,
            bytes_read: 0,
        })
    }
}

struct Fixture {
    endpoint: BoundReadEndpoint,
    session_id: Uuid,
    device_hash: String,
    serial_manifest: SysCfgSerialProviderManifest,
    purple_manifest: PurpleProviderManifest,
    write_context: SysCfgSerialContext,
    vault_root: PathBuf,
    vault: FileBackupVault,
    key: VaultKey,
    backup: BackupPipelineEvidence,
}

impl Fixture {
    fn new() -> Self {
        let session_id = Uuid::new_v4();
        let device_hash = "c".repeat(64);
        let serial_manifest = serial_manifest();
        let purple_manifest = purple_manifest();
        let selected =
            select_candidate(&doctor_manifest(), HostPlatform::Windows, &[observation()])
                .expect("candidate should select");
        let owner = LeaseOwner {
            session_id,
            worker_id: "syscfg-selected-write".to_owned(),
            run_id: Uuid::new_v4(),
        };
        let mut leases = LeaseManager::default();
        let platform_session = reserve_and_run_doctor(
            &doctor_manifest(),
            &doctor_context(session_id, &device_hash),
            HostPlatform::Windows,
            &[observation()],
            &mut ReadyProbe,
            &mut leases,
            PlatformDoctorReservation {
                owner,
                current_tick: 10,
                ttl_ticks: 100,
            },
        )
        .expect("Doctor should reserve endpoint");
        let endpoint = bind_read_endpoint(
            selected,
            platform_session,
            &ReadTransportAuthorization {
                session_id,
                device_identity_hash: device_hash.clone(),
                granted_permissions: required_transport_permissions(),
                allow_control_line_side_effects: true,
                current_tick: 20,
            },
        )
        .expect("endpoint should bind");

        let vault_root = secure_temp_dir();
        let vault = FileBackupVault::open_existing(&vault_root).expect("vault should open");
        let key = VaultKey::from_bytes("test-key-v1", [7u8; 32]).expect("key should build");
        let read_context = syscfg_context(session_id, &device_hash, required_read_permissions());
        let receipt = ReadExchangeReceipt {
            schema_version: SYSCFG_READ_TRANSPORT_VERSION.to_owned(),
            session_id,
            lease_id: endpoint.lease.lease_id,
            hardware_fingerprint: endpoint.candidate.hardware_fingerprint.clone(),
            operation: SysCfgReadOperation::List,
            command_action: "list".to_owned(),
            command_key: None,
            bytes_written: b"syscfg list\n".len(),
            bytes_read: RAW_BACKUP.len(),
            response_sha256: sha256_hex(RAW_BACKUP),
            prompt_verified: true,
        };
        let backup_authorization = BackupAuthorization {
            session_id,
            device_identity_hash: device_hash.clone(),
            granted_permissions: required_backup_permissions(),
            current_tick: 20,
        };
        let backup = capture_encrypt_verify_backup(BackupVaultRequest {
            capture: CapturedSysCfgList {
                endpoint: &endpoint,
                provider: &serial_manifest,
                context: &read_context,
                read_receipt: &receipt,
                raw_response: RAW_BACKUP,
            },
            authorization: &backup_authorization,
            vault: &vault,
            key: &key,
        })
        .expect("backup should be verified");
        let write_context = syscfg_context(session_id, &device_hash, required_write_permissions());

        Self {
            endpoint,
            session_id,
            device_hash,
            serial_manifest,
            purple_manifest,
            write_context,
            vault_root,
            vault,
            key,
            backup,
        }
    }

    fn authorization(&self) -> WriteTransportAuthorization {
        WriteTransportAuthorization {
            session_id: self.session_id,
            device_identity_hash: self.device_hash.clone(),
            granted_permissions: required_write_transport_permissions(),
            explicit_authorization: true,
            allow_control_line_side_effects: true,
            current_tick: 20,
        }
    }

    fn request<'a>(
        &'a self,
        authorization: &'a WriteTransportAuthorization,
        key: &'a VaultKey,
        selection: SelectedNonIdentityFieldWrite,
    ) -> SelectedWriteRequest<'a> {
        SelectedWriteRequest {
            endpoint: &self.endpoint,
            serial_manifest: &self.serial_manifest,
            purple_manifest: &self.purple_manifest,
            context: &self.write_context,
            backup_evidence: &self.backup,
            vault: &self.vault,
            key,
            authorization,
            selection,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.vault_root);
    }
}

type ScriptedExchangeResult = Result<Vec<u8>, String>;
type ScriptedExchange = (Vec<u8>, ScriptedExchangeResult);

struct ScriptedTransport {
    steps: VecDeque<ScriptedExchange>,
    observed: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    fn new(steps: Vec<ScriptedExchange>) -> Self {
        Self {
            steps: steps.into(),
            observed: Vec::new(),
        }
    }
}

impl SerialTransport for ScriptedTransport {
    fn exchange(
        &mut self,
        command: &[u8],
        _max_response_bytes: usize,
    ) -> Result<Vec<u8>, SerialTransportError> {
        self.observed.push(command.to_vec());
        let Some((expected, result)) = self.steps.pop_front() else {
            return Err(SerialTransportError {
                message: "unexpected extra exchange".to_owned(),
            });
        };
        if command != expected {
            return Err(SerialTransportError {
                message: "unexpected fixed command".to_owned(),
            });
        }
        result.map_err(|message| SerialTransportError { message })
    }
}

fn ok(response: &[u8]) -> Result<Vec<u8>, String> {
    Ok(response.to_vec())
}

#[test]
fn one_approved_diagnostic_field_commits_after_exact_readback() {
    let fixture = Fixture::new();
    let authorization = fixture.authorization();
    let mut transport = ScriptedTransport::new(vec![
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: OLD\r\n>\r\n"),
        ),
        (b"syscfg add DiagFlag NEW\n".to_vec(), ok(b"OK\r\n>\r\n")),
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: NEW\r\n>\r\n"),
        ),
    ]);
    let evidence = execute_selected_write_with_transport(
        fixture.request(
            &authorization,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .expect("selected write should execute");

    assert_eq!(
        evidence.outcome.status,
        TransactionStatus::VerifiedCommitted
    );
    assert!(!evidence.outcome.recovery_required);
    assert!(evidence.rollback_package_verified);
    assert_eq!(evidence.selected_class, SysCfgFieldClass::Diagnostic);
    assert_eq!(transport.observed.len(), 3);
    let durable = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!durable.contains("PRIVATE-SERIAL"));
    assert!(!durable.contains("OLD"));
    assert!(!durable.contains("NEW"));
}

#[test]
fn changed_precondition_stops_before_any_write() {
    let fixture = Fixture::new();
    let authorization = fixture.authorization();
    let mut transport = ScriptedTransport::new(vec![(
        b"syscfg print DiagFlag\n".to_vec(),
        ok(b"DiagFlag: CHANGED\r\n>\r\n"),
    )]);
    let evidence = execute_selected_write_with_transport(
        fixture.request(
            &authorization,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .expect("transaction should produce a failed-no-write outcome");

    assert_eq!(evidence.outcome.status, TransactionStatus::FailedNoWrite);
    assert_eq!(
        transport.observed,
        vec![b"syscfg print DiagFlag\n".to_vec()]
    );
}

#[test]
fn readback_mismatch_rolls_back_and_verifies_original_value() {
    let fixture = Fixture::new();
    let authorization = fixture.authorization();
    let mut transport = ScriptedTransport::new(vec![
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: OLD\r\n>\r\n"),
        ),
        (b"syscfg add DiagFlag NEW\n".to_vec(), ok(b"OK\r\n>\r\n")),
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: OTHER\r\n>\r\n"),
        ),
        (b"syscfg add DiagFlag OLD\n".to_vec(), ok(b"OK\r\n>\r\n")),
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: OLD\r\n>\r\n"),
        ),
    ]);
    let evidence = execute_selected_write_with_transport(
        fixture.request(
            &authorization,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .expect("transaction should return rollback evidence");

    assert_eq!(
        evidence.outcome.status,
        TransactionStatus::RolledBackVerified
    );
    assert!(!evidence.outcome.recovery_required);
    assert!(evidence.outcome.fields[0].rollback_attempted);
    assert!(evidence.outcome.fields[0].rollback_verified);
}

#[test]
fn rollback_failure_escalates_to_recovery_required() {
    let fixture = Fixture::new();
    let authorization = fixture.authorization();
    let mut transport = ScriptedTransport::new(vec![
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: OLD\r\n>\r\n"),
        ),
        (b"syscfg add DiagFlag NEW\n".to_vec(), ok(b"OK\r\n>\r\n")),
        (
            b"syscfg print DiagFlag\n".to_vec(),
            ok(b"DiagFlag: OTHER\r\n>\r\n"),
        ),
        (
            b"syscfg add DiagFlag OLD\n".to_vec(),
            Err("simulated rollback transport failure".to_owned()),
        ),
    ]);
    let evidence = execute_selected_write_with_transport(
        fixture.request(
            &authorization,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .expect("transaction should return recovery evidence");

    assert_eq!(evidence.outcome.status, TransactionStatus::RecoveryRequired);
    assert!(evidence.outcome.recovery_required);
    assert!(evidence.outcome.fields[0].rollback_attempted);
    assert!(!evidence.outcome.fields[0].rollback_verified);
}

#[test]
fn identity_field_and_wrong_backup_key_are_blocked_before_transport() {
    let fixture = Fixture::new();
    let authorization = fixture.authorization();
    let wrong_key = VaultKey::from_bytes("test-key-v1", [8u8; 32]).expect("wrong key builds");
    let mut transport = ScriptedTransport::new(Vec::new());

    assert!(execute_selected_write_with_transport(
        fixture.request(
            &authorization,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("SrNm", "OTHER-SERIAL"),
        ),
        &mut transport,
    )
    .is_err());
    assert!(execute_selected_write_with_transport(
        fixture.request(
            &authorization,
            &wrong_key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .is_err());
    assert!(transport.observed.is_empty());
}

#[test]
fn missing_authorization_and_expired_lease_are_blocked_before_transport() {
    let fixture = Fixture::new();
    let mut denied = fixture.authorization();
    denied.explicit_authorization = false;
    let mut expired = fixture.authorization();
    expired.current_tick = fixture.endpoint.lease.expires_at_tick;
    let mut transport = ScriptedTransport::new(Vec::new());

    assert!(execute_selected_write_with_transport(
        fixture.request(
            &denied,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .is_err());
    assert!(execute_selected_write_with_transport(
        fixture.request(
            &expired,
            &fixture.key,
            SelectedNonIdentityFieldWrite::new("DiagFlag", "NEW"),
        ),
        &mut transport,
    )
    .is_err());
    assert!(transport.observed.is_empty());
}

fn secure_temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!("tgcheckm8-write-{}", Uuid::new_v4()));
    fs::create_dir(&path).expect("temporary vault directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure temporary permissions");
    }
    path
}

#[allow(dead_code)]
fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}
