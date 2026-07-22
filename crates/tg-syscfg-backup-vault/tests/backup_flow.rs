use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_leases::{LeaseManager, LeaseOwner};
use tg_purple::SysCfgFieldClass;
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
    BackupVaultRequest, CapturedSysCfgList, FileBackupVault, VaultKey,
};
use tg_syscfg_read_transport::{
    bind_read_endpoint, required_transport_permissions, ReadExchangeReceipt,
    ReadTransportAuthorization, SysCfgReadOperation, SYSCFG_READ_TRANSPORT_VERSION,
};
use tg_syscfg_serial::{
    required_read_permissions, required_write_permissions, SerialLink, SysCfgFieldPolicy,
    SysCfgSerialContext, SysCfgSerialProviderManifest, SYSCFG_SERIAL_VERSION,
};
use uuid::Uuid;

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

fn provider_manifest() -> SysCfgSerialProviderManifest {
    SysCfgSerialProviderManifest {
        schema_version: SYSCFG_SERIAL_VERSION.to_owned(),
        provider_id: "synthetic.syscfg-read".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        supported_board_configs: BTreeSet::from(["d331pap".to_owned()]),
        links: BTreeSet::from([SerialLink::UsbSerial]),
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "a".repeat(40),
        declared_licence: Some("MIT".to_owned()),
        supports_write: false,
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
        ]),
        required_backup_keys: BTreeSet::from(["SrNm".to_owned(), "Regn".to_owned()]),
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

fn logical_context(session_id: Uuid, device_hash: &str) -> SysCfgSerialContext {
    SysCfgSerialContext {
        session_id,
        provider_id: "synthetic.syscfg-read".to_owned(),
        device_identity_hash: device_hash.to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        purple_proof: purple_proof(session_id),
        granted_permissions: required_read_permissions(),
        policy_profile: "development".to_owned(),
    }
}

fn observation() -> RawSerialPortObservation {
    RawSerialPortObservation {
        port_name: "COM77".to_owned(),
        vid: Some(0x1209),
        pid: Some(0x0001),
        serial_number: Some("SYNTHETIC-BACKUP-ADAPTER".to_owned()),
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

fn bound_endpoint(
    current_tick: u64,
) -> (tg_syscfg_read_transport::BoundReadEndpoint, Uuid, String) {
    let session_id = Uuid::new_v4();
    let device_hash = "c".repeat(64);
    let selected = select_candidate(&doctor_manifest(), HostPlatform::Windows, &[observation()])
        .expect("candidate should select");
    let owner = LeaseOwner {
        session_id,
        worker_id: "syscfg-backup-vault".to_owned(),
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
            current_tick,
        },
    )
    .expect("endpoint should bind");
    (endpoint, session_id, device_hash)
}

fn list_receipt(
    endpoint: &tg_syscfg_read_transport::BoundReadEndpoint,
    response: &[u8],
) -> ReadExchangeReceipt {
    ReadExchangeReceipt {
        schema_version: SYSCFG_READ_TRANSPORT_VERSION.to_owned(),
        session_id: endpoint.session_id,
        lease_id: endpoint.lease.lease_id,
        hardware_fingerprint: endpoint.candidate.hardware_fingerprint.clone(),
        operation: SysCfgReadOperation::List,
        command_action: "list".to_owned(),
        command_key: None,
        bytes_written: b"syscfg list\n".len(),
        bytes_read: response.len(),
        response_sha256: sha256_hex(response),
        prompt_verified: true,
    }
}

fn authorization(session_id: Uuid, device_hash: &str, current_tick: u64) -> BackupAuthorization {
    BackupAuthorization {
        session_id,
        device_identity_hash: device_hash.to_owned(),
        granted_permissions: required_backup_permissions(),
        current_tick,
    }
}

macro_rules! run_backup {
    ($endpoint:expr, $session_id:expr, $device_hash:expr, $receipt:expr, $raw:expr, $authorization:expr, $vault:expr, $key:expr) => {{
        let provider = provider_manifest();
        let context = logical_context($session_id, $device_hash);
        let receipt = $receipt;
        let authorization = $authorization;
        capture_encrypt_verify_backup(BackupVaultRequest {
            capture: CapturedSysCfgList {
                endpoint: $endpoint,
                provider: &provider,
                context: &context,
                read_receipt: &receipt,
                raw_response: $raw,
            },
            authorization: &authorization,
            vault: $vault,
            key: $key,
        })
    }};
}

fn secure_temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!("tgcheckm8-vault-{}", Uuid::new_v4()));
    fs::create_dir(&path).expect("temporary vault directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure temporary permissions");
    }
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

#[test]
fn complete_list_is_snapshotted_encrypted_reopened_and_rollback_ready() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let raw = b"syscfg list\r\nSrNm: PRIVATE-SERIAL\r\nRegn: LL/A\r\n>\r\n";
    let root = secure_temp_dir();
    let vault = FileBackupVault::open_existing(&root).expect("vault should open");
    let key = VaultKey::from_bytes("test-key-v1", [7u8; 32]).expect("key should build");
    let evidence = run_backup!(
        &endpoint,
        session_id,
        &device_hash,
        list_receipt(&endpoint, raw),
        raw,
        authorization(session_id, &device_hash, 20),
        &vault,
        &key
    )
    .expect("complete backup should pass");

    assert!(evidence.snapshot.verified);
    assert!(evidence.backup.verified);
    assert!(evidence.backup.rollback_ready);
    assert!(evidence.encrypted.verified_readback);
    assert_eq!(evidence.encrypted.field_count, 2);

    let durable = serde_json::to_string(&evidence).expect("evidence should serialize");
    assert!(!durable.contains("PRIVATE-SERIAL"));
    assert!(!durable.contains("LL/A"));
    let stored = fs::read(vault.object_path_for_local_operator(evidence.encrypted.object_id))
        .expect("encrypted object should exist");
    assert!(!stored
        .windows("PRIVATE-SERIAL".len())
        .any(|part| part == b"PRIVATE-SERIAL"));

    let recovered = vault
        .read_for_rollback(&evidence.backup, &evidence.encrypted, &key)
        .expect("verified backup should reopen");
    assert_eq!(recovered.bytes_for_rollback(), raw);
    cleanup(&root);
}

#[test]
fn missing_required_backup_key_blocks_snapshot_and_receipt() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let raw = b"syscfg list\r\nRegn: LL/A\r\n>\r\n";
    let root = secure_temp_dir();
    let vault = FileBackupVault::open_existing(&root).expect("vault should open");
    let key = VaultKey::from_bytes("test-key-v1", [7u8; 32]).expect("key should build");
    let result = run_backup!(
        &endpoint,
        session_id,
        &device_hash,
        list_receipt(&endpoint, raw),
        raw,
        authorization(session_id, &device_hash, 20),
        &vault,
        &key
    );
    assert!(result.is_err());
    assert_eq!(fs::read_dir(&root).expect("vault directory").count(), 0);
    cleanup(&root);
}

#[test]
fn print_receipt_cannot_be_promoted_to_full_backup() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let raw = b"syscfg print Regn\r\nRegn: LL/A\r\n>\r\n";
    let mut receipt = list_receipt(&endpoint, raw);
    receipt.operation = SysCfgReadOperation::Print {
        key: "Regn".to_owned(),
    };
    receipt.command_action = "print".to_owned();
    receipt.command_key = Some("Regn".to_owned());
    let root = secure_temp_dir();
    let vault = FileBackupVault::open_existing(&root).expect("vault should open");
    let key = VaultKey::from_bytes("test-key-v1", [7u8; 32]).expect("key should build");
    assert!(run_backup!(
        &endpoint,
        session_id,
        &device_hash,
        receipt,
        raw,
        authorization(session_id, &device_hash, 20),
        &vault,
        &key
    )
    .is_err());
    cleanup(&root);
}

#[test]
fn wrong_key_and_ciphertext_tampering_are_detected() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let raw = b"syscfg list\r\nSrNm: PRIVATE-SERIAL\r\nRegn: LL/A\r\n>\r\n";
    let root = secure_temp_dir();
    let vault = FileBackupVault::open_existing(&root).expect("vault should open");
    let key = VaultKey::from_bytes("test-key-v1", [7u8; 32]).expect("key should build");
    let evidence = run_backup!(
        &endpoint,
        session_id,
        &device_hash,
        list_receipt(&endpoint, raw),
        raw,
        authorization(session_id, &device_hash, 20),
        &vault,
        &key
    )
    .expect("complete backup should pass");
    let wrong = VaultKey::from_bytes("test-key-v1", [8u8; 32]).expect("wrong key should build");
    assert!(vault
        .read_for_rollback(&evidence.backup, &evidence.encrypted, &wrong)
        .is_err());

    let path = vault.object_path_for_local_operator(evidence.encrypted.object_id);
    let mut stored = fs::read(&path).expect("stored package");
    let last = stored.len() - 1;
    stored[last] ^= 0x01;
    fs::write(&path, stored).expect("tamper package");
    assert!(vault
        .read_for_rollback(&evidence.backup, &evidence.encrypted, &key)
        .is_err());
    cleanup(&root);
}

#[test]
fn missing_permission_and_expired_lease_block_before_persistence() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let raw = b"syscfg list\r\nSrNm: PRIVATE-SERIAL\r\nRegn: LL/A\r\n>\r\n";
    let root = secure_temp_dir();
    let vault = FileBackupVault::open_existing(&root).expect("vault should open");
    let key = VaultKey::from_bytes("test-key-v1", [7u8; 32]).expect("key should build");
    let mut denied = authorization(session_id, &device_hash, 20);
    denied.granted_permissions.remove(&Permission::VaultWrite);
    assert!(run_backup!(
        &endpoint,
        session_id,
        &device_hash,
        list_receipt(&endpoint, raw),
        raw,
        denied,
        &vault,
        &key
    )
    .is_err());
    assert!(run_backup!(
        &endpoint,
        session_id,
        &device_hash,
        list_receipt(&endpoint, raw),
        raw,
        authorization(
            session_id,
            &device_hash,
            endpoint.lease.expires_at_tick
        ),
        &vault,
        &key
    )
    .is_err());
    assert_eq!(fs::read_dir(&root).expect("vault directory").count(), 0);
    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn group_or_world_accessible_vault_root_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("tgcheckm8-insecure-{}", Uuid::new_v4()));
    fs::create_dir(&root).expect("temporary vault directory");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
        .expect("insecure temporary permissions");
    assert!(FileBackupVault::open_existing(&root).is_err());
    cleanup(&root);
}

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}
