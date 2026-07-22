//! Deterministic Purple/Diags and SysCfg service contracts.
//!
//! This crate contains no exploit, bootchain, serial transport, or device-write
//! implementation. It defines the rules that future providers must satisfy.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tg_contracts::{DeviceMode, Maturity, Permission};
use uuid::Uuid;

pub const PURPLE_CONTRACT_VERSION: &str = "tgcheckm8.purple.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChipGeneration {
    A5A5x,
    A6A11,
    A12A13,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PwnProvider {
    A5ArduinoMax3421e,
    SoftwareCheckm8,
    Usbliter8Rp2350,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurpleTransport {
    UsbSerial,
    DcsdSerial,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurpleBootStage {
    LockDeviceIdentity,
    EnterDfu,
    PwnDfu,
    VerifyPwnedDfu,
    SelectBootchain,
    VerifyBootchainIntegrity,
    SendStageOne,
    SendStageTwo,
    SendStageThree,
    WaitForPurpleMode,
    VerifyPurpleIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleProviderManifest {
    pub schema_version: String,
    pub provider_id: String,
    pub version: String,
    pub generation: ChipGeneration,
    pub pwn_provider: PwnProvider,
    pub supported_product_types: BTreeSet<String>,
    pub transports: BTreeSet<PurpleTransport>,
    pub required_hardware: BTreeSet<String>,
    pub maturity: Maturity,
    pub source_repository: String,
    pub source_commit: String,
    pub declared_licence: Option<String>,
    pub proof_requirements: BTreeSet<String>,
    pub supports_syscfg_read: bool,
    pub supports_syscfg_write: bool,
    pub allowed_write_classes: BTreeSet<SysCfgFieldClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleBootPlan {
    pub provider_id: String,
    pub stages: Vec<PurpleBootStage>,
    pub required_permissions: BTreeSet<Permission>,
    pub expected_final_mode: DeviceMode,
    pub required_hardware: BTreeSet<String>,
    pub required_proofs: BTreeSet<String>,
}

pub fn validate_provider(
    manifest: &PurpleProviderManifest,
    policy_profile: &str,
) -> Result<(), PurpleError> {
    if manifest.schema_version != PURPLE_CONTRACT_VERSION {
        return Err(PurpleError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.provider_id.trim().is_empty()
        || manifest.version.trim().is_empty()
        || manifest.source_repository.trim().is_empty()
        || manifest.source_commit.trim().is_empty()
    {
        return Err(PurpleError::IncompleteProviderIdentity);
    }
    if manifest.supported_product_types.is_empty() {
        return Err(PurpleError::MissingDeviceCoverage);
    }
    if manifest.transports.is_empty() {
        return Err(PurpleError::MissingTransport);
    }

    let mandatory_proofs = [
        "device_identity_locked",
        "pwned_dfu_verified",
        "bootchain_integrity_verified",
        "purple_mode_verified",
        "purple_identity_match",
    ];
    if mandatory_proofs
        .iter()
        .any(|proof| !manifest.proof_requirements.contains(*proof))
    {
        return Err(PurpleError::MissingProviderProof);
    }

    match (&manifest.generation, &manifest.pwn_provider) {
        (ChipGeneration::A5A5x, PwnProvider::A5ArduinoMax3421e)
        | (ChipGeneration::A6A11, PwnProvider::SoftwareCheckm8)
        | (ChipGeneration::A12A13, PwnProvider::Usbliter8Rp2350) => {}
        _ => return Err(PurpleError::GenerationProviderMismatch),
    }

    if manifest.supports_syscfg_write && manifest.allowed_write_classes.is_empty() {
        return Err(PurpleError::WritePolicyMissing);
    }
    if policy_profile == "stable" {
        if manifest.maturity != Maturity::Stable {
            return Err(PurpleError::ImmatureStableProvider);
        }
        if manifest
            .declared_licence
            .as_deref()
            .map_or(true, str::is_empty)
        {
            return Err(PurpleError::MissingDeclaredLicence);
        }
    }
    Ok(())
}

pub fn build_boot_plan(
    manifest: &PurpleProviderManifest,
    policy_profile: &str,
) -> Result<PurpleBootPlan, PurpleError> {
    validate_provider(manifest, policy_profile)?;

    let mut permissions = BTreeSet::from([
        Permission::DeviceObserve,
        Permission::UsbRead,
        Permission::UsbWrite,
        Permission::SerialRead,
    ]);
    if manifest.pwn_provider == PwnProvider::A5ArduinoMax3421e {
        permissions.insert(Permission::ArduinoControl);
    }

    Ok(PurpleBootPlan {
        provider_id: manifest.provider_id.clone(),
        stages: vec![
            PurpleBootStage::LockDeviceIdentity,
            PurpleBootStage::EnterDfu,
            PurpleBootStage::PwnDfu,
            PurpleBootStage::VerifyPwnedDfu,
            PurpleBootStage::SelectBootchain,
            PurpleBootStage::VerifyBootchainIntegrity,
            PurpleBootStage::SendStageOne,
            PurpleBootStage::SendStageTwo,
            PurpleBootStage::SendStageThree,
            PurpleBootStage::WaitForPurpleMode,
            PurpleBootStage::VerifyPurpleIdentity,
        ],
        required_permissions: permissions,
        expected_final_mode: DeviceMode::PurpleDiagnostic,
        required_hardware: manifest.required_hardware.clone(),
        required_proofs: manifest.proof_requirements.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SysCfgFieldClass {
    Diagnostic,
    Calibration,
    Manufacturing,
    IdentityCritical,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgFieldRecord {
    pub key: String,
    pub class: SysCfgFieldClass,
    pub encoded_value_hash: String,
    pub checksum_valid: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgSnapshot {
    pub snapshot_id: Uuid,
    pub session_id: Uuid,
    pub provider_id: String,
    pub device_identity_hash: String,
    pub product_type: String,
    pub board_config: String,
    pub blob_sha256: String,
    pub fields: BTreeMap<String, SysCfgFieldRecord>,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgBackupReceipt {
    pub snapshot_id: Uuid,
    pub device_identity_hash: String,
    pub board_config: String,
    pub source_blob_sha256: String,
    pub backup_sha256: String,
    pub verified: bool,
    pub rollback_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SysCfgWriteIntent {
    RestoreFromVerifiedBackup,
    RepairSelectedFields,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgChange {
    pub field_key: String,
    pub class: SysCfgFieldClass,
    pub expected_before_hash: String,
    pub requested_after_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgWriteRequest {
    pub session_id: Uuid,
    pub provider_id: String,
    pub current_device_identity_hash: String,
    pub current_board_config: String,
    pub intent: SysCfgWriteIntent,
    pub backup: SysCfgBackupReceipt,
    pub changes: Vec<SysCfgChange>,
    pub requested_permissions: BTreeSet<Permission>,
    pub explicit_authorization: bool,
    pub policy_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgWriteDecision {
    pub approved: bool,
    pub blockers: Vec<String>,
    pub granted_permissions: BTreeSet<Permission>,
    pub required_post_write_proofs: BTreeSet<String>,
}

pub fn evaluate_write_request(
    manifest: &PurpleProviderManifest,
    snapshot: &SysCfgSnapshot,
    request: &SysCfgWriteRequest,
) -> SysCfgWriteDecision {
    let mut blockers = Vec::new();

    if let Err(error) = validate_provider(manifest, &request.policy_profile) {
        blockers.push(error.to_string());
    }
    if !manifest.supports_syscfg_write {
        blockers.push("provider does not declare SysCfg write support".to_owned());
    }
    if !snapshot.verified {
        blockers.push("SysCfg snapshot is not verified".to_owned());
    }
    if !request.backup.verified || !request.backup.rollback_ready {
        blockers.push("verified rollback-ready backup is required".to_owned());
    }
    if request.backup.snapshot_id != snapshot.snapshot_id
        || request.backup.source_blob_sha256 != snapshot.blob_sha256
    {
        blockers.push("backup does not bind to the locked snapshot".to_owned());
    }
    if snapshot.session_id != request.session_id {
        blockers.push("snapshot belongs to another session".to_owned());
    }
    if manifest.provider_id != request.provider_id || snapshot.provider_id != request.provider_id {
        blockers.push("provider identity mismatch".to_owned());
    }
    if snapshot.device_identity_hash != request.current_device_identity_hash
        || request.backup.device_identity_hash != request.current_device_identity_hash
    {
        blockers.push("device identity mismatch".to_owned());
    }
    if snapshot.board_config != request.current_board_config
        || request.backup.board_config != request.current_board_config
    {
        blockers.push("board configuration mismatch".to_owned());
    }
    if !request.explicit_authorization {
        blockers.push("explicit write authorization is required".to_owned());
    }
    if request.changes.is_empty() {
        blockers.push("at least one field change is required".to_owned());
    }

    let required_permissions = BTreeSet::from([
        Permission::SerialWrite,
        Permission::SysCfgRestoreSameBoard,
        Permission::VaultRead,
        Permission::VaultWrite,
    ]);
    if !required_permissions.is_subset(&request.requested_permissions) {
        blockers.push("write request is missing mandatory permissions".to_owned());
    }

    let mut seen = BTreeSet::new();
    for change in &request.changes {
        if !seen.insert(change.field_key.clone()) {
            blockers.push(format!("duplicate field change: {}", change.field_key));
            continue;
        }
        let Some(field) = snapshot.fields.get(&change.field_key) else {
            blockers.push(format!(
                "field is absent from snapshot: {}",
                change.field_key
            ));
            continue;
        };
        if field.key != change.field_key
            || field.class != change.class
            || field.encoded_value_hash != change.expected_before_hash
        {
            blockers.push(format!("field precondition mismatch: {}", change.field_key));
        }
        if !field.checksum_valid || !field.writable {
            blockers.push(format!(
                "field is not safely writable: {}",
                change.field_key
            ));
        }
        if change.requested_after_hash.trim().is_empty()
            || change.requested_after_hash == change.expected_before_hash
        {
            blockers.push(format!(
                "field has no valid requested change: {}",
                change.field_key
            ));
        }
        if matches!(
            change.class,
            SysCfgFieldClass::IdentityCritical | SysCfgFieldClass::Unknown
        ) {
            blockers.push(format!("field class is blocked: {}", change.field_key));
        }
        if !manifest.allowed_write_classes.contains(&change.class) {
            blockers.push(format!(
                "provider policy blocks field: {}",
                change.field_key
            ));
        }
        if request.policy_profile == "stable"
            && !matches!(
                change.class,
                SysCfgFieldClass::Diagnostic | SysCfgFieldClass::Calibration
            )
        {
            blockers.push(format!("stable policy blocks field: {}", change.field_key));
        }
    }

    SysCfgWriteDecision {
        approved: blockers.is_empty(),
        blockers,
        granted_permissions: if request
            .requested_permissions
            .is_superset(&required_permissions)
        {
            required_permissions
        } else {
            BTreeSet::new()
        },
        required_post_write_proofs: BTreeSet::from([
            "same_device_identity".to_owned(),
            "same_board_identity".to_owned(),
            "transport_write_acknowledged".to_owned(),
            "exact_readback_match".to_owned(),
            "rollback_package_verified".to_owned(),
        ]),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgReadbackProof {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub board_config: String,
    pub observed_field_hashes: BTreeMap<String, String>,
    pub transport_write_acknowledged: bool,
    pub rollback_package_sha256: String,
    pub valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgWriteVerification {
    pub verified: bool,
    pub failures: Vec<String>,
}

pub fn verify_write_readback(
    request: &SysCfgWriteRequest,
    proof: &SysCfgReadbackProof,
) -> SysCfgWriteVerification {
    let mut failures = Vec::new();

    if proof.session_id != request.session_id {
        failures.push("read-back belongs to another session".to_owned());
    }
    if proof.device_identity_hash != request.current_device_identity_hash {
        failures.push("read-back device identity mismatch".to_owned());
    }
    if proof.board_config != request.current_board_config {
        failures.push("read-back board mismatch".to_owned());
    }
    if !proof.valid || !proof.transport_write_acknowledged {
        failures.push("transport write acknowledgment is invalid".to_owned());
    }
    if proof.rollback_package_sha256.trim().is_empty() {
        failures.push("rollback package proof is missing".to_owned());
    }

    let requested_keys: BTreeSet<&str> = request
        .changes
        .iter()
        .map(|change| change.field_key.as_str())
        .collect();
    let observed_keys: BTreeSet<&str> = proof
        .observed_field_hashes
        .keys()
        .map(String::as_str)
        .collect();
    if requested_keys != observed_keys {
        failures.push("read-back field set does not exactly match the request".to_owned());
    }

    for change in &request.changes {
        match proof.observed_field_hashes.get(&change.field_key) {
            Some(observed) if observed == &change.requested_after_hash => {}
            Some(_) => failures.push(format!("read-back mismatch: {}", change.field_key)),
            None => failures.push(format!("read-back missing field: {}", change.field_key)),
        }
    }

    SysCfgWriteVerification {
        verified: failures.is_empty(),
        failures,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurpleError {
    #[error("unsupported Purple contract version: {0}")]
    UnsupportedVersion(String),
    #[error("provider identity or provenance is incomplete")]
    IncompleteProviderIdentity,
    #[error("provider has no device coverage")]
    MissingDeviceCoverage,
    #[error("provider has no Purple transport")]
    MissingTransport,
    #[error("provider is missing mandatory transition proof requirements")]
    MissingProviderProof,
    #[error("chip generation and pwn provider do not match")]
    GenerationProviderMismatch,
    #[error("write-capable provider has no allowed field classes")]
    WritePolicyMissing,
    #[error("stable policy requires a Stable Purple provider")]
    ImmatureStableProvider,
    #[error("stable policy requires a declared licence")]
    MissingDeclaredLicence,
}
