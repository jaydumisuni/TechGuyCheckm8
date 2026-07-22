//! Shared deterministic contracts for the TGCHECKM8 control plane.
//!
//! These types contain no exploit implementation and grant no device authority.
//! They define the stable language used by the gateway, workers, evidence judge
//! and future user interfaces.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const CONTRACT_VERSION: &str = "tgcheckm8.contracts.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Diagnose,
    Jailbreak,
    BootRamdisk,
    PreserveDevice,
    SaveShsh,
    BuildIpsw,
    RestoreSigned,
    RestoreWithShsh,
    RestoreTethered,
    JustBoot,
    EnterDiagnosticMode,
    ReadSysCfg,
    BackupSysCfg,
    RestoreSysCfgSameBoard,
    PreserveActivationArtifacts,
    RestoreActivationArtifactsSameDevice,
    ExportSupportPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMode {
    Disconnected,
    Normal,
    Recovery,
    Dfu,
    PwnedDfu,
    PwnedIbss,
    PwnedIbec,
    Kdfu,
    PurpleDiagnostic,
    RamdiskBooting,
    RamdiskSsh,
    TetheredOs,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Idle,
    Detected,
    IntakeLocked,
    RouteProposed,
    AwaitingAuthorization,
    Preparing,
    WaitingForDeviceMode,
    ExecutingStage,
    StageVerification,
    RecoveryRequired,
    Rebooting,
    FinalVerification,
    CompletedVerified,
    CompletedUnverified,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    DeviceObserve,
    DeviceRestart,
    DeviceErase,
    UsbRead,
    UsbWrite,
    SerialRead,
    SerialWrite,
    ArduinoControl,
    SshConnect,
    FilesystemRead,
    FilesystemWrite,
    FilesystemMountReadonly,
    FilesystemMountReadwrite,
    NormalModeLockdown,
    NormalModeAfcRead,
    NormalModeAfcWrite,
    NormalModeDiagnostics,
    RamdiskBoot,
    FirmwareDownload,
    FirmwareExtract,
    FirmwarePatch,
    FirmwareRestore,
    VaultRead,
    VaultWrite,
    ShshRead,
    ShshSave,
    ActivationArtifactRead,
    ActivationArtifactRestoreSameDevice,
    SysCfgRead,
    SysCfgBackup,
    SysCfgRestoreSameBoard,
    NetworkLoopback,
    NetworkApprovedSource,
    ProcessSpawn,
    PackStage,
    PackActivate,
    SupportExportRedacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub product_type: String,
    pub board_config: Option<String>,
    pub chip: Option<String>,
    pub cpid: Option<String>,
    pub ecid_hash: Option<String>,
    pub udid_hash: Option<String>,
    pub serial_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareIdentity {
    pub version: String,
    pub build: Option<String>,
    pub architecture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentity {
    pub os: String,
    pub version: Option<String>,
    pub architecture: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    pub schema_version: String,
    pub session_id: Uuid,
    pub operation: OperationKind,
    pub device: DeviceIdentity,
    pub firmware: Option<FirmwareIdentity>,
    pub host: HostIdentity,
    pub current_mode: DeviceMode,
    pub requested_permissions: BTreeSet<Permission>,
    pub policy_profile: String,
    pub offline_required: bool,
}

impl SessionRequest {
    pub fn new(
        operation: OperationKind,
        device: DeviceIdentity,
        host: HostIdentity,
        current_mode: DeviceMode,
    ) -> Self {
        Self {
            schema_version: CONTRACT_VERSION.to_owned(),
            session_id: Uuid::new_v4(),
            operation,
            device,
            firmware: None,
            host,
            current_mode,
            requested_permissions: BTreeSet::new(),
            policy_profile: "stable".to_owned(),
            offline_required: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineManifest {
    pub schema_version: String,
    pub engine_id: String,
    pub version: String,
    pub maturity: Maturity,
    pub capabilities: BTreeSet<String>,
    pub requested_permissions: BTreeSet<Permission>,
    pub supported_hosts: BTreeSet<String>,
    pub executes_external_code: bool,
    pub requires_network: bool,
    pub modifies_device: bool,
    pub provenance: Provenance,
    pub proof_requirements: BTreeSet<String>,
    pub failure_behavior: FailureBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Maturity {
    Discovered,
    Imported,
    ContractValid,
    SimulationTested,
    HardwareTested,
    Beta,
    Stable,
    Deprecated,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source_repository: String,
    pub source_commit: String,
    pub source_release: Option<String>,
    pub licence: String,
    pub local_patch_hash: Option<String>,
    pub build_recipe_hash: Option<String>,
    pub artifact_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureBehavior {
    StopAndRecover,
    FailClosed,
    RetryUnderController,
    ObservationOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageResult {
    SuccessVerified,
    SuccessPartial,
    Unverified,
    RetryableFailure,
    UserActionRequired,
    Unsupported,
    BlockedByPolicy,
    DeviceDisconnected,
    IdentityMismatch,
    RecoveryRequired,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Observation,
    Execution,
    Transition,
    Integrity,
    Authorization,
    Recovery,
    FinalProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub schema_version: String,
    pub evidence_id: Uuid,
    pub session_id: Uuid,
    pub stage_id: String,
    pub sequence: u64,
    pub class: EvidenceClass,
    pub source: String,
    pub collector_version: String,
    pub device_identity_hash: Option<String>,
    pub values: BTreeMap<String, String>,
    pub artifact_hashes: BTreeMap<String, String>,
    pub valid: bool,
    pub redaction_class: RedactionClass,
    pub supersedes: Vec<Uuid>,
    pub contradicts: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    Public,
    DeviceSensitive,
    Secret,
    ArtifactContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub safe_to_retry: bool,
    pub maximum_attempts: u8,
    pub expected_device_state_after_failure: DeviceMode,
    pub cleanup_actions: Vec<String>,
    pub rollback_actions: Vec<String>,
    pub manual_actions: Vec<String>,
    pub restore_required_conditions: Vec<String>,
    pub recovery_proof_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub approved: bool,
    pub route_id: Option<String>,
    pub engine_ids: Vec<String>,
    pub granted_permissions: BTreeSet<Permission>,
    pub unmet_requirements: Vec<String>,
    pub blockers: Vec<String>,
    pub rationale_codes: Vec<String>,
}

impl RouteDecision {
    pub fn blocked(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            approved: false,
            route_id: None,
            engine_ids: Vec::new(),
            granted_permissions: BTreeSet::new(),
            unmet_requirements: Vec::new(),
            blockers: vec![detail.into()],
            rationale_codes: vec![code.into()],
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported contract version: {0}")]
    UnsupportedVersion(String),
    #[error("stable policy cannot approve blocked or pre-hardware-tested engine")]
    ImmatureStableEngine,
    #[error("granted permission was not requested by both route and engine")]
    PermissionExpansion,
    #[error("device identity does not match the locked session")]
    IdentityMismatch,
    #[error("mandatory evidence is missing or invalid")]
    MissingProof,
}

pub fn validate_engine_for_policy(
    manifest: &EngineManifest,
    policy_profile: &str,
) -> Result<(), ContractError> {
    if manifest.schema_version != CONTRACT_VERSION {
        return Err(ContractError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }

    if policy_profile == "stable" && manifest.maturity != Maturity::Stable {
        return Err(ContractError::ImmatureStableEngine);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn stable_policy_rejects_beta_engine() {
        let manifest = EngineManifest {
            schema_version: CONTRACT_VERSION.to_owned(),
            engine_id: "test".to_owned(),
            version: "0.1.0".to_owned(),
            maturity: Maturity::Beta,
            capabilities: BTreeSet::new(),
            requested_permissions: BTreeSet::new(),
            supported_hosts: BTreeSet::new(),
            executes_external_code: false,
            requires_network: false,
            modifies_device: false,
            provenance: provenance(),
            proof_requirements: BTreeSet::new(),
            failure_behavior: FailureBehavior::FailClosed,
        };

        assert_eq!(
            validate_engine_for_policy(&manifest, "stable"),
            Err(ContractError::ImmatureStableEngine)
        );
    }

    #[test]
    fn blocked_route_has_no_engines_or_permissions() {
        let decision = RouteDecision::blocked("unknown_cpid", "CPID is not approved");
        assert!(!decision.approved);
        assert!(decision.engine_ids.is_empty());
        assert!(decision.granted_permissions.is_empty());
    }

    #[test]
    fn session_defaults_to_offline_stable_policy() {
        let request = SessionRequest::new(
            OperationKind::Diagnose,
            DeviceIdentity {
                product_type: "iPhone10,6".to_owned(),
                board_config: None,
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
            DeviceMode::Recovery,
        );

        assert_eq!(request.policy_profile, "stable");
        assert!(request.offline_required);
    }
}
