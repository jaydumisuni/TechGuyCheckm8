//! Deterministic Purple/Diags boot provider contracts.
//!
//! This crate contains no Apple diagnostic images, exploit code, USB transport,
//! iRecovery implementation, or free-form iBoot shell. It defines a fixed,
//! hash-pinned route from verified pwned DFU to verified Purple mode.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tg_apple_observe::{match_reconnect, LockedDeviceIdentity, ObservedAppleDevice};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_usbliter8::PwnDfuFinalProof;
use uuid::Uuid;

pub const PURPLE_BOOT_VERSION: &str = "tgcheckm8.purple-boot.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootArtifactKind {
    RawIbss,
    DiagImg4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetAcquisition {
    UserSuppliedLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootArtifactDescriptor {
    pub kind: BootArtifactKind,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub acquisition: AssetAcquisition,
    pub redistribution_allowed: bool,
    pub source_description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurpleTransport {
    UsbSerial,
    DcsdSerial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleBootRouteManifest {
    pub schema_version: String,
    pub route_id: String,
    pub version: String,
    pub product_type: String,
    pub board_config: String,
    pub cpid: String,
    pub pwn_provider: String,
    pub raw_ibss: BootArtifactDescriptor,
    pub diag_image: BootArtifactDescriptor,
    pub requires_power_button_hold_seconds: Option<u8>,
    pub recovery_settle_millis: u64,
    pub transports: BTreeSet<PurpleTransport>,
    pub maturity: Maturity,
    pub route_source_evidence: BTreeSet<String>,
    pub declared_route_licence: Option<String>,
    pub requested_permissions: BTreeSet<Permission>,
    pub proof_requirements: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurpleBootStep {
    VerifyPwnedDfu,
    VerifyRawIbss,
    SendRawIbss,
    SendCustomBoot,
    HoldPowerButton { seconds: u8 },
    WaitForRecovery,
    VerifyRecoveryIdentity,
    WaitForRecoverySettle { milliseconds: u64 },
    VerifyDiagImage,
    SendDiagImage,
    SetUsbSerialBootArgs,
    SaveEnvironment,
    Go,
    WaitForPurple,
    VerifyPurpleIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleBootRequest {
    pub session_id: Uuid,
    pub route_id: String,
    pub locked_identity: LockedDeviceIdentity,
    pub pwn_proof: PwnDfuFinalProof,
    pub pwn_observation: ObservedAppleDevice,
    pub authorized_device_service: bool,
    pub explicit_operator_authorization: bool,
    pub granted_permissions: BTreeSet<Permission>,
    pub policy_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedBootArtifact {
    pub kind: BootArtifactKind,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleBootPlan {
    pub session_id: Uuid,
    pub route_id: String,
    pub product_type: String,
    pub board_config: String,
    pub cpid: String,
    pub pwn_provider: String,
    pub artifacts: Vec<PinnedBootArtifact>,
    pub steps: Vec<PurpleBootStep>,
    pub granted_permissions: BTreeSet<Permission>,
    pub required_proofs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactTransferReceipt {
    pub kind: BootArtifactKind,
    pub observed_sha256: String,
    pub observed_size_bytes: u64,
    pub transfer_acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleStepReceipt {
    pub step: PurpleBootStep,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleBootRunEvidence {
    pub session_id: Uuid,
    pub route_id: String,
    pub step_receipts: Vec<PurpleStepReceipt>,
    pub artifact_receipts: Vec<ArtifactTransferReceipt>,
    pub recovery_observation: ObservedAppleDevice,
    pub purple_observation: ObservedAppleDevice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleBootFinalProof {
    pub session_id: Uuid,
    pub route_id: String,
    pub verified: bool,
    pub final_mode: DeviceMode,
    pub failures: Vec<String>,
}

pub fn required_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::UsbRead,
        Permission::UsbWrite,
        Permission::FilesystemRead,
        Permission::ProcessSpawn,
        Permission::SerialRead,
    ])
}

pub fn validate_route_manifest(
    manifest: &PurpleBootRouteManifest,
    policy_profile: &str,
) -> Result<(), PurpleBootError> {
    if manifest.schema_version != PURPLE_BOOT_VERSION {
        return Err(PurpleBootError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.route_id.trim().is_empty()
        || manifest.version.trim().is_empty()
        || manifest.product_type.trim().is_empty()
        || manifest.board_config.trim().is_empty()
        || manifest.pwn_provider.trim().is_empty()
    {
        return Err(PurpleBootError::IncompleteRouteIdentity);
    }
    if manifest.pwn_provider != "usbliter8" {
        return Err(PurpleBootError::UnsupportedPwnProvider(
            manifest.pwn_provider.clone(),
        ));
    }
    let normalized_cpid = normalize_cpid(&manifest.cpid)?;
    if normalized_cpid != manifest.cpid {
        return Err(PurpleBootError::NonCanonicalCpid(manifest.cpid.clone()));
    }
    if !matches!(manifest.cpid.as_str(), "8006" | "8020" | "8030") {
        return Err(PurpleBootError::UnsupportedCpid(manifest.cpid.clone()));
    }
    if manifest.requested_permissions != required_permissions() {
        return Err(PurpleBootError::PermissionContractMismatch);
    }
    if manifest.transports.is_empty() {
        return Err(PurpleBootError::MissingPurpleTransport);
    }
    if manifest.recovery_settle_millis == 0 {
        return Err(PurpleBootError::InvalidRecoverySettle);
    }
    if manifest.route_source_evidence.is_empty()
        || manifest
            .route_source_evidence
            .iter()
            .any(|source| source.trim().is_empty())
    {
        return Err(PurpleBootError::MissingSourceEvidence);
    }

    validate_artifact_descriptor(&manifest.raw_ibss, BootArtifactKind::RawIbss)?;
    validate_artifact_descriptor(&manifest.diag_image, BootArtifactKind::DiagImg4)?;

    let mandatory_proofs = [
        "pwned_dfu_same_device",
        "raw_ibss_hash_verified",
        "custom_boot_acknowledged",
        "recovery_same_device",
        "diag_image_hash_verified",
        "fixed_boot_commands_acknowledged",
        "purple_mode_same_device",
    ];
    if mandatory_proofs
        .iter()
        .any(|proof| !manifest.proof_requirements.contains(*proof))
    {
        return Err(PurpleBootError::MissingMandatoryProof);
    }

    if policy_profile == "stable" {
        if manifest.maturity != Maturity::Stable {
            return Err(PurpleBootError::ImmatureStableRoute);
        }
        if !artifacts_are_pinned(manifest) {
            return Err(PurpleBootError::UnpinnedBootArtifacts);
        }
        match manifest.declared_route_licence.as_deref() {
            Some(licence) if !licence.trim().is_empty() => {}
            _ => return Err(PurpleBootError::MissingDeclaredRouteLicence),
        }
    }

    Ok(())
}

pub fn build_purple_boot_plan(
    manifest: &PurpleBootRouteManifest,
    request: &PurpleBootRequest,
) -> Result<PurpleBootPlan, PurpleBootError> {
    validate_route_manifest(manifest, &request.policy_profile)?;
    if request.route_id != manifest.route_id {
        return Err(PurpleBootError::RouteIdentityMismatch);
    }
    if request.session_id != request.pwn_proof.session_id {
        return Err(PurpleBootError::PwnProofSessionMismatch);
    }
    if !request.pwn_proof.verified {
        return Err(PurpleBootError::UnverifiedPwnProof);
    }
    if request.pwn_proof.expected_cpid != manifest.cpid
        || request.locked_identity.cpid != manifest.cpid
    {
        return Err(PurpleBootError::RouteCpidMismatch);
    }
    if request.locked_identity.product_type.as_deref() != Some(manifest.product_type.as_str()) {
        return Err(PurpleBootError::RouteProductMismatch);
    }
    if request.locked_identity.board_config.as_deref() != Some(manifest.board_config.as_str()) {
        return Err(PurpleBootError::RouteBoardMismatch);
    }
    if request.pwn_observation.mode != DeviceMode::PwnedDfu
        || request.pwn_observation.pwn_provider.as_deref() != Some("usbliter8")
    {
        return Err(PurpleBootError::InvalidPwnObservation);
    }
    let pwn_identity = match_reconnect(
        &request.locked_identity,
        &request.pwn_observation,
        &BTreeSet::from([DeviceMode::PwnedDfu]),
    );
    if !pwn_identity.matched {
        return Err(PurpleBootError::PwnIdentityMismatch(pwn_identity.blockers));
    }
    if !request.authorized_device_service || !request.explicit_operator_authorization {
        return Err(PurpleBootError::AuthorizationRequired);
    }

    let required = required_permissions();
    if request.granted_permissions != required {
        return Err(PurpleBootError::PermissionGrantMismatch);
    }
    if !artifacts_are_pinned(manifest) {
        return Err(PurpleBootError::UnpinnedBootArtifacts);
    }

    let raw_ibss = pin_artifact(&manifest.raw_ibss)?;
    let diag_image = pin_artifact(&manifest.diag_image)?;
    let mut steps = vec![
        PurpleBootStep::VerifyPwnedDfu,
        PurpleBootStep::VerifyRawIbss,
        PurpleBootStep::SendRawIbss,
        PurpleBootStep::SendCustomBoot,
    ];
    if let Some(seconds) = manifest.requires_power_button_hold_seconds {
        if seconds == 0 {
            return Err(PurpleBootError::InvalidPowerButtonHold);
        }
        steps.push(PurpleBootStep::HoldPowerButton { seconds });
    }
    steps.extend([
        PurpleBootStep::WaitForRecovery,
        PurpleBootStep::VerifyRecoveryIdentity,
        PurpleBootStep::WaitForRecoverySettle {
            milliseconds: manifest.recovery_settle_millis,
        },
        PurpleBootStep::VerifyDiagImage,
        PurpleBootStep::SendDiagImage,
        PurpleBootStep::SetUsbSerialBootArgs,
        PurpleBootStep::SaveEnvironment,
        PurpleBootStep::Go,
        PurpleBootStep::WaitForPurple,
        PurpleBootStep::VerifyPurpleIdentity,
    ]);

    Ok(PurpleBootPlan {
        session_id: request.session_id,
        route_id: manifest.route_id.clone(),
        product_type: manifest.product_type.clone(),
        board_config: manifest.board_config.clone(),
        cpid: manifest.cpid.clone(),
        pwn_provider: manifest.pwn_provider.clone(),
        artifacts: vec![raw_ibss, diag_image],
        steps,
        granted_permissions: required,
        required_proofs: manifest.proof_requirements.clone(),
    })
}

pub fn finalize_purple_boot(
    plan: &PurpleBootPlan,
    locked_identity: &LockedDeviceIdentity,
    evidence: &PurpleBootRunEvidence,
) -> PurpleBootFinalProof {
    let mut failures = Vec::new();

    if evidence.session_id != plan.session_id {
        failures.push("Purple evidence belongs to another session".to_owned());
    }
    if evidence.route_id != plan.route_id {
        failures.push("Purple evidence route mismatch".to_owned());
    }

    let observed_steps: Vec<PurpleBootStep> = evidence
        .step_receipts
        .iter()
        .map(|receipt| receipt.step.clone())
        .collect();
    if observed_steps != plan.steps {
        failures.push("Purple step sequence does not exactly match the fixed plan".to_owned());
    }
    if evidence
        .step_receipts
        .iter()
        .any(|receipt| !receipt.acknowledged)
    {
        failures.push("one or more Purple steps lack acknowledgment".to_owned());
    }

    let expected_kinds: BTreeSet<BootArtifactKind> =
        plan.artifacts.iter().map(|artifact| artifact.kind.clone()).collect();
    let observed_kinds: BTreeSet<BootArtifactKind> = evidence
        .artifact_receipts
        .iter()
        .map(|receipt| receipt.kind.clone())
        .collect();
    if expected_kinds != observed_kinds || evidence.artifact_receipts.len() != plan.artifacts.len() {
        failures.push("artifact receipt set does not exactly match the plan".to_owned());
    }
    for artifact in &plan.artifacts {
        match evidence
            .artifact_receipts
            .iter()
            .find(|receipt| receipt.kind == artifact.kind)
        {
            Some(receipt)
                if receipt.transfer_acknowledged
                    && receipt.observed_sha256 == artifact.sha256
                    && receipt.observed_size_bytes == artifact.size_bytes => {}
            Some(_) => failures.push(format!("artifact proof mismatch: {:?}", artifact.kind)),
            None => failures.push(format!("artifact proof missing: {:?}", artifact.kind)),
        }
    }

    let recovery_match = match_reconnect(
        locked_identity,
        &evidence.recovery_observation,
        &BTreeSet::from([DeviceMode::Recovery]),
    );
    if !recovery_match.matched {
        failures.push("recovery identity proof failed".to_owned());
        failures.extend(recovery_match.blockers);
    }

    let purple_match = match_reconnect(
        locked_identity,
        &evidence.purple_observation,
        &BTreeSet::from([DeviceMode::PurpleDiagnostic]),
    );
    if !purple_match.matched {
        failures.push("Purple identity proof failed".to_owned());
        failures.extend(purple_match.blockers);
    }

    PurpleBootFinalProof {
        session_id: plan.session_id,
        route_id: plan.route_id.clone(),
        verified: failures.is_empty(),
        final_mode: evidence.purple_observation.mode.clone(),
        failures,
    }
}

fn validate_artifact_descriptor(
    descriptor: &BootArtifactDescriptor,
    expected_kind: BootArtifactKind,
) -> Result<(), PurpleBootError> {
    if descriptor.kind != expected_kind {
        return Err(PurpleBootError::ArtifactKindMismatch);
    }
    if descriptor.redistribution_allowed {
        return Err(PurpleBootError::AppleAssetRedistributionForbidden);
    }
    if descriptor.source_description.trim().is_empty() {
        return Err(PurpleBootError::MissingArtifactSourceDescription);
    }
    match (descriptor.sha256.as_deref(), descriptor.size_bytes) {
        (None, None) => Ok(()),
        (Some(hash), Some(size)) if size > 0 => validate_sha256(hash),
        _ => Err(PurpleBootError::IncompleteArtifactPin),
    }
}

fn artifacts_are_pinned(manifest: &PurpleBootRouteManifest) -> bool {
    artifact_is_pinned(&manifest.raw_ibss) && artifact_is_pinned(&manifest.diag_image)
}

fn artifact_is_pinned(descriptor: &BootArtifactDescriptor) -> bool {
    descriptor
        .sha256
        .as_deref()
        .is_some_and(|hash| validate_sha256(hash).is_ok())
        && descriptor.size_bytes.is_some_and(|size| size > 0)
}

fn pin_artifact(
    descriptor: &BootArtifactDescriptor,
) -> Result<PinnedBootArtifact, PurpleBootError> {
    let sha256 = descriptor
        .sha256
        .clone()
        .ok_or(PurpleBootError::UnpinnedBootArtifacts)?;
    validate_sha256(&sha256)?;
    let size_bytes = descriptor
        .size_bytes
        .filter(|size| *size > 0)
        .ok_or(PurpleBootError::UnpinnedBootArtifacts)?;
    Ok(PinnedBootArtifact {
        kind: descriptor.kind.clone(),
        sha256,
        size_bytes,
    })
}

fn normalize_cpid(value: &str) -> Result<String, PurpleBootError> {
    let trimmed = value.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let parsed = u16::from_str_radix(raw, 16)
        .map_err(|_| PurpleBootError::InvalidCpid(value.to_owned()))?;
    Ok(format!("{parsed:04X}"))
}

fn validate_sha256(value: &str) -> Result<(), PurpleBootError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(PurpleBootError::InvalidSha256)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurpleBootError {
    #[error("unsupported Purple boot contract version: {0}")]
    UnsupportedVersion(String),
    #[error("Purple route identity is incomplete")]
    IncompleteRouteIdentity,
    #[error("unsupported pwn provider: {0}")]
    UnsupportedPwnProvider(String),
    #[error("invalid CPID: {0}")]
    InvalidCpid(String),
    #[error("route CPID must use canonical four-digit uppercase hexadecimal: {0}")]
    NonCanonicalCpid(String),
    #[error("route CPID is outside the current A12/A13 usbliter8 provider: {0}")]
    UnsupportedCpid(String),
    #[error("Purple route permissions do not match the fixed boot profile")]
    PermissionContractMismatch,
    #[error("Purple route has no output transport")]
    MissingPurpleTransport,
    #[error("recovery settle duration must be greater than zero")]
    InvalidRecoverySettle,
    #[error("Purple route is missing public source evidence")]
    MissingSourceEvidence,
    #[error("boot artifact kind does not match its route slot")]
    ArtifactKindMismatch,
    #[error("TGCHECKM8 must not redistribute Apple diagnostic boot assets")]
    AppleAssetRedistributionForbidden,
    #[error("boot artifact source description is required")]
    MissingArtifactSourceDescription,
    #[error("artifact hash and size must either both be present or both be absent")]
    IncompleteArtifactPin,
    #[error("SHA-256 must contain exactly 64 hexadecimal characters")]
    InvalidSha256,
    #[error("Purple route is missing mandatory proof requirements")]
    MissingMandatoryProof,
    #[error("stable policy requires a Stable Purple route")]
    ImmatureStableRoute,
    #[error("raw iBSS and Diags image must both be hash-pinned")]
    UnpinnedBootArtifacts,
    #[error("stable policy requires a declared route licence")]
    MissingDeclaredRouteLicence,
    #[error("request route does not match the route manifest")]
    RouteIdentityMismatch,
    #[error("pwned-DFU proof belongs to another session")]
    PwnProofSessionMismatch,
    #[error("pwned-DFU proof is not verified")]
    UnverifiedPwnProof,
    #[error("route CPID does not match the pwn proof or locked device")]
    RouteCpidMismatch,
    #[error("route product type does not match the locked device")]
    RouteProductMismatch,
    #[error("route board configuration does not match the locked device")]
    RouteBoardMismatch,
    #[error("host pwned-DFU observation is invalid")]
    InvalidPwnObservation,
    #[error("host pwned-DFU identity mismatch: {0:?}")]
    PwnIdentityMismatch(Vec<String>),
    #[error("authorized device service and explicit operator authorization are required")]
    AuthorizationRequired,
    #[error("Purple stage permissions must exactly match the fixed grant")]
    PermissionGrantMismatch,
    #[error("power-button hold duration must be greater than zero")]
    InvalidPowerButtonHold,
}
