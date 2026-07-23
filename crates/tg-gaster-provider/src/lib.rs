//! Hash-pinned, fixed-command Gaster provider for documented A8-A11 routes.
//!
//! The provider exposes only `pwn` and `reset`. It never accepts a free-form
//! command line, does not select ramdisk assets, and cannot declare success
//! without a same-device host reconnect carrying `PWND:[checkm8]`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_apple_observe::{match_reconnect, LockedDeviceIdentity, ObservedAppleDevice};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_process::{run_supervised, ProcessPolicy, ProcessSpec, SupervisedOutcome};
use uuid::Uuid;

pub const GASTER_PROVIDER_VERSION: &str = "tgcheckm8.gaster-provider.v1";
pub const GASTER_SOURCE_REPOSITORY: &str = "https://github.com/0x7ff/gaster";
pub const GASTER_SOURCE_COMMIT: &str = "7fffffff38a1bed1cdc1c5bae0df70f14395129b";
pub const GASTER_LICENCE: &str = "Apache-2.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasterProviderManifest {
    pub schema_version: String,
    pub engine_id: String,
    pub source_repository: String,
    pub source_commit: String,
    pub licence: String,
    pub executable_sha256: Option<String>,
    pub supported_cpids: BTreeSet<String>,
    pub hardware_verified_cpids: BTreeSet<String>,
    pub maturity: Maturity,
    pub requested_permissions: BTreeSet<Permission>,
    pub proof_requirements: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasterAction {
    Pwn,
    Reset,
}

impl GasterAction {
    fn argument(&self) -> &'static str {
        match self {
            Self::Pwn => "pwn",
            Self::Reset => "reset",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasterPlanRequest {
    pub session_id: Uuid,
    pub locked_identity: LockedDeviceIdentity,
    pub starting_observation: ObservedAppleDevice,
    pub policy_profile: String,
    pub authorized_device_service: bool,
    pub explicit_operator_authorization: bool,
    pub granted_permissions: BTreeSet<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasterPwnPlan {
    pub session_id: Uuid,
    pub engine_id: String,
    pub normalized_cpid: String,
    pub executable_sha256: String,
    pub actions: Vec<GasterAction>,
    pub requested_permissions: BTreeSet<Permission>,
    pub required_proofs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasterExecutionRequest<'a> {
    pub plan: &'a GasterPwnPlan,
    pub action: GasterAction,
    pub executable: PathBuf,
    pub working_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasterRunReceipt {
    pub session_id: Uuid,
    pub engine_id: String,
    pub action: GasterAction,
    pub executable_sha256: String,
    pub status_code: Option<i32>,
    pub process_success: bool,
    pub cleanup_verified: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub elapsed_millis: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasterFinalProof {
    pub session_id: Uuid,
    pub engine_id: String,
    pub verified: bool,
    pub normalized_cpid: String,
    pub pwn_provider: Option<String>,
    pub observed_mode: DeviceMode,
    pub blockers: Vec<String>,
}

pub fn required_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::UsbRead,
        Permission::UsbWrite,
        Permission::ProcessSpawn,
    ])
}

pub fn validate_manifest(
    manifest: &GasterProviderManifest,
    policy_profile: &str,
) -> Result<(), GasterError> {
    if manifest.schema_version != GASTER_PROVIDER_VERSION {
        return Err(GasterError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.engine_id.trim().is_empty()
        || manifest.source_repository != GASTER_SOURCE_REPOSITORY
        || manifest.source_commit != GASTER_SOURCE_COMMIT
        || manifest.licence != GASTER_LICENCE
    {
        return Err(GasterError::InvalidProvenance);
    }
    if manifest.requested_permissions != required_permissions() {
        return Err(GasterError::PermissionContractMismatch);
    }
    if manifest.supported_cpids.is_empty() {
        return Err(GasterError::MissingCpidCoverage);
    }
    for cpid in manifest
        .supported_cpids
        .iter()
        .chain(manifest.hardware_verified_cpids.iter())
    {
        normalize_cpid(cpid)?;
    }
    if !manifest
        .hardware_verified_cpids
        .is_subset(&manifest.supported_cpids)
    {
        return Err(GasterError::VerifiedCpidOutsideCoverage);
    }
    let mandatory = [
        "executable_hash_verified",
        "starting_dfu_identity_locked",
        "gaster_pwn_process_verified",
        "gaster_reset_process_verified",
        "host_pwnd_reconnect_verified",
        "same_device_identity",
    ];
    if mandatory
        .iter()
        .any(|item| !manifest.proof_requirements.contains(*item))
    {
        return Err(GasterError::MissingMandatoryProof);
    }
    if let Some(hash) = manifest.executable_sha256.as_deref() {
        validate_sha256(hash)?;
    }
    if policy_profile == "stable" {
        if manifest.maturity != Maturity::Stable {
            return Err(GasterError::ImmatureStableProvider);
        }
        if manifest.executable_sha256.is_none() {
            return Err(GasterError::UnpinnedExecutable);
        }
        if manifest.hardware_verified_cpids != manifest.supported_cpids {
            return Err(GasterError::StableCoverageNotHardwareVerified);
        }
    }
    Ok(())
}

pub fn build_pwn_plan(
    manifest: &GasterProviderManifest,
    request: &GasterPlanRequest,
) -> Result<GasterPwnPlan, GasterError> {
    validate_manifest(manifest, &request.policy_profile)?;
    if !request.authorized_device_service || !request.explicit_operator_authorization {
        return Err(GasterError::AuthorizationRequired);
    }
    if request.granted_permissions != required_permissions() {
        return Err(GasterError::PermissionGrantMismatch);
    }
    let cpid = normalize_cpid(&request.locked_identity.cpid)?;
    if !manifest.supported_cpids.contains(&cpid) {
        return Err(GasterError::UnsupportedCpid(cpid));
    }
    if request.policy_profile == "stable" && !manifest.hardware_verified_cpids.contains(&cpid) {
        return Err(GasterError::CpidNotHardwareVerified(cpid));
    }
    let starting = match_reconnect(
        &request.locked_identity,
        &request.starting_observation,
        &BTreeSet::from([DeviceMode::Dfu]),
    );
    if !starting.matched {
        return Err(GasterError::InvalidStartingDfu(starting.blockers));
    }
    if request.starting_observation.pwn_provider.is_some() {
        return Err(GasterError::DeviceAlreadyPwned);
    }
    let executable_sha256 = manifest
        .executable_sha256
        .clone()
        .ok_or(GasterError::UnpinnedExecutable)?;

    Ok(GasterPwnPlan {
        session_id: request.session_id,
        engine_id: manifest.engine_id.clone(),
        normalized_cpid: cpid,
        executable_sha256,
        actions: vec![GasterAction::Pwn, GasterAction::Reset],
        requested_permissions: required_permissions(),
        required_proofs: manifest.proof_requirements.clone(),
    })
}

pub fn execute_action(
    policy: &ProcessPolicy,
    request: &GasterExecutionRequest<'_>,
) -> Result<GasterRunReceipt, GasterError> {
    if !request.plan.actions.contains(&request.action) {
        return Err(GasterError::ActionOutsidePlan);
    }
    let observed_hash = sha256_file(&request.executable)?;
    if observed_hash != request.plan.executable_sha256 {
        return Err(GasterError::ExecutableHashMismatch {
            expected: request.plan.executable_sha256.clone(),
            observed: observed_hash,
        });
    }
    let outcome = run_supervised(
        policy,
        &ProcessSpec {
            executable: request.executable.clone(),
            args: vec![request.action.argument().to_owned()],
            environment: BTreeMap::new(),
            working_directory: request.working_directory.clone(),
        },
    )?;
    Ok(receipt(request.plan, request.action.clone(), outcome))
}

pub fn verify_pwnd_reconnect(
    plan: &GasterPwnPlan,
    locked_identity: &LockedDeviceIdentity,
    pwn_receipt: &GasterRunReceipt,
    reset_receipt: &GasterRunReceipt,
    observed: &ObservedAppleDevice,
) -> GasterFinalProof {
    let mut blockers = Vec::new();
    if pwn_receipt.session_id != plan.session_id
        || reset_receipt.session_id != plan.session_id
        || pwn_receipt.engine_id != plan.engine_id
        || reset_receipt.engine_id != plan.engine_id
    {
        blockers.push("Gaster run receipt scope mismatch".to_owned());
    }
    if pwn_receipt.action != GasterAction::Pwn
        || reset_receipt.action != GasterAction::Reset
    {
        blockers.push("Gaster actions were not executed in the required sequence".to_owned());
    }
    for receipt in [pwn_receipt, reset_receipt] {
        if !receipt.process_success || !receipt.cleanup_verified {
            blockers.push(format!("{:?} process or cleanup was not verified", receipt.action));
        }
        if receipt.executable_sha256 != plan.executable_sha256 {
            blockers.push("Gaster executable hash changed between plan and execution".to_owned());
        }
    }
    let reconnect = match_reconnect(
        locked_identity,
        observed,
        &BTreeSet::from([DeviceMode::PwnedDfu]),
    );
    blockers.extend(reconnect.blockers);
    if observed.pwn_provider.as_deref() != Some("checkm8") {
        blockers.push("host reconnect did not report PWND:[checkm8]".to_owned());
    }

    GasterFinalProof {
        session_id: plan.session_id,
        engine_id: plan.engine_id.clone(),
        verified: blockers.is_empty(),
        normalized_cpid: plan.normalized_cpid.clone(),
        pwn_provider: observed.pwn_provider.clone(),
        observed_mode: observed.mode.clone(),
        blockers,
    }
}

fn receipt(
    plan: &GasterPwnPlan,
    action: GasterAction,
    outcome: SupervisedOutcome,
) -> GasterRunReceipt {
    GasterRunReceipt {
        session_id: plan.session_id,
        engine_id: plan.engine_id.clone(),
        action,
        executable_sha256: plan.executable_sha256.clone(),
        status_code: outcome.status_code,
        process_success: outcome.success,
        cleanup_verified: outcome.cleanup.verified(),
        stdout_sha256: sha256_bytes(&outcome.stdout.bytes),
        stderr_sha256: sha256_bytes(&outcome.stderr.bytes),
        stdout_bytes: outcome.stdout.total_bytes,
        stderr_bytes: outcome.stderr.total_bytes,
        stdout_truncated: outcome.stdout.truncated,
        stderr_truncated: outcome.stderr.truncated,
        elapsed_millis: outcome.elapsed_millis,
    }
}

pub fn sha256_file(path: &Path) -> Result<String, GasterError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(to_hex(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

fn normalize_cpid(value: &str) -> Result<String, GasterError> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_ascii_uppercase();
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GasterError::InvalidCpid(value.to_owned()));
    }
    Ok(digits)
}

fn validate_sha256(value: &str) -> Result<(), GasterError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GasterError::InvalidSha256(value.to_owned()));
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, thiserror::Error)]
pub enum GasterError {
    #[error("unsupported Gaster provider version: {0}")]
    UnsupportedVersion(String),
    #[error("Gaster provider provenance does not match the approved source pin")]
    InvalidProvenance,
    #[error("Gaster permission contract mismatch")]
    PermissionContractMismatch,
    #[error("Gaster provider has no CPID coverage")]
    MissingCpidCoverage,
    #[error("hardware-verified CPID is outside declared coverage")]
    VerifiedCpidOutsideCoverage,
    #[error("Gaster provider is not mature enough for Stable")]
    ImmatureStableProvider,
    #[error("Stable Gaster coverage is not fully hardware verified")]
    StableCoverageNotHardwareVerified,
    #[error("Gaster executable is not hash-pinned")]
    UnpinnedExecutable,
    #[error("missing mandatory Gaster proof requirement")]
    MissingMandatoryProof,
    #[error("device-service and explicit operator authorization are required")]
    AuthorizationRequired,
    #[error("granted permissions do not exactly match the Gaster contract")]
    PermissionGrantMismatch,
    #[error("unsupported Gaster CPID: {0}")]
    UnsupportedCpid(String),
    #[error("CPID is not hardware verified for Stable: {0}")]
    CpidNotHardwareVerified(String),
    #[error("invalid starting DFU evidence: {0:?}")]
    InvalidStartingDfu(Vec<String>),
    #[error("device already reports a pwn provider before this run")]
    DeviceAlreadyPwned,
    #[error("requested action is outside the fixed Gaster plan")]
    ActionOutsidePlan,
    #[error("invalid CPID: {0}")]
    InvalidCpid(String),
    #[error("invalid SHA-256: {0}")]
    InvalidSha256(String),
    #[error("Gaster executable hash mismatch: expected {expected}, observed {observed}")]
    ExecutableHashMismatch { expected: String, observed: String },
    #[error(transparent)]
    Process(#[from] tg_process::ProcessError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
