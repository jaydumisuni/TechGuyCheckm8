//! Device/build-exact ramdisk provider packs derived from documented recipes.
//!
//! The pack format stores hashes and typed boot steps only. It does not bundle
//! Apple images, accept free-form iBoot commands, or execute a device operation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_apple_route_reference::{AppleRouteReferenceManifest, PwnProvider, RouteEnvironment};
use tg_contracts::Maturity;

pub const RAMDISK_PACK_VERSION: &str = "tgcheckm8.ramdisk-pack.v1";
pub const SSHRD_SOURCE_REPOSITORY: &str = "https://github.com/verygenericname/SSHRD_Script";
pub const SSHRD_SOURCE_COMMIT: &str = "d99ec4a19172b87d80fd9dea25eabf39291425a0";
pub const SSHRD_LICENCE: &str = "BSD-3-Clause";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetRole {
    GasterExecutable,
    IRecoveryExecutable,
    IBss,
    IBec,
    Logo,
    Ramdisk,
    DeviceTree,
    TrustCache,
    KernelCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRecord {
    pub role: AssetRole,
    pub relative_path: String,
    pub sha256: String,
    pub byte_len: u64,
    pub redistribution_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReference {
    pub source_id: String,
    pub repository: String,
    pub commit: String,
    pub licence: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedRecoveryCommand {
    Go,
    SetPictureOne,
    Ramdisk,
    DeviceTree,
    Firmware,
    BootX,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootCheckpoint {
    PwnedDfuVerified,
    PatchedIbootReady,
    RamdiskReady,
    PurpleDiagnosticReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootStep {
    RequireCheckpoint(BootCheckpoint),
    SendAsset(AssetRole),
    RecoveryCommand(FixedRecoveryCommand),
    WaitMillis(u64),
    ProveCheckpoint(BootCheckpoint),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RamdiskProviderPack {
    pub schema_version: String,
    pub pack_id: String,
    pub route_reference_profile_id: String,
    pub product_type: String,
    pub board_config: String,
    pub cpid: String,
    pub firmware_build: String,
    pub environment: RouteEnvironment,
    pub pwn_provider: PwnProvider,
    pub source_references: Vec<SourceReference>,
    pub assets: BTreeMap<AssetRole, AssetRecord>,
    pub boot_steps: Vec<BootStep>,
    pub maturity: Maturity,
    pub hardware_transcript_sha256: Option<String>,
    pub recovery_proof_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackBindingDecision {
    pub ready_for_hardware_verification: bool,
    pub execution_authorized: bool,
    pub blockers: Vec<String>,
    pub required_assets: BTreeSet<AssetRole>,
    pub asset_hashes: BTreeMap<AssetRole, String>,
}

pub fn sshrd_boot_steps(
    cpid: &str,
    include_logo: bool,
    include_trustcache: bool,
    final_environment: RouteEnvironment,
) -> Result<Vec<BootStep>, RamdiskPackError> {
    let cpid = normalize_cpid(cpid)?;
    let mut steps = vec![
        BootStep::RequireCheckpoint(BootCheckpoint::PwnedDfuVerified),
        BootStep::SendAsset(AssetRole::IBss),
        BootStep::WaitMillis(2_000),
        BootStep::SendAsset(AssetRole::IBec),
    ];
    if matches!(cpid.as_str(), "8010" | "8011" | "8012" | "8015") {
        steps.push(BootStep::RecoveryCommand(FixedRecoveryCommand::Go));
    }
    steps.extend([
        BootStep::WaitMillis(2_000),
        BootStep::ProveCheckpoint(BootCheckpoint::PatchedIbootReady),
    ]);
    if include_logo {
        steps.extend([
            BootStep::SendAsset(AssetRole::Logo),
            BootStep::RecoveryCommand(FixedRecoveryCommand::SetPictureOne),
        ]);
    }
    steps.extend([
        BootStep::SendAsset(AssetRole::Ramdisk),
        BootStep::RecoveryCommand(FixedRecoveryCommand::Ramdisk),
        BootStep::SendAsset(AssetRole::DeviceTree),
        BootStep::RecoveryCommand(FixedRecoveryCommand::DeviceTree),
    ]);
    if include_trustcache {
        steps.extend([
            BootStep::SendAsset(AssetRole::TrustCache),
            BootStep::RecoveryCommand(FixedRecoveryCommand::Firmware),
        ]);
    }
    steps.extend([
        BootStep::SendAsset(AssetRole::KernelCache),
        BootStep::RecoveryCommand(FixedRecoveryCommand::BootX),
        BootStep::ProveCheckpoint(match final_environment {
            RouteEnvironment::Ramdisk | RouteEnvironment::Jailbreak => BootCheckpoint::RamdiskReady,
            RouteEnvironment::PurpleDiags => BootCheckpoint::PurpleDiagnosticReady,
        }),
    ]);
    Ok(steps)
}

pub fn validate_pack(pack: &RamdiskProviderPack) -> Result<(), RamdiskPackError> {
    if pack.schema_version != RAMDISK_PACK_VERSION {
        return Err(RamdiskPackError::UnsupportedVersion(
            pack.schema_version.clone(),
        ));
    }
    if pack.pack_id.trim().is_empty()
        || pack.route_reference_profile_id.trim().is_empty()
        || pack.product_type.trim().is_empty()
        || pack.board_config.trim().is_empty()
        || pack.firmware_build.trim().is_empty()
    {
        return Err(RamdiskPackError::IncompleteRouteIdentity);
    }
    let cpid = normalize_cpid(&pack.cpid)?;
    if pack.pwn_provider != PwnProvider::Gaster {
        return Err(RamdiskPackError::UnsupportedPackProvider);
    }
    if pack.source_references.is_empty() {
        return Err(RamdiskPackError::MissingSourceReferences);
    }
    validate_source_references(&pack.source_references)?;
    if pack.boot_steps.is_empty() {
        return Err(RamdiskPackError::MissingBootPlan);
    }
    let expected = sshrd_boot_steps(
        &cpid,
        pack.assets.contains_key(&AssetRole::Logo),
        pack.assets.contains_key(&AssetRole::TrustCache),
        pack.environment.clone(),
    )?;
    if pack.boot_steps != expected {
        return Err(RamdiskPackError::BootPlanDiffersFromKnownRecipe);
    }
    let required = required_assets(&pack.boot_steps);
    for role in &required {
        let asset = pack
            .assets
            .get(role)
            .ok_or_else(|| RamdiskPackError::MissingRequiredAsset(role.clone()))?;
        validate_asset(asset)?;
        if asset.role != *role {
            return Err(RamdiskPackError::AssetRoleMismatch(role.clone()));
        }
    }
    for (role, asset) in &pack.assets {
        if asset.role != *role {
            return Err(RamdiskPackError::AssetRoleMismatch(role.clone()));
        }
        validate_asset(asset)?;
    }
    if pack.maturity == Maturity::Stable {
        if pack.hardware_transcript_sha256.is_none() || pack.recovery_proof_sha256.is_none() {
            return Err(RamdiskPackError::StableEvidenceMissing);
        }
        validate_sha256(
            pack.hardware_transcript_sha256
                .as_deref()
                .unwrap_or_default(),
        )?;
        validate_sha256(pack.recovery_proof_sha256.as_deref().unwrap_or_default())?;
    }
    Ok(())
}

pub fn bind_to_route_reference(
    pack: &RamdiskProviderPack,
    route: &AppleRouteReferenceManifest,
) -> PackBindingDecision {
    let mut blockers = Vec::new();
    if let Err(error) = validate_pack(pack) {
        blockers.push(error.to_string());
    }
    if route.reference_profile_id != pack.route_reference_profile_id {
        blockers.push("route-reference profile mismatch".to_owned());
    }
    if !route.product_types.contains(&pack.product_type)
        || !route.board_configs.contains(&pack.board_config)
        || !route.firmware_builds.contains(&pack.firmware_build)
    {
        blockers.push("pack device or firmware is outside the route reference".to_owned());
    }
    if route.pwn_provider != pack.pwn_provider {
        blockers.push("pack pwn provider differs from the route reference".to_owned());
    }
    if !route.environments.contains(&pack.environment) {
        blockers.push("pack environment is outside the route reference".to_owned());
    }

    let required_assets = required_assets(&pack.boot_steps);
    let asset_hashes = pack
        .assets
        .iter()
        .map(|(role, asset)| (role.clone(), asset.sha256.clone()))
        .collect();
    PackBindingDecision {
        ready_for_hardware_verification: blockers.is_empty(),
        execution_authorized: false,
        blockers,
        required_assets,
        asset_hashes,
    }
}

pub fn classify_and_hash_asset(
    relative_path: &str,
    bytes: &[u8],
) -> Result<AssetRecord, RamdiskPackError> {
    validate_relative_path(relative_path)?;
    if bytes.is_empty() {
        return Err(RamdiskPackError::EmptyAsset(relative_path.to_owned()));
    }
    let file_name = Path::new(relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| RamdiskPackError::UnknownAsset(relative_path.to_owned()))?;
    let role = match file_name.to_ascii_lowercase().as_str() {
        "gaster" | "gaster.exe" => AssetRole::GasterExecutable,
        "irecovery" | "irecovery.exe" => AssetRole::IRecoveryExecutable,
        "ibss.img4" => AssetRole::IBss,
        "ibec.img4" => AssetRole::IBec,
        "logo.img4" => AssetRole::Logo,
        "ramdisk.img4" => AssetRole::Ramdisk,
        "devicetree.img4" => AssetRole::DeviceTree,
        "trustcache.img4" => AssetRole::TrustCache,
        "kernelcache.img4" => AssetRole::KernelCache,
        _ => return Err(RamdiskPackError::UnknownAsset(relative_path.to_owned())),
    };
    Ok(AssetRecord {
        role,
        relative_path: relative_path.to_owned(),
        sha256: to_hex(&Sha256::digest(bytes)),
        byte_len: bytes.len() as u64,
        redistribution_allowed: false,
    })
}

pub fn required_assets(steps: &[BootStep]) -> BTreeSet<AssetRole> {
    steps
        .iter()
        .filter_map(|step| match step {
            BootStep::SendAsset(role) => Some(role.clone()),
            _ => None,
        })
        .collect()
}

fn validate_source_references(references: &[SourceReference]) -> Result<(), RamdiskPackError> {
    let sshrd = references.iter().any(|source| {
        source.repository == SSHRD_SOURCE_REPOSITORY
            && source.commit == SSHRD_SOURCE_COMMIT
            && source.licence == SSHRD_LICENCE
    });
    let gaster = references.iter().any(|source| {
        source.repository == "https://github.com/0x7ff/gaster"
            && source.commit == "7fffffff38a1bed1cdc1c5bae0df70f14395129b"
            && source.licence == "Apache-2.0"
    });
    if !sshrd || !gaster {
        return Err(RamdiskPackError::ApprovedSourcePinMissing);
    }
    for source in references {
        if source.source_id.trim().is_empty()
            || source.role.trim().is_empty()
            || !source.repository.starts_with("https://github.com/")
            || !is_commit(&source.commit)
            || source.licence.trim().is_empty()
        {
            return Err(RamdiskPackError::InvalidSourceReference(
                source.source_id.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_asset(asset: &AssetRecord) -> Result<(), RamdiskPackError> {
    validate_relative_path(&asset.relative_path)?;
    validate_sha256(&asset.sha256)?;
    if asset.byte_len == 0 {
        return Err(RamdiskPackError::EmptyAsset(asset.relative_path.clone()));
    }
    if asset.redistribution_allowed {
        return Err(RamdiskPackError::UnexpectedRedistributionPermission(
            asset.relative_path.clone(),
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), RamdiskPackError> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(RamdiskPackError::UnsafeRelativePath(value.to_owned()));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(RamdiskPackError::UnsafeRelativePath(value.to_owned()));
    }
    Ok(())
}

fn normalize_cpid(value: &str) -> Result<String, RamdiskPackError> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_ascii_uppercase();
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RamdiskPackError::InvalidCpid(value.to_owned()));
    }
    Ok(digits)
}

fn validate_sha256(value: &str) -> Result<(), RamdiskPackError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RamdiskPackError::InvalidSha256(value.to_owned()));
    }
    Ok(())
}

fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RamdiskPackError {
    #[error("unsupported ramdisk pack version: {0}")]
    UnsupportedVersion(String),
    #[error("ramdisk pack route identity is incomplete")]
    IncompleteRouteIdentity,
    #[error("invalid CPID: {0}")]
    InvalidCpid(String),
    #[error("only the documented Gaster provider is accepted in this pack version")]
    UnsupportedPackProvider,
    #[error("ramdisk pack has no source references")]
    MissingSourceReferences,
    #[error("approved Gaster or SSHRD source pin is missing")]
    ApprovedSourcePinMissing,
    #[error("invalid source reference: {0}")]
    InvalidSourceReference(String),
    #[error("ramdisk pack has no boot plan")]
    MissingBootPlan,
    #[error("boot plan differs from the fixed documented SSHRD recipe")]
    BootPlanDiffersFromKnownRecipe,
    #[error("missing required asset: {0:?}")]
    MissingRequiredAsset(AssetRole),
    #[error("asset map key and embedded role differ: {0:?}")]
    AssetRoleMismatch(AssetRole),
    #[error("unknown package asset: {0}")]
    UnknownAsset(String),
    #[error("asset is empty: {0}")]
    EmptyAsset(String),
    #[error("unsafe relative path: {0}")]
    UnsafeRelativePath(String),
    #[error("invalid SHA-256: {0}")]
    InvalidSha256(String),
    #[error("provider pack unexpectedly permits redistribution: {0}")]
    UnexpectedRedistributionPermission(String),
    #[error("Stable pack is missing hardware transcript or recovery proof")]
    StableEvidenceMissing,
}
