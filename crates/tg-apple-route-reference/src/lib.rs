//! Known-good Apple route references and X-Ray evidence binding.
//!
//! This crate does not execute exploits, boot assets, ramdisks, Purple images,
//! jailbreaks, restores, or device writes. It determines whether a documented
//! route has enough pinned evidence to enter hardware verification.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tg_contracts::Maturity;

pub const APPLE_ROUTE_REFERENCE_VERSION: &str = "tgcheckm8.apple-route-reference.v1";
pub const XRAY_APPLE_CERTIFICATE_VERSION: &str = "ttg.xray.apple-route-certificate.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppleGeneration {
    A5A5x,
    A6A7,
    A8A11,
    A12A13,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PwnProvider {
    ArduinoMax3421e,
    Ipwndfu,
    Gaster,
    Usbliter8Rp2350,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceClassification {
    DocumentedKnownGood,
    WorkingPackage,
    HardwareVerified,
    Research,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteEnvironment {
    Ramdisk,
    PurpleDiags,
    Jailbreak,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedTransition {
    AppleDfu,
    PwnedDfu,
    PatchedIbootOrRecovery,
    RamdiskBooting,
    RamdiskReady,
    PurpleDiagnostic,
    JailbreakRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PwnSourcePin {
    pub repository: String,
    pub commit: String,
    pub licence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCatalog {
    pub url: String,
    pub role: String,
    pub artifacts_bundled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAssetPolicy {
    pub local_only: bool,
    pub sha256_required: bool,
    pub device_exact: bool,
    pub redistribution_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleRouteReferenceManifest {
    pub schema_version: String,
    pub route_id: String,
    pub reference_profile_id: String,
    pub classification: ReferenceClassification,
    pub generation: AppleGeneration,
    pub pwn_provider: PwnProvider,
    pub product_types: BTreeSet<String>,
    pub board_configs: BTreeSet<String>,
    pub firmware_builds: BTreeSet<String>,
    pub environments: BTreeSet<RouteEnvironment>,
    pub pwn_source: PwnSourcePin,
    pub reference_catalogs: Vec<ReferenceCatalog>,
    pub asset_policy: RouteAssetPolicy,
    pub expected_transitions: Vec<ExpectedTransition>,
    pub required_asset_roles: BTreeSet<String>,
    pub maturity: Maturity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAssetPin {
    pub role: String,
    pub sha256: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XRayAppleRouteCertificate {
    pub schema_version: String,
    pub scan_id: String,
    pub certification_verdict: String,
    pub profile_status: String,
    pub profile_id: String,
    pub device_identity_hash: String,
    pub product_type: String,
    pub board_config: String,
    pub cpid: String,
    pub firmware_build: String,
    pub bundle_manifest_sha256: String,
    pub signature_verified: bool,
    pub write_allowed: bool,
    pub observed_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug)]
pub struct RouteVerificationRequest<'a> {
    pub manifest: &'a AppleRouteReferenceManifest,
    pub certificate: &'a XRayAppleRouteCertificate,
    pub local_assets: &'a [LocalAssetPin],
    pub current_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteVerificationDecision {
    pub ready_for_hardware_verification: bool,
    pub execution_authorized: bool,
    pub blockers: Vec<String>,
    pub asset_hashes: BTreeMap<String, String>,
    pub required_proofs: BTreeSet<String>,
}

pub fn validate_manifest(
    manifest: &AppleRouteReferenceManifest,
) -> Result<(), RouteReferenceError> {
    if manifest.schema_version != APPLE_ROUTE_REFERENCE_VERSION {
        return Err(RouteReferenceError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.route_id.trim().is_empty() || manifest.reference_profile_id.trim().is_empty() {
        return Err(RouteReferenceError::IncompleteRouteIdentity);
    }
    if manifest.product_types.is_empty()
        || manifest.board_configs.is_empty()
        || manifest.firmware_builds.is_empty()
        || manifest.environments.is_empty()
        || manifest.required_asset_roles.is_empty()
    {
        return Err(RouteReferenceError::MissingExactCoverage);
    }
    if !manifest
        .pwn_source
        .repository
        .starts_with("https://github.com/")
        || !is_commit(&manifest.pwn_source.commit)
        || manifest.pwn_source.licence.trim().is_empty()
    {
        return Err(RouteReferenceError::InvalidPwnProvenance);
    }
    if manifest.reference_catalogs.is_empty()
        || manifest.reference_catalogs.iter().any(|catalog| {
            !catalog.url.starts_with("https://")
                || catalog.role.trim().is_empty()
                || catalog.artifacts_bundled
        })
    {
        return Err(RouteReferenceError::InvalidReferenceCatalog);
    }
    if !manifest.asset_policy.local_only
        || !manifest.asset_policy.sha256_required
        || !manifest.asset_policy.device_exact
        || manifest.asset_policy.redistribution_allowed
    {
        return Err(RouteReferenceError::UnsafeAssetPolicy);
    }
    if manifest.expected_transitions.first() != Some(&ExpectedTransition::AppleDfu)
        || !manifest
            .expected_transitions
            .contains(&ExpectedTransition::PwnedDfu)
    {
        return Err(RouteReferenceError::InvalidTransitionPlan);
    }
    match (&manifest.generation, &manifest.pwn_provider) {
        (AppleGeneration::A5A5x, PwnProvider::ArduinoMax3421e)
        | (AppleGeneration::A6A7, PwnProvider::Ipwndfu)
        | (AppleGeneration::A8A11, PwnProvider::Gaster)
        | (AppleGeneration::A12A13, PwnProvider::Usbliter8Rp2350) => {}
        _ => return Err(RouteReferenceError::GenerationProviderMismatch),
    }
    if manifest.classification == ReferenceClassification::DocumentedKnownGood
        && matches!(manifest.maturity, Maturity::Discovered | Maturity::Imported)
    {
        return Err(RouteReferenceError::InsufficientReferenceMaturity);
    }
    Ok(())
}

pub fn evaluate_hardware_verification(
    request: RouteVerificationRequest<'_>,
) -> RouteVerificationDecision {
    let mut blockers = Vec::new();
    if let Err(error) = validate_manifest(request.manifest) {
        blockers.push(error.to_string());
    }

    let certificate = request.certificate;
    if certificate.schema_version != XRAY_APPLE_CERTIFICATE_VERSION {
        blockers.push("unsupported X-Ray Apple certificate version".to_owned());
    }
    if certificate.certification_verdict != "CERTIFIED" {
        blockers.push("X-Ray device identity is not certified".to_owned());
    }
    if !matches!(
        certificate.profile_status.as_str(),
        "MATCHED" | "CANDIDATE_PROFILE"
    ) {
        blockers.push("X-Ray route profile is not matched or candidate-certified".to_owned());
    }
    if certificate.profile_id != request.manifest.reference_profile_id {
        blockers.push("X-Ray route reference profile mismatch".to_owned());
    }
    if certificate.write_allowed {
        blockers.push("X-Ray certificate attempted to grant write authority".to_owned());
    }
    if !certificate.signature_verified || !is_sha256(&certificate.bundle_manifest_sha256) {
        blockers.push("X-Ray evidence bundle signature or manifest hash is invalid".to_owned());
    }
    if certificate.device_identity_hash.trim().is_empty()
        || certificate.product_type.trim().is_empty()
        || certificate.board_config.trim().is_empty()
        || certificate.cpid.trim().is_empty()
        || certificate.firmware_build.trim().is_empty()
    {
        blockers.push("X-Ray certificate identity or firmware build is incomplete".to_owned());
    }
    if !request
        .manifest
        .product_types
        .contains(&certificate.product_type)
        || !request
            .manifest
            .board_configs
            .contains(&certificate.board_config)
        || !request
            .manifest
            .firmware_builds
            .contains(&certificate.firmware_build)
    {
        blockers.push("X-Ray device or firmware is outside the exact route manifest".to_owned());
    }
    if request.current_unix < certificate.observed_at_unix
        || request.current_unix > certificate.expires_at_unix
    {
        blockers.push("X-Ray certificate is not currently valid".to_owned());
    }

    let mut asset_hashes = BTreeMap::new();
    for asset in request.local_assets {
        if asset.role.trim().is_empty() || !is_sha256(&asset.sha256) || asset.byte_len == 0 {
            blockers.push(format!("invalid local asset pin: {}", asset.role));
            continue;
        }
        if asset_hashes
            .insert(asset.role.clone(), asset.sha256.clone())
            .is_some()
        {
            blockers.push(format!("duplicate local asset role: {}", asset.role));
        }
    }
    for role in &request.manifest.required_asset_roles {
        if !asset_hashes.contains_key(role) {
            blockers.push(format!("missing required local asset: {role}"));
        }
    }

    RouteVerificationDecision {
        ready_for_hardware_verification: blockers.is_empty(),
        execution_authorized: false,
        blockers,
        asset_hashes,
        required_proofs: BTreeSet::from([
            "xray_identity_certified".to_owned(),
            "reference_source_pinned".to_owned(),
            "local_assets_hash_pinned".to_owned(),
            "device_exact_route_manifest".to_owned(),
            "firmware_build_exact_match".to_owned(),
            "known_good_sequence_reproduced".to_owned(),
            "hardware_transcript_required".to_owned(),
        ]),
    }
}

fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteReferenceError {
    #[error("unsupported Apple route reference version: {0}")]
    UnsupportedVersion(String),
    #[error("Apple route identity is incomplete")]
    IncompleteRouteIdentity,
    #[error("device-exact route coverage is missing")]
    MissingExactCoverage,
    #[error("pwn-provider provenance is invalid")]
    InvalidPwnProvenance,
    #[error("reference catalogue is invalid or attempts to bundle artifacts")]
    InvalidReferenceCatalog,
    #[error("route asset policy must be local-only, device-exact and hash-pinned")]
    UnsafeAssetPolicy,
    #[error("expected Apple transport transitions are incomplete or unordered")]
    InvalidTransitionPlan,
    #[error("Apple generation and pwn provider do not match")]
    GenerationProviderMismatch,
    #[error("documented known-good route maturity is too low")]
    InsufficientReferenceMaturity,
}
