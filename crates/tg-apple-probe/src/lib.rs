//! Approved read-only Apple probe execution.
//!
//! The only supported profile in this phase is the fixed `irecovery -q`
//! information query. Callers cannot supply arbitrary arguments or commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_apple_observe::{
    default_apple_dfu_rule, observe, ObservationCatalog, ObservationSource, ObservedAppleDevice,
    RawUsbObservation,
};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_process::{run_supervised, ProcessPolicy, ProcessSpec, TerminationReason};

pub const PROBE_CONTRACT_VERSION: &str = "tgcheckm8.apple-probe.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeProfile {
    IRecoveryDfuQuery,
}

impl ProbeProfile {
    fn fixed_arguments(&self) -> Vec<String> {
        match self {
            Self::IRecoveryDfuQuery => vec!["-q".to_owned()],
        }
    }

    pub fn required_permissions(&self) -> BTreeSet<Permission> {
        match self {
            Self::IRecoveryDfuQuery => BTreeSet::from([
                Permission::DeviceObserve,
                Permission::UsbRead,
                Permission::ProcessSpawn,
            ]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadOnlyProbeManifest {
    pub schema_version: String,
    pub probe_id: String,
    pub version: String,
    pub profile: ProbeProfile,
    pub supported_hosts: BTreeSet<String>,
    pub maturity: Maturity,
    pub source_repository: String,
    pub source_commit: String,
    pub declared_licence: Option<String>,
    pub expected_executable_sha256: Option<String>,
    pub requested_permissions: BTreeSet<Permission>,
    pub proof_requirements: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeInstallation {
    pub executable: PathBuf,
    pub working_directory: PathBuf,
    pub source: ObservationSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedIRecoveryQuery {
    pub cpid: String,
    pub ecid: String,
    pub pwn_provider: Option<String>,
    pub mode: DeviceMode,
    pub product_type: Option<String>,
    pub board_config: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRunEvidence {
    pub probe_id: String,
    pub probe_version: String,
    pub executable_sha256: String,
    pub granted_permissions: BTreeSet<Permission>,
    pub termination: String,
    pub status_code: Option<i32>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub cleanup_verified: bool,
    pub elapsed_millis: u128,
    pub observed: ObservedAppleDevice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeDoctorReport {
    pub probe_id: String,
    pub manifest_valid: bool,
    pub executable_present: bool,
    pub supported_host: bool,
    pub hash_match: bool,
    pub ready: bool,
    pub findings: Vec<String>,
}

pub fn validate_manifest(
    manifest: &ReadOnlyProbeManifest,
    host: &str,
    policy_profile: &str,
) -> Result<(), ProbeError> {
    if manifest.schema_version != PROBE_CONTRACT_VERSION {
        return Err(ProbeError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.probe_id.trim().is_empty()
        || manifest.version.trim().is_empty()
        || manifest.source_repository.trim().is_empty()
        || manifest.source_commit.trim().is_empty()
    {
        return Err(ProbeError::IncompleteManifest);
    }
    if !manifest.supported_hosts.contains(host) {
        return Err(ProbeError::UnsupportedHost(host.to_owned()));
    }
    if let Some(hash) = manifest.expected_executable_sha256.as_deref() {
        if !is_sha256(hash) {
            return Err(ProbeError::InvalidExecutableHash);
        }
    }
    if manifest.requested_permissions != manifest.profile.required_permissions() {
        return Err(ProbeError::PermissionContractMismatch);
    }
    if manifest
        .proof_requirements
        .iter()
        .any(|proof| proof.trim().is_empty())
    {
        return Err(ProbeError::InvalidProofRequirement);
    }
    if !manifest
        .proof_requirements
        .contains("redacted_identity_observed")
    {
        return Err(ProbeError::MissingMandatoryProof);
    }
    if policy_profile == "stable" {
        if manifest.maturity != Maturity::Stable {
            return Err(ProbeError::ImmatureStableProbe);
        }
        if manifest.expected_executable_sha256.is_none() {
            return Err(ProbeError::StableProbeUnpinned);
        }
        match manifest.declared_licence.as_deref() {
            Some(licence) if !licence.trim().is_empty() => {}
            _ => return Err(ProbeError::MissingDeclaredLicence),
        }
    }
    Ok(())
}

pub fn inspect_installation(
    manifest: &ReadOnlyProbeManifest,
    installation: &ProbeInstallation,
    host: &str,
    policy_profile: &str,
) -> ProbeDoctorReport {
    let mut findings = Vec::new();
    let manifest_valid = match validate_manifest(manifest, host, policy_profile) {
        Ok(()) => true,
        Err(error) => {
            findings.push(error.to_string());
            false
        }
    };
    let executable_present = installation.executable.is_file();
    if !executable_present {
        findings.push("probe executable is missing".to_owned());
    }
    let supported_host = manifest.supported_hosts.contains(host);
    if !supported_host {
        findings.push("host is not declared by the probe manifest".to_owned());
    }
    let hash_match = match (
        executable_present,
        manifest.expected_executable_sha256.as_deref(),
    ) {
        (true, Some(expected)) => match sha256_file(&installation.executable) {
            Ok(actual) if actual == expected => true,
            Ok(_) => {
                findings.push("probe executable hash mismatch".to_owned());
                false
            }
            Err(error) => {
                findings.push(error.to_string());
                false
            }
        },
        (true, None) => {
            findings.push("probe executable is not pinned by SHA-256".to_owned());
            false
        }
        (false, _) => false,
    };

    ProbeDoctorReport {
        probe_id: manifest.probe_id.clone(),
        manifest_valid,
        executable_present,
        supported_host,
        hash_match,
        ready: manifest_valid && executable_present && supported_host && hash_match,
        findings,
    }
}

pub fn run_probe(
    process_policy: &ProcessPolicy,
    manifest: &ReadOnlyProbeManifest,
    installation: &ProbeInstallation,
    granted_permissions: &BTreeSet<Permission>,
    host: &str,
    policy_profile: &str,
) -> Result<ProbeRunEvidence, ProbeError> {
    validate_manifest(manifest, host, policy_profile)?;
    let required_permissions = manifest.profile.required_permissions();
    let missing_permissions: Vec<Permission> = required_permissions
        .difference(granted_permissions)
        .cloned()
        .collect();
    if !missing_permissions.is_empty() {
        return Err(ProbeError::MissingPermissions(missing_permissions));
    }

    let expected_executable_sha256 = manifest
        .expected_executable_sha256
        .as_deref()
        .ok_or(ProbeError::UnpinnedExecutable)?;
    let executable_sha256 = sha256_file(&installation.executable)?;
    if executable_sha256 != expected_executable_sha256 {
        return Err(ProbeError::ExecutableHashMismatch);
    }

    let outcome = run_supervised(
        process_policy,
        &ProcessSpec {
            executable: installation.executable.clone(),
            args: manifest.profile.fixed_arguments(),
            environment: BTreeMap::new(),
            working_directory: installation.working_directory.clone(),
        },
    )?;
    if !outcome.success {
        return Err(ProbeError::ProbeProcessFailed {
            status_code: outcome.status_code,
            timed_out: outcome.termination == TerminationReason::TimeoutKilled,
            cleanup_verified: outcome.cleanup.verified(),
        });
    }

    let output = outcome.stdout.utf8_lossy();
    let parsed = parse_irecovery_query(&output)?;
    let canonical_serial = canonical_serial(&parsed);
    let observed = observe(
        &ObservationCatalog {
            rules: vec![default_apple_dfu_rule()],
        },
        &RawUsbObservation {
            vendor_id: 0x05ac,
            product_id: 0x1227,
            serial: Some(canonical_serial),
            product_type: parsed.product_type,
            board_config: parsed.board_config,
            source: installation.source.clone(),
        },
    )?;

    Ok(ProbeRunEvidence {
        probe_id: manifest.probe_id.clone(),
        probe_version: manifest.version.clone(),
        executable_sha256,
        granted_permissions: required_permissions,
        termination: match outcome.termination {
            TerminationReason::Exited => "exited".to_owned(),
            TerminationReason::TimeoutKilled => "timeout_killed".to_owned(),
        },
        status_code: outcome.status_code,
        stdout_truncated: outcome.stdout.truncated,
        stderr_truncated: outcome.stderr.truncated,
        cleanup_verified: outcome.cleanup.verified(),
        elapsed_millis: outcome.elapsed_millis,
        observed,
    })
}

pub fn parse_irecovery_query(output: &str) -> Result<ParsedIRecoveryQuery, ProbeError> {
    let mut fields = BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_uppercase();
        if matches!(
            key.as_str(),
            "CPID" | "ECID" | "PWND" | "MODE" | "PRODUCT" | "MODEL" | "NAME"
        ) {
            fields.insert(key, value.trim().to_owned());
        }
    }

    let cpid = normalize_cpid(fields.get("CPID").ok_or(ProbeError::MissingField("CPID"))?)?;
    let ecid = normalize_ecid(fields.get("ECID").ok_or(ProbeError::MissingField("ECID"))?)?;
    let mode_text = fields.get("MODE").ok_or(ProbeError::MissingField("MODE"))?;
    let mode = match mode_text.as_str() {
        "DFU" | "DFU via Debug USB (KIS)" => DeviceMode::Dfu,
        other => return Err(ProbeError::UnsupportedObservedMode(other.to_owned())),
    };
    let pwn_provider = fields
        .get("PWND")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "N/A")
        .map(str::to_owned);

    Ok(ParsedIRecoveryQuery {
        cpid,
        ecid,
        pwn_provider,
        mode,
        product_type: optional_field(&fields, "PRODUCT"),
        board_config: optional_field(&fields, "MODEL"),
        display_name: optional_field(&fields, "NAME"),
    })
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, ProbeError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(to_hex(&digest.finalize()))
}

fn canonical_serial(parsed: &ParsedIRecoveryQuery) -> String {
    let mut serial = format!("CPID:{} ECID:{}", parsed.cpid, parsed.ecid);
    if let Some(provider) = parsed.pwn_provider.as_deref() {
        serial.push_str(" PWND:[");
        serial.push_str(provider);
        serial.push(']');
    }
    serial
}

fn optional_field(fields: &BTreeMap<String, String>, key: &str) -> Option<String> {
    fields
        .get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "N/A")
        .map(str::to_owned)
}

fn normalize_cpid(value: &str) -> Result<String, ProbeError> {
    let raw = strip_hex_prefix(value);
    let parsed = u16::from_str_radix(raw, 16)
        .map_err(|_| ProbeError::InvalidHexField("CPID", value.to_owned()))?;
    Ok(format!("{parsed:04X}"))
}

fn normalize_ecid(value: &str) -> Result<String, ProbeError> {
    let raw = strip_hex_prefix(value);
    let parsed = u64::from_str_radix(raw, 16)
        .map_err(|_| ProbeError::InvalidHexField("ECID", value.to_owned()))?;
    Ok(format!("{parsed:016X}"))
}

fn strip_hex_prefix(value: &str) -> &str {
    value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
pub enum ProbeError {
    #[error("unsupported probe contract version: {0}")]
    UnsupportedVersion(String),
    #[error("probe manifest identity is incomplete")]
    IncompleteManifest,
    #[error("probe executable SHA-256 must contain exactly 64 hexadecimal characters")]
    InvalidExecutableHash,
    #[error("probe does not declare support for host: {0}")]
    UnsupportedHost(String),
    #[error("probe manifest permissions do not match the fixed read-only profile")]
    PermissionContractMismatch,
    #[error("probe execution is missing permissions: {0:?}")]
    MissingPermissions(Vec<Permission>),
    #[error("probe manifest contains an empty proof requirement")]
    InvalidProofRequirement,
    #[error("probe manifest is missing redacted identity proof")]
    MissingMandatoryProof,
    #[error("stable policy requires a Stable probe")]
    ImmatureStableProbe,
    #[error("stable policy requires a pinned probe executable")]
    StableProbeUnpinned,
    #[error("stable policy requires a declared licence")]
    MissingDeclaredLicence,
    #[error("probe executable is not pinned by the manifest")]
    UnpinnedExecutable,
    #[error("probe executable hash does not match the manifest")]
    ExecutableHashMismatch,
    #[error("probe process failed: status={status_code:?}, timed_out={timed_out}, cleanup_verified={cleanup_verified}")]
    ProbeProcessFailed {
        status_code: Option<i32>,
        timed_out: bool,
        cleanup_verified: bool,
    },
    #[error("irecovery query is missing field: {0}")]
    MissingField(&'static str),
    #[error("irecovery query contains invalid hexadecimal {0}: {1}")]
    InvalidHexField(&'static str, String),
    #[error("irecovery query returned a mode outside the DFU probe profile: {0}")]
    UnsupportedObservedMode(String),
    #[error(transparent)]
    Observation(#[from] tg_apple_observe::ObservationError),
    #[error(transparent)]
    Process(#[from] tg_process::ProcessError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
