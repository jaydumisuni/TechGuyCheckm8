//! Read-only serial-link discovery, selection, lease, and reconnect contracts.
//!
//! This crate does not send serial bytes and does not implement SysCfg commands.
//! Raw port names and adapter serial numbers are intentionally non-serializable;
//! durable reports contain only hashes and normalized USB metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_leases::{LeaseError, LeaseGrant, LeaseManager, LeaseOwner, ResourceKey, ResourceKind};
use tg_purple_boot::PurpleBootFinalProof;
use tg_syscfg_serial::SerialLink;
use uuid::Uuid;

pub const SERIAL_DOCTOR_VERSION: &str = "tgcheckm8.serial-doctor.v1";
pub const MAX_RULES: usize = 256;
pub const MAX_CANDIDATES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialParity {
    None,
    Odd,
    Even,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialStopBits {
    One,
    Two,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialSettings {
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: SerialParity,
    pub stop_bits: SerialStopBits,
    pub timeout_millis: u64,
}

impl SerialSettings {
    pub fn validate(&self) -> Result<(), SerialDoctorError> {
        if self.baud_rate == 0 || !matches!(self.data_bits, 5..=8) || self.timeout_millis == 0 {
            return Err(SerialDoctorError::InvalidSerialSettings);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RawSerialPortObservation {
    pub port_name: String,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub serial_number: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub physical_location: Option<String>,
}

impl fmt::Debug for RawSerialPortObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawSerialPortObservation")
            .field("port_name", &"<redacted>")
            .field("vid", &self.vid)
            .field("pid", &self.pid)
            .field("serial_number", &"<redacted>")
            .field("manufacturer", &self.manufacturer)
            .field("product", &self.product)
            .field("physical_location", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialMatchRule {
    pub rule_id: String,
    pub link: SerialLink,
    pub host: Option<HostPlatform>,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub manufacturer_contains: Option<String>,
    pub product_contains: Option<String>,
    pub settings: SerialSettings,
    pub priority: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialDoctorManifest {
    pub schema_version: String,
    pub provider_id: String,
    pub version: String,
    pub maturity: Maturity,
    pub rules: Vec<SerialMatchRule>,
    pub requested_permissions: BTreeSet<Permission>,
    pub proof_requirements: BTreeSet<String>,
}

pub fn required_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::UsbRead,
        Permission::SerialRead,
    ])
}

pub fn validate_manifest(
    manifest: &SerialDoctorManifest,
    policy_profile: &str,
) -> Result<(), SerialDoctorError> {
    if manifest.schema_version != SERIAL_DOCTOR_VERSION {
        return Err(SerialDoctorError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.provider_id.trim().is_empty() || manifest.version.trim().is_empty() {
        return Err(SerialDoctorError::IncompleteProviderIdentity);
    }
    if manifest.rules.is_empty() || manifest.rules.len() > MAX_RULES {
        return Err(SerialDoctorError::InvalidRuleCount(manifest.rules.len()));
    }
    if manifest.requested_permissions != required_permissions() {
        return Err(SerialDoctorError::PermissionContractMismatch);
    }

    let mut rule_ids = BTreeSet::new();
    for rule in &manifest.rules {
        if rule.rule_id.trim().is_empty() || !rule_ids.insert(rule.rule_id.clone()) {
            return Err(SerialDoctorError::InvalidRuleIdentity(rule.rule_id.clone()));
        }
        if rule.vid.is_some() != rule.pid.is_some() {
            return Err(SerialDoctorError::IncompleteUsbIdentity(rule.rule_id.clone()));
        }
        if rule.vid.is_none()
            && rule.manufacturer_contains.is_none()
            && rule.product_contains.is_none()
        {
            return Err(SerialDoctorError::UnboundedMatchRule(rule.rule_id.clone()));
        }
        if rule
            .manufacturer_contains
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
            || rule
                .product_contains
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
        {
            return Err(SerialDoctorError::EmptyMatchPattern(rule.rule_id.clone()));
        }
        rule.settings.validate()?;
    }

    for required in [
        "purple_mode_same_session",
        "unique_serial_candidate",
        "stable_hardware_fingerprint",
        "exclusive_open_verified",
        "serial_settings_verified",
        "zero_bytes_written",
        "serial_lease_acquired",
    ] {
        if !manifest.proof_requirements.contains(required) {
            return Err(SerialDoctorError::MissingMandatoryProof(required.to_owned()));
        }
    }

    if policy_profile == "stable" && manifest.maturity != Maturity::Stable {
        return Err(SerialDoctorError::ImmatureStableProvider);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialCandidateReceipt {
    pub rule_id: String,
    pub link: SerialLink,
    pub hardware_fingerprint: String,
    pub port_name_hash: String,
    pub physical_location_hash: Option<String>,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub manufacturer_hash: Option<String>,
    pub product_hash: Option<String>,
    pub identity_strength: IdentityStrength,
    pub match_score: u32,
    pub settings: SerialSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStrength {
    UsbSerialAndLocation,
    UsbSerial,
    PhysicalLocation,
    WeakMetadata,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SelectedSerialCandidate {
    port_name: String,
    pub receipt: SerialCandidateReceipt,
}

impl SelectedSerialCandidate {
    pub fn port_name_for_adapter(&self) -> &str {
        &self.port_name
    }
}

impl fmt::Debug for SelectedSerialCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedSerialCandidate")
            .field("port_name", &"<redacted>")
            .field("receipt", &self.receipt)
            .finish()
    }
}

pub fn select_candidate(
    manifest: &SerialDoctorManifest,
    host: HostPlatform,
    observations: &[RawSerialPortObservation],
) -> Result<SelectedSerialCandidate, SerialDoctorError> {
    validate_manifest(manifest, "development")?;
    if observations.is_empty() {
        return Err(SerialDoctorError::NoCandidates);
    }
    if observations.len() > MAX_CANDIDATES {
        return Err(SerialDoctorError::TooManyCandidates(observations.len()));
    }

    let mut matches = Vec::new();
    for observation in observations {
        validate_observation(observation)?;
        for rule in &manifest.rules {
            if let Some(candidate) = match_candidate(rule, &host, observation) {
                matches.push(candidate);
            }
        }
    }
    if matches.is_empty() {
        return Err(SerialDoctorError::NoMatchingCandidate);
    }

    matches.sort_by(|left, right| {
        right
            .receipt
            .match_score
            .cmp(&left.receipt.match_score)
            .then_with(|| {
                right
                    .receipt
                    .identity_strength
                    .rank()
                    .cmp(&left.receipt.identity_strength.rank())
            })
            .then_with(|| {
                left.receipt
                    .hardware_fingerprint
                    .cmp(&right.receipt.hardware_fingerprint)
            })
    });

    let best = matches.remove(0);
    if matches.first().is_some_and(|next| {
        next.receipt.match_score == best.receipt.match_score
            && next.receipt.identity_strength == best.receipt.identity_strength
            && next.receipt.hardware_fingerprint != best.receipt.hardware_fingerprint
    }) {
        return Err(SerialDoctorError::AmbiguousCandidates);
    }
    if matches.iter().any(|next| {
        next.receipt.hardware_fingerprint == best.receipt.hardware_fingerprint
            && next.receipt.port_name_hash != best.receipt.port_name_hash
    }) {
        return Err(SerialDoctorError::DuplicatePhysicalCandidate);
    }
    Ok(best)
}

fn match_candidate(
    rule: &SerialMatchRule,
    host: &HostPlatform,
    observation: &RawSerialPortObservation,
) -> Option<SelectedSerialCandidate> {
    if rule.host.as_ref().is_some_and(|expected| expected != host) {
        return None;
    }
    if rule.vid.is_some() && (rule.vid != observation.vid || rule.pid != observation.pid) {
        return None;
    }
    if !contains_case_insensitive(
        observation.manufacturer.as_deref(),
        rule.manufacturer_contains.as_deref(),
    ) || !contains_case_insensitive(
        observation.product.as_deref(),
        rule.product_contains.as_deref(),
    ) {
        return None;
    }

    let identity_strength = identity_strength(observation);
    let fingerprint = hardware_fingerprint(observation);
    let specificity = u32::from(rule.vid.is_some()) * 100
        + u32::from(rule.manufacturer_contains.is_some()) * 20
        + u32::from(rule.product_contains.is_some()) * 20
        + u32::from(rule.host.is_some()) * 10
        + identity_strength.rank();

    Some(SelectedSerialCandidate {
        port_name: observation.port_name.clone(),
        receipt: SerialCandidateReceipt {
            rule_id: rule.rule_id.clone(),
            link: rule.link.clone(),
            hardware_fingerprint: fingerprint,
            port_name_hash: hash_text(&observation.port_name),
            physical_location_hash: observation
                .physical_location
                .as_deref()
                .map(hash_text),
            vid: observation.vid,
            pid: observation.pid,
            manufacturer_hash: observation.manufacturer.as_deref().map(hash_text),
            product_hash: observation.product.as_deref().map(hash_text),
            identity_strength,
            match_score: u32::from(rule.priority) * 1000 + specificity,
            settings: rule.settings.clone(),
        },
    })
}

fn validate_observation(observation: &RawSerialPortObservation) -> Result<(), SerialDoctorError> {
    if observation.port_name.trim().is_empty() {
        return Err(SerialDoctorError::EmptyPortName);
    }
    if observation.vid.is_some() != observation.pid.is_some() {
        return Err(SerialDoctorError::IncompleteObservedUsbIdentity);
    }
    if observation.serial_number.is_none()
        && observation.physical_location.is_none()
        && observation.vid.is_none()
        && observation.manufacturer.is_none()
        && observation.product.is_none()
    {
        return Err(SerialDoctorError::UnidentifiableCandidate);
    }
    Ok(())
}

fn identity_strength(observation: &RawSerialPortObservation) -> IdentityStrength {
    match (
        observation.serial_number.is_some(),
        observation.physical_location.is_some(),
    ) {
        (true, true) => IdentityStrength::UsbSerialAndLocation,
        (true, false) => IdentityStrength::UsbSerial,
        (false, true) => IdentityStrength::PhysicalLocation,
        (false, false) => IdentityStrength::WeakMetadata,
    }
}

impl IdentityStrength {
    fn rank(&self) -> u32 {
        match self {
            Self::UsbSerialAndLocation => 40,
            Self::UsbSerial => 30,
            Self::PhysicalLocation => 20,
            Self::WeakMetadata => 10,
        }
    }
}

fn hardware_fingerprint(observation: &RawSerialPortObservation) -> String {
    let serial = observation.serial_number.as_deref().unwrap_or("-");
    let location = observation.physical_location.as_deref().unwrap_or("-");
    let manufacturer = observation.manufacturer.as_deref().unwrap_or("-");
    let product = observation.product.as_deref().unwrap_or("-");
    hash_text(&format!(
        "{:04x}:{:04x}|{}|{}|{}|{}",
        observation.vid.unwrap_or_default(),
        observation.pid.unwrap_or_default(),
        serial.trim().to_ascii_lowercase(),
        location.trim().to_ascii_lowercase(),
        manufacturer.trim().to_ascii_lowercase(),
        product.trim().to_ascii_lowercase()
    ))
}

fn contains_case_insensitive(value: Option<&str>, pattern: Option<&str>) -> bool {
    match pattern {
        None => true,
        Some(pattern) => value.is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .contains(&pattern.to_ascii_lowercase())
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialDoctorContext {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub purple_proof: PurpleBootFinalProof,
    pub granted_permissions: BTreeSet<Permission>,
    pub policy_profile: String,
}

fn validate_context(
    manifest: &SerialDoctorManifest,
    context: &SerialDoctorContext,
) -> Result<(), SerialDoctorError> {
    validate_manifest(manifest, &context.policy_profile)?;
    if context.device_identity_hash.trim().is_empty() {
        return Err(SerialDoctorError::MissingDeviceIdentity);
    }
    if context.purple_proof.session_id != context.session_id
        || !context.purple_proof.verified
        || context.purple_proof.final_mode != DeviceMode::PurpleDiagnostic
    {
        return Err(SerialDoctorError::UnverifiedPurpleSession);
    }
    if context.granted_permissions != required_permissions() {
        return Err(SerialDoctorError::PermissionGrantMismatch);
    }
    Ok(())
}

pub trait SerialOpenProbe {
    fn probe(
        &mut self,
        port_name: &str,
        settings: &SerialSettings,
    ) -> Result<SerialProbeObservation, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialProbeObservation {
    pub opened: bool,
    pub exclusive: bool,
    pub settings_applied: bool,
    pub bytes_written: u64,
    pub bytes_read: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialDoctorVerdict {
    Ready,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialDoctorReport {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub verdict: SerialDoctorVerdict,
    pub candidate: SerialCandidateReceipt,
    pub opened: bool,
    pub exclusive: bool,
    pub settings_verified: bool,
    pub zero_bytes_written: bool,
    pub bytes_read: u64,
    pub failures: Vec<String>,
}

pub fn run_doctor<P: SerialOpenProbe>(
    manifest: &SerialDoctorManifest,
    context: &SerialDoctorContext,
    host: HostPlatform,
    observations: &[RawSerialPortObservation],
    probe: &mut P,
) -> Result<(SelectedSerialCandidate, SerialDoctorReport), SerialDoctorError> {
    validate_context(manifest, context)?;
    let candidate = select_candidate(manifest, host, observations)?;
    let probe_result = probe
        .probe(
            candidate.port_name_for_adapter(),
            &candidate.receipt.settings,
        )
        .map_err(SerialDoctorError::ProbeFailed)?;

    let mut failures = Vec::new();
    if !probe_result.opened {
        failures.push("serial_open_failed".to_owned());
    }
    if !probe_result.exclusive {
        failures.push("exclusive_open_not_proven".to_owned());
    }
    if !probe_result.settings_applied {
        failures.push("serial_settings_not_applied".to_owned());
    }
    if probe_result.bytes_written != 0 {
        failures.push("read_only_probe_wrote_bytes".to_owned());
    }
    let verdict = if failures.is_empty() {
        SerialDoctorVerdict::Ready
    } else {
        SerialDoctorVerdict::Blocked
    };
    let report = SerialDoctorReport {
        session_id: context.session_id,
        device_identity_hash: context.device_identity_hash.clone(),
        verdict,
        candidate: candidate.receipt.clone(),
        opened: probe_result.opened,
        exclusive: probe_result.exclusive,
        settings_verified: probe_result.settings_applied,
        zero_bytes_written: probe_result.bytes_written == 0,
        bytes_read: probe_result.bytes_read,
        failures,
    };
    Ok((candidate, report))
}

pub fn acquire_serial_lease(
    manager: &mut LeaseManager,
    report: &SerialDoctorReport,
    owner: LeaseOwner,
    current_tick: u64,
    ttl_ticks: u64,
) -> Result<LeaseGrant, SerialDoctorError> {
    if report.verdict != SerialDoctorVerdict::Ready {
        return Err(SerialDoctorError::DoctorNotReady);
    }
    if owner.session_id != report.session_id {
        return Err(SerialDoctorError::LeaseSessionMismatch);
    }
    let mut resources = BTreeSet::from([ResourceKey {
        kind: ResourceKind::Serial,
        stable_id: report.candidate.hardware_fingerprint.clone(),
    }]);
    if let Some(location_hash) = &report.candidate.physical_location_hash {
        resources.insert(ResourceKey {
            kind: ResourceKind::Usb,
            stable_id: location_hash.clone(),
        });
    }
    manager
        .acquire(resources, owner, current_tick, ttl_ticks)
        .map_err(SerialDoctorError::Lease)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconnectContinuity {
    ExactFingerprint,
    SameUsbLocation,
}

pub fn verify_reconnect(
    before: &SerialCandidateReceipt,
    after: &SerialCandidateReceipt,
) -> Result<ReconnectContinuity, SerialDoctorError> {
    if before.hardware_fingerprint == after.hardware_fingerprint {
        return Ok(ReconnectContinuity::ExactFingerprint);
    }
    if before.vid == after.vid
        && before.pid == after.pid
        && before.physical_location_hash.is_some()
        && before.physical_location_hash == after.physical_location_hash
    {
        return Ok(ReconnectContinuity::SameUsbLocation);
    }
    Err(SerialDoctorError::ReconnectIdentityMismatch)
}

fn hash_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SerialDoctorError {
    #[error("unsupported serial Doctor contract version: {0}")]
    UnsupportedVersion(String),
    #[error("serial Doctor provider identity is incomplete")]
    IncompleteProviderIdentity,
    #[error("serial Doctor rule count is invalid: {0}")]
    InvalidRuleCount(usize),
    #[error("serial Doctor permission contract does not match")]
    PermissionContractMismatch,
    #[error("serial rule identity is empty or duplicated: {0}")]
    InvalidRuleIdentity(String),
    #[error("serial rule has an incomplete USB identity: {0}")]
    IncompleteUsbIdentity(String),
    #[error("serial rule is not bounded by USB or descriptive metadata: {0}")]
    UnboundedMatchRule(String),
    #[error("serial rule contains an empty match pattern: {0}")]
    EmptyMatchPattern(String),
    #[error("serial settings are invalid")]
    InvalidSerialSettings,
    #[error("mandatory proof is missing: {0}")]
    MissingMandatoryProof(String),
    #[error("stable policy requires a stable provider")]
    ImmatureStableProvider,
    #[error("no serial candidates were observed")]
    NoCandidates,
    #[error("too many serial candidates were observed: {0}")]
    TooManyCandidates(usize),
    #[error("no serial candidate matched an approved rule")]
    NoMatchingCandidate,
    #[error("multiple serial candidates have equal authority")]
    AmbiguousCandidates,
    #[error("one physical candidate appeared through multiple port paths")]
    DuplicatePhysicalCandidate,
    #[error("serial candidate has an empty port name")]
    EmptyPortName,
    #[error("serial candidate has incomplete USB identity")]
    IncompleteObservedUsbIdentity,
    #[error("serial candidate has no stable identifying metadata")]
    UnidentifiableCandidate,
    #[error("device identity hash is missing")]
    MissingDeviceIdentity,
    #[error("Purple mode was not independently verified for this session")]
    UnverifiedPurpleSession,
    #[error("serial Doctor permissions do not exactly match the grant")]
    PermissionGrantMismatch,
    #[error("serial open probe failed: {0}")]
    ProbeFailed(String),
    #[error("serial Doctor report is not ready")]
    DoctorNotReady,
    #[error("serial lease owner session does not match the report")]
    LeaseSessionMismatch,
    #[error("serial lease failed: {0}")]
    Lease(LeaseError),
    #[error("serial reconnect identity does not match the selected adapter")]
    ReconnectIdentityMismatch,
}

impl From<LeaseError> for SerialDoctorError {
    fn from(value: LeaseError) -> Self {
        Self::Lease(value)
    }
}

pub fn summarize_candidates(
    observations: &[RawSerialPortObservation],
) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for observation in observations {
        let key = match (observation.vid, observation.pid) {
            (Some(vid), Some(pid)) => format!("{vid:04x}:{pid:04x}"),
            _ => "non_usb_or_unknown".to_owned(),
        };
        *summary.entry(key).or_insert(0) += 1;
    }
    summary
}
