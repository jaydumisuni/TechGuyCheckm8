//! Read-only Apple USB observation and reconnect identity matching.
//!
//! This crate does not open USB devices and cannot send control transfers. Host
//! adapters provide observations; this crate parses, redacts, classifies and
//! verifies continuity between reconnects.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_contracts::DeviceMode;

pub const OBSERVATION_SCHEMA_VERSION: &str = "tgcheckm8.apple-observe.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    WindowsUsb,
    MacIokit,
    LinuxUsbfs,
    RecordedFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawUsbObservation {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub product_type: Option<String>,
    pub board_config: Option<String>,
    pub source: ObservationSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeRule {
    pub rule_id: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub mode: DeviceMode,
    pub serial_must_contain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservationCatalog {
    pub rules: Vec<ModeRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedAppleDevice {
    pub schema_version: String,
    pub rule_id: Option<String>,
    pub mode: DeviceMode,
    pub cpid: Option<String>,
    pub ecid_hash: Option<String>,
    pub serial_hash: Option<String>,
    pub pwn_provider: Option<String>,
    pub product_type: Option<String>,
    pub board_config: Option<String>,
    pub device_identity_hash: Option<String>,
    pub source: ObservationSource,
    pub evidence_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedDeviceIdentity {
    pub cpid: String,
    pub ecid_hash: String,
    pub product_type: Option<String>,
    pub board_config: Option<String>,
    pub identity_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconnectDecision {
    pub matched: bool,
    pub observed_mode: DeviceMode,
    pub blockers: Vec<String>,
}

pub fn observe(
    catalog: &ObservationCatalog,
    raw: &RawUsbObservation,
) -> Result<ObservedAppleDevice, ObservationError> {
    let matching: Vec<&ModeRule> = catalog
        .rules
        .iter()
        .filter(|rule| rule.vendor_id == raw.vendor_id && rule.product_id == raw.product_id)
        .filter(|rule| {
            rule.serial_must_contain.as_ref().map_or(true, |required| {
                raw.serial
                    .as_deref()
                    .map_or(false, |serial| serial.contains(required))
            })
        })
        .collect();

    if matching.len() > 1 {
        return Err(ObservationError::AmbiguousModeRules(
            matching
                .iter()
                .map(|rule| rule.rule_id.clone())
                .collect(),
        ));
    }

    let rule = matching.first().copied();
    let serial = raw.serial.as_deref();
    let cpid = serial.and_then(|value| parse_serial_tag(value, "CPID:"));
    let ecid = serial.and_then(|value| parse_serial_tag(value, "ECID:"));
    let pwn_provider = serial.and_then(parse_pwn_provider);
    let serial_hash = serial.map(redact_hash);
    let ecid_hash = ecid.as_deref().map(redact_hash);

    let mut mode = rule.map_or(DeviceMode::Unknown, |value| value.mode.clone());
    if mode == DeviceMode::Dfu && pwn_provider.is_some() {
        mode = DeviceMode::PwnedDfu;
    }

    let device_identity_hash = match (cpid.as_deref(), ecid_hash.as_deref()) {
        (Some(cpid), Some(ecid_hash)) => Some(compute_identity_hash(
            cpid,
            ecid_hash,
            raw.product_type.as_deref(),
            raw.board_config.as_deref(),
        )),
        _ => None,
    };
    let evidence_complete = rule.is_some() && cpid.is_some() && ecid_hash.is_some();

    Ok(ObservedAppleDevice {
        schema_version: OBSERVATION_SCHEMA_VERSION.to_owned(),
        rule_id: rule.map(|value| value.rule_id.clone()),
        mode,
        cpid,
        ecid_hash,
        serial_hash,
        pwn_provider,
        product_type: raw.product_type.clone(),
        board_config: raw.board_config.clone(),
        device_identity_hash,
        source: raw.source.clone(),
        evidence_complete,
    })
}

pub fn lock_identity(
    observation: &ObservedAppleDevice,
) -> Result<LockedDeviceIdentity, ObservationError> {
    if observation.schema_version != OBSERVATION_SCHEMA_VERSION {
        return Err(ObservationError::UnsupportedVersion(
            observation.schema_version.clone(),
        ));
    }
    let cpid = observation
        .cpid
        .clone()
        .ok_or(ObservationError::MissingCpid)?;
    let ecid_hash = observation
        .ecid_hash
        .clone()
        .ok_or(ObservationError::MissingEcid)?;
    let identity_hash = observation
        .device_identity_hash
        .clone()
        .ok_or(ObservationError::IncompleteIdentity)?;

    Ok(LockedDeviceIdentity {
        cpid,
        ecid_hash,
        product_type: observation.product_type.clone(),
        board_config: observation.board_config.clone(),
        identity_hash,
    })
}

pub fn match_reconnect(
    locked: &LockedDeviceIdentity,
    observed: &ObservedAppleDevice,
    allowed_modes: &BTreeSet<DeviceMode>,
) -> ReconnectDecision {
    let mut blockers = Vec::new();

    if !allowed_modes.contains(&observed.mode) {
        blockers.push(format!("unexpected reconnect mode: {:?}", observed.mode));
    }
    if observed.cpid.as_deref() != Some(locked.cpid.as_str()) {
        blockers.push("CPID mismatch".to_owned());
    }
    if observed.ecid_hash.as_deref() != Some(locked.ecid_hash.as_str()) {
        blockers.push("ECID mismatch".to_owned());
    }
    if locked.product_type.is_some() && observed.product_type != locked.product_type {
        blockers.push("product type mismatch".to_owned());
    }
    if locked.board_config.is_some() && observed.board_config != locked.board_config {
        blockers.push("board configuration mismatch".to_owned());
    }
    if observed.device_identity_hash.as_deref() != Some(locked.identity_hash.as_str()) {
        blockers.push("derived identity hash mismatch".to_owned());
    }
    if !observed.evidence_complete {
        blockers.push("reconnect evidence is incomplete".to_owned());
    }

    ReconnectDecision {
        matched: blockers.is_empty(),
        observed_mode: observed.mode.clone(),
        blockers,
    }
}

pub fn default_apple_dfu_rule() -> ModeRule {
    ModeRule {
        rule_id: "apple.dfu.05ac-1227".to_owned(),
        vendor_id: 0x05ac,
        product_id: 0x1227,
        mode: DeviceMode::Dfu,
        serial_must_contain: Some("CPID:".to_owned()),
    }
}

fn parse_serial_tag(serial: &str, tag: &str) -> Option<String> {
    serial
        .split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(tag))
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_matches(|character| character == '[' || character == ']'))
        .map(str::to_ascii_uppercase)
}

fn parse_pwn_provider(serial: &str) -> Option<String> {
    let start = serial.find("PWND:[")? + "PWND:[".len();
    let end = serial[start..].find(']')? + start;
    let provider = serial[start..end].trim();
    if provider.is_empty() {
        None
    } else {
        Some(provider.to_owned())
    }
}

fn compute_identity_hash(
    cpid: &str,
    ecid_hash: &str,
    product_type: Option<&str>,
    board_config: Option<&str>,
) -> String {
    let material = format!(
        "cpid={cpid}|ecid={ecid_hash}|product={}|board={}",
        product_type.unwrap_or(""),
        board_config.unwrap_or("")
    );
    redact_hash(&material)
}

fn redact_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    to_hex(&digest)
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
pub enum ObservationError {
    #[error("multiple mode rules matched: {0:?}")]
    AmbiguousModeRules(Vec<String>),
    #[error("unsupported observation version: {0}")]
    UnsupportedVersion(String),
    #[error("CPID is missing from the device observation")]
    MissingCpid,
    #[error("ECID is missing from the device observation")]
    MissingEcid,
    #[error("device identity evidence is incomplete")]
    IncompleteIdentity,
}
