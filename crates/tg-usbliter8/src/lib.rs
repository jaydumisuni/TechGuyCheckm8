//! Deterministic contracts for the usbliter8 RP2350 hardware pwn provider.
//!
//! This crate does not contain exploit firmware, USB timing code, a serial-port
//! implementation, or firmware-flashing logic. It validates approved board
//! manifests, physical handoff evidence, synthetic board logs, and the final
//! host-side pwned-DFU reconnect proof.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_apple_observe::{match_reconnect, LockedDeviceIdentity, ObservedAppleDevice};
use tg_contracts::{DeviceMode, Maturity, Permission};
use uuid::Uuid;

pub const USBLITER8_NODE_VERSION: &str = "tgcheckm8.usbliter8-node.v1";
pub const MAX_BOARD_LOG_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McuFamily {
    Rp2350,
    Rp2040,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardModel {
    WaveshareRp2350UsbA,
    WaveshareRp2350Zero,
    PimoroniTiny2350,
    RaspberryPiPico2,
    AdafruitFeatherRp2040,
    RaspberryPiPico,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usbliter8NodeManifest {
    pub schema_version: String,
    pub node_id: String,
    pub firmware_version: String,
    pub mcu_family: McuFamily,
    pub board_model: BoardModel,
    pub source_repository: String,
    pub source_commit: String,
    pub declared_licence: Option<String>,
    pub uf2_sha256: Option<String>,
    pub supported_cpids: BTreeSet<String>,
    pub hardware_verified_cpids: BTreeSet<String>,
    pub maturity: Maturity,
    pub auto_mode: bool,
    pub required_hardware: BTreeSet<String>,
    pub requested_permissions: BTreeSet<Permission>,
    pub proof_requirements: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStage {
    LockHostDfuIdentity,
    VerifyBoardFirmware,
    DisconnectDeviceFromHost,
    ConnectDeviceToBoard,
    WaitForBoardDfuIdentity,
    ExecuteHardwarePwn,
    VerifyBoardPwndState,
    DisconnectDeviceFromBoard,
    ReconnectDeviceToHost,
    VerifyHostPwndDfu,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalHandoffAcknowledgement {
    pub host_dfu_observed: bool,
    pub disconnected_from_host: bool,
    pub connected_to_board: bool,
    pub direct_lightning_usb_a_path: bool,
    pub board_power_cycled_for_session: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PwnDfuRequest {
    pub session_id: Uuid,
    pub node_id: String,
    pub locked_identity: LockedDeviceIdentity,
    pub expected_cpid: String,
    pub policy_profile: String,
    pub authorized_device_service: bool,
    pub explicit_operator_authorization: bool,
    pub handoff: PhysicalHandoffAcknowledgement,
    pub granted_permissions: BTreeSet<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PwnDfuPlan {
    pub session_id: Uuid,
    pub node_id: String,
    pub expected_cpid: String,
    pub firmware_sha256: String,
    pub stages: Vec<NodeStage>,
    pub granted_permissions: BTreeSet<Permission>,
    pub required_proofs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardRunEvidence {
    pub log_sha256: String,
    pub log_bytes: usize,
    pub initial_cpid: Option<String>,
    pub post_exploit_cpid: Option<String>,
    pub initially_pwned: bool,
    pub post_exploit_pwnd_observed: bool,
    pub success_marker: bool,
    pub failure_marker: bool,
    pub rediscovery_failed: bool,
    pub unsupported_cpid: Option<String>,
    pub elapsed_millis: Option<u64>,
    pub self_verified_pwnd: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostReconnectAcknowledgement {
    pub disconnected_from_board: bool,
    pub reconnected_to_host: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PwnDfuFinalProof {
    pub session_id: Uuid,
    pub verified: bool,
    pub node_id: String,
    pub expected_cpid: String,
    pub firmware_sha256: String,
    pub board_log_sha256: String,
    pub host_mode: DeviceMode,
    pub host_pwn_provider: Option<String>,
    pub failures: Vec<String>,
}

pub fn required_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::UsbRead,
        Permission::UsbWrite,
        Permission::SerialRead,
    ])
}

pub fn validate_node_manifest(
    manifest: &Usbliter8NodeManifest,
    policy_profile: &str,
) -> Result<(), Usbliter8Error> {
    if manifest.schema_version != USBLITER8_NODE_VERSION {
        return Err(Usbliter8Error::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.node_id.trim().is_empty()
        || manifest.firmware_version.trim().is_empty()
        || manifest.source_repository.trim().is_empty()
        || manifest.source_commit.trim().is_empty()
    {
        return Err(Usbliter8Error::IncompleteManifest);
    }
    if manifest.requested_permissions != required_permissions() {
        return Err(Usbliter8Error::PermissionContractMismatch);
    }
    if manifest.supported_cpids.is_empty() {
        return Err(Usbliter8Error::MissingCpidCoverage);
    }
    for cpid in manifest
        .supported_cpids
        .iter()
        .chain(manifest.hardware_verified_cpids.iter())
    {
        validate_supported_cpid(cpid)?;
    }
    if !manifest
        .hardware_verified_cpids
        .is_subset(&manifest.supported_cpids)
    {
        return Err(Usbliter8Error::VerifiedCpidOutsideCoverage);
    }
    if manifest.mcu_family == McuFamily::Rp2040 && manifest.hardware_verified_cpids.contains("8030")
    {
        return Err(Usbliter8Error::A13CannotBeVerifiedOnRp2040);
    }
    if manifest.required_hardware.is_empty() {
        return Err(Usbliter8Error::MissingHardwareRequirements);
    }

    let mandatory_proofs = [
        "board_firmware_hash_verified",
        "board_dfu_identity_verified",
        "board_success_marker",
        "board_self_verified_pwnd",
        "host_pwnd_reconnect_verified",
        "same_device_identity",
    ];
    if mandatory_proofs
        .iter()
        .any(|proof| !manifest.proof_requirements.contains(*proof))
    {
        return Err(Usbliter8Error::MissingMandatoryProof);
    }

    if let Some(hash) = manifest.uf2_sha256.as_deref() {
        validate_sha256(hash)?;
    }

    if policy_profile == "stable" {
        if manifest.maturity != Maturity::Stable {
            return Err(Usbliter8Error::ImmatureStableNode);
        }
        if manifest.mcu_family != McuFamily::Rp2350 {
            return Err(Usbliter8Error::StableRequiresRp2350);
        }
        if manifest.uf2_sha256.is_none() {
            return Err(Usbliter8Error::UnpinnedFirmware);
        }
        if manifest.hardware_verified_cpids != manifest.supported_cpids {
            return Err(Usbliter8Error::StableCoverageNotHardwareVerified);
        }
        match manifest.declared_licence.as_deref() {
            Some(licence) if !licence.trim().is_empty() => {}
            _ => return Err(Usbliter8Error::MissingDeclaredLicence),
        }
    }

    Ok(())
}

pub fn build_pwn_plan(
    manifest: &Usbliter8NodeManifest,
    request: &PwnDfuRequest,
) -> Result<PwnDfuPlan, Usbliter8Error> {
    validate_node_manifest(manifest, &request.policy_profile)?;
    let expected_cpid = normalize_cpid(&request.expected_cpid)?;
    if request.node_id != manifest.node_id {
        return Err(Usbliter8Error::NodeIdentityMismatch);
    }
    if request.locked_identity.cpid != expected_cpid {
        return Err(Usbliter8Error::LockedCpidMismatch);
    }
    if !manifest.supported_cpids.contains(&expected_cpid) {
        return Err(Usbliter8Error::UnsupportedCpid(expected_cpid));
    }
    if request.policy_profile == "stable"
        && !manifest.hardware_verified_cpids.contains(&expected_cpid)
    {
        return Err(Usbliter8Error::CpidNotHardwareVerified(expected_cpid));
    }
    if !request.authorized_device_service || !request.explicit_operator_authorization {
        return Err(Usbliter8Error::AuthorizationRequired);
    }
    if !request.handoff.host_dfu_observed
        || !request.handoff.disconnected_from_host
        || !request.handoff.connected_to_board
        || !request.handoff.direct_lightning_usb_a_path
        || !request.handoff.board_power_cycled_for_session
    {
        return Err(Usbliter8Error::IncompletePhysicalHandoff);
    }

    let required = required_permissions();
    let missing: Vec<Permission> = required
        .difference(&request.granted_permissions)
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(Usbliter8Error::MissingPermissions(missing));
    }

    let firmware_sha256 = manifest
        .uf2_sha256
        .clone()
        .ok_or(Usbliter8Error::UnpinnedFirmware)?;

    Ok(PwnDfuPlan {
        session_id: request.session_id,
        node_id: manifest.node_id.clone(),
        expected_cpid,
        firmware_sha256,
        stages: vec![
            NodeStage::LockHostDfuIdentity,
            NodeStage::VerifyBoardFirmware,
            NodeStage::DisconnectDeviceFromHost,
            NodeStage::ConnectDeviceToBoard,
            NodeStage::WaitForBoardDfuIdentity,
            NodeStage::ExecuteHardwarePwn,
            NodeStage::VerifyBoardPwndState,
            NodeStage::DisconnectDeviceFromBoard,
            NodeStage::ReconnectDeviceToHost,
            NodeStage::VerifyHostPwndDfu,
        ],
        granted_permissions: required,
        required_proofs: manifest.proof_requirements.clone(),
    })
}

pub fn parse_board_log(log: &[u8]) -> Result<BoardRunEvidence, Usbliter8Error> {
    if log.len() > MAX_BOARD_LOG_BYTES {
        return Err(Usbliter8Error::BoardLogTooLarge(log.len()));
    }
    let log_text = std::str::from_utf8(log).map_err(|_| Usbliter8Error::InvalidUtf8Log)?;
    let mut initial_cpid = None;
    let mut post_exploit_cpid = None;
    let mut initially_pwned = false;
    let mut post_exploit_pwnd_observed = false;
    let mut identity_count = 0_usize;
    let mut success_marker = false;
    let mut failure_marker = false;
    let mut rediscovery_failed = false;
    let mut unsupported_cpid = None;
    let mut elapsed_millis = None;
    let mut identity_line_expected = false;

    for line in log_text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("got Apple DFU device:") {
            identity_line_expected = true;
            continue;
        }
        if identity_line_expected {
            let parsed_cpid = parse_tag(trimmed, "CPID:")
                .map(|value| normalize_cpid(&value))
                .transpose()?;
            let pwnd = trimmed.contains("PWND:[");
            if identity_count == 0 {
                initial_cpid = parsed_cpid;
                initially_pwned = pwnd;
            } else {
                post_exploit_cpid = parsed_cpid;
                post_exploit_pwnd_observed |= pwnd;
            }
            identity_count += 1;
            identity_line_expected = false;
        }
        if trimmed.contains("already PWNED!") {
            initially_pwned = true;
        }
        if let Some(value) = parse_unsupported_cpid(trimmed) {
            unsupported_cpid = Some(value);
        }
        if trimmed.contains("cannot re-discover the device after the exploit!") {
            rediscovery_failed = true;
        }
        if trimmed.contains("exploit SUCCESS!") {
            success_marker = true;
        }
        if trimmed.contains("exploit FAILED!") {
            failure_marker = true;
        }
        if let Some(value) = parse_elapsed_millis(trimmed) {
            elapsed_millis = Some(value);
        }
    }

    if success_marker && failure_marker {
        return Err(Usbliter8Error::ContradictoryBoardLog);
    }

    let self_verified_pwnd = success_marker
        && !failure_marker
        && !rediscovery_failed
        && unsupported_cpid.is_none()
        && initial_cpid.is_some()
        && post_exploit_cpid.is_some()
        && !initially_pwned
        && post_exploit_pwnd_observed;

    Ok(BoardRunEvidence {
        log_sha256: sha256_bytes(log),
        log_bytes: log.len(),
        initial_cpid,
        post_exploit_cpid,
        initially_pwned,
        post_exploit_pwnd_observed,
        success_marker,
        failure_marker,
        rediscovery_failed,
        unsupported_cpid,
        elapsed_millis,
        self_verified_pwnd,
    })
}

pub fn finalize_pwn_proof(
    plan: &PwnDfuPlan,
    locked_identity: &LockedDeviceIdentity,
    board: &BoardRunEvidence,
    reconnect: &HostReconnectAcknowledgement,
    host_observation: &ObservedAppleDevice,
) -> PwnDfuFinalProof {
    let mut failures = Vec::new();

    if plan.expected_cpid != locked_identity.cpid {
        failures.push("plan CPID no longer matches the locked device".to_owned());
    }
    if board.initial_cpid.as_deref() != Some(plan.expected_cpid.as_str()) {
        failures.push("board intake observed a different or missing CPID".to_owned());
    }
    if board.post_exploit_cpid.as_deref() != Some(plan.expected_cpid.as_str()) {
        failures.push("board post-exploit observation has a different or missing CPID".to_owned());
    }
    if board.initially_pwned {
        failures.push("board reported that the device was already pwned".to_owned());
    }
    if !board.success_marker || !board.self_verified_pwnd || !board.post_exploit_pwnd_observed {
        failures.push("board did not produce self-verified pwn success".to_owned());
    }
    if board.failure_marker || board.rediscovery_failed || board.unsupported_cpid.is_some() {
        failures.push("board evidence contains a failure condition".to_owned());
    }
    if !reconnect.disconnected_from_board || !reconnect.reconnected_to_host {
        failures.push("physical return to the host is incomplete".to_owned());
    }
    if host_observation.mode != DeviceMode::PwnedDfu {
        failures.push("host did not observe pwned DFU".to_owned());
    }
    if host_observation.pwn_provider.as_deref() != Some("usbliter8") {
        failures.push("host PWND provider is not usbliter8".to_owned());
    }

    let identity_decision = match_reconnect(
        locked_identity,
        host_observation,
        &BTreeSet::from([DeviceMode::PwnedDfu]),
    );
    failures.extend(identity_decision.blockers);

    PwnDfuFinalProof {
        session_id: plan.session_id,
        verified: failures.is_empty(),
        node_id: plan.node_id.clone(),
        expected_cpid: plan.expected_cpid.clone(),
        firmware_sha256: plan.firmware_sha256.clone(),
        board_log_sha256: board.log_sha256.clone(),
        host_mode: host_observation.mode.clone(),
        host_pwn_provider: host_observation.pwn_provider.clone(),
        failures,
    }
}

fn validate_supported_cpid(cpid: &str) -> Result<(), Usbliter8Error> {
    let normalized = normalize_cpid(cpid)?;
    if !matches!(normalized.as_str(), "8006" | "8020" | "8030") {
        return Err(Usbliter8Error::UnsupportedManifestCpid(normalized));
    }
    Ok(())
}

fn normalize_cpid(value: &str) -> Result<String, Usbliter8Error> {
    let trimmed = value.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let parsed =
        u16::from_str_radix(raw, 16).map_err(|_| Usbliter8Error::InvalidCpid(value.to_owned()))?;
    Ok(format!("{parsed:04X}"))
}

fn validate_sha256(value: &str) -> Result<(), Usbliter8Error> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Usbliter8Error::InvalidFirmwareHash)
    }
}

fn parse_tag(line: &str, tag: &str) -> Option<String> {
    line.split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(tag))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_unsupported_cpid(line: &str) -> Option<String> {
    let start = line.find('T')? + 1;
    let suffix = &line[start..];
    let raw = suffix.get(..4)?;
    if suffix.get(4..)?.starts_with(" is not supported") {
        normalize_cpid(raw).ok()
    } else {
        None
    }
}

fn parse_elapsed_millis(line: &str) -> Option<u64> {
    let prefix = "took - ";
    let start = line.find(prefix)? + prefix.len();
    let suffix = &line[start..];
    let end = suffix.find("ms")?;
    suffix[..end].trim().parse().ok()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
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
pub enum Usbliter8Error {
    #[error("unsupported usbliter8 node contract version: {0}")]
    UnsupportedVersion(String),
    #[error("node manifest identity or provenance is incomplete")]
    IncompleteManifest,
    #[error("node manifest permissions do not match the hardware-pwn profile")]
    PermissionContractMismatch,
    #[error("node manifest has no CPID coverage")]
    MissingCpidCoverage,
    #[error("invalid CPID: {0}")]
    InvalidCpid(String),
    #[error("CPID is outside usbliter8 source coverage: {0}")]
    UnsupportedManifestCpid(String),
    #[error("hardware-verified CPIDs must be a subset of supported CPIDs")]
    VerifiedCpidOutsideCoverage,
    #[error("A13/T8030 cannot be marked hardware-verified on RP2040")]
    A13CannotBeVerifiedOnRp2040,
    #[error("node manifest has no hardware requirements")]
    MissingHardwareRequirements,
    #[error("node manifest is missing mandatory proof requirements")]
    MissingMandatoryProof,
    #[error("UF2 SHA-256 must contain exactly 64 hexadecimal characters")]
    InvalidFirmwareHash,
    #[error("stable policy requires a Stable node")]
    ImmatureStableNode,
    #[error("stable policy requires RP2350 hardware")]
    StableRequiresRp2350,
    #[error("node firmware is not pinned by SHA-256")]
    UnpinnedFirmware,
    #[error("stable CPID coverage is not fully hardware-verified")]
    StableCoverageNotHardwareVerified,
    #[error("stable policy requires a declared licence")]
    MissingDeclaredLicence,
    #[error("request node identity does not match the manifest")]
    NodeIdentityMismatch,
    #[error("locked device CPID does not match the requested CPID")]
    LockedCpidMismatch,
    #[error("requested CPID is unsupported by this node: {0}")]
    UnsupportedCpid(String),
    #[error("requested CPID lacks hardware verification: {0}")]
    CpidNotHardwareVerified(String),
    #[error("authorized service and explicit operator authorization are required")]
    AuthorizationRequired,
    #[error("physical host-to-board handoff is incomplete")]
    IncompletePhysicalHandoff,
    #[error("hardware-pwn stage is missing permissions: {0:?}")]
    MissingPermissions(Vec<Permission>),
    #[error("board log exceeds the maximum size: {0} bytes")]
    BoardLogTooLarge(usize),
    #[error("board log is not valid UTF-8")]
    InvalidUtf8Log,
    #[error("board log contains both success and failure markers")]
    ContradictoryBoardLog,
}
