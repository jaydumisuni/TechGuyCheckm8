//! Fixed, lease-bound SysCfg read transport for verified Purple/Diags sessions.
//!
//! The transport accepts only `syscfg list` and `syscfg print <catalogued-key>`.
//! It has no representation for `syscfg add` and exposes no free-form terminal.
//! Raw response bytes and parsed values are intentionally non-serializable.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use sha2::{Digest, Sha256};
use tg_contracts::Permission;
use tg_leases::{LeaseGrant, ResourceKey, ResourceKind};
use tg_serial_doctor::{
    SelectedSerialCandidate, SerialCandidateReceipt, SerialDoctorVerdict, SerialParity,
    SerialSettings, SerialStopBits,
};
use tg_serial_platform::PlatformDoctorSession;
use tg_syscfg_serial::{
    encode_command, parse_print_response, parse_syscfg_list, EncodedCommand, FieldRead,
    RawSysCfgDump, SysCfgCommand, SysCfgSerialContext, SysCfgSerialError,
    SysCfgSerialProviderManifest,
};
use uuid::Uuid;

pub const SYSCFG_READ_TRANSPORT_VERSION: &str = "tgcheckm8.syscfg-read-transport.v1";
pub const ABSOLUTE_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const ABSOLUTE_MAX_TIMEOUTS: u16 = 64;
pub const ABSOLUTE_MAX_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SysCfgReadOperation {
    List,
    Print { key: String },
}

impl SysCfgReadOperation {
    fn encode(
        &self,
        manifest: &SysCfgSerialProviderManifest,
    ) -> Result<EncodedCommand, SysCfgReadTransportError> {
        match self {
            Self::List => encode_command(manifest, &SysCfgCommand::List),
            Self::Print { key } => {
                encode_command(manifest, &SysCfgCommand::Print { key: key.clone() })
            }
        }
        .map_err(SysCfgReadTransportError::SysCfg)
    }

    fn key(&self) -> Option<&str> {
        match self {
            Self::List => None,
            Self::Print { key } => Some(key),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFramePolicy {
    pub schema_version: String,
    pub max_response_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_consecutive_timeouts: u16,
}

impl ReadFramePolicy {
    pub fn validate(
        &self,
        provider: &SysCfgSerialProviderManifest,
    ) -> Result<(), SysCfgReadTransportError> {
        if self.schema_version != SYSCFG_READ_TRANSPORT_VERSION {
            return Err(SysCfgReadTransportError::UnsupportedVersion(
                self.schema_version.clone(),
            ));
        }
        if self.max_response_bytes == 0
            || self.max_response_bytes > ABSOLUTE_MAX_RESPONSE_BYTES
            || self.max_response_bytes > provider.max_response_bytes
        {
            return Err(SysCfgReadTransportError::InvalidResponseLimit(
                self.max_response_bytes,
            ));
        }
        if self.read_chunk_bytes == 0
            || self.read_chunk_bytes > ABSOLUTE_MAX_CHUNK_BYTES
            || self.read_chunk_bytes > self.max_response_bytes
        {
            return Err(SysCfgReadTransportError::InvalidChunkSize(
                self.read_chunk_bytes,
            ));
        }
        if self.max_consecutive_timeouts == 0
            || self.max_consecutive_timeouts > ABSOLUTE_MAX_TIMEOUTS
        {
            return Err(SysCfgReadTransportError::InvalidTimeoutLimit(
                self.max_consecutive_timeouts,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadTransportAuthorization {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub granted_permissions: BTreeSet<Permission>,
    pub allow_control_line_side_effects: bool,
    pub current_tick: u64,
}

pub fn required_transport_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::SerialRead,
        Permission::SerialWrite,
        Permission::SysCfgRead,
    ])
}

#[derive(Clone)]
pub struct BoundReadEndpoint {
    port_name: String,
    pub candidate: SerialCandidateReceipt,
    pub settings: SerialSettings,
    pub lease: LeaseGrant,
    pub session_id: Uuid,
    pub device_identity_hash: String,
}

impl BoundReadEndpoint {
    pub fn port_name_for_adapter(&self) -> &str {
        &self.port_name
    }
}

impl fmt::Debug for BoundReadEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundReadEndpoint")
            .field("port_name", &"<redacted>")
            .field("candidate", &self.candidate)
            .field("settings", &self.settings)
            .field("lease_id", &self.lease.lease_id)
            .field("session_id", &self.session_id)
            .field("device_identity_hash", &self.device_identity_hash)
            .finish()
    }
}

pub fn bind_read_endpoint(
    selected: SelectedSerialCandidate,
    platform_session: PlatformDoctorSession,
    authorization: &ReadTransportAuthorization,
) -> Result<BoundReadEndpoint, SysCfgReadTransportError> {
    if authorization.granted_permissions != required_transport_permissions() {
        return Err(SysCfgReadTransportError::PermissionGrantMismatch);
    }
    if authorization.device_identity_hash.trim().is_empty() {
        return Err(SysCfgReadTransportError::MissingDeviceIdentity);
    }
    if !authorization.allow_control_line_side_effects {
        return Err(SysCfgReadTransportError::ControlLineAcknowledgementRequired);
    }
    if platform_session.report.verdict != SerialDoctorVerdict::Ready {
        return Err(SysCfgReadTransportError::DoctorNotReady);
    }
    if platform_session.report.session_id != authorization.session_id
        || platform_session.lease.owner.session_id != authorization.session_id
    {
        return Err(SysCfgReadTransportError::SessionMismatch);
    }
    if platform_session.report.device_identity_hash != authorization.device_identity_hash {
        return Err(SysCfgReadTransportError::DeviceIdentityMismatch);
    }
    if selected.receipt != platform_session.report.candidate {
        return Err(SysCfgReadTransportError::CandidateReceiptMismatch);
    }
    if authorization.current_tick >= platform_session.lease.expires_at_tick {
        return Err(SysCfgReadTransportError::LeaseExpired);
    }
    let serial_resource = ResourceKey {
        kind: ResourceKind::Serial,
        stable_id: selected.receipt.hardware_fingerprint.clone(),
    };
    if !platform_session.lease.resources.contains(&serial_resource) {
        return Err(SysCfgReadTransportError::SerialLeaseMissing);
    }

    Ok(BoundReadEndpoint {
        port_name: selected.port_name_for_adapter().to_owned(),
        settings: selected.receipt.settings.clone(),
        candidate: selected.receipt,
        lease: platform_session.lease,
        session_id: authorization.session_id,
        device_identity_hash: authorization.device_identity_hash.clone(),
    })
}

pub struct RawCommandResponse {
    bytes: Vec<u8>,
    pub bytes_written: usize,
    pub prompt_verified: bool,
    pub timeout_count: u16,
}

impl RawCommandResponse {
    pub fn from_channel(
        bytes: Vec<u8>,
        bytes_written: usize,
        prompt_verified: bool,
        timeout_count: u16,
    ) -> Self {
        Self {
            bytes,
            bytes_written,
            prompt_verified,
            timeout_count,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn sha256(&self) -> String {
        sha256_hex(&self.bytes)
    }
}

impl fmt::Debug for RawCommandResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawCommandResponse")
            .field("byte_len", &self.bytes.len())
            .field("response_sha256", &self.sha256())
            .field("bytes_written", &self.bytes_written)
            .field("prompt_verified", &self.prompt_verified)
            .field("timeout_count", &self.timeout_count)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

pub trait SysCfgReadCommandChannel {
    fn exchange(
        &mut self,
        endpoint: &BoundReadEndpoint,
        command: &EncodedCommand,
        policy: &ReadFramePolicy,
    ) -> Result<RawCommandResponse, SysCfgReadTransportError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SerialportSysCfgReadChannel;

impl SysCfgReadCommandChannel for SerialportSysCfgReadChannel {
    fn exchange(
        &mut self,
        endpoint: &BoundReadEndpoint,
        command: &EncodedCommand,
        policy: &ReadFramePolicy,
    ) -> Result<RawCommandResponse, SysCfgReadTransportError> {
        let mut port = build_port(endpoint.port_name_for_adapter(), &endpoint.settings)
            .open()
            .map_err(|error| SysCfgReadTransportError::OpenFailed(error.to_string()))?;
        port.write_all(command.as_bytes())
            .map_err(|error| SysCfgReadTransportError::WriteFailed(error.to_string()))?;
        port.flush()
            .map_err(|error| SysCfgReadTransportError::FlushFailed(error.to_string()))?;

        let mut response = Vec::new();
        let mut chunk = vec![0u8; policy.read_chunk_bytes];
        let mut consecutive_timeouts = 0u16;
        let mut total_timeouts = 0u16;
        loop {
            match port.read(&mut chunk) {
                Ok(0) => {
                    consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                    total_timeouts = total_timeouts.saturating_add(1);
                }
                Ok(count) => {
                    response.extend_from_slice(&chunk[..count]);
                    consecutive_timeouts = 0;
                    if response.len() > policy.max_response_bytes {
                        return Err(SysCfgReadTransportError::ResponseTooLarge(response.len()));
                    }
                    if contains_prompt_line(&response) {
                        return Ok(RawCommandResponse::from_channel(
                            response,
                            command.as_bytes().len(),
                            true,
                            total_timeouts,
                        ));
                    }
                }
                Err(error) if error.kind() == ErrorKind::TimedOut => {
                    consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                    total_timeouts = total_timeouts.saturating_add(1);
                }
                Err(error) => {
                    return Err(SysCfgReadTransportError::ReadFailed(error.to_string()));
                }
            }
            if consecutive_timeouts >= policy.max_consecutive_timeouts {
                return Err(SysCfgReadTransportError::PromptTimeout {
                    response_bytes: response.len(),
                    timeout_count: consecutive_timeouts,
                });
            }
        }
    }
}

fn build_port(port_name: &str, settings: &SerialSettings) -> serialport::SerialPortBuilder {
    let builder = serialport::new(port_name, settings.baud_rate)
        .data_bits(to_data_bits(settings.data_bits).unwrap_or(DataBits::Eight))
        .flow_control(FlowControl::None)
        .parity(to_parity(&settings.parity))
        .stop_bits(to_stop_bits(&settings.stop_bits))
        .timeout(Duration::from_millis(settings.timeout_millis))
        .preserve_dtr_on_open();
    #[cfg(unix)]
    let builder = builder.exclusive(true);
    builder
}

fn to_data_bits(bits: u8) -> Option<DataBits> {
    match bits {
        5 => Some(DataBits::Five),
        6 => Some(DataBits::Six),
        7 => Some(DataBits::Seven),
        8 => Some(DataBits::Eight),
        _ => None,
    }
}

fn to_parity(parity: &SerialParity) -> Parity {
    match parity {
        SerialParity::None => Parity::None,
        SerialParity::Odd => Parity::Odd,
        SerialParity::Even => Parity::Even,
    }
}

fn to_stop_bits(stop_bits: &SerialStopBits) -> StopBits {
    match stop_bits {
        SerialStopBits::One => StopBits::One,
        SerialStopBits::Two => StopBits::Two,
    }
}

fn contains_prompt_line(response: &[u8]) -> bool {
    response.split(|byte| *byte == b'\n').any(|line| {
        let trimmed = trim_ascii(line);
        trimmed == b">"
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadExchangeReceipt {
    pub schema_version: String,
    pub session_id: Uuid,
    pub lease_id: Uuid,
    pub hardware_fingerprint: String,
    pub operation: SysCfgReadOperation,
    pub command_action: String,
    pub command_key: Option<String>,
    pub bytes_written: usize,
    pub bytes_read: usize,
    pub response_sha256: String,
    pub prompt_verified: bool,
}

pub enum ParsedSysCfgRead {
    List(RawSysCfgDump),
    Print(FieldRead),
}

impl fmt::Debug for ParsedSysCfgRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List(dump) => formatter.debug_tuple("List").field(dump).finish(),
            Self::Print(field) => formatter.debug_tuple("Print").field(field).finish(),
        }
    }
}

pub struct SysCfgReadExecution {
    pub receipt: ReadExchangeReceipt,
    pub parsed: ParsedSysCfgRead,
}

impl fmt::Debug for SysCfgReadExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SysCfgReadExecution")
            .field("receipt", &self.receipt)
            .field("parsed", &self.parsed)
            .finish()
    }
}

pub fn execute_read<C: SysCfgReadCommandChannel>(
    channel: &mut C,
    endpoint: &BoundReadEndpoint,
    provider: &SysCfgSerialProviderManifest,
    logical_context: &SysCfgSerialContext,
    operation: SysCfgReadOperation,
    policy: &ReadFramePolicy,
) -> Result<SysCfgReadExecution, SysCfgReadTransportError> {
    policy.validate(provider)?;
    if logical_context.session_id != endpoint.session_id {
        return Err(SysCfgReadTransportError::SessionMismatch);
    }
    if logical_context.device_identity_hash != endpoint.device_identity_hash {
        return Err(SysCfgReadTransportError::DeviceIdentityMismatch);
    }

    let command = operation.encode(provider)?;
    let raw = channel.exchange(endpoint, &command, policy)?;
    if raw.bytes_written != command.as_bytes().len() {
        return Err(SysCfgReadTransportError::CommandWriteCountMismatch {
            expected: command.as_bytes().len(),
            observed: raw.bytes_written,
        });
    }
    if !raw.prompt_verified || !contains_prompt_line(raw.bytes()) {
        return Err(SysCfgReadTransportError::PromptNotVerified);
    }
    if raw.byte_len() > policy.max_response_bytes {
        return Err(SysCfgReadTransportError::ResponseTooLarge(raw.byte_len()));
    }

    let parsed = match &operation {
        SysCfgReadOperation::List => ParsedSysCfgRead::List(
            parse_syscfg_list(provider, raw.bytes()).map_err(SysCfgReadTransportError::SysCfg)?,
        ),
        SysCfgReadOperation::Print { key } => ParsedSysCfgRead::Print(
            parse_print_response(provider, key, raw.bytes())
                .map_err(SysCfgReadTransportError::SysCfg)?,
        ),
    };
    let receipt = ReadExchangeReceipt {
        schema_version: SYSCFG_READ_TRANSPORT_VERSION.to_owned(),
        session_id: endpoint.session_id,
        lease_id: endpoint.lease.lease_id,
        hardware_fingerprint: endpoint.candidate.hardware_fingerprint.clone(),
        operation: operation.clone(),
        command_action: command.action().to_owned(),
        command_key: operation.key().map(str::to_owned),
        bytes_written: raw.bytes_written,
        bytes_read: raw.byte_len(),
        response_sha256: raw.sha256(),
        prompt_verified: true,
    };
    Ok(SysCfgReadExecution { receipt, parsed })
}

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SysCfgReadTransportError {
    #[error("unsupported SysCfg read transport version: {0}")]
    UnsupportedVersion(String),
    #[error("invalid response limit: {0}")]
    InvalidResponseLimit(usize),
    #[error("invalid read chunk size: {0}")]
    InvalidChunkSize(usize),
    #[error("invalid consecutive timeout limit: {0}")]
    InvalidTimeoutLimit(u16),
    #[error("transport permission grant does not match")]
    PermissionGrantMismatch,
    #[error("device identity hash is missing")]
    MissingDeviceIdentity,
    #[error("control-line side effects were not acknowledged")]
    ControlLineAcknowledgementRequired,
    #[error("Serial Doctor report is not ready")]
    DoctorNotReady,
    #[error("session identity does not match")]
    SessionMismatch,
    #[error("device identity does not match")]
    DeviceIdentityMismatch,
    #[error("selected candidate does not match the Doctor receipt")]
    CandidateReceiptMismatch,
    #[error("serial lease has expired")]
    LeaseExpired,
    #[error("serial resource is missing from the lease")]
    SerialLeaseMissing,
    #[error("serial open failed: {0}")]
    OpenFailed(String),
    #[error("serial command write failed: {0}")]
    WriteFailed(String),
    #[error("serial flush failed: {0}")]
    FlushFailed(String),
    #[error("serial response read failed: {0}")]
    ReadFailed(String),
    #[error("serial response exceeded the bounded size: {0}")]
    ResponseTooLarge(usize),
    #[error("serial prompt timed out after {timeout_count} timeouts and {response_bytes} bytes")]
    PromptTimeout {
        response_bytes: usize,
        timeout_count: u16,
    },
    #[error("serial prompt was not independently verified")]
    PromptNotVerified,
    #[error("command write count mismatch: expected {expected}, observed {observed}")]
    CommandWriteCountMismatch { expected: usize, observed: usize },
    #[error("SysCfg parser rejected the exchange: {0}")]
    SysCfg(SysCfgSerialError),
}
