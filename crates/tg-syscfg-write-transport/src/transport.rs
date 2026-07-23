use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serialport::{ClearBuffer, DataBits, FlowControl, Parity, SerialPort, StopBits};
use tg_serial_doctor::{SerialParity, SerialSettings, SerialStopBits};
use tg_syscfg_read_transport::BoundReadEndpoint;
use tg_syscfg_serial::{SerialTransport, SerialTransportError, SysCfgSerialProviderManifest};

use crate::{
    SysCfgWriteTransportError, ABSOLUTE_MAX_CHUNK_BYTES, ABSOLUTE_MAX_RESPONSE_BYTES,
    ABSOLUTE_MAX_TIMEOUTS, SYSCFG_WRITE_TRANSPORT_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFramePolicy {
    pub schema_version: String,
    pub max_response_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_consecutive_timeouts: u16,
}

impl WriteFramePolicy {
    pub fn validate(
        &self,
        provider: &SysCfgSerialProviderManifest,
    ) -> Result<(), SysCfgWriteTransportError> {
        if self.schema_version != SYSCFG_WRITE_TRANSPORT_VERSION {
            return Err(SysCfgWriteTransportError::UnsupportedVersion(
                self.schema_version.clone(),
            ));
        }
        if self.max_response_bytes == 0
            || self.max_response_bytes > ABSOLUTE_MAX_RESPONSE_BYTES
            || self.max_response_bytes != provider.max_response_bytes
        {
            return Err(SysCfgWriteTransportError::InvalidResponseLimit(
                self.max_response_bytes,
            ));
        }
        if self.read_chunk_bytes == 0
            || self.read_chunk_bytes > ABSOLUTE_MAX_CHUNK_BYTES
            || self.read_chunk_bytes > self.max_response_bytes
        {
            return Err(SysCfgWriteTransportError::InvalidChunkSize(
                self.read_chunk_bytes,
            ));
        }
        if self.max_consecutive_timeouts == 0
            || self.max_consecutive_timeouts > ABSOLUTE_MAX_TIMEOUTS
        {
            return Err(SysCfgWriteTransportError::InvalidTimeoutLimit(
                self.max_consecutive_timeouts,
            ));
        }
        Ok(())
    }
}

pub struct SerialportSysCfgWriteTransport {
    port: Box<dyn SerialPort>,
    policy: WriteFramePolicy,
}

impl SerialportSysCfgWriteTransport {
    pub fn open(
        endpoint: &BoundReadEndpoint,
        provider: &SysCfgSerialProviderManifest,
        policy: WriteFramePolicy,
    ) -> Result<Self, SysCfgWriteTransportError> {
        policy.validate(provider)?;
        let port = build_port(endpoint.port_name_for_adapter(), &endpoint.settings)
            .open()
            .map_err(|error| SysCfgWriteTransportError::OpenFailed(error.to_string()))?;
        Ok(Self { port, policy })
    }
}

impl fmt::Debug for SerialportSysCfgWriteTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerialportSysCfgWriteTransport")
            .field("port", &"<redacted>")
            .field("policy", &self.policy)
            .finish()
    }
}

impl SerialTransport for SerialportSysCfgWriteTransport {
    fn exchange(
        &mut self,
        command: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SerialTransportError> {
        if !command_is_allowed(command) {
            return Err(transport_error("command surface violation"));
        }
        if max_response_bytes == 0 || max_response_bytes > self.policy.max_response_bytes {
            return Err(transport_error(
                "response limit violates write-frame policy",
            ));
        }

        self.port
            .clear(ClearBuffer::Input)
            .map_err(|error| transport_error(format!("input clear failed: {error}")))?;
        self.port
            .write_all(command)
            .map_err(|error| transport_error(format!("command write failed: {error}")))?;
        self.port
            .flush()
            .map_err(|error| transport_error(format!("serial flush failed: {error}")))?;

        let mut response = Vec::new();
        let mut chunk = vec![0u8; self.policy.read_chunk_bytes];
        let mut consecutive_timeouts = 0u16;
        loop {
            match self.port.read(&mut chunk) {
                Ok(0) => {
                    consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                }
                Ok(count) => {
                    response.extend_from_slice(&chunk[..count]);
                    consecutive_timeouts = 0;
                    if response.len() > max_response_bytes {
                        return Err(transport_error(format!(
                            "response exceeded bounded size: {}",
                            response.len()
                        )));
                    }
                    if contains_prompt_line(&response) {
                        return Ok(response);
                    }
                }
                Err(error) if error.kind() == ErrorKind::TimedOut => {
                    consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                }
                Err(error) => {
                    return Err(transport_error(format!("response read failed: {error}")));
                }
            }
            if consecutive_timeouts >= self.policy.max_consecutive_timeouts {
                return Err(transport_error(format!(
                    "prompt timeout after {} timeouts and {} bytes",
                    consecutive_timeouts,
                    response.len()
                )));
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

fn command_is_allowed(command: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(command) else {
        return false;
    };
    if text.len() > 8192 || !text.ends_with('\n') || text[..text.len() - 1].contains('\n') {
        return false;
    }
    let body = &text[..text.len() - 1];
    if let Some(key) = body.strip_prefix("syscfg print ") {
        return valid_key(key);
    }
    let Some(rest) = body.strip_prefix("syscfg add ") else {
        return false;
    };
    let Some((key, value)) = rest.split_once(' ') else {
        return false;
    };
    valid_key(key) && valid_value(value)
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 32
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'#' || byte == b'_')
}

fn valid_value(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.is_ascii()
        && !value.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b';' | b'&' | b'|' | b'`' | b'$' | b'<' | b'>' | b'\\')
        })
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

fn transport_error(message: impl Into<String>) -> SerialTransportError {
    SerialTransportError {
        message: message.into(),
    }
}
