//! Cross-platform serial inventory and guarded open adapter for TGCHECKM8.
//!
//! Inventory uses the pinned `serialport` crate. Opening a port is blocked until
//! an explicit control-line side-effect acknowledgement is supplied because some
//! hosts may pulse DTR during open even when DTR preservation is requested.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serialport::{
    DataBits, FlowControl, Parity, SerialPortInfo, SerialPortType, StopBits, UsbPortInfo,
};
use tg_leases::{LeaseGrant, LeaseManager, LeaseOwner, ResourceKey, ResourceKind};
use tg_serial_doctor::{
    run_doctor, select_candidate, HostPlatform, RawSerialPortObservation, SelectedSerialCandidate,
    SerialDoctorContext, SerialDoctorError, SerialDoctorManifest, SerialDoctorReport,
    SerialDoctorVerdict, SerialOpenProbe, SerialParity, SerialProbeObservation, SerialSettings,
    SerialStopBits,
};

pub const SERIAL_PLATFORM_VERSION: &str = "tgcheckm8.serial-platform.v1";
pub const PINNED_SERIALPORT_VERSION: &str = "4.9.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySummary {
    pub schema_version: String,
    pub host: HostPlatform,
    pub total_ports: usize,
    pub usb_ports: usize,
    pub retained_usb_ports: usize,
    pub skipped_non_usb_ports: usize,
    pub macos_duplicate_pairs_removed: usize,
}

#[derive(Debug, Clone)]
pub struct InventoryBatch {
    pub observations: Vec<RawSerialPortObservation>,
    pub summary: InventorySummary,
}

pub trait SerialInventorySource {
    fn inventory(&self, host: HostPlatform) -> Result<InventoryBatch, SerialPlatformError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SerialportInventory;

impl SerialInventorySource for SerialportInventory {
    fn inventory(&self, host: HostPlatform) -> Result<InventoryBatch, SerialPlatformError> {
        let ports = serialport::available_ports()
            .map_err(|error| SerialPlatformError::InventoryFailed(error.to_string()))?;
        Ok(inventory_from_port_infos(host, ports))
    }
}

pub fn inventory_from_port_infos(host: HostPlatform, ports: Vec<SerialPortInfo>) -> InventoryBatch {
    let total_ports = ports.len();
    let usb_ports = ports
        .iter()
        .filter(|port| matches!(port.port_type, SerialPortType::UsbPort(_)))
        .count();
    let (normalized, removed) = normalize_usb_port_infos(&host, ports);
    let observations = normalized
        .into_iter()
        .filter_map(port_info_to_observation)
        .collect::<Vec<_>>();

    InventoryBatch {
        summary: InventorySummary {
            schema_version: SERIAL_PLATFORM_VERSION.to_owned(),
            host,
            total_ports,
            usb_ports,
            retained_usb_ports: observations.len(),
            skipped_non_usb_ports: total_ports.saturating_sub(usb_ports),
            macos_duplicate_pairs_removed: removed,
        },
        observations,
    }
}

fn normalize_usb_port_infos(
    host: &HostPlatform,
    ports: Vec<SerialPortInfo>,
) -> (Vec<SerialPortInfo>, usize) {
    let usb_ports = ports
        .into_iter()
        .filter(|port| matches!(port.port_type, SerialPortType::UsbPort(_)))
        .collect::<Vec<_>>();
    if *host != HostPlatform::Macos {
        return (usb_ports, 0);
    }

    let mut by_pair = BTreeMap::<String, SerialPortInfo>::new();
    let mut unpaired = Vec::new();
    let mut removed = 0usize;
    for port in usb_ports {
        let Some(pair_key) = macos_pair_key(&port.port_name) else {
            unpaired.push(port);
            continue;
        };
        let key = format!("{}|{}", pair_key, usb_metadata_key(&port));
        match by_pair.get(&key) {
            None => {
                by_pair.insert(key, port);
            }
            Some(existing) => {
                removed += 1;
                if is_macos_callout(&port.port_name) && !is_macos_callout(&existing.port_name) {
                    by_pair.insert(key, port);
                }
            }
        }
    }
    unpaired.extend(by_pair.into_values());
    unpaired.sort_by(|left, right| left.port_name.cmp(&right.port_name));
    (unpaired, removed)
}

fn macos_pair_key(port_name: &str) -> Option<&str> {
    port_name
        .strip_prefix("/dev/cu.")
        .or_else(|| port_name.strip_prefix("/dev/tty."))
}

fn is_macos_callout(port_name: &str) -> bool {
    port_name.starts_with("/dev/cu.")
}

fn usb_metadata_key(port: &SerialPortInfo) -> String {
    match &port.port_type {
        SerialPortType::UsbPort(info) => format!(
            "{:04x}:{:04x}|{}|{}|{}|{}",
            info.vid,
            info.pid,
            info.serial_number.as_deref().unwrap_or("-"),
            info.manufacturer.as_deref().unwrap_or("-"),
            info.product.as_deref().unwrap_or("-"),
            info.interface
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("-")
        ),
        _ => "non-usb".to_owned(),
    }
}

fn port_info_to_observation(port: SerialPortInfo) -> Option<RawSerialPortObservation> {
    let SerialPortType::UsbPort(info) = port.port_type else {
        return None;
    };
    Some(RawSerialPortObservation {
        port_name: port.port_name,
        vid: Some(info.vid),
        pid: Some(info.pid),
        serial_number: composite_serial(info.serial_number, info.interface),
        manufacturer: info.manufacturer,
        product: info.product,
        physical_location: None,
    })
}

fn composite_serial(serial_number: Option<String>, interface: Option<u8>) -> Option<String> {
    match (serial_number, interface) {
        (Some(serial), Some(interface)) => Some(format!("{serial}#usb-interface={interface}")),
        (Some(serial), None) => Some(serial),
        (None, _) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSafetyAcknowledgement {
    pub allow_control_line_side_effects: bool,
}

#[derive(Debug, Clone)]
pub struct SerialportOpenProbe {
    acknowledgement: OpenSafetyAcknowledgement,
}

impl SerialportOpenProbe {
    pub fn new(acknowledgement: OpenSafetyAcknowledgement) -> Self {
        Self { acknowledgement }
    }
}

impl SerialOpenProbe for SerialportOpenProbe {
    fn probe(
        &mut self,
        port_name: &str,
        settings: &SerialSettings,
    ) -> Result<SerialProbeObservation, String> {
        if !self.acknowledgement.allow_control_line_side_effects {
            return Err(
                "serial open blocked: control-line side effects were not acknowledged".to_owned(),
            );
        }
        let mut port = build_port(port_name, settings)
            .open()
            .map_err(|error| format!("serial open failed: {error}"))?;

        let settings_applied = port
            .baud_rate()
            .map(|value| value == settings.baud_rate)
            .unwrap_or(false)
            && port
                .data_bits()
                .map(|value| value == to_data_bits(settings.data_bits).unwrap_or(DataBits::Eight))
                .unwrap_or(false)
            && port
                .parity()
                .map(|value| value == to_parity(&settings.parity))
                .unwrap_or(false)
            && port
                .stop_bits()
                .map(|value| value == to_stop_bits(&settings.stop_bits))
                .unwrap_or(false)
            && port.timeout() == Duration::from_millis(settings.timeout_millis);

        let second_open = build_port(port_name, settings).open();
        let exclusive = second_open.is_err();
        drop(second_open);
        drop(port);

        Ok(SerialProbeObservation {
            opened: true,
            exclusive,
            settings_applied,
            bytes_written: 0,
            bytes_read: 0,
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDoctorSession {
    pub report: SerialDoctorReport,
    pub lease: LeaseGrant,
}

pub fn reserve_and_run_doctor<P: SerialOpenProbe>(
    manifest: &SerialDoctorManifest,
    context: &SerialDoctorContext,
    host: HostPlatform,
    observations: &[RawSerialPortObservation],
    probe: &mut P,
    leases: &mut LeaseManager,
    owner: LeaseOwner,
    current_tick: u64,
    ttl_ticks: u64,
) -> Result<PlatformDoctorSession, SerialPlatformError> {
    if owner.session_id != context.session_id {
        return Err(SerialPlatformError::LeaseSessionMismatch);
    }
    let selected = select_candidate(manifest, host.clone(), observations)
        .map_err(SerialPlatformError::Doctor)?;
    let lease = acquire_preopen_lease(leases, &selected, owner.clone(), current_tick, ttl_ticks)?;

    let result = run_doctor(manifest, context, host, observations, probe);
    let (_, report) = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = leases.release(lease.lease_id, &owner);
            return Err(SerialPlatformError::Doctor(error));
        }
    };
    if report.candidate.hardware_fingerprint != selected.receipt.hardware_fingerprint {
        let _ = leases.release(lease.lease_id, &owner);
        return Err(SerialPlatformError::CandidateChangedDuringProbe);
    }
    if report.verdict != SerialDoctorVerdict::Ready {
        let _ = leases.release(lease.lease_id, &owner);
        return Err(SerialPlatformError::DoctorBlocked(report.failures));
    }
    Ok(PlatformDoctorSession { report, lease })
}

fn acquire_preopen_lease(
    leases: &mut LeaseManager,
    selected: &SelectedSerialCandidate,
    owner: LeaseOwner,
    current_tick: u64,
    ttl_ticks: u64,
) -> Result<LeaseGrant, SerialPlatformError> {
    let mut resources = BTreeSet::from([ResourceKey {
        kind: ResourceKind::Serial,
        stable_id: selected.receipt.hardware_fingerprint.clone(),
    }]);
    if let Some(location) = &selected.receipt.physical_location_hash {
        resources.insert(ResourceKey {
            kind: ResourceKind::Usb,
            stable_id: location.clone(),
        });
    }
    leases
        .acquire(resources, owner, current_tick, ttl_ticks)
        .map_err(|error| SerialPlatformError::Lease(error.to_string()))
}

pub fn synthetic_usb_port(
    port_name: &str,
    vid: u16,
    pid: u16,
    serial_number: Option<&str>,
    manufacturer: Option<&str>,
    product: Option<&str>,
    interface: Option<u8>,
) -> SerialPortInfo {
    SerialPortInfo {
        port_name: port_name.to_owned(),
        port_type: SerialPortType::UsbPort(UsbPortInfo {
            vid,
            pid,
            serial_number: serial_number.map(str::to_owned),
            manufacturer: manufacturer.map(str::to_owned),
            product: product.map(str::to_owned),
            interface,
        }),
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SerialPlatformError {
    #[error("serial inventory failed: {0}")]
    InventoryFailed(String),
    #[error("serial Doctor failed: {0}")]
    Doctor(SerialDoctorError),
    #[error("serial lease failed: {0}")]
    Lease(String),
    #[error("serial lease owner session does not match the Doctor context")]
    LeaseSessionMismatch,
    #[error("serial candidate changed between reservation and probe")]
    CandidateChangedDuringProbe,
    #[error("serial Doctor blocked the open probe: {0:?}")]
    DoctorBlocked(Vec<String>),
}
