use std::collections::BTreeSet;

use serialport::{SerialPortInfo, SerialPortType};
use tg_contracts::{DeviceMode, Maturity};
use tg_leases::{LeaseManager, LeaseOwner};
use tg_purple_boot::PurpleBootFinalProof;
use tg_serial_doctor::{
    required_permissions, HostPlatform, SerialDoctorContext, SerialDoctorManifest, SerialMatchRule,
    SerialOpenProbe, SerialParity, SerialProbeObservation, SerialSettings, SerialStopBits,
    SERIAL_DOCTOR_VERSION,
};
use tg_serial_platform::{
    inventory_from_port_infos, reserve_and_run_doctor, synthetic_usb_port,
    OpenSafetyAcknowledgement, SerialPlatformError, SerialportOpenProbe,
};
use tg_syscfg_serial::SerialLink;
use uuid::Uuid;

fn settings() -> SerialSettings {
    SerialSettings {
        baud_rate: 115_200,
        data_bits: 8,
        parity: SerialParity::None,
        stop_bits: SerialStopBits::One,
        timeout_millis: 1_000,
    }
}

fn manifest() -> SerialDoctorManifest {
    SerialDoctorManifest {
        schema_version: SERIAL_DOCTOR_VERSION.to_owned(),
        provider_id: "synthetic.serial-platform".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        rules: vec![SerialMatchRule {
            rule_id: "synthetic-adapter".to_owned(),
            link: SerialLink::UsbSerial,
            host: None,
            vid: Some(0x1209),
            pid: Some(0x0001),
            manufacturer_contains: Some("Synthetic Lab".to_owned()),
            product_contains: Some("Diags Adapter".to_owned()),
            settings: settings(),
            priority: 100,
        }],
        requested_permissions: required_permissions(),
        proof_requirements: BTreeSet::from([
            "purple_mode_same_session".to_owned(),
            "unique_serial_candidate".to_owned(),
            "stable_hardware_fingerprint".to_owned(),
            "exclusive_open_verified".to_owned(),
            "serial_settings_verified".to_owned(),
            "zero_bytes_written".to_owned(),
            "serial_lease_acquired".to_owned(),
        ]),
    }
}

fn context(session_id: Uuid) -> SerialDoctorContext {
    SerialDoctorContext {
        session_id,
        device_identity_hash: "a".repeat(64),
        purple_proof: PurpleBootFinalProof {
            session_id,
            route_id: "synthetic-purple".to_owned(),
            verified: true,
            final_mode: DeviceMode::PurpleDiagnostic,
            cleanup_required: true,
            environment_backup_sha256: "b".repeat(64),
            failures: Vec::new(),
        },
        granted_permissions: required_permissions(),
        policy_profile: "development".to_owned(),
    }
}

fn usb(port_name: &str, serial: Option<&str>, interface: Option<u8>) -> SerialPortInfo {
    synthetic_usb_port(
        port_name,
        0x1209,
        0x0001,
        serial,
        Some("Synthetic Lab"),
        Some("Diags Adapter"),
        interface,
    )
}

#[derive(Debug, Clone)]
struct FakeProbe {
    observation: SerialProbeObservation,
}

impl SerialOpenProbe for FakeProbe {
    fn probe(
        &mut self,
        _port_name: &str,
        _settings: &SerialSettings,
    ) -> Result<SerialProbeObservation, String> {
        Ok(self.observation.clone())
    }
}

#[test]
fn inventory_filters_non_usb_ports_and_reports_counts() {
    let ports = vec![
        usb("COM9", Some("SYN-1"), Some(2)),
        SerialPortInfo {
            port_name: "COM1".to_owned(),
            port_type: SerialPortType::PciPort,
        },
    ];

    let batch = inventory_from_port_infos(HostPlatform::Windows, ports);
    assert_eq!(batch.summary.total_ports, 2);
    assert_eq!(batch.summary.usb_ports, 1);
    assert_eq!(batch.summary.retained_usb_ports, 1);
    assert_eq!(batch.summary.skipped_non_usb_ports, 1);
    assert_eq!(batch.observations.len(), 1);
    assert_eq!(batch.observations[0].port_name, "COM9");
}

#[test]
fn macos_callout_and_dialin_pair_is_deduplicated_to_callout() {
    let batch = inventory_from_port_infos(
        HostPlatform::Macos,
        vec![
            usb("/dev/tty.synthetic", Some("SYN-1"), Some(1)),
            usb("/dev/cu.synthetic", Some("SYN-1"), Some(1)),
        ],
    );

    assert_eq!(batch.summary.macos_duplicate_pairs_removed, 1);
    assert_eq!(batch.observations.len(), 1);
    assert_eq!(batch.observations[0].port_name, "/dev/cu.synthetic");
}

#[test]
fn usb_interface_is_bound_into_the_operational_serial_identity() {
    let batch = inventory_from_port_infos(
        HostPlatform::Linux,
        vec![usb("/dev/ttyUSB0", Some("SYN-1"), Some(3))],
    );

    assert_eq!(
        batch.observations[0].serial_number.as_deref(),
        Some("SYN-1#usb-interface=3")
    );
}

#[test]
fn durable_inventory_summary_contains_no_raw_port_or_serial() {
    let batch = inventory_from_port_infos(
        HostPlatform::Windows,
        vec![usb("COM-PRIVATE", Some("SERIAL-PRIVATE"), Some(1))],
    );
    let encoded = serde_json::to_string(&batch.summary).expect("summary serializes");
    assert!(!encoded.contains("COM-PRIVATE"));
    assert!(!encoded.contains("SERIAL-PRIVATE"));
}

#[test]
fn real_open_probe_is_blocked_without_side_effect_acknowledgement() {
    let mut probe = SerialportOpenProbe::new(OpenSafetyAcknowledgement {
        allow_control_line_side_effects: false,
    });
    let error = probe
        .probe("definitely-not-a-real-port", &settings())
        .expect_err("open must stop before touching the host");
    assert!(error.contains("control-line side effects were not acknowledged"));
}

#[test]
fn reservation_precedes_probe_and_is_retained_on_success() {
    let session_id = Uuid::new_v4();
    let batch = inventory_from_port_infos(
        HostPlatform::Windows,
        vec![usb("COM9", Some("SYN-1"), Some(1))],
    );
    let owner = LeaseOwner {
        session_id,
        worker_id: "serial-platform".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let mut probe = FakeProbe {
        observation: SerialProbeObservation {
            opened: true,
            exclusive: true,
            settings_applied: true,
            bytes_written: 0,
            bytes_read: 0,
        },
    };

    let session = reserve_and_run_doctor(
        &manifest(),
        &context(session_id),
        HostPlatform::Windows,
        &batch.observations,
        &mut probe,
        &mut leases,
        owner,
        10,
        30,
    )
    .expect("ready probe should keep its lease");

    assert_eq!(session.report.session_id, session_id);
    assert_eq!(leases.active_resource_count(), 1);
}

#[test]
fn blocked_probe_releases_preopen_lease() {
    let session_id = Uuid::new_v4();
    let batch = inventory_from_port_infos(
        HostPlatform::Linux,
        vec![usb("/dev/ttyUSB0", Some("SYN-1"), Some(1))],
    );
    let owner = LeaseOwner {
        session_id,
        worker_id: "serial-platform".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let mut probe = FakeProbe {
        observation: SerialProbeObservation {
            opened: true,
            exclusive: false,
            settings_applied: true,
            bytes_written: 0,
            bytes_read: 0,
        },
    };

    let error = reserve_and_run_doctor(
        &manifest(),
        &context(session_id),
        HostPlatform::Linux,
        &batch.observations,
        &mut probe,
        &mut leases,
        owner,
        10,
        30,
    )
    .expect_err("non-exclusive open must be blocked");

    assert!(matches!(error, SerialPlatformError::DoctorBlocked(_)));
    assert_eq!(leases.active_resource_count(), 0);
}

#[test]
fn lease_owner_must_match_the_doctor_session() {
    let session_id = Uuid::new_v4();
    let batch = inventory_from_port_infos(
        HostPlatform::Windows,
        vec![usb("COM9", Some("SYN-1"), Some(1))],
    );
    let owner = LeaseOwner {
        session_id: Uuid::new_v4(),
        worker_id: "serial-platform".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let mut probe = FakeProbe {
        observation: SerialProbeObservation {
            opened: true,
            exclusive: true,
            settings_applied: true,
            bytes_written: 0,
            bytes_read: 0,
        },
    };

    assert_eq!(
        reserve_and_run_doctor(
            &manifest(),
            &context(session_id),
            HostPlatform::Windows,
            &batch.observations,
            &mut probe,
            &mut leases,
            owner,
            10,
            30,
        ),
        Err(SerialPlatformError::LeaseSessionMismatch)
    );
}
