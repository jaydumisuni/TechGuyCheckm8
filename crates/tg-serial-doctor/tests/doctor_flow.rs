use std::collections::BTreeSet;

use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_leases::{LeaseManager, LeaseOwner};
use tg_purple_boot::PurpleBootFinalProof;
use tg_serial_doctor::{
    acquire_serial_lease, required_permissions, run_doctor, select_candidate, verify_reconnect,
    HostPlatform, RawSerialPortObservation, ReconnectContinuity, SerialDoctorContext,
    SerialDoctorError, SerialDoctorManifest, SerialDoctorVerdict, SerialMatchRule,
    SerialOpenProbe, SerialParity, SerialProbeObservation, SerialSettings, SerialStopBits,
    SERIAL_DOCTOR_VERSION,
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
        provider_id: "synthetic.serial-doctor".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        rules: vec![SerialMatchRule {
            rule_id: "synthetic-usb-serial".to_owned(),
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

fn observation(port_name: &str, serial: &str, location: &str) -> RawSerialPortObservation {
    RawSerialPortObservation {
        port_name: port_name.to_owned(),
        vid: Some(0x1209),
        pid: Some(0x0001),
        serial_number: Some(serial.to_owned()),
        manufacturer: Some("Synthetic Lab".to_owned()),
        product: Some("Diags Adapter".to_owned()),
        physical_location: Some(location.to_owned()),
    }
}

fn purple_proof(session_id: Uuid) -> PurpleBootFinalProof {
    PurpleBootFinalProof {
        session_id,
        route_id: "synthetic-purple-route".to_owned(),
        verified: true,
        final_mode: DeviceMode::PurpleDiagnostic,
        cleanup_required: true,
        environment_backup_sha256: "a".repeat(64),
        failures: Vec::new(),
    }
}

fn context(session_id: Uuid) -> SerialDoctorContext {
    SerialDoctorContext {
        session_id,
        device_identity_hash: "b".repeat(64),
        purple_proof: purple_proof(session_id),
        granted_permissions: required_permissions(),
        policy_profile: "development".to_owned(),
    }
}

#[derive(Debug)]
struct Probe {
    result: Result<SerialProbeObservation, String>,
    observed_port: Option<String>,
    observed_settings: Option<SerialSettings>,
}

impl Probe {
    fn ready() -> Self {
        Self {
            result: Ok(SerialProbeObservation {
                opened: true,
                exclusive: true,
                settings_applied: true,
                bytes_written: 0,
                bytes_read: 0,
            }),
            observed_port: None,
            observed_settings: None,
        }
    }
}

impl SerialOpenProbe for Probe {
    fn probe(
        &mut self,
        port_name: &str,
        settings: &SerialSettings,
    ) -> Result<SerialProbeObservation, String> {
        self.observed_port = Some(port_name.to_owned());
        self.observed_settings = Some(settings.clone());
        self.result.clone()
    }
}

#[test]
fn unique_candidate_produces_read_only_ready_report() {
    let session_id = Uuid::new_v4();
    let mut probe = Probe::ready();
    let raw = observation("COM77", "SYNTHETIC-ADAPTER-001", "usb-root-1-port-4");

    let (selected, report) = run_doctor(
        &manifest(),
        &context(session_id),
        HostPlatform::Windows,
        &[raw],
        &mut probe,
    )
    .expect("synthetic candidate should pass");

    assert_eq!(report.verdict, SerialDoctorVerdict::Ready);
    assert!(report.zero_bytes_written);
    assert_eq!(probe.observed_port.as_deref(), Some("COM77"));
    assert_eq!(probe.observed_settings, Some(settings()));
    assert_eq!(selected.port_name_for_adapter(), "COM77");

    let encoded = serde_json::to_string(&report).expect("report should serialize");
    assert!(!encoded.contains("COM77"));
    assert!(!encoded.contains("SYNTHETIC-ADAPTER-001"));
    assert!(!format!("{selected:?}").contains("COM77"));
}

#[test]
fn equal_authority_candidates_are_rejected() {
    let error = select_candidate(
        &manifest(),
        HostPlatform::Linux,
        &[
            observation("/dev/ttyUSB0", "SYN-A", "1-4"),
            observation("/dev/ttyUSB1", "SYN-B", "1-5"),
        ],
    )
    .expect_err("equal candidates must fail closed");

    assert_eq!(error, SerialDoctorError::AmbiguousCandidates);
}

#[test]
fn duplicate_interfaces_for_one_physical_adapter_are_rejected() {
    let error = select_candidate(
        &manifest(),
        HostPlatform::Macos,
        &[
            observation("/dev/cu.synthetic", "SYN-A", "location-1"),
            observation("/dev/tty.synthetic", "SYN-A", "location-1"),
        ],
    )
    .expect_err("two paths for one fingerprint are ambiguous");

    assert_eq!(error, SerialDoctorError::DuplicatePhysicalCandidate);
}

#[test]
fn accidental_probe_write_blocks_the_doctor() {
    let session_id = Uuid::new_v4();
    let mut probe = Probe {
        result: Ok(SerialProbeObservation {
            opened: true,
            exclusive: true,
            settings_applied: true,
            bytes_written: 1,
            bytes_read: 0,
        }),
        observed_port: None,
        observed_settings: None,
    };

    let (_, report) = run_doctor(
        &manifest(),
        &context(session_id),
        HostPlatform::Windows,
        &[observation("COM8", "SYN-A", "location-1")],
        &mut probe,
    )
    .expect("doctor should produce a blocked report");

    assert_eq!(report.verdict, SerialDoctorVerdict::Blocked);
    assert_eq!(report.failures, vec!["read_only_probe_wrote_bytes"]);
}

#[test]
fn wrong_session_purple_proof_is_rejected() {
    let session_id = Uuid::new_v4();
    let mut wrong = context(session_id);
    wrong.purple_proof.session_id = Uuid::new_v4();
    let mut probe = Probe::ready();

    let error = run_doctor(
        &manifest(),
        &wrong,
        HostPlatform::Windows,
        &[observation("COM8", "SYN-A", "location-1")],
        &mut probe,
    )
    .expect_err("wrong-session proof must fail");

    assert_eq!(error, SerialDoctorError::UnverifiedPurpleSession);
}

#[test]
fn broad_or_missing_permissions_are_rejected() {
    let session_id = Uuid::new_v4();
    let mut wrong = context(session_id);
    wrong.granted_permissions.insert(Permission::SerialWrite);
    let mut probe = Probe::ready();

    let error = run_doctor(
        &manifest(),
        &wrong,
        HostPlatform::Windows,
        &[observation("COM8", "SYN-A", "location-1")],
        &mut probe,
    )
    .expect_err("permission superset must not be accepted");

    assert_eq!(error, SerialDoctorError::PermissionGrantMismatch);
}

#[test]
fn ready_report_acquires_exclusive_serial_and_usb_resources() {
    let session_id = Uuid::new_v4();
    let mut probe = Probe::ready();
    let (_, report) = run_doctor(
        &manifest(),
        &context(session_id),
        HostPlatform::Windows,
        &[observation("COM8", "SYN-A", "location-1")],
        &mut probe,
    )
    .expect("doctor should pass");

    let owner = LeaseOwner {
        session_id,
        worker_id: "serial-doctor".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let first = acquire_serial_lease(&mut leases, &report, owner.clone(), 10, 30)
        .expect("first lease should pass");
    assert_eq!(first.resources.len(), 2);

    let conflict = acquire_serial_lease(&mut leases, &report, owner, 11, 30)
        .expect_err("second lease should conflict");
    assert!(matches!(conflict, SerialDoctorError::Lease(_)));
}

#[test]
fn port_renumbering_preserves_exact_hardware_identity() {
    let before = select_candidate(
        &manifest(),
        HostPlatform::Windows,
        &[observation("COM8", "SYN-A", "location-1")],
    )
    .expect("before candidate");
    let after = select_candidate(
        &manifest(),
        HostPlatform::Windows,
        &[observation("COM19", "SYN-A", "location-1")],
    )
    .expect("after candidate");

    assert_eq!(
        verify_reconnect(&before.receipt, &after.receipt),
        Ok(ReconnectContinuity::ExactFingerprint)
    );
}

#[test]
fn same_usb_location_can_recover_when_adapter_serial_changes() {
    let before = select_candidate(
        &manifest(),
        HostPlatform::Linux,
        &[observation("/dev/ttyUSB0", "SERIAL-A", "1-4")],
    )
    .expect("before candidate");
    let after = select_candidate(
        &manifest(),
        HostPlatform::Linux,
        &[observation("/dev/ttyUSB1", "SERIAL-B", "1-4")],
    )
    .expect("after candidate");

    assert_eq!(
        verify_reconnect(&before.receipt, &after.receipt),
        Ok(ReconnectContinuity::SameUsbLocation)
    );
}

#[test]
fn changed_usb_location_is_rejected() {
    let before = select_candidate(
        &manifest(),
        HostPlatform::Linux,
        &[observation("/dev/ttyUSB0", "SERIAL-A", "1-4")],
    )
    .expect("before candidate");
    let after = select_candidate(
        &manifest(),
        HostPlatform::Linux,
        &[observation("/dev/ttyUSB1", "SERIAL-B", "1-5")],
    )
    .expect("after candidate");

    assert_eq!(
        verify_reconnect(&before.receipt, &after.receipt),
        Err(SerialDoctorError::ReconnectIdentityMismatch)
    );
}
