use std::collections::BTreeSet;

use tg_contracts::{Maturity, Permission};
use tg_serial_doctor::{
    required_permissions, summarize_candidates, validate_manifest, HostPlatform,
    RawSerialPortObservation, SerialDoctorError, SerialDoctorManifest, SerialMatchRule,
    SerialParity, SerialSettings, SerialStopBits, SERIAL_DOCTOR_VERSION,
};
use tg_syscfg_serial::SerialLink;

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
            rule_id: "bounded-synthetic-rule".to_owned(),
            link: SerialLink::UsbSerial,
            host: Some(HostPlatform::Linux),
            vid: Some(0x1209),
            pid: Some(0x0001),
            manufacturer_contains: None,
            product_contains: Some("Synthetic".to_owned()),
            settings: settings(),
            priority: 10,
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

#[test]
fn simulation_provider_cannot_claim_stable_policy() {
    assert_eq!(
        validate_manifest(&manifest(), "stable"),
        Err(SerialDoctorError::ImmatureStableProvider)
    );
}

#[test]
fn permission_superset_is_not_an_exact_contract() {
    let mut invalid = manifest();
    invalid.requested_permissions.insert(Permission::SerialWrite);
    assert_eq!(
        validate_manifest(&invalid, "development"),
        Err(SerialDoctorError::PermissionContractMismatch)
    );
}

#[test]
fn unbounded_rule_is_rejected() {
    let mut invalid = manifest();
    invalid.rules[0].vid = None;
    invalid.rules[0].pid = None;
    invalid.rules[0].product_contains = None;
    assert_eq!(
        validate_manifest(&invalid, "development"),
        Err(SerialDoctorError::UnboundedMatchRule(
            "bounded-synthetic-rule".to_owned()
        ))
    );
}

#[test]
fn incomplete_usb_identity_is_rejected() {
    let mut invalid = manifest();
    invalid.rules[0].pid = None;
    assert_eq!(
        validate_manifest(&invalid, "development"),
        Err(SerialDoctorError::IncompleteUsbIdentity(
            "bounded-synthetic-rule".to_owned()
        ))
    );
}

#[test]
fn candidate_summary_contains_no_raw_port_or_serial_values() {
    let observations = vec![RawSerialPortObservation {
        port_name: "/dev/ttyUSB-secret".to_owned(),
        vid: Some(0x1209),
        pid: Some(0x0001),
        serial_number: Some("PRIVATE-SERIAL".to_owned()),
        manufacturer: Some("Synthetic".to_owned()),
        product: Some("Synthetic Adapter".to_owned()),
        physical_location: Some("private-location".to_owned()),
    }];

    let summary = summarize_candidates(&observations);
    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert_eq!(summary.get("1209:0001"), Some(&1));
    assert!(!encoded.contains("ttyUSB-secret"));
    assert!(!encoded.contains("PRIVATE-SERIAL"));
    assert!(!encoded.contains("private-location"));
}
