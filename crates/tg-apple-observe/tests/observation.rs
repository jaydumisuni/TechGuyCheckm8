use std::collections::BTreeSet;

use tg_apple_observe::{
    default_apple_dfu_rule, lock_identity, match_reconnect, observe, ModeRule,
    ObservationCatalog, ObservationError, ObservationSource, RawUsbObservation,
};
use tg_contracts::DeviceMode;

const SYNTHETIC_ECID: &str = "DEADBEEF00000001";
const OTHER_SYNTHETIC_ECID: &str = "DEADBEEF00000002";
const PWND_SERIAL: &str = "CPID:8020 CPRV:11 CPFM:03 SCEP:01 BDID:0E ECID:DEADBEEF00000001 IBFL:3C SRTG:[iBoot-SYNTHETIC] PWND:[usbliter8]";

fn catalog() -> ObservationCatalog {
    ObservationCatalog {
        rules: vec![
            default_apple_dfu_rule(),
            ModeRule {
                rule_id: "fixture.purple".to_owned(),
                vendor_id: 0x05ac,
                product_id: 0x1337,
                mode: DeviceMode::PurpleDiagnostic,
                serial_must_contain: Some("CPID:".to_owned()),
            },
        ],
    }
}

fn dfu(serial: &str) -> RawUsbObservation {
    RawUsbObservation {
        vendor_id: 0x05ac,
        product_id: 0x1227,
        serial: Some(serial.to_owned()),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        source: ObservationSource::RecordedFixture,
    }
}

fn purple(serial: &str) -> RawUsbObservation {
    RawUsbObservation {
        vendor_id: 0x05ac,
        product_id: 0x1337,
        serial: Some(serial.to_owned()),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        source: ObservationSource::RecordedFixture,
    }
}

#[test]
fn usbliter8_marker_promotes_dfu_observation_to_pwned_dfu() {
    let observed = observe(&catalog(), &dfu(PWND_SERIAL)).unwrap();

    assert_eq!(observed.mode, DeviceMode::PwnedDfu);
    assert_eq!(observed.cpid.as_deref(), Some("8020"));
    assert_eq!(observed.pwn_provider.as_deref(), Some("usbliter8"));
    assert!(observed.evidence_complete);
    assert_ne!(observed.ecid_hash.as_deref(), Some(SYNTHETIC_ECID));
    assert_ne!(observed.serial_hash.as_deref(), Some(PWND_SERIAL));
}

#[test]
fn same_device_can_reconnect_from_pwned_dfu_to_purple() {
    let initial = observe(&catalog(), &dfu(PWND_SERIAL)).unwrap();
    let locked = lock_identity(&initial).unwrap();
    let reconnect = observe(&catalog(), &purple(PWND_SERIAL)).unwrap();
    let allowed = BTreeSet::from([DeviceMode::PurpleDiagnostic]);

    let decision = match_reconnect(&locked, &reconnect, &allowed);
    assert!(decision.matched);
    assert!(decision.blockers.is_empty());
}

#[test]
fn different_ecid_is_blocked_even_with_same_pwn_marker() {
    let initial = observe(&catalog(), &dfu(PWND_SERIAL)).unwrap();
    let locked = lock_identity(&initial).unwrap();
    let other_serial = PWND_SERIAL.replace(SYNTHETIC_ECID, OTHER_SYNTHETIC_ECID);
    let reconnect = observe(&catalog(), &purple(&other_serial)).unwrap();
    let allowed = BTreeSet::from([DeviceMode::PurpleDiagnostic]);

    let decision = match_reconnect(&locked, &reconnect, &allowed);
    assert!(!decision.matched);
    assert!(decision
        .blockers
        .iter()
        .any(|blocker| blocker.contains("ECID mismatch")));
}

#[test]
fn unexpected_reconnect_mode_is_blocked() {
    let initial = observe(&catalog(), &dfu(PWND_SERIAL)).unwrap();
    let locked = lock_identity(&initial).unwrap();
    let reconnect = observe(&catalog(), &dfu(PWND_SERIAL)).unwrap();
    let allowed = BTreeSet::from([DeviceMode::PurpleDiagnostic]);

    let decision = match_reconnect(&locked, &reconnect, &allowed);
    assert!(!decision.matched);
    assert!(decision
        .blockers
        .iter()
        .any(|blocker| blocker.contains("unexpected reconnect mode")));
}

#[test]
fn ambiguous_mode_rules_fail_closed() {
    let mut catalog = catalog();
    catalog.rules.push(default_apple_dfu_rule());

    assert!(matches!(
        observe(&catalog, &dfu(PWND_SERIAL)),
        Err(ObservationError::AmbiguousModeRules(rules)) if rules.len() == 2
    ));
}

#[test]
fn unknown_usb_device_is_observed_without_claiming_apple_mode() {
    let raw = RawUsbObservation {
        vendor_id: 0xffff,
        product_id: 0xffff,
        serial: Some("synthetic-unknown".to_owned()),
        product_type: None,
        board_config: None,
        source: ObservationSource::RecordedFixture,
    };

    let observed = observe(&catalog(), &raw).unwrap();
    assert_eq!(observed.mode, DeviceMode::Unknown);
    assert!(!observed.evidence_complete);
    assert!(observed.rule_id.is_none());
}

#[test]
fn incomplete_dfu_identity_cannot_be_locked() {
    let raw = dfu("CPID:8020 PWND:[usbliter8]");
    let observed = observe(&catalog(), &raw).unwrap();

    assert_eq!(
        lock_identity(&observed),
        Err(ObservationError::MissingEcid)
    );
}
