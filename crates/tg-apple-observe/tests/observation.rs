use std::collections::BTreeSet;

use serde::Deserialize;
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
    let serialized = serde_json::to_string(&observed).unwrap();
    assert!(!serialized.contains(SYNTHETIC_ECID));
    assert!(!serialized.contains(PWND_SERIAL));
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

#[derive(Debug, Deserialize)]
struct RecordedFixture {
    synthetic: bool,
    catalog: Vec<ModeRule>,
    observations: Vec<FixtureObservation>,
}

#[derive(Debug, Deserialize)]
struct FixtureObservation {
    name: String,
    vendor_id: u16,
    product_id: u16,
    serial: Option<String>,
    product_type: Option<String>,
    board_config: Option<String>,
    source: ObservationSource,
    expected_mode: DeviceMode,
    expected_pwn_provider: Option<String>,
    expected_identity_match: Option<bool>,
}

impl FixtureObservation {
    fn raw(&self) -> RawUsbObservation {
        RawUsbObservation {
            vendor_id: self.vendor_id,
            product_id: self.product_id,
            serial: self.serial.clone(),
            product_type: self.product_type.clone(),
            board_config: self.board_config.clone(),
            source: self.source.clone(),
        }
    }
}

#[test]
fn synthetic_fixture_proves_pwnd_to_purple_identity_continuity() {
    let fixture: RecordedFixture = serde_json::from_str(include_str!(
        "../../../fixtures/apple/usbliter8-a12-pwnd-to-purple.synthetic.json"
    ))
    .unwrap();
    assert!(fixture.synthetic);

    let catalog = ObservationCatalog {
        rules: fixture.catalog,
    };
    let pwned_fixture = fixture
        .observations
        .iter()
        .find(|observation| observation.name == "pwned_dfu")
        .unwrap();
    let purple_fixture = fixture
        .observations
        .iter()
        .find(|observation| observation.name == "purple_reconnect")
        .unwrap();

    let pwned = observe(&catalog, &pwned_fixture.raw()).unwrap();
    assert_eq!(pwned.mode, pwned_fixture.expected_mode);
    assert_eq!(
        pwned.pwn_provider,
        pwned_fixture.expected_pwn_provider.clone()
    );
    let locked = lock_identity(&pwned).unwrap();

    let purple = observe(&catalog, &purple_fixture.raw()).unwrap();
    assert_eq!(purple.mode, purple_fixture.expected_mode);
    let decision = match_reconnect(
        &locked,
        &purple,
        &BTreeSet::from([DeviceMode::PurpleDiagnostic]),
    );
    assert_eq!(
        decision.matched,
        purple_fixture.expected_identity_match.unwrap_or(false)
    );
    assert!(decision.blockers.is_empty());
}
