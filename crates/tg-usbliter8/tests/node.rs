use std::collections::BTreeSet;

use tg_apple_observe::{
    default_apple_dfu_rule, lock_identity, observe, ObservationCatalog, ObservationSource,
    RawUsbObservation,
};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_usbliter8::{
    build_pwn_plan, finalize_pwn_proof, parse_board_log, required_permissions,
    validate_node_manifest, BoardModel, HostReconnectAcknowledgement, McuFamily,
    PhysicalHandoffAcknowledgement, PwnDfuRequest, Usbliter8Error, Usbliter8NodeManifest,
    USBLITER8_NODE_VERSION,
};
use uuid::Uuid;

const ECID_A: &str = "DEADBEEF00000001";
const ECID_B: &str = "DEADBEEF00000002";
const DFU_SERIAL_A: &str = "CPID:8020 ECID:DEADBEEF00000001";
const PWND_SERIAL_A: &str = "CPID:8020 ECID:DEADBEEF00000001 PWND:[usbliter8]";

fn manifest(
    mcu_family: McuFamily,
    maturity: Maturity,
    firmware_hash: Option<String>,
) -> Usbliter8NodeManifest {
    Usbliter8NodeManifest {
        schema_version: USBLITER8_NODE_VERSION.to_owned(),
        node_id: "usbliter8.waveshare-rp2350-usb-a".to_owned(),
        firmware_version: "1.0.0-research".to_owned(),
        mcu_family,
        board_model: BoardModel::WaveshareRp2350UsbA,
        source_repository: "https://github.com/prdgmshift/usbliter8".to_owned(),
        source_commit: "afe8b5c8998fce63e76c0b2a88c606c61e2950c7".to_owned(),
        declared_licence: Some("research-source-review-required".to_owned()),
        uf2_sha256: firmware_hash,
        supported_cpids: BTreeSet::from(["8006".to_owned(), "8020".to_owned(), "8030".to_owned()]),
        hardware_verified_cpids: BTreeSet::from(["8020".to_owned()]),
        maturity,
        auto_mode: true,
        required_hardware: BTreeSet::from([
            "rp2350_usb_host".to_owned(),
            "short_lightning_usb_a_cable".to_owned(),
        ]),
        requested_permissions: required_permissions(),
        proof_requirements: [
            "board_firmware_hash_verified",
            "board_dfu_identity_verified",
            "board_success_marker",
            "board_self_verified_pwnd",
            "host_pwnd_reconnect_verified",
            "same_device_identity",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

fn raw(serial: &str) -> RawUsbObservation {
    RawUsbObservation {
        vendor_id: 0x05ac,
        product_id: 0x1227,
        serial: Some(serial.to_owned()),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        source: ObservationSource::RecordedFixture,
    }
}

fn observed(serial: &str) -> tg_apple_observe::ObservedAppleDevice {
    observe(
        &ObservationCatalog {
            rules: vec![default_apple_dfu_rule()],
        },
        &raw(serial),
    )
    .unwrap()
}

fn locked() -> tg_apple_observe::LockedDeviceIdentity {
    lock_identity(&observed(DFU_SERIAL_A)).unwrap()
}

fn request(node_id: &str) -> PwnDfuRequest {
    PwnDfuRequest {
        session_id: Uuid::new_v4(),
        node_id: node_id.to_owned(),
        locked_identity: locked(),
        expected_cpid: "0x8020".to_owned(),
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        handoff: PhysicalHandoffAcknowledgement {
            host_dfu_observed: true,
            disconnected_from_host: true,
            connected_to_board: true,
            direct_lightning_usb_a_path: true,
            board_power_cycled_for_session: true,
        },
        granted_permissions: required_permissions(),
    }
}

fn success_log() -> Vec<u8> {
    b"============ usbliter8 v1.0 ============\ngot Apple DFU device:\nCPID:8020 CPRV:11 CPFM:03 ECID:DEADBEEF00000001\ngot Apple DFU device:\nCPID:8020 CPRV:11 CPFM:03 ECID:DEADBEEF00000001 PWND:[usbliter8]\ntook - 812ms\nexploit SUCCESS!\n".to_vec()
}

#[test]
fn development_plan_requires_pinned_firmware_and_complete_handoff() {
    let pinned = manifest(
        McuFamily::Rp2350,
        Maturity::Discovered,
        Some("11".repeat(32)),
    );
    let plan = build_pwn_plan(&pinned, &request(&pinned.node_id)).unwrap();

    assert_eq!(plan.expected_cpid, "8020");
    assert_eq!(plan.firmware_sha256, "11".repeat(32));
    assert_eq!(plan.granted_permissions, required_permissions());
    assert_eq!(
        plan.stages.last().unwrap(),
        &tg_usbliter8::NodeStage::VerifyHostPwndDfu
    );

    let unpinned = manifest(McuFamily::Rp2350, Maturity::Discovered, None);
    assert_eq!(
        build_pwn_plan(&unpinned, &request(&unpinned.node_id)),
        Err(Usbliter8Error::UnpinnedFirmware)
    );
}

#[test]
fn missing_usb_write_permission_blocks_before_handoff() {
    let node = manifest(
        McuFamily::Rp2350,
        Maturity::Discovered,
        Some("22".repeat(32)),
    );
    let mut request = request(&node.node_id);
    request.granted_permissions.remove(&Permission::UsbWrite);

    assert_eq!(
        build_pwn_plan(&node, &request),
        Err(Usbliter8Error::MissingPermissions(vec![
            Permission::UsbWrite
        ]))
    );
}

#[test]
fn incomplete_physical_handoff_is_blocked() {
    let node = manifest(
        McuFamily::Rp2350,
        Maturity::Discovered,
        Some("33".repeat(32)),
    );
    let mut request = request(&node.node_id);
    request.handoff.direct_lightning_usb_a_path = false;

    assert_eq!(
        build_pwn_plan(&node, &request),
        Err(Usbliter8Error::IncompletePhysicalHandoff)
    );
}

#[test]
fn rp2040_cannot_claim_a13_hardware_verification() {
    let mut node = manifest(
        McuFamily::Rp2040,
        Maturity::HardwareTested,
        Some("44".repeat(32)),
    );
    node.board_model = BoardModel::RaspberryPiPico;
    node.hardware_verified_cpids.insert("8030".to_owned());

    assert_eq!(
        validate_node_manifest(&node, "development"),
        Err(Usbliter8Error::A13CannotBeVerifiedOnRp2040)
    );
}

#[test]
fn board_log_requires_self_verified_success() {
    let evidence = parse_board_log(&success_log()).unwrap();
    assert_eq!(evidence.initial_cpid.as_deref(), Some("8020"));
    assert_eq!(evidence.post_exploit_cpid.as_deref(), Some("8020"));
    assert!(!evidence.initially_pwned);
    assert!(evidence.post_exploit_pwnd_observed);
    assert!(evidence.success_marker);
    assert!(evidence.self_verified_pwnd);
    assert_eq!(evidence.elapsed_millis, Some(812));
    assert!(!evidence.log_sha256.contains(ECID_A));
}

#[test]
fn contradictory_board_log_is_rejected() {
    let log = b"got Apple DFU device:\nCPID:8020 ECID:DEADBEEF00000001\nexploit SUCCESS!\nexploit FAILED!\n";
    assert_eq!(
        parse_board_log(log),
        Err(Usbliter8Error::ContradictoryBoardLog)
    );
}

#[test]
fn unsupported_cpid_log_never_becomes_self_verified() {
    let log = b"got Apple DFU device:\nCPID:8040 ECID:DEADBEEF00000001\nT8040 is not supported (yet?)\nexploit FAILED!\n";
    let evidence = parse_board_log(log).unwrap();
    assert_eq!(evidence.unsupported_cpid.as_deref(), Some("8040"));
    assert!(!evidence.self_verified_pwnd);
}

#[test]
fn board_success_plus_same_host_pwnd_reconnect_proves_stage() {
    let node = manifest(
        McuFamily::Rp2350,
        Maturity::Discovered,
        Some("55".repeat(32)),
    );
    let request = request(&node.node_id);
    let plan = build_pwn_plan(&node, &request).unwrap();
    let board = parse_board_log(&success_log()).unwrap();
    let host = observed(PWND_SERIAL_A);

    let proof = finalize_pwn_proof(
        &plan,
        &request.locked_identity,
        &board,
        &HostReconnectAcknowledgement {
            disconnected_from_board: true,
            reconnected_to_host: true,
        },
        &host,
    );

    assert!(proof.verified);
    assert!(proof.failures.is_empty());
    assert_eq!(proof.host_mode, DeviceMode::PwnedDfu);
    assert_eq!(proof.host_pwn_provider.as_deref(), Some("usbliter8"));
}

#[test]
fn different_host_device_blocks_even_after_board_success() {
    let node = manifest(
        McuFamily::Rp2350,
        Maturity::Discovered,
        Some("66".repeat(32)),
    );
    let request = request(&node.node_id);
    let plan = build_pwn_plan(&node, &request).unwrap();
    let board = parse_board_log(&success_log()).unwrap();
    let different_serial = PWND_SERIAL_A.replace(ECID_A, ECID_B);
    let host = observed(&different_serial);

    let proof = finalize_pwn_proof(
        &plan,
        &request.locked_identity,
        &board,
        &HostReconnectAcknowledgement {
            disconnected_from_board: true,
            reconnected_to_host: true,
        },
        &host,
    );

    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("ECID mismatch")));
}

#[test]
fn host_without_usbliter8_marker_blocks_board_success() {
    let node = manifest(
        McuFamily::Rp2350,
        Maturity::Discovered,
        Some("77".repeat(32)),
    );
    let request = request(&node.node_id);
    let plan = build_pwn_plan(&node, &request).unwrap();
    let board = parse_board_log(&success_log()).unwrap();
    let host = observed(DFU_SERIAL_A);

    let proof = finalize_pwn_proof(
        &plan,
        &request.locked_identity,
        &board,
        &HostReconnectAcknowledgement {
            disconnected_from_board: true,
            reconnected_to_host: true,
        },
        &host,
    );

    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("pwned DFU")));
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("PWND provider")));
}
