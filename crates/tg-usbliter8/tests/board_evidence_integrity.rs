use std::collections::BTreeSet;

use tg_apple_observe::{LockedDeviceIdentity, ObservationSource, ObservedAppleDevice};
use tg_contracts::DeviceMode;
use tg_usbliter8::{
    finalize_pwn_proof, required_permissions, BoardRunEvidence, HostReconnectAcknowledgement,
    NodeStage, PwnDfuPlan,
};
use uuid::Uuid;

fn locked() -> LockedDeviceIdentity {
    LockedDeviceIdentity {
        cpid: "8020".to_owned(),
        ecid_hash: "e".repeat(64),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        identity_hash: "i".repeat(64),
    }
}

fn host_pwnd() -> ObservedAppleDevice {
    ObservedAppleDevice {
        schema_version: "tgcheckm8.apple-observe.v1".to_owned(),
        rule_id: Some("fixture".to_owned()),
        mode: DeviceMode::PwnedDfu,
        cpid: Some("8020".to_owned()),
        ecid_hash: Some("e".repeat(64)),
        serial_hash: Some("s".repeat(64)),
        pwn_provider: Some("usbliter8".to_owned()),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        device_identity_hash: Some("i".repeat(64)),
        source: ObservationSource::RecordedFixture,
        evidence_complete: true,
    }
}

fn valid_plan() -> PwnDfuPlan {
    PwnDfuPlan {
        session_id: Uuid::new_v4(),
        node_id: "usbliter8.waveshare-rp2350-usb-a".to_owned(),
        expected_cpid: "8020".to_owned(),
        firmware_sha256: "a".repeat(64),
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
        granted_permissions: required_permissions(),
        required_proofs: BTreeSet::from([
            "board_firmware_hash_verified".to_owned(),
            "board_dfu_identity_verified".to_owned(),
            "board_success_marker".to_owned(),
            "board_self_verified_pwnd".to_owned(),
            "host_pwnd_reconnect_verified".to_owned(),
            "same_device_identity".to_owned(),
        ]),
    }
}

#[test]
fn forged_board_log_receipt_cannot_produce_verified_pwnd_proof() {
    let plan = valid_plan();
    let board = BoardRunEvidence {
        log_sha256: "not-a-sha256".to_owned(),
        log_bytes: 0,
        initial_cpid: Some("8020".to_owned()),
        post_exploit_cpid: Some("8020".to_owned()),
        initially_pwned: false,
        post_exploit_pwnd_observed: true,
        success_marker: true,
        failure_marker: false,
        rediscovery_failed: false,
        unsupported_cpid: None,
        elapsed_millis: Some(1),
        self_verified_pwnd: true,
    };
    let reconnect = HostReconnectAcknowledgement {
        disconnected_from_board: true,
        reconnected_to_host: true,
    };

    let proof = finalize_pwn_proof(&plan, &locked(), &board, &reconnect, &host_pwnd());

    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("board evidence integrity")));
}
