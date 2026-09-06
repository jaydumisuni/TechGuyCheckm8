use std::collections::BTreeSet;

use tg_apple_observe::{LockedDeviceIdentity, ObservationSource, ObservedAppleDevice};
use tg_contracts::DeviceMode;
use tg_gaster_provider::{
    required_permissions, verify_pwnd_reconnect, GasterAction, GasterPwnPlan, GasterRunReceipt,
};
use tg_process::TerminationReason;
use uuid::Uuid;

fn locked() -> LockedDeviceIdentity {
    LockedDeviceIdentity {
        cpid: "8015".to_owned(),
        ecid_hash: "e".repeat(64),
        product_type: Some("iPhone10,6".to_owned()),
        board_config: Some("d221ap".to_owned()),
        identity_hash: "i".repeat(64),
    }
}

fn reconnected() -> ObservedAppleDevice {
    ObservedAppleDevice {
        schema_version: "tgcheckm8.apple-observe.v1".to_owned(),
        rule_id: Some("apple.dfu.05ac-1227".to_owned()),
        mode: DeviceMode::PwnedDfu,
        cpid: Some("8015".to_owned()),
        ecid_hash: Some("e".repeat(64)),
        serial_hash: Some("s".repeat(64)),
        pwn_provider: Some("checkm8".to_owned()),
        product_type: Some("iPhone10,6".to_owned()),
        board_config: Some("d221ap".to_owned()),
        device_identity_hash: Some("i".repeat(64)),
        source: ObservationSource::RecordedFixture,
        evidence_complete: true,
    }
}

fn required_proofs() -> BTreeSet<String> {
    BTreeSet::from([
        "executable_hash_verified".to_owned(),
        "starting_dfu_identity_locked".to_owned(),
        "gaster_pwn_process_verified".to_owned(),
        "gaster_reset_process_verified".to_owned(),
        "host_pwnd_reconnect_verified".to_owned(),
        "same_device_identity".to_owned(),
    ])
}

fn plan(session_id: Uuid) -> GasterPwnPlan {
    GasterPwnPlan {
        session_id,
        engine_id: "apple.gaster.a8-a11".to_owned(),
        normalized_cpid: "8015".to_owned(),
        executable_sha256: "a".repeat(64),
        actions: vec![GasterAction::Pwn, GasterAction::Reset],
        requested_permissions: required_permissions(),
        required_proofs: required_proofs(),
    }
}

fn receipt(session_id: Uuid, action: GasterAction) -> GasterRunReceipt {
    GasterRunReceipt {
        session_id,
        engine_id: "apple.gaster.a8-a11".to_owned(),
        action,
        executable_sha256: "a".repeat(64),
        termination: TerminationReason::Exited,
        status_code: Some(0),
        process_success: true,
        cleanup_verified: true,
        stdout_sha256: "b".repeat(64),
        stderr_sha256: "c".repeat(64),
        stdout_bytes: 8,
        stderr_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        elapsed_millis: 4,
        timeout_millis: 5_000,
        max_stdout_bytes: 4_096,
        max_stderr_bytes: 4_096,
    }
}

#[test]
fn contradictory_timeout_receipt_cannot_prove_pwnd_reconnect() {
    let session_id = Uuid::new_v4();
    let plan = plan(session_id);
    let mut pwn = receipt(session_id, GasterAction::Pwn);
    let reset = receipt(session_id, GasterAction::Reset);
    pwn.termination = TerminationReason::TimeoutKilled;

    let proof = verify_pwnd_reconnect(&plan, &locked(), &pwn, &reset, &reconnected());

    assert!(!proof.verified);
    assert!(proof
        .blockers
        .iter()
        .any(|blocker| blocker.contains("receipt integrity")));
}

#[test]
fn inconsistent_capture_receipt_cannot_prove_pwnd_reconnect() {
    let session_id = Uuid::new_v4();
    let plan = plan(session_id);
    let pwn = receipt(session_id, GasterAction::Pwn);
    let mut reset = receipt(session_id, GasterAction::Reset);
    reset.stdout_bytes = reset.max_stdout_bytes + 1;
    reset.stdout_truncated = false;

    let proof = verify_pwnd_reconnect(&plan, &locked(), &pwn, &reset, &reconnected());

    assert!(!proof.verified);
    assert!(proof
        .blockers
        .iter()
        .any(|blocker| blocker.contains("receipt integrity")));
}

#[test]
fn forged_gaster_plan_cannot_prove_pwnd_reconnect() {
    let session_id = Uuid::new_v4();
    let mut forged_plan = plan(session_id);
    forged_plan.normalized_cpid = "DEAD".to_owned();
    forged_plan.actions.clear();
    forged_plan.requested_permissions.clear();
    forged_plan.required_proofs.clear();
    let pwn = receipt(session_id, GasterAction::Pwn);
    let reset = receipt(session_id, GasterAction::Reset);

    let proof = verify_pwnd_reconnect(&forged_plan, &locked(), &pwn, &reset, &reconnected());

    assert!(!proof.verified);
    assert!(proof
        .blockers
        .iter()
        .any(|blocker| blocker.contains("plan integrity")));
}
