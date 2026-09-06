use std::collections::BTreeSet;

use tg_apple_observe::{LockedDeviceIdentity, ObservationSource, ObservedAppleDevice};
use tg_contracts::DeviceMode;
use tg_purple_boot::{finalize_purple_boot, PurpleBootPlan, PurpleBootRunEvidence};
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

fn observation(mode: DeviceMode) -> ObservedAppleDevice {
    ObservedAppleDevice {
        schema_version: "tgcheckm8.apple-observe.v1".to_owned(),
        rule_id: Some("fixture".to_owned()),
        mode,
        cpid: Some("8020".to_owned()),
        ecid_hash: Some("e".repeat(64)),
        serial_hash: Some("s".repeat(64)),
        pwn_provider: None,
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        device_identity_hash: Some("i".repeat(64)),
        source: ObservationSource::RecordedFixture,
        evidence_complete: true,
    }
}

#[test]
fn forged_empty_plan_cannot_produce_verified_purple_proof() {
    let session_id = Uuid::new_v4();
    let plan = PurpleBootPlan {
        session_id,
        route_id: "forged-empty-plan".to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        cpid: "8020".to_owned(),
        pwn_provider: "usbliter8".to_owned(),
        artifacts: vec![],
        environment_backup_sha256: "not-a-sha256".to_owned(),
        cleanup_required: false,
        steps: vec![],
        granted_permissions: BTreeSet::new(),
        required_proofs: BTreeSet::new(),
    };
    let evidence = PurpleBootRunEvidence {
        session_id,
        route_id: plan.route_id.clone(),
        step_receipts: vec![],
        artifact_receipts: vec![],
        recovery_observation: observation(DeviceMode::Recovery),
        purple_observation: observation(DeviceMode::PurpleDiagnostic),
    };

    let proof = finalize_purple_boot(&plan, &locked(), &evidence);

    assert!(!proof.verified);
    assert!(proof
        .failures
        .iter()
        .any(|failure| failure.contains("plan integrity")));
}
