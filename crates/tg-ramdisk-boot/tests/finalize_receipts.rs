use std::collections::{BTreeMap, BTreeSet};

use tg_apple_route_reference::{PwnProvider, RouteEnvironment};
use tg_contracts::Maturity;
use tg_ramdisk_boot::{finalize_runtime, RamdiskBootRuntime};
use tg_ramdisk_pack::{
    AssetRole, BootCheckpoint, BootStep, FixedRecoveryCommand, RamdiskProviderPack,
    RAMDISK_PACK_VERSION,
};
use uuid::Uuid;

fn pack() -> RamdiskProviderPack {
    RamdiskProviderPack {
        schema_version: RAMDISK_PACK_VERSION.to_owned(),
        pack_id: "receipt-order-proof".to_owned(),
        route_reference_profile_id: "apple:a8-a11:gaster-reference".to_owned(),
        product_type: "iPhone10,6".to_owned(),
        board_config: "d221ap".to_owned(),
        cpid: "8015".to_owned(),
        firmware_build: "20H350".to_owned(),
        environment: RouteEnvironment::Ramdisk,
        pwn_provider: PwnProvider::Gaster,
        source_references: vec![],
        assets: BTreeMap::new(),
        boot_steps: vec![
            BootStep::RequireCheckpoint(BootCheckpoint::PwnedDfuVerified),
            BootStep::SendAsset(AssetRole::IBss),
            BootStep::RecoveryCommand(FixedRecoveryCommand::Go),
            BootStep::ProveCheckpoint(BootCheckpoint::RamdiskReady),
        ],
        maturity: Maturity::SimulationTested,
        hardware_transcript_sha256: None,
        recovery_proof_sha256: None,
    }
}

#[test]
fn final_proof_rejects_missing_process_receipts_even_when_progress_is_complete() {
    let pack = pack();
    let runtime = RamdiskBootRuntime {
        session_id: Uuid::new_v4(),
        pack_id: pack.pack_id.clone(),
        product_type: pack.product_type.clone(),
        board_config: pack.board_config.clone(),
        cpid: pack.cpid.clone(),
        firmware_build: pack.firmware_build.clone(),
        irecovery_sha256: "a".repeat(64),
        next_step: pack.boot_steps.len(),
        completed_checkpoints: BTreeSet::from([
            BootCheckpoint::PwnedDfuVerified,
            BootCheckpoint::RamdiskReady,
        ]),
        process_receipts: vec![],
        checkpoint_hashes: BTreeMap::from([(BootCheckpoint::RamdiskReady, "b".repeat(64))]),
        failed: false,
        failure: None,
    };

    let proof = finalize_runtime(&runtime, &pack);

    assert!(!proof.verified);
    assert!(proof
        .blockers
        .iter()
        .any(|blocker| blocker.contains("process receipt sequence")));
}
