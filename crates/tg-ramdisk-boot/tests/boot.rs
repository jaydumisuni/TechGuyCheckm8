use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tg_apple_observe::LockedDeviceIdentity;
use tg_apple_route_reference::{PwnProvider, RouteEnvironment};
use tg_contracts::{DeviceMode, Maturity};
use tg_gaster_provider::GasterFinalProof;
use tg_process::ProcessPolicy;
use tg_ramdisk_boot::{
    acknowledge_checkpoint, acknowledge_wait, execute_current_process_step, finalize_runtime,
    next_instruction, required_permissions, sha256_file, start_runtime, BootInstallation,
    BootStartRequest, CheckpointEvidence, IRecoveryProviderManifest, NextInstruction,
    IRECOVERY_LICENCE, IRECOVERY_SOURCE_COMMIT, IRECOVERY_SOURCE_REPOSITORY, RAMDISK_BOOT_VERSION,
};
use tg_ramdisk_pack::{
    classify_and_hash_asset, sshrd_boot_steps, AssetRecord, AssetRole, BootCheckpoint,
    RamdiskProviderPack, SourceReference, RAMDISK_PACK_VERSION, SSHRD_LICENCE, SSHRD_SOURCE_COMMIT,
    SSHRD_SOURCE_REPOSITORY,
};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    asset_root: PathBuf,
    irecovery: PathBuf,
    pack: RamdiskProviderPack,
    manifest: IRecoveryProviderManifest,
    gaster_proof: GasterFinalProof,
    identity: LockedDeviceIdentity,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn fixture() -> Fixture {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("tg-ramdisk-boot-{}", Uuid::new_v4()));
    let asset_root = root.join("assets-root");
    let bin_root = root.join("bin");
    fs::create_dir_all(asset_root.join("assets")).expect("create asset root");
    fs::create_dir_all(&bin_root).expect("create bin root");

    let irecovery = bin_root.join("irecovery");
    fs::write(
        &irecovery,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> irecovery-calls.log\nexit 0\n",
    )
    .expect("write irecovery fixture");
    let mut permissions = fs::metadata(&irecovery).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&irecovery, permissions).expect("chmod fixture");

    let file_bytes: Vec<(&str, &[u8])> = vec![
        ("assets/iBSS.img4", b"ibss"),
        ("assets/iBEC.img4", b"ibec"),
        ("assets/ramdisk.img4", b"ramdisk"),
        ("assets/devicetree.img4", b"devicetree"),
        ("assets/kernelcache.img4", b"kernelcache"),
    ];
    let mut assets = BTreeMap::<AssetRole, AssetRecord>::new();
    for (relative, bytes) in file_bytes {
        let path = asset_root.join(relative);
        fs::write(&path, bytes).expect("write asset");
        let record = classify_and_hash_asset(relative, bytes).expect("classify asset");
        assets.insert(record.role.clone(), record);
    }

    let pack = RamdiskProviderPack {
        schema_version: RAMDISK_PACK_VERSION.to_owned(),
        pack_id: "iphone10,6-d221ap-20h350-sshrd".to_owned(),
        route_reference_profile_id: "apple:a8-a11:gaster-reference".to_owned(),
        product_type: "iPhone10,6".to_owned(),
        board_config: "d221ap".to_owned(),
        cpid: "8015".to_owned(),
        firmware_build: "20H350".to_owned(),
        environment: RouteEnvironment::Ramdisk,
        pwn_provider: PwnProvider::Gaster,
        source_references: vec![
            SourceReference {
                source_id: "gaster".to_owned(),
                repository: "https://github.com/0x7ff/gaster".to_owned(),
                commit: "7fffffff38a1bed1cdc1c5bae0df70f14395129b".to_owned(),
                licence: "Apache-2.0".to_owned(),
                role: "pwned_dfu_provider".to_owned(),
            },
            SourceReference {
                source_id: "sshrd-script".to_owned(),
                repository: SSHRD_SOURCE_REPOSITORY.to_owned(),
                commit: SSHRD_SOURCE_COMMIT.to_owned(),
                licence: SSHRD_LICENCE.to_owned(),
                role: "known_working_build_and_boot_recipe".to_owned(),
            },
        ],
        boot_steps: sshrd_boot_steps("8015", false, false, RouteEnvironment::Ramdisk)
            .expect("known recipe"),
        assets,
        maturity: Maturity::SimulationTested,
        hardware_transcript_sha256: None,
        recovery_proof_sha256: None,
    };

    let manifest = IRecoveryProviderManifest {
        schema_version: RAMDISK_BOOT_VERSION.to_owned(),
        provider_id: "apple.irecovery.fixed-boot".to_owned(),
        source_repository: IRECOVERY_SOURCE_REPOSITORY.to_owned(),
        source_commit: IRECOVERY_SOURCE_COMMIT.to_owned(),
        licence: IRECOVERY_LICENCE.to_owned(),
        executable_sha256: Some(sha256_file(&irecovery).expect("hash irecovery")),
        maturity: Maturity::SimulationTested,
        requested_permissions: required_permissions(),
        proof_requirements: BTreeSet::from([
            "irecovery_hash_verified".to_owned(),
            "asset_hash_verified_before_send".to_owned(),
            "fixed_step_order_enforced".to_owned(),
            "process_cleanup_verified".to_owned(),
            "same_device_checkpoints".to_owned(),
            "final_environment_verified".to_owned(),
        ]),
    };
    let session_id = Uuid::new_v4();
    let gaster_proof = GasterFinalProof {
        session_id,
        engine_id: "apple.gaster.a8-a11".to_owned(),
        verified: true,
        normalized_cpid: "8015".to_owned(),
        pwn_provider: Some("checkm8".to_owned()),
        observed_mode: DeviceMode::PwnedDfu,
        blockers: vec![],
    };
    let identity = LockedDeviceIdentity {
        cpid: "8015".to_owned(),
        ecid_hash: "e".repeat(64),
        product_type: Some("iPhone10,6".to_owned()),
        board_config: Some("d221ap".to_owned()),
        identity_hash: "i".repeat(64),
    };

    Fixture {
        root,
        asset_root,
        irecovery,
        pack,
        manifest,
        gaster_proof,
        identity,
    }
}

#[cfg(unix)]
fn process_policy(fixture: &Fixture) -> ProcessPolicy {
    ProcessPolicy::new(
        vec![fixture
            .irecovery
            .parent()
            .expect("bin parent")
            .to_path_buf()],
        fixture.root.clone(),
        Duration::from_secs(5),
        Duration::from_millis(10),
        4096,
        4096,
    )
    .expect("process policy")
}

#[cfg(unix)]
fn start(fixture: &Fixture) -> tg_ramdisk_boot::RamdiskBootRuntime {
    start_runtime(BootStartRequest {
        session_id: fixture.gaster_proof.session_id,
        pack: &fixture.pack,
        irecovery_manifest: &fixture.manifest,
        gaster_proof: &fixture.gaster_proof,
        locked_identity: &fixture.identity,
        installation: &BootInstallation {
            irecovery_executable: fixture.irecovery.clone(),
            working_directory: fixture.root.clone(),
            asset_root: fixture.asset_root.clone(),
        },
        authorized_device_service: true,
        explicit_operator_authorization: true,
        usb_lease_verified: true,
        granted_permissions: &required_permissions(),
        policy_profile: "development",
    })
    .expect("start runtime")
}

#[cfg(unix)]
#[test]
fn complete_known_recipe_runs_fixed_commands_and_proves_environment() {
    let fixture = fixture();
    let policy = process_policy(&fixture);
    let installation = BootInstallation {
        irecovery_executable: fixture.irecovery.clone(),
        working_directory: fixture.root.clone(),
        asset_root: fixture.asset_root.clone(),
    };
    let mut runtime = start(&fixture);

    loop {
        match next_instruction(&runtime, &fixture.pack) {
            NextInstruction::ProcessRequired { .. } => {
                execute_current_process_step(&policy, &mut runtime, &fixture.pack, &installation)
                    .expect("process step");
            }
            NextInstruction::WaitRequired { millis, .. } => {
                acknowledge_wait(&mut runtime, &fixture.pack, millis).expect("wait");
            }
            NextInstruction::CheckpointRequired { checkpoint, .. } => {
                let (mode, marker) = match checkpoint {
                    BootCheckpoint::PatchedIbootReady => {
                        (DeviceMode::Recovery, "patched_iboot_ready")
                    }
                    BootCheckpoint::RamdiskReady => (DeviceMode::RamdiskSsh, "sshrd_ready"),
                    other => panic!("unexpected checkpoint: {other:?}"),
                };
                acknowledge_checkpoint(
                    &mut runtime,
                    &fixture.pack,
                    CheckpointEvidence {
                        checkpoint,
                        same_device: true,
                        observed_mode: mode,
                        environment_marker: marker.to_owned(),
                        evidence_sha256: "a".repeat(64),
                    },
                )
                .expect("checkpoint");
            }
            NextInstruction::Complete => break,
            NextInstruction::Failed { reason } => panic!("runtime failed: {reason}"),
        }
    }

    let proof = finalize_runtime(&runtime, &fixture.pack);
    assert!(proof.verified, "{:?}", proof.blockers);
    let calls =
        fs::read_to_string(fixture.root.join("irecovery-calls.log")).expect("read call transcript");
    assert!(calls
        .lines()
        .any(|line| line.starts_with("-f ") && line.contains("iBSS.img4")));
    assert!(calls.lines().any(|line| line == "-c go"));
    assert!(calls.lines().any(|line| line == "-c ramdisk"));
    assert!(calls.lines().any(|line| line == "-c devicetree"));
    assert!(calls.lines().any(|line| line == "-c bootx"));
    assert!(!calls.contains(";"));
}

#[cfg(unix)]
#[test]
fn changed_asset_is_blocked_before_send() {
    let fixture = fixture();
    let policy = process_policy(&fixture);
    let installation = BootInstallation {
        irecovery_executable: fixture.irecovery.clone(),
        working_directory: fixture.root.clone(),
        asset_root: fixture.asset_root.clone(),
    };
    let mut runtime = start(&fixture);
    fs::write(fixture.asset_root.join("assets/iBSS.img4"), b"changed").expect("change asset");

    assert!(
        execute_current_process_step(&policy, &mut runtime, &fixture.pack, &installation).is_err()
    );
    assert!(!fixture.root.join("irecovery-calls.log").exists());
}

#[cfg(unix)]
#[test]
fn short_wait_does_not_advance() {
    let fixture = fixture();
    let policy = process_policy(&fixture);
    let installation = BootInstallation {
        irecovery_executable: fixture.irecovery.clone(),
        working_directory: fixture.root.clone(),
        asset_root: fixture.asset_root.clone(),
    };
    let mut runtime = start(&fixture);
    execute_current_process_step(&policy, &mut runtime, &fixture.pack, &installation)
        .expect("send ibss");
    let before = runtime.next_step;
    assert!(acknowledge_wait(&mut runtime, &fixture.pack, 1_999).is_err());
    assert_eq!(runtime.next_step, before);
}

#[cfg(unix)]
#[test]
fn wrong_device_checkpoint_is_rejected() {
    let fixture = fixture();
    let policy = process_policy(&fixture);
    let installation = BootInstallation {
        irecovery_executable: fixture.irecovery.clone(),
        working_directory: fixture.root.clone(),
        asset_root: fixture.asset_root.clone(),
    };
    let mut runtime = start(&fixture);
    execute_current_process_step(&policy, &mut runtime, &fixture.pack, &installation)
        .expect("send ibss");
    acknowledge_wait(&mut runtime, &fixture.pack, 2_000).expect("wait");
    execute_current_process_step(&policy, &mut runtime, &fixture.pack, &installation)
        .expect("send ibec");
    execute_current_process_step(&policy, &mut runtime, &fixture.pack, &installation).expect("go");
    acknowledge_wait(&mut runtime, &fixture.pack, 2_000).expect("wait");

    assert!(acknowledge_checkpoint(
        &mut runtime,
        &fixture.pack,
        CheckpointEvidence {
            checkpoint: BootCheckpoint::PatchedIbootReady,
            same_device: false,
            observed_mode: DeviceMode::Recovery,
            environment_marker: "patched_iboot_ready".to_owned(),
            evidence_sha256: "b".repeat(64),
        }
    )
    .is_err());
}
