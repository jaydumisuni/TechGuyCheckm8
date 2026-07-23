use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tg_apple_observe::{LockedDeviceIdentity, ObservationSource, ObservedAppleDevice};
use tg_contracts::{DeviceMode, Maturity};
use tg_gaster_provider::{
    build_pwn_plan, execute_action, required_permissions, sha256_file, validate_manifest,
    verify_pwnd_reconnect, GasterAction, GasterExecutionRequest, GasterPlanRequest,
    GasterProviderManifest, GASTER_LICENCE, GASTER_PROVIDER_VERSION, GASTER_SOURCE_COMMIT,
    GASTER_SOURCE_REPOSITORY,
};
use tg_process::ProcessPolicy;
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

fn observation(mode: DeviceMode, provider: Option<&str>) -> ObservedAppleDevice {
    ObservedAppleDevice {
        schema_version: "tgcheckm8.apple-observe.v1".to_owned(),
        rule_id: Some("apple.dfu.05ac-1227".to_owned()),
        mode,
        cpid: Some("8015".to_owned()),
        ecid_hash: Some("e".repeat(64)),
        serial_hash: Some("s".repeat(64)),
        pwn_provider: provider.map(str::to_owned),
        product_type: Some("iPhone10,6".to_owned()),
        board_config: Some("d221ap".to_owned()),
        device_identity_hash: Some("i".repeat(64)),
        source: ObservationSource::RecordedFixture,
        evidence_complete: true,
    }
}

fn manifest(hash: String) -> GasterProviderManifest {
    GasterProviderManifest {
        schema_version: GASTER_PROVIDER_VERSION.to_owned(),
        engine_id: "apple.gaster.a8-a11".to_owned(),
        source_repository: GASTER_SOURCE_REPOSITORY.to_owned(),
        source_commit: GASTER_SOURCE_COMMIT.to_owned(),
        licence: GASTER_LICENCE.to_owned(),
        executable_sha256: Some(hash),
        supported_cpids: BTreeSet::from([
            "7000".to_owned(),
            "7001".to_owned(),
            "8000".to_owned(),
            "8001".to_owned(),
            "8003".to_owned(),
            "8010".to_owned(),
            "8011".to_owned(),
            "8012".to_owned(),
            "8015".to_owned(),
        ]),
        hardware_verified_cpids: BTreeSet::new(),
        maturity: Maturity::SimulationTested,
        requested_permissions: required_permissions(),
        proof_requirements: BTreeSet::from([
            "executable_hash_verified".to_owned(),
            "starting_dfu_identity_locked".to_owned(),
            "gaster_pwn_process_verified".to_owned(),
            "gaster_reset_process_verified".to_owned(),
            "host_pwnd_reconnect_verified".to_owned(),
            "same_device_identity".to_owned(),
        ]),
    }
}

#[cfg(unix)]
fn fake_gaster() -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("tg-gaster-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create temp root");
    let executable = root.join("gaster");
    fs::write(
        &executable,
        "#!/bin/sh\ncase \"$1\" in pwn|reset) echo \"gaster:$1\"; exit 0;; *) exit 64;; esac\n",
    )
    .expect("write fixture");
    let mut permissions = fs::metadata(&executable).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).expect("chmod fixture");
    (root, executable)
}

#[test]
fn unpinned_provider_is_blocked() {
    let mut manifest = manifest("a".repeat(64));
    manifest.executable_sha256 = None;
    let request = GasterPlanRequest {
        session_id: Uuid::new_v4(),
        locked_identity: locked(),
        starting_observation: observation(DeviceMode::Dfu, None),
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
    };

    assert!(build_pwn_plan(&manifest, &request).is_err());
}

#[test]
fn a12_cpid_is_not_in_gaster_coverage() {
    let mut locked = locked();
    locked.cpid = "8020".to_owned();
    let mut start = observation(DeviceMode::Dfu, None);
    start.cpid = Some("8020".to_owned());
    let request = GasterPlanRequest {
        session_id: Uuid::new_v4(),
        locked_identity: locked,
        starting_observation: start,
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
    };

    assert!(build_pwn_plan(&manifest("a".repeat(64)), &request).is_err());
}

#[cfg(unix)]
#[test]
fn fixed_pwn_reset_and_same_device_proof_pass() {
    let (root, executable) = fake_gaster();
    let hash = sha256_file(&executable).expect("hash fixture");
    let manifest = manifest(hash);
    assert!(validate_manifest(&manifest, "development").is_ok());

    let request = GasterPlanRequest {
        session_id: Uuid::new_v4(),
        locked_identity: locked(),
        starting_observation: observation(DeviceMode::Dfu, None),
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
    };
    let plan = build_pwn_plan(&manifest, &request).expect("build plan");
    let policy = ProcessPolicy::new(
        vec![root.clone()],
        root.clone(),
        Duration::from_secs(5),
        Duration::from_millis(10),
        4096,
        4096,
    )
    .expect("process policy");

    let pwn = execute_action(
        &policy,
        &GasterExecutionRequest {
            plan: &plan,
            action: GasterAction::Pwn,
            executable: executable.clone(),
            working_directory: root.clone(),
        },
    )
    .expect("pwn fixture");
    let reset = execute_action(
        &policy,
        &GasterExecutionRequest {
            plan: &plan,
            action: GasterAction::Reset,
            executable,
            working_directory: root.clone(),
        },
    )
    .expect("reset fixture");

    let proof = verify_pwnd_reconnect(
        &plan,
        &request.locked_identity,
        &pwn,
        &reset,
        &observation(DeviceMode::PwnedDfu, Some("checkm8")),
    );
    assert!(proof.verified, "{:?}", proof.blockers);
    assert!(pwn.process_success && reset.process_success);
    assert!(pwn.cleanup_verified && reset.cleanup_verified);
    fs::remove_dir_all(root).expect("remove temp root");
}

#[cfg(unix)]
#[test]
fn executable_hash_change_is_blocked_before_spawn() {
    let (root, executable) = fake_gaster();
    let original_hash = sha256_file(&executable).expect("hash fixture");
    let manifest = manifest(original_hash);
    let request = GasterPlanRequest {
        session_id: Uuid::new_v4(),
        locked_identity: locked(),
        starting_observation: observation(DeviceMode::Dfu, None),
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: required_permissions(),
    };
    let plan = build_pwn_plan(&manifest, &request).expect("build plan");
    fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("modify fixture");
    let policy = ProcessPolicy::new(
        vec![root.clone()],
        root.clone(),
        Duration::from_secs(5),
        Duration::from_millis(10),
        4096,
        4096,
    )
    .expect("process policy");

    let result = execute_action(
        &policy,
        &GasterExecutionRequest {
            plan: &plan,
            action: GasterAction::Pwn,
            executable,
            working_directory: root.clone(),
        },
    );
    assert!(result.is_err());
    fs::remove_dir_all(root).expect("remove temp root");
}
