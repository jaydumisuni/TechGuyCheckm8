use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use tg_cli::{execute, CliError};
use tg_contracts::{
    EngineManifest, FailureBehavior, Maturity, Permission, Provenance, CONTRACT_VERSION,
};
use tg_journal::Journal;
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tg-cli-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest(maturity: Maturity) -> EngineManifest {
    EngineManifest {
        schema_version: CONTRACT_VERSION.to_owned(),
        engine_id: "fixture-engine".to_owned(),
        version: "1.0.0".to_owned(),
        maturity,
        capabilities: BTreeSet::from(["health".to_owned()]),
        requested_permissions: BTreeSet::from([Permission::DeviceObserve]),
        supported_hosts: BTreeSet::from(["linux".to_owned()]),
        executes_external_code: false,
        requires_network: false,
        modifies_device: false,
        provenance: Provenance {
            source_repository: "owner/repo".to_owned(),
            source_commit: "0123456789abcdef".to_owned(),
            source_release: None,
            licence: "MIT".to_owned(),
            local_patch_hash: None,
            build_recipe_hash: None,
            artifact_hashes: BTreeMap::new(),
        },
        proof_requirements: BTreeSet::new(),
        failure_behavior: FailureBehavior::ObservationOnly,
    }
}

#[test]
fn status_declares_zero_device_authority() {
    let output = execute(["status"]).unwrap();
    let payload: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(payload["device_access"], false);
    assert_eq!(payload["gateway_bind"], "loopback_only");
    assert_eq!(payload["worker_execution"], "simulator_only");
    assert_eq!(payload["model_authority"], false);
}

#[test]
fn device_changing_commands_do_not_exist() {
    for command in ["jailbreak", "restore", "boot-ramdisk", "write-syscfg"] {
        assert!(matches!(
            execute([command]),
            Err(CliError::UnknownCommand(value)) if value == command
        ));
    }
}

#[test]
fn verify_journal_reports_chain_summary() {
    let root = TestDirectory::new();
    let session = Uuid::new_v4();
    let path = {
        let mut journal = Journal::open(&root.0, session).unwrap();
        journal
            .append("session_started", BTreeMap::new())
            .unwrap();
        journal.path().to_path_buf()
    };

    let output = execute([
        "verify-journal".to_owned(),
        path.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let payload: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(payload["verified"], true);
    assert_eq!(payload["session_id"], session.to_string());
    assert_eq!(payload["entries"], 1);
}

#[test]
fn stable_manifest_inspection_reports_policy_result() {
    let root = TestDirectory::new();
    let path = root.0.join("engine.json");
    fs::write(
        &path,
        serde_json::to_vec(&manifest(Maturity::Stable)).unwrap(),
    )
    .unwrap();

    let output = execute([
        "inspect-engine".to_owned(),
        path.to_string_lossy().into_owned(),
        "stable".to_owned(),
    ])
    .unwrap();
    let payload: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(payload["engine_id"], "fixture-engine");
    assert_eq!(payload["policy_valid"], true);
}

#[test]
fn beta_manifest_is_not_misreported_as_stable() {
    let root = TestDirectory::new();
    let path = root.0.join("engine.json");
    fs::write(
        &path,
        serde_json::to_vec(&manifest(Maturity::Beta)).unwrap(),
    )
    .unwrap();

    let output = execute([
        "inspect-engine".to_owned(),
        path.to_string_lossy().into_owned(),
        "stable".to_owned(),
    ])
    .unwrap();
    let payload: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(payload["policy_valid"], false);
    assert!(payload["policy_error"].as_str().is_some());
}

#[test]
fn invalid_profile_is_rejected() {
    let root = TestDirectory::new();
    let path = root.0.join("engine.json");
    fs::write(
        &path,
        serde_json::to_vec(&manifest(Maturity::Stable)).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        execute([
            "inspect-engine".to_owned(),
            path.to_string_lossy().into_owned(),
            "unsafe".to_owned()
        ]),
        Err(CliError::InvalidProfile(profile)) if profile == "unsafe"
    ));
}
