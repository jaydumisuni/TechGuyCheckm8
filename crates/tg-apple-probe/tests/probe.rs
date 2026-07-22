use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tg_apple_observe::ObservationSource;
use tg_apple_probe::{
    inspect_installation, parse_irecovery_query, run_probe, sha256_file, ProbeError,
    ProbeInstallation, ProbeProfile, ReadOnlyProbeManifest, PROBE_CONTRACT_VERSION,
};
use tg_contracts::{DeviceMode, Maturity};
use tg_process::ProcessPolicy;
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tg-apple-probe-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tg-irecovery-fixture"))
}

fn source_for_host() -> ObservationSource {
    match std::env::consts::OS {
        "windows" => ObservationSource::WindowsUsb,
        "macos" => ObservationSource::MacIokit,
        _ => ObservationSource::LinuxUsbfs,
    }
}

fn manifest(hash: String, maturity: Maturity, licence: Option<&str>) -> ReadOnlyProbeManifest {
    ReadOnlyProbeManifest {
        schema_version: PROBE_CONTRACT_VERSION.to_owned(),
        probe_id: "apple.irecovery.dfu.query".to_owned(),
        version: "0.1.0".to_owned(),
        profile: ProbeProfile::IRecoveryDfuQuery,
        supported_hosts: BTreeSet::from([std::env::consts::OS.to_owned()]),
        maturity,
        source_repository: "https://github.com/libimobiledevice/libirecovery".to_owned(),
        source_commit: "04d04f7cbaa4696504e91c1478ddd56160ed6776".to_owned(),
        declared_licence: licence.map(str::to_owned),
        expected_executable_sha256: hash,
        proof_requirements: BTreeSet::from([
            "redacted_identity_observed".to_owned(),
            "process_cleanup_verified".to_owned(),
        ]),
    }
}

fn installation(work: &TestDirectory) -> ProbeInstallation {
    ProbeInstallation {
        executable: fixture_binary(),
        working_directory: work.0.clone(),
        source: source_for_host(),
    }
}

fn process_policy(work: &TestDirectory) -> ProcessPolicy {
    let executable_root = fixture_binary().parent().unwrap().to_path_buf();
    ProcessPolicy::new(
        vec![executable_root],
        work.0.clone(),
        Duration::from_secs(2),
        Duration::from_millis(5),
        64 * 1024,
        16 * 1024,
    )
    .unwrap()
}

#[test]
fn parser_accepts_official_irecovery_query_shape() {
    let parsed = parse_irecovery_query(
        "CPID: 0x8020\nECID: 0xdeadbeef00000001\nPWND: usbliter8\nMODE: DFU\nPRODUCT: iPhone11,6\nMODEL: d331pap\nNAME: Synthetic Device\n",
    )
    .unwrap();

    assert_eq!(parsed.cpid, "8020");
    assert_eq!(parsed.ecid, "DEADBEEF00000001");
    assert_eq!(parsed.pwn_provider.as_deref(), Some("usbliter8"));
    assert_eq!(parsed.mode, DeviceMode::Dfu);
    assert_eq!(parsed.product_type.as_deref(), Some("iPhone11,6"));
    assert_eq!(parsed.board_config.as_deref(), Some("d331pap"));
}

#[test]
fn parser_rejects_recovery_mode_for_dfu_only_profile() {
    assert!(matches!(
        parse_irecovery_query(
            "CPID: 0x8020\nECID: 0xdeadbeef00000001\nMODE: Recovery\n"
        ),
        Err(ProbeError::UnsupportedObservedMode(mode)) if mode == "Recovery"
    ));
}

#[test]
fn parser_rejects_missing_ecid() {
    assert!(matches!(
        parse_irecovery_query("CPID: 0x8020\nMODE: DFU\n"),
        Err(ProbeError::MissingField("ECID"))
    ));
}

#[test]
fn parser_rejects_invalid_hex_identity() {
    assert!(matches!(
        parse_irecovery_query("CPID: not-hex\nECID: 0x1\nMODE: DFU\n"),
        Err(ProbeError::InvalidHexField("CPID", _))
    ));
}

#[test]
fn supervised_fixture_runs_only_the_fixed_query_profile() {
    let work = TestDirectory::new();
    let hash = sha256_file(fixture_binary()).unwrap();
    let manifest = manifest(hash, Maturity::SimulationTested, Some("LGPL-2.1-or-later"));

    let evidence = run_probe(
        &process_policy(&work),
        &manifest,
        &installation(&work),
        std::env::consts::OS,
        "development",
    )
    .unwrap();

    assert_eq!(evidence.status_code, Some(0));
    assert!(evidence.cleanup_verified);
    assert!(!evidence.stdout_truncated);
    assert_eq!(evidence.observed.mode, DeviceMode::PwnedDfu);
    assert_eq!(evidence.observed.cpid.as_deref(), Some("8020"));
    assert_eq!(
        evidence.observed.pwn_provider.as_deref(),
        Some("usbliter8")
    );
    assert!(evidence.observed.evidence_complete);
    let serialized = serde_json::to_string(&evidence).unwrap();
    assert!(!serialized.contains("DEADBEEF00000001"));
}

#[test]
fn executable_hash_mismatch_blocks_before_probe_execution() {
    let work = TestDirectory::new();
    let manifest = manifest(
        "00".repeat(32),
        Maturity::SimulationTested,
        Some("LGPL-2.1-or-later"),
    );

    assert!(matches!(
        run_probe(
            &process_policy(&work),
            &manifest,
            &installation(&work),
            std::env::consts::OS,
            "development"
        ),
        Err(ProbeError::ExecutableHashMismatch)
    ));
}

#[test]
fn doctor_reports_verified_fixture_ready() {
    let work = TestDirectory::new();
    let hash = sha256_file(fixture_binary()).unwrap();
    let manifest = manifest(hash, Maturity::SimulationTested, Some("LGPL-2.1-or-later"));

    let report = inspect_installation(
        &manifest,
        &installation(&work),
        std::env::consts::OS,
        "development",
    );
    assert!(report.ready);
    assert!(report.findings.is_empty());
}

#[test]
fn stable_policy_requires_stable_maturity_and_licence() {
    let work = TestDirectory::new();
    let hash = sha256_file(fixture_binary()).unwrap();
    let immature = manifest(hash.clone(), Maturity::SimulationTested, None);
    let stable_without_licence = manifest(hash, Maturity::Stable, None);

    let immature_report = inspect_installation(
        &immature,
        &installation(&work),
        std::env::consts::OS,
        "stable",
    );
    assert!(!immature_report.ready);
    assert!(immature_report
        .findings
        .iter()
        .any(|finding| finding.contains("Stable probe")));

    let licence_report = inspect_installation(
        &stable_without_licence,
        &installation(&work),
        std::env::consts::OS,
        "stable",
    );
    assert!(!licence_report.ready);
    assert!(licence_report
        .findings
        .iter()
        .any(|finding| finding.contains("declared licence")));
}
