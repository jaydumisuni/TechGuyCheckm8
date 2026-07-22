use std::path::PathBuf;

use tg_apple_observe::ObservationSource;
use tg_apple_probe::{inspect_installation, ProbeInstallation, ReadOnlyProbeManifest};
use tg_contracts::{Maturity, Permission};

#[test]
fn upstream_irecovery_manifest_is_valid_research_but_not_executable_ready() {
    let manifest: ReadOnlyProbeManifest = serde_json::from_str(include_str!(
        "../../../manifests/probes/irecovery-dfu-query.research.json"
    ))
    .unwrap();

    assert_eq!(manifest.maturity, Maturity::Discovered);
    assert!(manifest.expected_executable_sha256.is_none());
    assert_eq!(
        manifest.requested_permissions,
        [
            Permission::DeviceObserve,
            Permission::UsbRead,
            Permission::ProcessSpawn,
        ]
        .into_iter()
        .collect()
    );

    let installation = ProbeInstallation {
        executable: PathBuf::from("definitely-not-installed-irecovery"),
        working_directory: std::env::temp_dir(),
        source: ObservationSource::RecordedFixture,
    };
    let report = inspect_installation(
        &manifest,
        &installation,
        std::env::consts::OS,
        "development",
    );
    assert!(report.manifest_valid);
    assert!(!report.ready);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.contains("missing") || finding.contains("not pinned")));
}
