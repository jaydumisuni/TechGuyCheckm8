use std::collections::BTreeSet;

use tg_apple_route_reference::{
    evaluate_hardware_verification, validate_manifest, AppleGeneration,
    AppleRouteReferenceManifest, ExpectedTransition, LocalAssetPin, PwnProvider, PwnSourcePin,
    ReferenceCatalog, ReferenceClassification, RouteAssetPolicy, RouteEnvironment,
    RouteVerificationRequest, XRayAppleRouteCertificate, APPLE_ROUTE_REFERENCE_VERSION,
    XRAY_APPLE_CERTIFICATE_VERSION,
};
use tg_contracts::Maturity;

fn manifest() -> AppleRouteReferenceManifest {
    AppleRouteReferenceManifest {
        schema_version: APPLE_ROUTE_REFERENCE_VERSION.to_owned(),
        route_id: "iphone10,6-d221ap-gaster-ramdisk".to_owned(),
        reference_profile_id: "apple:a8-a11:gaster-reference".to_owned(),
        classification: ReferenceClassification::DocumentedKnownGood,
        generation: AppleGeneration::A8A11,
        pwn_provider: PwnProvider::Gaster,
        product_types: BTreeSet::from(["iPhone10,6".to_owned()]),
        board_configs: BTreeSet::from(["d221ap".to_owned()]),
        firmware_builds: BTreeSet::from(["20H350".to_owned()]),
        environments: BTreeSet::from([RouteEnvironment::Ramdisk]),
        pwn_source: PwnSourcePin {
            repository: "https://github.com/0x7ff/gaster".to_owned(),
            commit: "7fffffff38a1bed1cdc1c5bae0df70f14395129b".to_owned(),
            licence: "Apache-2.0".to_owned(),
        },
        reference_catalogs: vec![ReferenceCatalog {
            url: "https://file.unlocktool.net".to_owned(),
            role: "working_ramdisk_and_diags_reference".to_owned(),
            artifacts_bundled: false,
        }],
        asset_policy: RouteAssetPolicy {
            local_only: true,
            sha256_required: true,
            device_exact: true,
            redistribution_allowed: false,
        },
        expected_transitions: vec![
            ExpectedTransition::AppleDfu,
            ExpectedTransition::PwnedDfu,
            ExpectedTransition::PatchedIbootOrRecovery,
            ExpectedTransition::RamdiskBooting,
            ExpectedTransition::RamdiskReady,
        ],
        required_asset_roles: BTreeSet::from([
            "gaster_executable".to_owned(),
            "bootchain".to_owned(),
            "ramdisk".to_owned(),
        ]),
        maturity: Maturity::ContractValid,
    }
}

fn certificate() -> XRayAppleRouteCertificate {
    XRayAppleRouteCertificate {
        schema_version: XRAY_APPLE_CERTIFICATE_VERSION.to_owned(),
        scan_id: "xray-synthetic-a11".to_owned(),
        certification_verdict: "CERTIFIED".to_owned(),
        profile_status: "CANDIDATE_PROFILE".to_owned(),
        profile_id: "apple:a8-a11:gaster-reference".to_owned(),
        device_identity_hash: "a".repeat(64),
        product_type: "iPhone10,6".to_owned(),
        board_config: "d221ap".to_owned(),
        cpid: "0x8015".to_owned(),
        firmware_build: "20H350".to_owned(),
        bundle_manifest_sha256: "b".repeat(64),
        signature_verified: true,
        write_allowed: false,
        observed_at_unix: 1_000,
        expires_at_unix: 2_000,
    }
}

fn assets() -> Vec<LocalAssetPin> {
    vec![
        LocalAssetPin {
            role: "gaster_executable".to_owned(),
            sha256: "1".repeat(64),
            byte_len: 1_024,
        },
        LocalAssetPin {
            role: "bootchain".to_owned(),
            sha256: "2".repeat(64),
            byte_len: 2_048,
        },
        LocalAssetPin {
            role: "ramdisk".to_owned(),
            sha256: "3".repeat(64),
            byte_len: 4_096,
        },
    ]
}

#[test]
fn documented_a11_route_is_ready_for_hardware_verification_only() {
    let manifest = manifest();
    let certificate = certificate();
    let assets = assets();

    assert!(validate_manifest(&manifest).is_ok());
    let decision = evaluate_hardware_verification(RouteVerificationRequest {
        manifest: &manifest,
        certificate: &certificate,
        local_assets: &assets,
        current_unix: 1_500,
    });

    assert!(decision.ready_for_hardware_verification);
    assert!(!decision.execution_authorized);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.asset_hashes.len(), 3);
    assert!(decision
        .required_proofs
        .contains("firmware_build_exact_match"));
    assert!(decision
        .required_proofs
        .contains("known_good_sequence_reproduced"));
}

#[test]
fn missing_ramdisk_pin_blocks_verification() {
    let manifest = manifest();
    let certificate = certificate();
    let mut assets = assets();
    assets.retain(|asset| asset.role != "ramdisk");

    let decision = evaluate_hardware_verification(RouteVerificationRequest {
        manifest: &manifest,
        certificate: &certificate,
        local_assets: &assets,
        current_unix: 1_500,
    });

    assert!(!decision.ready_for_hardware_verification);
    assert!(decision
        .blockers
        .iter()
        .any(|item| item == "missing required local asset: ramdisk"));
    assert!(!decision.execution_authorized);
}

#[test]
fn xray_cannot_grant_write_authority() {
    let manifest = manifest();
    let mut certificate = certificate();
    certificate.write_allowed = true;
    let assets = assets();

    let decision = evaluate_hardware_verification(RouteVerificationRequest {
        manifest: &manifest,
        certificate: &certificate,
        local_assets: &assets,
        current_unix: 1_500,
    });

    assert!(!decision.ready_for_hardware_verification);
    assert!(decision
        .blockers
        .iter()
        .any(|item| item.contains("attempted to grant write authority")));
    assert!(!decision.execution_authorized);
}

#[test]
fn a12_route_cannot_reuse_gaster_provider() {
    let mut manifest = manifest();
    manifest.generation = AppleGeneration::A12A13;
    manifest.product_types = BTreeSet::from(["iPhone11,6".to_owned()]);
    manifest.board_configs = BTreeSet::from(["d331pap".to_owned()]);

    assert!(validate_manifest(&manifest).is_err());
}

#[test]
fn device_identity_must_match_exact_route() {
    let manifest = manifest();
    let mut certificate = certificate();
    certificate.board_config = "d331pap".to_owned();
    let assets = assets();

    let decision = evaluate_hardware_verification(RouteVerificationRequest {
        manifest: &manifest,
        certificate: &certificate,
        local_assets: &assets,
        current_unix: 1_500,
    });

    assert!(!decision.ready_for_hardware_verification);
    assert!(decision
        .blockers
        .iter()
        .any(|item| item == "X-Ray device or firmware is outside the exact route manifest"));
}

#[test]
fn firmware_build_must_match_exact_route() {
    let manifest = manifest();
    let mut certificate = certificate();
    certificate.firmware_build = "20H999".to_owned();
    let assets = assets();

    let decision = evaluate_hardware_verification(RouteVerificationRequest {
        manifest: &manifest,
        certificate: &certificate,
        local_assets: &assets,
        current_unix: 1_500,
    });

    assert!(!decision.ready_for_hardware_verification);
    assert!(decision
        .blockers
        .iter()
        .any(|item| item == "X-Ray device or firmware is outside the exact route manifest"));
}
