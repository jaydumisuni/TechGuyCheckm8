use std::collections::{BTreeMap, BTreeSet};

use tg_apple_route_reference::{
    AppleGeneration, AppleRouteReferenceManifest, PwnProvider, PwnSourcePin, ReferenceCatalog,
    ReferenceClassification, RouteAssetPolicy, RouteEnvironment, APPLE_ROUTE_REFERENCE_VERSION,
};
use tg_contracts::Maturity;
use tg_ramdisk_pack::{
    bind_to_route_reference, classify_and_hash_asset, required_assets, sshrd_boot_steps,
    validate_pack, AssetRole, BootStep, FixedRecoveryCommand, RamdiskProviderPack, SourceReference,
    RAMDISK_PACK_VERSION, SSHRD_LICENCE, SSHRD_SOURCE_COMMIT, SSHRD_SOURCE_REPOSITORY,
};

fn sources() -> Vec<SourceReference> {
    vec![
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
    ]
}

fn assets(include_trustcache: bool) -> BTreeMap<AssetRole, tg_ramdisk_pack::AssetRecord> {
    let mut files = vec![
        ("bin/gaster", b"gaster".as_slice()),
        ("bin/irecovery", b"irecovery".as_slice()),
        ("assets/iBSS.img4", b"ibss".as_slice()),
        ("assets/iBEC.img4", b"ibec".as_slice()),
        ("assets/logo.img4", b"logo".as_slice()),
        ("assets/ramdisk.img4", b"ramdisk".as_slice()),
        ("assets/devicetree.img4", b"devicetree".as_slice()),
        ("assets/kernelcache.img4", b"kernelcache".as_slice()),
    ];
    if include_trustcache {
        files.push(("assets/trustcache.img4", b"trustcache".as_slice()));
    }
    files
        .into_iter()
        .map(|(path, bytes)| {
            let asset = classify_and_hash_asset(path, bytes).expect("classify asset");
            (asset.role.clone(), asset)
        })
        .collect()
}

fn pack() -> RamdiskProviderPack {
    let assets = assets(true);
    RamdiskProviderPack {
        schema_version: RAMDISK_PACK_VERSION.to_owned(),
        pack_id: "iphone10,6-d221ap-20h350-sshrd".to_owned(),
        route_reference_profile_id: "apple:a8-a11:gaster-reference".to_owned(),
        product_type: "iPhone10,6".to_owned(),
        board_config: "d221ap".to_owned(),
        cpid: "8015".to_owned(),
        firmware_build: "20H350".to_owned(),
        environment: RouteEnvironment::Ramdisk,
        pwn_provider: PwnProvider::Gaster,
        source_references: sources(),
        boot_steps: sshrd_boot_steps("8015", true, true, RouteEnvironment::Ramdisk)
            .expect("known steps"),
        assets,
        maturity: Maturity::SimulationTested,
        hardware_transcript_sha256: None,
        recovery_proof_sha256: None,
    }
}

fn route() -> AppleRouteReferenceManifest {
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
        expected_transitions: vec![],
        required_asset_roles: BTreeSet::from([
            "gaster_executable".to_owned(),
            "bootchain".to_owned(),
            "ramdisk".to_owned(),
        ]),
        maturity: Maturity::ContractValid,
    }
}

#[test]
fn a11_known_recipe_contains_go_and_fixed_order() {
    let steps =
        sshrd_boot_steps("0x8015", true, true, RouteEnvironment::Ramdisk).expect("known steps");
    assert!(steps.contains(&BootStep::RecoveryCommand(FixedRecoveryCommand::Go)));
    assert_eq!(
        steps.first(),
        Some(&BootStep::RequireCheckpoint(
            tg_ramdisk_pack::BootCheckpoint::PwnedDfuVerified
        ))
    );
    assert_eq!(
        steps.last(),
        Some(&BootStep::ProveCheckpoint(
            tg_ramdisk_pack::BootCheckpoint::RamdiskReady
        ))
    );
    assert!(required_assets(&steps).contains(&AssetRole::KernelCache));
}

#[test]
fn a9_recipe_does_not_invent_go_command() {
    let steps =
        sshrd_boot_steps("8000", false, false, RouteEnvironment::Ramdisk).expect("known steps");
    assert!(!steps.contains(&BootStep::RecoveryCommand(FixedRecoveryCommand::Go)));
}

#[test]
fn complete_pack_binds_to_exact_route_without_authorizing_execution() {
    let pack = pack();
    assert!(validate_pack(&pack).is_ok());
    let decision = bind_to_route_reference(&pack, &route());
    assert!(
        decision.ready_for_hardware_verification,
        "{:?}",
        decision.blockers
    );
    assert!(!decision.execution_authorized);
    assert!(decision.required_assets.contains(&AssetRole::Ramdisk));
}

#[test]
fn wrong_firmware_build_is_blocked() {
    let mut pack = pack();
    pack.firmware_build = "20H999".to_owned();
    let decision = bind_to_route_reference(&pack, &route());
    assert!(!decision.ready_for_hardware_verification);
    assert!(decision
        .blockers
        .iter()
        .any(|item| item.contains("outside the route reference")));
}

#[test]
fn changed_boot_order_is_blocked() {
    let mut pack = pack();
    pack.boot_steps.swap(1, 2);
    assert!(validate_pack(&pack).is_err());
}

#[test]
fn missing_kernelcache_is_blocked() {
    let mut pack = pack();
    pack.assets.remove(&AssetRole::KernelCache);
    assert!(validate_pack(&pack).is_err());
}

#[test]
fn path_traversal_is_rejected_before_hashing() {
    assert!(classify_and_hash_asset("../ramdisk.img4", b"ramdisk").is_err());
}

#[test]
fn stable_pack_requires_transcript_and_recovery_proof() {
    let mut pack = pack();
    pack.maturity = Maturity::Stable;
    assert!(validate_pack(&pack).is_err());
}
