use tg_apple_observe::{LockedDeviceIdentity, ObservationSource, ObservedAppleDevice};
use tg_contracts::DeviceMode;
use tg_gaster_provider::{build_pwn_plan, GasterPlanRequest, GasterProviderManifest};
use uuid::Uuid;

#[test]
fn tracked_research_manifest_is_valid_but_unrunnable() {
    let payload = include_str!("../../../engines/apple/gaster/provider.research.json");
    let manifest: GasterProviderManifest = serde_json::from_str(payload).expect("parse manifest");
    assert!(manifest.executable_sha256.is_none());
    assert!(manifest.hardware_verified_cpids.is_empty());

    let identity = LockedDeviceIdentity {
        cpid: "8015".to_owned(),
        ecid_hash: "e".repeat(64),
        product_type: Some("iPhone10,6".to_owned()),
        board_config: Some("d221ap".to_owned()),
        identity_hash: "i".repeat(64),
    };
    let observation = ObservedAppleDevice {
        schema_version: "tgcheckm8.apple-observe.v1".to_owned(),
        rule_id: Some("apple.dfu.05ac-1227".to_owned()),
        mode: DeviceMode::Dfu,
        cpid: Some("8015".to_owned()),
        ecid_hash: Some("e".repeat(64)),
        serial_hash: Some("s".repeat(64)),
        pwn_provider: None,
        product_type: Some("iPhone10,6".to_owned()),
        board_config: Some("d221ap".to_owned()),
        device_identity_hash: Some("i".repeat(64)),
        source: ObservationSource::RecordedFixture,
        evidence_complete: true,
    };
    let request = GasterPlanRequest {
        session_id: Uuid::new_v4(),
        locked_identity: identity,
        starting_observation: observation,
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        granted_permissions: manifest.requested_permissions.clone(),
    };

    assert!(build_pwn_plan(&manifest, &request).is_err());
}
