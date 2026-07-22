use tg_contracts::Maturity;
use tg_usbliter8::{
    build_pwn_plan, required_permissions, validate_node_manifest, McuFamily,
    PhysicalHandoffAcknowledgement, PwnDfuRequest, Usbliter8Error, Usbliter8NodeManifest,
};
use uuid::Uuid;

#[test]
fn upstream_node_manifest_tracks_source_without_claiming_runtime_readiness() {
    let manifest: Usbliter8NodeManifest = serde_json::from_str(include_str!(
        "../../../manifests/engines/usbliter8-rp2350.research.json"
    ))
    .unwrap();

    assert_eq!(manifest.maturity, Maturity::Discovered);
    assert_eq!(manifest.mcu_family, McuFamily::Rp2350);
    assert!(manifest.uf2_sha256.is_none());
    assert!(manifest.hardware_verified_cpids.is_empty());
    assert_eq!(manifest.requested_permissions, required_permissions());
    assert!(validate_node_manifest(&manifest, "development").is_ok());

    let request = PwnDfuRequest {
        session_id: Uuid::new_v4(),
        node_id: manifest.node_id.clone(),
        locked_identity: tg_apple_observe::LockedDeviceIdentity {
            cpid: "8020".to_owned(),
            ecid_hash: "synthetic-ecid-hash".to_owned(),
            product_type: Some("iPhone11,6".to_owned()),
            board_config: Some("d331pap".to_owned()),
            identity_hash: "synthetic-identity-hash".to_owned(),
        },
        expected_cpid: "8020".to_owned(),
        policy_profile: "development".to_owned(),
        authorized_device_service: true,
        explicit_operator_authorization: true,
        handoff: PhysicalHandoffAcknowledgement {
            host_dfu_observed: true,
            disconnected_from_host: true,
            connected_to_board: true,
            direct_lightning_usb_a_path: true,
            board_power_cycled_for_session: true,
        },
        granted_permissions: required_permissions(),
    };

    assert_eq!(
        build_pwn_plan(&manifest, &request),
        Err(Usbliter8Error::UnpinnedFirmware)
    );
}
