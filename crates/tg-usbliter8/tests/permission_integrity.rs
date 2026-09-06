use std::collections::BTreeSet;

use tg_apple_observe::LockedDeviceIdentity;
use tg_contracts::{Maturity, Permission};
use tg_usbliter8::{
    build_pwn_plan, required_permissions, BoardModel, McuFamily, PhysicalHandoffAcknowledgement,
    PwnDfuRequest, Usbliter8NodeManifest, USBLITER8_NODE_VERSION,
};
use uuid::Uuid;

fn manifest() -> Usbliter8NodeManifest {
    Usbliter8NodeManifest {
        schema_version: USBLITER8_NODE_VERSION.to_owned(),
        node_id: "usbliter8.waveshare-rp2350-usb-a".to_owned(),
        firmware_version: "synthetic-v1".to_owned(),
        mcu_family: McuFamily::Rp2350,
        board_model: BoardModel::WaveshareRp2350UsbA,
        source_repository: "https://github.com/TechDudeSpeaks/usbliter8".to_owned(),
        source_commit: "a".repeat(40),
        declared_licence: Some("GPL-3.0-only".to_owned()),
        uf2_sha256: Some("b".repeat(64)),
        supported_cpids: BTreeSet::from(["8020".to_owned()]),
        hardware_verified_cpids: BTreeSet::new(),
        maturity: Maturity::SimulationTested,
        auto_mode: true,
        required_hardware: BTreeSet::from(["rp2350".to_owned()]),
        requested_permissions: required_permissions(),
        proof_requirements: BTreeSet::from([
            "board_firmware_hash_verified".to_owned(),
            "board_dfu_identity_verified".to_owned(),
            "board_success_marker".to_owned(),
            "board_self_verified_pwnd".to_owned(),
            "host_pwnd_reconnect_verified".to_owned(),
            "same_device_identity".to_owned(),
        ]),
    }
}

#[test]
fn permission_superset_cannot_build_hardware_pwn_plan() {
    let manifest = manifest();
    let locked_identity = LockedDeviceIdentity {
        cpid: "8020".to_owned(),
        ecid_hash: "e".repeat(64),
        product_type: Some("iPhone11,6".to_owned()),
        board_config: Some("d331pap".to_owned()),
        identity_hash: "i".repeat(64),
    };
    let mut granted_permissions = required_permissions();
    granted_permissions.insert(Permission::FilesystemRead);
    let request = PwnDfuRequest {
        session_id: Uuid::new_v4(),
        node_id: manifest.node_id.clone(),
        locked_identity,
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
        granted_permissions,
    };

    assert!(build_pwn_plan(&manifest, &request).is_err());
}
