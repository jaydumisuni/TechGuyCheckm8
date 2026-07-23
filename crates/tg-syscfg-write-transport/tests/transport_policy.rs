use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{Maturity, Permission};
use tg_purple::SysCfgFieldClass;
use tg_syscfg_serial::{
    required_read_permissions, required_write_permissions, SerialLink, SysCfgFieldPolicy,
    SysCfgSerialProviderManifest, SYSCFG_SERIAL_VERSION,
};
use tg_syscfg_write_transport::{
    required_write_transport_permissions, WriteFramePolicy, SYSCFG_WRITE_TRANSPORT_VERSION,
};

fn provider() -> SysCfgSerialProviderManifest {
    SysCfgSerialProviderManifest {
        schema_version: SYSCFG_SERIAL_VERSION.to_owned(),
        provider_id: "synthetic.write-policy".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        supported_board_configs: BTreeSet::from(["d331pap".to_owned()]),
        links: BTreeSet::from([SerialLink::UsbSerial]),
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "a".repeat(40),
        declared_licence: Some("MIT".to_owned()),
        supports_write: true,
        max_response_bytes: 4096,
        field_catalog: BTreeMap::from([(
            "DiagFlag".to_owned(),
            SysCfgFieldPolicy {
                class: SysCfgFieldClass::Diagnostic,
                writable: true,
                max_value_bytes: 16,
                response_labels: BTreeSet::from(["DiagFlag".to_owned()]),
            },
        )]),
        required_backup_keys: BTreeSet::from(["DiagFlag".to_owned()]),
        requested_read_permissions: required_read_permissions(),
        requested_write_permissions: required_write_permissions(),
        proof_requirements: BTreeSet::from([
            "purple_mode_same_device".to_owned(),
            "full_syscfg_list_captured".to_owned(),
            "backup_vault_verified".to_owned(),
            "field_precondition_verified".to_owned(),
            "typed_write_only".to_owned(),
            "exact_readback_match".to_owned(),
            "rollback_verified_or_recovery_required".to_owned(),
        ]),
    }
}

#[test]
fn frame_policy_is_exact_and_bounded() {
    let provider = provider();
    let valid = WriteFramePolicy {
        schema_version: SYSCFG_WRITE_TRANSPORT_VERSION.to_owned(),
        max_response_bytes: 4096,
        read_chunk_bytes: 256,
        max_consecutive_timeouts: 3,
    };
    assert!(valid.validate(&provider).is_ok());

    let mut mismatched = valid.clone();
    mismatched.max_response_bytes = 2048;
    assert!(mismatched.validate(&provider).is_err());

    let mut unbounded = valid;
    unbounded.max_consecutive_timeouts = 0;
    assert!(unbounded.validate(&provider).is_err());
}

#[test]
fn write_transport_permission_contract_includes_backup_and_rollback_authority() {
    let permissions = required_write_transport_permissions();
    assert_eq!(permissions, required_write_permissions());
    assert!(permissions.contains(&Permission::SerialWrite));
    assert!(permissions.contains(&Permission::SysCfgBackup));
    assert!(permissions.contains(&Permission::SysCfgRestoreSameBoard));
    assert!(permissions.contains(&Permission::VaultRead));
    assert!(permissions.contains(&Permission::VaultWrite));
}
