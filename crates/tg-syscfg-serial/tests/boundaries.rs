use tg_syscfg_serial::{
    encode_command, parse_syscfg_list, SysCfgCommand, SysCfgSerialError,
    SysCfgSerialProviderManifest,
};

fn research_manifest() -> SysCfgSerialProviderManifest {
    serde_json::from_str(include_str!(
        "../../../providers/syscfg-serial/magiccfg-research.json"
    ))
    .unwrap()
}

#[test]
fn oversized_serial_response_is_rejected_before_parsing() {
    let mut manifest = research_manifest();
    manifest.max_response_bytes = 8;
    assert!(matches!(
        parse_syscfg_list(&manifest, b"Regn: LL/A\n"),
        Err(SysCfgSerialError::ResponseTooLarge(size)) if size == 11
    ));
}

#[test]
fn nul_byte_is_rejected_before_utf8_field_parsing() {
    let manifest = research_manifest();
    assert!(matches!(
        parse_syscfg_list(&manifest, b"Regn: LL/A\0\n"),
        Err(SysCfgSerialError::NulInResponse)
    ));
}

#[test]
fn research_manifest_cannot_encode_any_write() {
    let manifest = research_manifest();
    assert!(matches!(
        encode_command(
            &manifest,
            &SysCfgCommand::Add {
                key: "BCMS".to_owned(),
                value: "synthetic".to_owned(),
            },
        ),
        Err(SysCfgSerialError::WriteCapabilityDisabled)
    ));
}
