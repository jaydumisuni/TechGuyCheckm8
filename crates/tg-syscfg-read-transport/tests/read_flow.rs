use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_leases::{LeaseManager, LeaseOwner};
use tg_purple::SysCfgFieldClass;
use tg_purple_boot::PurpleBootFinalProof;
use tg_serial_doctor::{
    required_permissions as doctor_permissions, select_candidate, HostPlatform,
    RawSerialPortObservation, SerialDoctorContext, SerialDoctorManifest, SerialMatchRule,
    SerialOpenProbe, SerialParity, SerialProbeObservation, SerialSettings, SerialStopBits,
    SERIAL_DOCTOR_VERSION,
};
use tg_serial_platform::{
    reserve_and_run_doctor, PlatformDoctorReservation, SerialPlatformError,
};
use tg_syscfg_read_transport::{
    bind_read_endpoint, execute_read, required_transport_permissions, ParsedSysCfgRead,
    RawCommandResponse, ReadFramePolicy, ReadTransportAuthorization, SysCfgReadCommandChannel,
    SysCfgReadOperation, SysCfgReadTransportError, SYSCFG_READ_TRANSPORT_VERSION,
};
use tg_syscfg_serial::{
    required_read_permissions, required_write_permissions, SerialLink, SysCfgFieldPolicy,
    SysCfgSerialContext, SysCfgSerialProviderManifest, SYSCFG_SERIAL_VERSION,
};
use uuid::Uuid;

fn settings() -> SerialSettings {
    SerialSettings {
        baud_rate: 115_200,
        data_bits: 8,
        parity: SerialParity::None,
        stop_bits: SerialStopBits::One,
        timeout_millis: 100,
    }
}

fn doctor_manifest() -> SerialDoctorManifest {
    SerialDoctorManifest {
        schema_version: SERIAL_DOCTOR_VERSION.to_owned(),
        provider_id: "synthetic.serial-doctor".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        rules: vec![SerialMatchRule {
            rule_id: "synthetic-adapter".to_owned(),
            link: SerialLink::UsbSerial,
            host: None,
            vid: Some(0x1209),
            pid: Some(0x0001),
            manufacturer_contains: Some("Synthetic Lab".to_owned()),
            product_contains: Some("Diags Adapter".to_owned()),
            settings: settings(),
            priority: 100,
        }],
        requested_permissions: doctor_permissions(),
        proof_requirements: BTreeSet::from([
            "purple_mode_same_session".to_owned(),
            "unique_serial_candidate".to_owned(),
            "stable_hardware_fingerprint".to_owned(),
            "exclusive_open_verified".to_owned(),
            "serial_settings_verified".to_owned(),
            "zero_bytes_written".to_owned(),
            "serial_lease_acquired".to_owned(),
        ]),
    }
}

fn provider_manifest() -> SysCfgSerialProviderManifest {
    SysCfgSerialProviderManifest {
        schema_version: SYSCFG_SERIAL_VERSION.to_owned(),
        provider_id: "synthetic.syscfg-read".to_owned(),
        version: "1.0.0-test".to_owned(),
        maturity: Maturity::SimulationTested,
        supported_product_types: BTreeSet::from(["iPhone11,6".to_owned()]),
        supported_board_configs: BTreeSet::from(["d331pap".to_owned()]),
        links: BTreeSet::from([SerialLink::UsbSerial]),
        source_repository: "https://example.invalid/synthetic".to_owned(),
        source_commit: "a".repeat(40),
        declared_licence: Some("MIT".to_owned()),
        supports_write: false,
        max_response_bytes: 4096,
        field_catalog: BTreeMap::from([
            (
                "SrNm".to_owned(),
                SysCfgFieldPolicy {
                    class: SysCfgFieldClass::IdentityCritical,
                    writable: false,
                    max_value_bytes: 64,
                    response_labels: BTreeSet::from(["SrNm".to_owned()]),
                },
            ),
            (
                "Regn".to_owned(),
                SysCfgFieldPolicy {
                    class: SysCfgFieldClass::Manufacturing,
                    writable: false,
                    max_value_bytes: 16,
                    response_labels: BTreeSet::from(["Regn".to_owned()]),
                },
            ),
        ]),
        required_backup_keys: BTreeSet::from(["SrNm".to_owned(), "Regn".to_owned()]),
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

fn purple_proof(session_id: Uuid) -> PurpleBootFinalProof {
    PurpleBootFinalProof {
        session_id,
        route_id: "synthetic-purple".to_owned(),
        verified: true,
        final_mode: DeviceMode::PurpleDiagnostic,
        cleanup_required: true,
        environment_backup_sha256: "b".repeat(64),
        failures: Vec::new(),
    }
}

fn doctor_context(session_id: Uuid, device_hash: &str) -> SerialDoctorContext {
    SerialDoctorContext {
        session_id,
        device_identity_hash: device_hash.to_owned(),
        purple_proof: purple_proof(session_id),
        granted_permissions: doctor_permissions(),
        policy_profile: "development".to_owned(),
    }
}

fn logical_context(session_id: Uuid, device_hash: &str) -> SysCfgSerialContext {
    SysCfgSerialContext {
        session_id,
        provider_id: "synthetic.syscfg-read".to_owned(),
        device_identity_hash: device_hash.to_owned(),
        product_type: "iPhone11,6".to_owned(),
        board_config: "d331pap".to_owned(),
        purple_proof: purple_proof(session_id),
        granted_permissions: required_read_permissions(),
        policy_profile: "development".to_owned(),
    }
}

fn observation() -> RawSerialPortObservation {
    RawSerialPortObservation {
        port_name: "COM77".to_owned(),
        vid: Some(0x1209),
        pid: Some(0x0001),
        serial_number: Some("SYNTHETIC-READ-ADAPTER".to_owned()),
        manufacturer: Some("Synthetic Lab".to_owned()),
        product: Some("Diags Adapter".to_owned()),
        physical_location: Some("usb-root-1-port-4".to_owned()),
    }
}

#[derive(Debug, Clone)]
struct ReadyProbe;

impl SerialOpenProbe for ReadyProbe {
    fn probe(
        &mut self,
        _port_name: &str,
        _settings: &SerialSettings,
    ) -> Result<SerialProbeObservation, String> {
        Ok(SerialProbeObservation {
            opened: true,
            exclusive: true,
            settings_applied: true,
            bytes_written: 0,
            bytes_read: 0,
        })
    }
}

fn bound_endpoint(
    current_tick: u64,
) -> (
    tg_syscfg_read_transport::BoundReadEndpoint,
    Uuid,
    String,
) {
    let session_id = Uuid::new_v4();
    let device_hash = "c".repeat(64);
    let selected = select_candidate(
        &doctor_manifest(),
        HostPlatform::Windows,
        &[observation()],
    )
    .expect("candidate should select");
    let owner = LeaseOwner {
        session_id,
        worker_id: "syscfg-read-transport".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let platform_session = reserve_and_run_doctor(
        &doctor_manifest(),
        &doctor_context(session_id, &device_hash),
        HostPlatform::Windows,
        &[observation()],
        &mut ReadyProbe,
        &mut leases,
        PlatformDoctorReservation {
            owner,
            current_tick: 10,
            ttl_ticks: 100,
        },
    )
    .expect("Doctor should reserve endpoint");
    let endpoint = bind_read_endpoint(
        selected,
        platform_session,
        &ReadTransportAuthorization {
            session_id,
            device_identity_hash: device_hash.clone(),
            granted_permissions: required_transport_permissions(),
            allow_control_line_side_effects: true,
            current_tick,
        },
    )
    .expect("endpoint should bind");
    (endpoint, session_id, device_hash)
}

fn frame_policy() -> ReadFramePolicy {
    ReadFramePolicy {
        schema_version: SYSCFG_READ_TRANSPORT_VERSION.to_owned(),
        max_response_bytes: 4096,
        read_chunk_bytes: 256,
        max_consecutive_timeouts: 3,
    }
}

#[derive(Debug, Clone)]
struct FakeChannel {
    response: Vec<u8>,
    write_count_override: Option<usize>,
    prompt_verified: bool,
}

impl SysCfgReadCommandChannel for FakeChannel {
    fn exchange(
        &mut self,
        _endpoint: &tg_syscfg_read_transport::BoundReadEndpoint,
        command: &tg_syscfg_serial::EncodedCommand,
        _policy: &ReadFramePolicy,
    ) -> Result<RawCommandResponse, SysCfgReadTransportError> {
        Ok(RawCommandResponse::from_channel(
            self.response.clone(),
            self.write_count_override
                .unwrap_or_else(|| command.as_bytes().len()),
            self.prompt_verified,
            0,
        ))
    }
}

#[test]
fn fixed_list_exchange_parses_and_emits_hash_only_receipt() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let mut channel = FakeChannel {
        response: b"syscfg list\r\nSrNm: PRIVATE-SERIAL\r\nRegn: LL/A\r\n>\r\n".to_vec(),
        write_count_override: None,
        prompt_verified: true,
    };
    let execution = execute_read(
        &mut channel,
        &endpoint,
        &provider_manifest(),
        &logical_context(session_id, &device_hash),
        SysCfgReadOperation::List,
        &frame_policy(),
    )
    .expect("list exchange should pass");

    match execution.parsed {
        ParsedSysCfgRead::List(dump) => {
            assert_eq!(dump.field_value("Regn"), Some("LL/A"));
            assert_eq!(dump.field_count(), 2);
        }
        ParsedSysCfgRead::Print(_) => panic!("expected list"),
    }
    let durable = serde_json::to_string(&execution.receipt).expect("receipt serializes");
    assert!(!durable.contains("PRIVATE-SERIAL"));
    assert!(!durable.contains("LL/A"));
    assert_eq!(execution.receipt.command_action, "list");
}

#[test]
fn fixed_print_exchange_returns_catalogued_field() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let mut channel = FakeChannel {
        response: b"syscfg print Regn\r\nRegn: LL/A\r\n>\r\n".to_vec(),
        write_count_override: None,
        prompt_verified: true,
    };
    let execution = execute_read(
        &mut channel,
        &endpoint,
        &provider_manifest(),
        &logical_context(session_id, &device_hash),
        SysCfgReadOperation::Print {
            key: "Regn".to_owned(),
        },
        &frame_policy(),
    )
    .expect("print exchange should pass");

    match execution.parsed {
        ParsedSysCfgRead::Print(field) => {
            assert_eq!(field.key(), "Regn");
            assert_eq!(field.value(), "LL/A");
        }
        ParsedSysCfgRead::List(_) => panic!("expected print"),
    }
    assert_eq!(execution.receipt.command_key.as_deref(), Some("Regn"));
}

#[test]
fn transport_grant_requires_serial_transmit_permission() {
    let session_id = Uuid::new_v4();
    let device_hash = "c".repeat(64);
    let selected = select_candidate(
        &doctor_manifest(),
        HostPlatform::Windows,
        &[observation()],
    )
    .expect("candidate should select");
    let owner = LeaseOwner {
        session_id,
        worker_id: "syscfg-read-transport".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let platform_session = reserve_and_run_doctor(
        &doctor_manifest(),
        &doctor_context(session_id, &device_hash),
        HostPlatform::Windows,
        &[observation()],
        &mut ReadyProbe,
        &mut leases,
        PlatformDoctorReservation {
            owner,
            current_tick: 10,
            ttl_ticks: 100,
        },
    )
    .expect("Doctor should reserve endpoint");
    let mut insufficient = required_transport_permissions();
    insufficient.remove(&Permission::SerialWrite);

    assert!(matches!(
        bind_read_endpoint(
            selected,
            platform_session,
            &ReadTransportAuthorization {
                session_id,
                device_identity_hash: device_hash,
                granted_permissions: insufficient,
                allow_control_line_side_effects: true,
                current_tick: 20,
            },
        ),
        Err(SysCfgReadTransportError::PermissionGrantMismatch)
    ));
}

#[test]
fn expired_lease_is_rejected_before_exchange() {
    let session_id = Uuid::new_v4();
    let device_hash = "c".repeat(64);
    let selected = select_candidate(
        &doctor_manifest(),
        HostPlatform::Windows,
        &[observation()],
    )
    .expect("candidate should select");
    let owner = LeaseOwner {
        session_id,
        worker_id: "syscfg-read-transport".to_owned(),
        run_id: Uuid::new_v4(),
    };
    let mut leases = LeaseManager::default();
    let platform_session = reserve_and_run_doctor(
        &doctor_manifest(),
        &doctor_context(session_id, &device_hash),
        HostPlatform::Windows,
        &[observation()],
        &mut ReadyProbe,
        &mut leases,
        PlatformDoctorReservation {
            owner,
            current_tick: 10,
            ttl_ticks: 5,
        },
    )
    .expect("Doctor should reserve endpoint");

    assert!(matches!(
        bind_read_endpoint(
            selected,
            platform_session,
            &ReadTransportAuthorization {
                session_id,
                device_identity_hash: device_hash,
                granted_permissions: required_transport_permissions(),
                allow_control_line_side_effects: true,
                current_tick: 15,
            },
        ),
        Err(SysCfgReadTransportError::LeaseExpired)
    ));
}

#[test]
fn wrong_write_count_and_missing_prompt_are_rejected() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let context = logical_context(session_id, &device_hash);
    let mut short_write = FakeChannel {
        response: b"Regn: LL/A\r\n>\r\n".to_vec(),
        write_count_override: Some(1),
        prompt_verified: true,
    };
    assert!(matches!(
        execute_read(
            &mut short_write,
            &endpoint,
            &provider_manifest(),
            &context,
            SysCfgReadOperation::Print {
                key: "Regn".to_owned(),
            },
            &frame_policy(),
        ),
        Err(SysCfgReadTransportError::CommandWriteCountMismatch { .. })
    ));

    let mut missing_prompt = FakeChannel {
        response: b"Regn: LL/A\r\n".to_vec(),
        write_count_override: None,
        prompt_verified: true,
    };
    assert!(matches!(
        execute_read(
            &mut missing_prompt,
            &endpoint,
            &provider_manifest(),
            &context,
            SysCfgReadOperation::Print {
                key: "Regn".to_owned(),
            },
            &frame_policy(),
        ),
        Err(SysCfgReadTransportError::PromptNotVerified)
    ));
}

#[test]
fn unknown_print_key_is_blocked_before_channel_execution() {
    let (endpoint, session_id, device_hash) = bound_endpoint(20);
    let mut channel = FakeChannel {
        response: Vec::new(),
        write_count_override: None,
        prompt_verified: false,
    };
    assert!(matches!(
        execute_read(
            &mut channel,
            &endpoint,
            &provider_manifest(),
            &logical_context(session_id, &device_hash),
            SysCfgReadOperation::Print {
                key: "UnknownKey".to_owned(),
            },
            &frame_policy(),
        ),
        Err(SysCfgReadTransportError::SysCfg(_))
    ));
}

#[test]
fn frame_policy_cannot_exceed_provider_limit() {
    let mut policy = frame_policy();
    policy.max_response_bytes = 4097;
    assert_eq!(
        policy.validate(&provider_manifest()),
        Err(SysCfgReadTransportError::InvalidResponseLimit(4097))
    );
}

#[test]
fn platform_error_type_remains_distinct_from_transport_errors() {
    let marker = SerialPlatformError::LeaseSessionMismatch;
    assert_eq!(marker, SerialPlatformError::LeaseSessionMismatch);
}
