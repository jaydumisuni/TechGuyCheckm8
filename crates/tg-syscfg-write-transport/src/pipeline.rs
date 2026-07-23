use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use tg_contracts::Permission;
use tg_purple::{
    PurpleProviderManifest, SysCfgChange, SysCfgFieldClass, SysCfgWriteIntent,
    SysCfgWriteRequest,
};
use tg_syscfg_backup_vault::{BackupPipelineEvidence, FileBackupVault, VaultKey};
use tg_syscfg_read_transport::BoundReadEndpoint;
use tg_syscfg_serial::{
    build_write_transaction_plan, execute_write_transaction, hash_value, parse_syscfg_list,
    required_write_permissions, SelectedFieldMutation, SerialTransport, SysCfgSerialContext,
    SysCfgSerialProviderManifest, WriteTransactionOutcome, WriteTransactionPlan,
};
use uuid::Uuid;

use crate::transport::{SerialportSysCfgWriteTransport, WriteFramePolicy};
use crate::{SysCfgWriteTransportError, SYSCFG_WRITE_TRANSPORT_VERSION};

pub struct SelectedNonIdentityFieldWrite {
    key: String,
    requested_value: String,
}

impl SelectedNonIdentityFieldWrite {
    pub fn new(key: impl Into<String>, requested_value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            requested_value: requested_value.into(),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Debug for SelectedNonIdentityFieldWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedNonIdentityFieldWrite")
            .field("key", &self.key)
            .field("requested_value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTransportAuthorization {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub granted_permissions: BTreeSet<Permission>,
    pub explicit_authorization: bool,
    pub allow_control_line_side_effects: bool,
    pub current_tick: u64,
}

pub fn required_write_transport_permissions() -> BTreeSet<Permission> {
    required_write_permissions()
}

pub struct SelectedWriteRequest<'a> {
    pub endpoint: &'a BoundReadEndpoint,
    pub serial_manifest: &'a SysCfgSerialProviderManifest,
    pub purple_manifest: &'a PurpleProviderManifest,
    pub context: &'a SysCfgSerialContext,
    pub backup_evidence: &'a BackupPipelineEvidence,
    pub vault: &'a FileBackupVault,
    pub key: &'a VaultKey,
    pub authorization: &'a WriteTransportAuthorization,
    pub selection: SelectedNonIdentityFieldWrite,
}

impl fmt::Debug for SelectedWriteRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedWriteRequest")
            .field("session_id", &self.context.session_id)
            .field("provider_id", &self.serial_manifest.provider_id)
            .field("device_identity_hash", &self.context.device_identity_hash)
            .field("board_config", &self.context.board_config)
            .field("selection", &self.selection)
            .field("backup", &self.backup_evidence.backup)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedWriteEvidence {
    pub schema_version: String,
    pub session_id: Uuid,
    pub provider_id: String,
    pub device_identity_hash: String,
    pub board_config: String,
    pub selected_field: String,
    pub selected_class: SysCfgFieldClass,
    pub backup_snapshot_id: Uuid,
    pub backup_envelope_sha256: String,
    pub rollback_package_verified: bool,
    pub outcome: WriteTransactionOutcome,
}

struct PreparedWrite {
    plan: WriteTransactionPlan,
    field_key: String,
    field_class: SysCfgFieldClass,
    backup_snapshot_id: Uuid,
    backup_envelope_sha256: String,
}

pub fn execute_selected_write_with_transport<T: SerialTransport>(
    request: SelectedWriteRequest<'_>,
    transport: &mut T,
) -> Result<SelectedWriteEvidence, SysCfgWriteTransportError> {
    let prepared = prepare_write(&request)?;
    Ok(execute_prepared(
        request.serial_manifest,
        request.context,
        prepared,
        transport,
    ))
}

pub fn execute_selected_write_with_serialport(
    request: SelectedWriteRequest<'_>,
    policy: WriteFramePolicy,
) -> Result<SelectedWriteEvidence, SysCfgWriteTransportError> {
    policy.validate(request.serial_manifest)?;
    let prepared = prepare_write(&request)?;
    let mut transport = SerialportSysCfgWriteTransport::open(
        request.endpoint,
        request.serial_manifest,
        policy,
    )?;
    Ok(execute_prepared(
        request.serial_manifest,
        request.context,
        prepared,
        &mut transport,
    ))
}

fn prepare_write(
    request: &SelectedWriteRequest<'_>,
) -> Result<PreparedWrite, SysCfgWriteTransportError> {
    validate_scope(request)?;

    let verified_backup = request
        .vault
        .read_for_rollback(
            &request.backup_evidence.backup,
            &request.backup_evidence.encrypted,
            request.key,
        )
        .map_err(|error| SysCfgWriteTransportError::BackupVerification(error.to_string()))?;
    let dump = parse_syscfg_list(
        request.serial_manifest,
        verified_backup.bytes_for_rollback(),
    )
    .map_err(|error| SysCfgWriteTransportError::BackupParse(error.to_string()))?;
    if dump.blob_sha256() != request.backup_evidence.snapshot.blob_sha256
        || dump.blob_sha256() != request.backup_evidence.backup.source_blob_sha256
        || dump.byte_len() != request.backup_evidence.encrypted.plaintext_bytes
    {
        return Err(SysCfgWriteTransportError::BackupScopeMismatch);
    }

    let field_policy = request
        .serial_manifest
        .field_catalog
        .get(request.selection.key())
        .ok_or(SysCfgWriteTransportError::UnknownSelectedField)?;
    if !matches!(
        field_policy.class,
        SysCfgFieldClass::Diagnostic | SysCfgFieldClass::Calibration
    ) {
        return Err(SysCfgWriteTransportError::BlockedSelectedFieldClass);
    }
    if !field_policy.writable
        || !request.serial_manifest.supports_write
        || !request.purple_manifest.supports_syscfg_write
        || !request
            .purple_manifest
            .allowed_write_classes
            .contains(&field_policy.class)
    {
        return Err(SysCfgWriteTransportError::SelectedFieldNotWritable);
    }

    let snapshot_field = request
        .backup_evidence
        .snapshot
        .fields
        .get(request.selection.key())
        .ok_or(SysCfgWriteTransportError::UnknownSelectedField)?;
    if snapshot_field.class != field_policy.class
        || !snapshot_field.writable
        || !snapshot_field.checksum_valid
    {
        return Err(SysCfgWriteTransportError::SelectedFieldNotWritable);
    }
    let requested_after_hash = hash_value(&request.selection.requested_value);
    if requested_after_hash == snapshot_field.encoded_value_hash {
        return Err(SysCfgWriteTransportError::UnchangedSelectedValue);
    }

    let write_request = SysCfgWriteRequest {
        session_id: request.context.session_id,
        provider_id: request.serial_manifest.provider_id.clone(),
        current_device_identity_hash: request.context.device_identity_hash.clone(),
        current_board_config: request.context.board_config.clone(),
        intent: SysCfgWriteIntent::RepairSelectedFields,
        backup: request.backup_evidence.backup.clone(),
        changes: vec![SysCfgChange {
            field_key: request.selection.key.clone(),
            class: field_policy.class.clone(),
            expected_before_hash: snapshot_field.encoded_value_hash.clone(),
            requested_after_hash,
        }],
        requested_permissions: required_write_permissions(),
        explicit_authorization: request.authorization.explicit_authorization,
        policy_profile: request.context.policy_profile.clone(),
    };
    let plan = build_write_transaction_plan(
        request.serial_manifest,
        request.purple_manifest,
        request.context,
        &request.backup_evidence.snapshot,
        &dump,
        &write_request,
        vec![SelectedFieldMutation {
            key: request.selection.key.clone(),
            requested_value: request.selection.requested_value.clone(),
        }],
    )
    .map_err(|error| SysCfgWriteTransportError::TransactionPlan(error.to_string()))?;
    if plan.field_count() != 1 || plan.field_keys() != vec![request.selection.key()] {
        return Err(SysCfgWriteTransportError::TransactionPlanMismatch);
    }

    Ok(PreparedWrite {
        plan,
        field_key: request.selection.key.clone(),
        field_class: field_policy.class.clone(),
        backup_snapshot_id: request.backup_evidence.snapshot.snapshot_id,
        backup_envelope_sha256: request.backup_evidence.encrypted.envelope_sha256.clone(),
    })
}

fn validate_scope(request: &SelectedWriteRequest<'_>) -> Result<(), SysCfgWriteTransportError> {
    if request.authorization.granted_permissions != required_write_transport_permissions() {
        return Err(SysCfgWriteTransportError::PermissionGrantMismatch);
    }
    if !request.authorization.explicit_authorization {
        return Err(SysCfgWriteTransportError::ExplicitAuthorizationRequired);
    }
    if !request.authorization.allow_control_line_side_effects {
        return Err(SysCfgWriteTransportError::ControlLineAcknowledgementRequired);
    }
    if request.authorization.session_id != request.context.session_id
        || request.endpoint.session_id != request.context.session_id
        || request.endpoint.lease.owner.session_id != request.context.session_id
        || request.backup_evidence.snapshot.session_id != request.context.session_id
        || request.backup_evidence.encrypted.session_id != request.context.session_id
    {
        return Err(SysCfgWriteTransportError::SessionMismatch);
    }
    if request.authorization.device_identity_hash.trim().is_empty()
        || request.authorization.device_identity_hash != request.context.device_identity_hash
        || request.endpoint.device_identity_hash != request.context.device_identity_hash
        || request.backup_evidence.snapshot.device_identity_hash
            != request.context.device_identity_hash
        || request.backup_evidence.backup.device_identity_hash
            != request.context.device_identity_hash
        || request.backup_evidence.encrypted.device_identity_hash
            != request.context.device_identity_hash
    {
        return Err(SysCfgWriteTransportError::DeviceIdentityMismatch);
    }
    if request.serial_manifest.provider_id != request.context.provider_id
        || request.purple_manifest.provider_id != request.context.provider_id
        || request.backup_evidence.snapshot.provider_id != request.context.provider_id
        || request.backup_evidence.encrypted.provider_id != request.context.provider_id
    {
        return Err(SysCfgWriteTransportError::ProviderIdentityMismatch);
    }
    if request.backup_evidence.snapshot.board_config != request.context.board_config
        || request.backup_evidence.backup.board_config != request.context.board_config
        || request.backup_evidence.encrypted.board_config != request.context.board_config
    {
        return Err(SysCfgWriteTransportError::BoardConfigurationMismatch);
    }
    if request.authorization.current_tick >= request.endpoint.lease.expires_at_tick {
        return Err(SysCfgWriteTransportError::LeaseExpired);
    }
    if !request.backup_evidence.snapshot.verified
        || !request.backup_evidence.backup.verified
        || !request.backup_evidence.backup.rollback_ready
        || !request.backup_evidence.encrypted.verified_readback
        || request.backup_evidence.backup.snapshot_id
            != request.backup_evidence.snapshot.snapshot_id
        || request.backup_evidence.encrypted.snapshot_id
            != request.backup_evidence.snapshot.snapshot_id
        || request.backup_evidence.backup.source_blob_sha256
            != request.backup_evidence.snapshot.blob_sha256
        || request.backup_evidence.encrypted.plaintext_sha256
            != request.backup_evidence.snapshot.blob_sha256
        || request.backup_evidence.backup.backup_sha256
            != request.backup_evidence.encrypted.envelope_sha256
    {
        return Err(SysCfgWriteTransportError::BackupScopeMismatch);
    }
    Ok(())
}

fn execute_prepared<T: SerialTransport>(
    manifest: &SysCfgSerialProviderManifest,
    context: &SysCfgSerialContext,
    prepared: PreparedWrite,
    transport: &mut T,
) -> SelectedWriteEvidence {
    let outcome = execute_write_transaction(manifest, &prepared.plan, transport);
    SelectedWriteEvidence {
        schema_version: SYSCFG_WRITE_TRANSPORT_VERSION.to_owned(),
        session_id: context.session_id,
        provider_id: context.provider_id.clone(),
        device_identity_hash: context.device_identity_hash.clone(),
        board_config: context.board_config.clone(),
        selected_field: prepared.field_key,
        selected_class: prepared.field_class,
        backup_snapshot_id: prepared.backup_snapshot_id,
        backup_envelope_sha256: prepared.backup_envelope_sha256,
        rollback_package_verified: true,
        outcome,
    }
}
