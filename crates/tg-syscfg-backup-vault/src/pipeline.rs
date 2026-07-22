use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use tg_contracts::Permission;
use tg_purple::{SysCfgBackupReceipt, SysCfgSnapshot};
use tg_syscfg_read_transport::{BoundReadEndpoint, ReadExchangeReceipt, SysCfgReadOperation};
use tg_syscfg_serial::{
    build_backup_receipt, capture_snapshot, parse_syscfg_list, required_read_permissions,
    SysCfgSerialContext, SysCfgSerialError, SysCfgSerialProviderManifest, VaultWriteReceipt,
};
use uuid::Uuid;

use crate::envelope::{sha256_hex, EncryptedBackupReceipt, VaultMetadata};
use crate::key::VaultKey;
use crate::store::FileBackupVault;
use crate::SYSCFG_BACKUP_VAULT_VERSION;

#[derive(Clone, PartialEq, Eq)]
pub struct BackupAuthorization {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub granted_permissions: BTreeSet<Permission>,
    pub current_tick: u64,
}

impl fmt::Debug for BackupAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupAuthorization")
            .field("session_id", &self.session_id)
            .field("device_identity_hash", &self.device_identity_hash)
            .field("granted_permissions", &self.granted_permissions)
            .field("current_tick", &self.current_tick)
            .finish()
    }
}

pub fn required_backup_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::SerialRead,
        Permission::SerialWrite,
        Permission::SysCfgRead,
        Permission::SysCfgBackup,
        Permission::VaultWrite,
    ])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPipelineEvidence {
    pub schema_version: String,
    pub snapshot: SysCfgSnapshot,
    pub backup: SysCfgBackupReceipt,
    pub encrypted: EncryptedBackupReceipt,
}

pub fn capture_encrypt_verify_backup(
    endpoint: &BoundReadEndpoint,
    provider: &SysCfgSerialProviderManifest,
    context: &SysCfgSerialContext,
    read_receipt: &ReadExchangeReceipt,
    raw_response: &[u8],
    authorization: &BackupAuthorization,
    vault: &FileBackupVault,
    key: &VaultKey,
) -> Result<BackupPipelineEvidence, SysCfgBackupVaultError> {
    validate_scope(endpoint, context, read_receipt, authorization)?;
    if context.granted_permissions != required_read_permissions() {
        return Err(SysCfgBackupVaultError::LogicalReadPermissionMismatch);
    }
    validate_capture(read_receipt, raw_response)?;

    let dump = parse_syscfg_list(provider, raw_response).map_err(SysCfgBackupVaultError::SysCfg)?;
    if dump.blob_sha256() != read_receipt.response_sha256
        || dump.byte_len() != read_receipt.bytes_read
    {
        return Err(SysCfgBackupVaultError::ResponseBindingMismatch);
    }
    let snapshot =
        capture_snapshot(provider, context, &dump).map_err(SysCfgBackupVaultError::SysCfg)?;
    if !snapshot.verified || snapshot.blob_sha256 != read_receipt.response_sha256 {
        return Err(SysCfgBackupVaultError::SnapshotNotVerified);
    }

    let object_id = Uuid::new_v4();
    let metadata = VaultMetadata {
        schema_version: SYSCFG_BACKUP_VAULT_VERSION.to_owned(),
        object_id,
        snapshot_id: snapshot.snapshot_id,
        session_id: snapshot.session_id,
        provider_id: snapshot.provider_id.clone(),
        device_identity_hash: snapshot.device_identity_hash.clone(),
        board_config: snapshot.board_config.clone(),
        source_blob_sha256: snapshot.blob_sha256.clone(),
        response_sha256: read_receipt.response_sha256.clone(),
        plaintext_bytes: raw_response.len(),
        field_count: dump.field_count(),
        key_id: key.key_id().to_owned(),
    };
    let persisted = vault.persist_verified(&metadata, raw_response, key)?;
    let vault_write = VaultWriteReceipt {
        session_id: context.session_id,
        device_identity_hash: context.device_identity_hash.clone(),
        board_config: context.board_config.clone(),
        plaintext_sha256: snapshot.blob_sha256.clone(),
        stored_package_sha256: persisted.envelope_sha256.clone(),
        plaintext_bytes: dump.byte_len(),
        encrypted: true,
        durable: true,
        rollback_ready: true,
    };
    let backup = build_backup_receipt(context, &snapshot, &dump, &vault_write)
        .map_err(SysCfgBackupVaultError::SysCfg)?;
    let encrypted = EncryptedBackupReceipt {
        schema_version: SYSCFG_BACKUP_VAULT_VERSION.to_owned(),
        object_id,
        snapshot_id: snapshot.snapshot_id,
        session_id: snapshot.session_id,
        provider_id: snapshot.provider_id.clone(),
        device_identity_hash: snapshot.device_identity_hash.clone(),
        board_config: snapshot.board_config.clone(),
        key_id: key.key_id().to_owned(),
        vault_object_name_hash: persisted.vault_object_name_hash,
        envelope_sha256: persisted.envelope_sha256,
        ciphertext_sha256: persisted.ciphertext_sha256,
        plaintext_sha256: snapshot.blob_sha256.clone(),
        plaintext_bytes: dump.byte_len(),
        encrypted_bytes: persisted.envelope_bytes,
        field_count: dump.field_count(),
        verified_readback: true,
    };
    Ok(BackupPipelineEvidence {
        schema_version: SYSCFG_BACKUP_VAULT_VERSION.to_owned(),
        snapshot,
        backup,
        encrypted,
    })
}

fn validate_scope(
    endpoint: &BoundReadEndpoint,
    context: &SysCfgSerialContext,
    receipt: &ReadExchangeReceipt,
    authorization: &BackupAuthorization,
) -> Result<(), SysCfgBackupVaultError> {
    if authorization.granted_permissions != required_backup_permissions() {
        return Err(SysCfgBackupVaultError::BackupPermissionMismatch);
    }
    if authorization.session_id != context.session_id
        || authorization.session_id != endpoint.session_id
        || endpoint.lease.owner.session_id != authorization.session_id
        || receipt.session_id != authorization.session_id
    {
        return Err(SysCfgBackupVaultError::SessionMismatch);
    }
    if authorization.device_identity_hash.trim().is_empty()
        || authorization.device_identity_hash != context.device_identity_hash
        || authorization.device_identity_hash != endpoint.device_identity_hash
    {
        return Err(SysCfgBackupVaultError::DeviceIdentityMismatch);
    }
    if receipt.lease_id != endpoint.lease.lease_id
        || receipt.hardware_fingerprint != endpoint.candidate.hardware_fingerprint
    {
        return Err(SysCfgBackupVaultError::ReadReceiptScopeMismatch);
    }
    if authorization.current_tick >= endpoint.lease.expires_at_tick {
        return Err(SysCfgBackupVaultError::LeaseExpired);
    }
    Ok(())
}

fn validate_capture(
    receipt: &ReadExchangeReceipt,
    raw_response: &[u8],
) -> Result<(), SysCfgBackupVaultError> {
    if receipt.operation != SysCfgReadOperation::List
        || receipt.command_action != "list"
        || receipt.command_key.is_some()
    {
        return Err(SysCfgBackupVaultError::ListCaptureRequired);
    }
    if !receipt.prompt_verified || !contains_prompt_line(raw_response) {
        return Err(SysCfgBackupVaultError::PromptNotVerified);
    }
    if raw_response.is_empty()
        || receipt.bytes_read != raw_response.len()
        || receipt.response_sha256 != sha256_hex(raw_response)
    {
        return Err(SysCfgBackupVaultError::ResponseBindingMismatch);
    }
    Ok(())
}

fn contains_prompt_line(response: &[u8]) -> bool {
    response.split(|byte| *byte == b'\n').any(|line| {
        let line = trim_ascii(line);
        line == b">"
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Debug, thiserror::Error)]
pub enum SysCfgBackupVaultError {
    #[error("backup permission grant does not match the exact contract")]
    BackupPermissionMismatch,
    #[error("logical SysCfg read permission grant does not match")]
    LogicalReadPermissionMismatch,
    #[error("session identity does not match")]
    SessionMismatch,
    #[error("device identity does not match")]
    DeviceIdentityMismatch,
    #[error("captured read receipt does not match the held endpoint")]
    ReadReceiptScopeMismatch,
    #[error("serial lease has expired")]
    LeaseExpired,
    #[error("a verified SysCfg list capture is required")]
    ListCaptureRequired,
    #[error("Diags prompt was not independently verified")]
    PromptNotVerified,
    #[error("raw response does not match the read receipt or parsed dump")]
    ResponseBindingMismatch,
    #[error("hash-only snapshot was not verified")]
    SnapshotNotVerified,
    #[error("invalid vault key identifier")]
    InvalidKeyId,
    #[error("invalid encryption key")]
    InvalidKey,
    #[error("secure random generation failed: {0}")]
    RandomFailed(String),
    #[error("vault root failed validation: {0}")]
    VaultRoot(String),
    #[error("vault root must be an existing non-symlink directory")]
    UnsafeVaultRoot,
    #[error("vault root permissions allow group or world access")]
    InsecureVaultPermissions,
    #[error("vault object is not a regular non-symlink file")]
    UnsafeVaultObject,
    #[error("vault write failed: {0}")]
    VaultWrite(String),
    #[error("vault read failed: {0}")]
    VaultRead(String),
    #[error("vault metadata failed: {0}")]
    Metadata(String),
    #[error("vault metadata size is invalid: {0}")]
    InvalidMetadataSize(usize),
    #[error("raw backup size is invalid: {0}")]
    InvalidPlaintextSize(usize),
    #[error("encrypted envelope exceeded the bounded size")]
    EnvelopeTooLarge,
    #[error("encrypted envelope is invalid")]
    InvalidEnvelope,
    #[error("unsupported encrypted envelope version: {0}")]
    UnsupportedEnvelopeVersion(u16),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("encrypted package authentication failed")]
    AuthenticationFailed,
    #[error("encrypted package metadata does not match")]
    MetadataScopeMismatch,
    #[error("encrypted package read-back did not match the source")]
    ReadbackMismatch,
    #[error("backup receipt scope does not match")]
    ReceiptScopeMismatch,
    #[error("stored package hash does not match the receipt")]
    PackageHashMismatch,
    #[error("SysCfg operation failed: {0}")]
    SysCfg(SysCfgSerialError),
}
