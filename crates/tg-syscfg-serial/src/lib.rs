//! Typed, fail-closed SysCfg serial provider contracts and transaction engine.
//!
//! This crate intentionally exposes no free-form Diags terminal. The supported
//! protocol surface is limited to `syscfg list`, `syscfg print <key>`, and
//! `syscfg add <key> <value>`. Raw configuration values remain in memory and
//! durable evidence contains hashes only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tg_contracts::{DeviceMode, Maturity, Permission};
use tg_purple::{
    evaluate_write_request, verify_write_readback, PurpleProviderManifest, SysCfgBackupReceipt,
    SysCfgFieldClass, SysCfgFieldRecord, SysCfgReadbackProof, SysCfgSnapshot, SysCfgWriteRequest,
    SysCfgWriteVerification,
};
use tg_purple_boot::PurpleBootFinalProof;
use uuid::Uuid;

pub const SYSCFG_SERIAL_VERSION: &str = "tgcheckm8.syscfg-serial.v1";
pub const ABSOLUTE_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialLink {
    UsbSerial,
    DcsdSerial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgFieldPolicy {
    pub class: SysCfgFieldClass,
    pub writable: bool,
    pub max_value_bytes: usize,
    pub response_labels: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgSerialProviderManifest {
    pub schema_version: String,
    pub provider_id: String,
    pub version: String,
    pub maturity: Maturity,
    pub supported_product_types: BTreeSet<String>,
    pub supported_board_configs: BTreeSet<String>,
    pub links: BTreeSet<SerialLink>,
    pub source_repository: String,
    pub source_commit: String,
    pub declared_licence: Option<String>,
    pub supports_write: bool,
    pub max_response_bytes: usize,
    pub field_catalog: BTreeMap<String, SysCfgFieldPolicy>,
    pub required_backup_keys: BTreeSet<String>,
    pub requested_read_permissions: BTreeSet<Permission>,
    pub requested_write_permissions: BTreeSet<Permission>,
    pub proof_requirements: BTreeSet<String>,
}

pub fn required_read_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::SerialRead,
        Permission::SysCfgRead,
        Permission::VaultWrite,
    ])
}

pub fn required_write_permissions() -> BTreeSet<Permission> {
    BTreeSet::from([
        Permission::DeviceObserve,
        Permission::SerialRead,
        Permission::SerialWrite,
        Permission::SysCfgRead,
        Permission::SysCfgBackup,
        Permission::SysCfgRestoreSameBoard,
        Permission::VaultRead,
        Permission::VaultWrite,
    ])
}

pub fn validate_provider_manifest(
    manifest: &SysCfgSerialProviderManifest,
    policy_profile: &str,
) -> Result<(), SysCfgSerialError> {
    if manifest.schema_version != SYSCFG_SERIAL_VERSION {
        return Err(SysCfgSerialError::UnsupportedVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.provider_id.trim().is_empty()
        || manifest.version.trim().is_empty()
        || manifest.source_repository.trim().is_empty()
        || manifest.source_commit.trim().is_empty()
    {
        return Err(SysCfgSerialError::IncompleteProviderIdentity);
    }
    if !is_git_commit(&manifest.source_commit) {
        return Err(SysCfgSerialError::InvalidSourceCommit);
    }
    if manifest.supported_product_types.is_empty()
        || manifest.supported_board_configs.is_empty()
        || manifest.links.is_empty()
    {
        return Err(SysCfgSerialError::MissingCoverage);
    }
    if manifest.max_response_bytes == 0 || manifest.max_response_bytes > ABSOLUTE_MAX_RESPONSE_BYTES
    {
        return Err(SysCfgSerialError::InvalidResponseLimit(
            manifest.max_response_bytes,
        ));
    }
    if manifest.field_catalog.is_empty() || manifest.required_backup_keys.is_empty() {
        return Err(SysCfgSerialError::MissingFieldCatalog);
    }
    if manifest.requested_read_permissions != required_read_permissions()
        || manifest.requested_write_permissions != required_write_permissions()
    {
        return Err(SysCfgSerialError::PermissionContractMismatch);
    }

    for (key, policy) in &manifest.field_catalog {
        validate_key(key)?;
        if policy.max_value_bytes == 0 || policy.max_value_bytes > 4096 {
            return Err(SysCfgSerialError::InvalidFieldLimit(key.clone()));
        }
        if policy.response_labels.is_empty() {
            return Err(SysCfgSerialError::MissingResponseLabel(key.clone()));
        }
        for label in &policy.response_labels {
            validate_key(label)?;
        }
        if policy.writable
            && !matches!(
                policy.class,
                SysCfgFieldClass::Diagnostic | SysCfgFieldClass::Calibration
            )
        {
            return Err(SysCfgSerialError::BlockedWritableClass(key.clone()));
        }
    }
    if manifest
        .required_backup_keys
        .iter()
        .any(|key| !manifest.field_catalog.contains_key(key))
    {
        return Err(SysCfgSerialError::UnknownRequiredBackupKey);
    }
    if !manifest.supports_write
        && manifest
            .field_catalog
            .values()
            .any(|policy| policy.writable)
    {
        return Err(SysCfgSerialError::WriteCapabilityMismatch);
    }
    if manifest.supports_write
        && !manifest
            .field_catalog
            .values()
            .any(|policy| policy.writable)
    {
        return Err(SysCfgSerialError::WriteCapabilityMismatch);
    }

    let mandatory_proofs = [
        "purple_mode_same_device",
        "full_syscfg_list_captured",
        "backup_vault_verified",
        "field_precondition_verified",
        "typed_write_only",
        "exact_readback_match",
        "rollback_verified_or_recovery_required",
    ];
    if mandatory_proofs
        .iter()
        .any(|proof| !manifest.proof_requirements.contains(*proof))
    {
        return Err(SysCfgSerialError::MissingMandatoryProof);
    }

    if policy_profile == "stable" {
        if manifest.maturity != Maturity::Stable {
            return Err(SysCfgSerialError::ImmatureStableProvider);
        }
        match manifest.declared_licence.as_deref() {
            Some(licence) if !licence.trim().is_empty() => {}
            _ => return Err(SysCfgSerialError::MissingDeclaredLicence),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysCfgSerialContext {
    pub session_id: Uuid,
    pub provider_id: String,
    pub device_identity_hash: String,
    pub product_type: String,
    pub board_config: String,
    pub purple_proof: PurpleBootFinalProof,
    pub granted_permissions: BTreeSet<Permission>,
    pub policy_profile: String,
}

fn validate_context(
    manifest: &SysCfgSerialProviderManifest,
    context: &SysCfgSerialContext,
    expected_permissions: &BTreeSet<Permission>,
) -> Result<(), SysCfgSerialError> {
    validate_provider_manifest(manifest, &context.policy_profile)?;
    if context.provider_id != manifest.provider_id {
        return Err(SysCfgSerialError::ProviderIdentityMismatch);
    }
    if context.device_identity_hash.trim().is_empty()
        || context.product_type.trim().is_empty()
        || context.board_config.trim().is_empty()
    {
        return Err(SysCfgSerialError::IncompleteDeviceIdentity);
    }
    if !manifest
        .supported_product_types
        .contains(&context.product_type)
        || !manifest
            .supported_board_configs
            .contains(&context.board_config)
    {
        return Err(SysCfgSerialError::UnsupportedDeviceRoute);
    }
    if context.purple_proof.session_id != context.session_id
        || !context.purple_proof.verified
        || context.purple_proof.final_mode != DeviceMode::PurpleDiagnostic
    {
        return Err(SysCfgSerialError::UnverifiedPurpleSession);
    }
    if context.granted_permissions != *expected_permissions {
        return Err(SysCfgSerialError::PermissionGrantMismatch);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub enum SysCfgCommand {
    List,
    Print { key: String },
    Add { key: String, value: String },
}

impl fmt::Debug for SysCfgCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List => formatter.write_str("SysCfgCommand::List"),
            Self::Print { key } => formatter
                .debug_struct("SysCfgCommand::Print")
                .field("key", key)
                .finish(),
            Self::Add { key, .. } => formatter
                .debug_struct("SysCfgCommand::Add")
                .field("key", key)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncodedCommand {
    action: &'static str,
    key: Option<String>,
    bytes: Vec<u8>,
}

impl EncodedCommand {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn action(&self) -> &'static str {
        self.action
    }

    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl fmt::Debug for EncodedCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedCommand")
            .field("action", &self.action)
            .field("key", &self.key)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

pub fn encode_command(
    manifest: &SysCfgSerialProviderManifest,
    command: &SysCfgCommand,
) -> Result<EncodedCommand, SysCfgSerialError> {
    match command {
        SysCfgCommand::List => Ok(EncodedCommand {
            action: "list",
            key: None,
            bytes: b"syscfg list\n".to_vec(),
        }),
        SysCfgCommand::Print { key } => {
            let policy = manifest
                .field_catalog
                .get(key)
                .ok_or_else(|| SysCfgSerialError::UnknownField(key.clone()))?;
            validate_key(key)?;
            if policy.max_value_bytes == 0 {
                return Err(SysCfgSerialError::InvalidFieldLimit(key.clone()));
            }
            Ok(EncodedCommand {
                action: "print",
                key: Some(key.clone()),
                bytes: format!("syscfg print {key}\n").into_bytes(),
            })
        }
        SysCfgCommand::Add { key, value } => {
            if !manifest.supports_write {
                return Err(SysCfgSerialError::WriteCapabilityDisabled);
            }
            let policy = manifest
                .field_catalog
                .get(key)
                .ok_or_else(|| SysCfgSerialError::UnknownField(key.clone()))?;
            if !policy.writable
                || !matches!(
                    policy.class,
                    SysCfgFieldClass::Diagnostic | SysCfgFieldClass::Calibration
                )
            {
                return Err(SysCfgSerialError::FieldNotWritable(key.clone()));
            }
            validate_key(key)?;
            validate_value(key, value, policy.max_value_bytes)?;
            Ok(EncodedCommand {
                action: "add",
                key: Some(key.clone()),
                bytes: format!("syscfg add {key} {value}\n").into_bytes(),
            })
        }
    }
}

pub struct RawSysCfgDump {
    bytes: Vec<u8>,
    fields: BTreeMap<String, String>,
}

impl RawSysCfgDump {
    pub fn blob_sha256(&self) -> String {
        sha256_hex(&self.bytes)
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn field_value(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

impl fmt::Debug for RawSysCfgDump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawSysCfgDump")
            .field("byte_len", &self.bytes.len())
            .field("field_count", &self.fields.len())
            .field("blob_sha256", &self.blob_sha256())
            .field("values", &"<redacted>")
            .finish()
    }
}

pub fn parse_syscfg_list(
    manifest: &SysCfgSerialProviderManifest,
    response: &[u8],
) -> Result<RawSysCfgDump, SysCfgSerialError> {
    validate_response(manifest, response)?;
    let text = std::str::from_utf8(response).map_err(|_| SysCfgSerialError::InvalidUtf8Response)?;
    let mut fields = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.eq_ignore_ascii_case("syscfg list")
            || line == ">"
            || response_line_is_error(line)
        {
            continue;
        }
        let Some((key, value)) = split_field_line(line) else {
            continue;
        };
        if !looks_like_key(key) || value.is_empty() {
            continue;
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(SysCfgSerialError::DuplicateField(key.to_owned()));
        }
    }
    if fields.is_empty() {
        return Err(SysCfgSerialError::NoSysCfgFields);
    }
    Ok(RawSysCfgDump {
        bytes: response.to_vec(),
        fields,
    })
}

pub struct FieldRead {
    key: String,
    value: String,
    value_hash: String,
}

impl FieldRead {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn value_hash(&self) -> &str {
        &self.value_hash
    }
}

impl fmt::Debug for FieldRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldRead")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .field("value_hash", &self.value_hash)
            .finish()
    }
}

pub fn parse_print_response(
    manifest: &SysCfgSerialProviderManifest,
    key: &str,
    response: &[u8],
) -> Result<FieldRead, SysCfgSerialError> {
    validate_response(manifest, response)?;
    let policy = manifest
        .field_catalog
        .get(key)
        .ok_or_else(|| SysCfgSerialError::UnknownField(key.to_owned()))?;
    let text = std::str::from_utf8(response).map_err(|_| SysCfgSerialError::InvalidUtf8Response)?;
    let mut found = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with("syscfg print ")
            || line == ">"
            || response_line_is_error(line)
        {
            continue;
        }
        let Some((label, value)) = split_field_line(line) else {
            continue;
        };
        if (label == key || policy.response_labels.contains(label)) && !value.is_empty() {
            if found.replace(value.to_owned()).is_some() {
                return Err(SysCfgSerialError::AmbiguousFieldResponse(key.to_owned()));
            }
        }
    }
    let value = found.ok_or_else(|| SysCfgSerialError::MissingFieldResponse(key.to_owned()))?;
    validate_value(key, &value, policy.max_value_bytes)?;
    Ok(FieldRead {
        key: key.to_owned(),
        value_hash: hash_value(&value),
        value,
    })
}

pub fn capture_snapshot(
    manifest: &SysCfgSerialProviderManifest,
    context: &SysCfgSerialContext,
    dump: &RawSysCfgDump,
) -> Result<SysCfgSnapshot, SysCfgSerialError> {
    validate_context(manifest, context, &required_read_permissions())?;
    if manifest
        .required_backup_keys
        .iter()
        .any(|key| !dump.fields.contains_key(key))
    {
        return Err(SysCfgSerialError::IncompleteBackupDump);
    }

    let fields = dump
        .fields
        .iter()
        .map(|(key, value)| {
            let policy = manifest.field_catalog.get(key);
            let class = policy
                .map(|field| field.class.clone())
                .unwrap_or(SysCfgFieldClass::Unknown);
            let writable = policy.map(|field| field.writable).unwrap_or(false);
            (
                key.clone(),
                SysCfgFieldRecord {
                    key: key.clone(),
                    class,
                    encoded_value_hash: hash_value(value),
                    checksum_valid: policy.is_some() && !value.is_empty(),
                    writable,
                },
            )
        })
        .collect();

    Ok(SysCfgSnapshot {
        snapshot_id: Uuid::new_v4(),
        session_id: context.session_id,
        provider_id: manifest.provider_id.clone(),
        device_identity_hash: context.device_identity_hash.clone(),
        product_type: context.product_type.clone(),
        board_config: context.board_config.clone(),
        blob_sha256: dump.blob_sha256(),
        fields,
        verified: true,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultWriteReceipt {
    pub session_id: Uuid,
    pub device_identity_hash: String,
    pub board_config: String,
    pub plaintext_sha256: String,
    pub stored_package_sha256: String,
    pub plaintext_bytes: usize,
    pub encrypted: bool,
    pub durable: bool,
    pub rollback_ready: bool,
}

pub fn build_backup_receipt(
    context: &SysCfgSerialContext,
    snapshot: &SysCfgSnapshot,
    dump: &RawSysCfgDump,
    vault: &VaultWriteReceipt,
) -> Result<SysCfgBackupReceipt, SysCfgSerialError> {
    if !snapshot.verified
        || snapshot.session_id != context.session_id
        || snapshot.device_identity_hash != context.device_identity_hash
        || snapshot.board_config != context.board_config
        || snapshot.blob_sha256 != dump.blob_sha256()
    {
        return Err(SysCfgSerialError::SnapshotScopeMismatch);
    }
    if vault.session_id != context.session_id
        || vault.device_identity_hash != context.device_identity_hash
        || vault.board_config != context.board_config
        || vault.plaintext_sha256 != snapshot.blob_sha256
        || vault.plaintext_bytes != dump.byte_len()
    {
        return Err(SysCfgSerialError::VaultReceiptScopeMismatch);
    }
    if !is_sha256(&vault.stored_package_sha256)
        || !vault.encrypted
        || !vault.durable
        || !vault.rollback_ready
    {
        return Err(SysCfgSerialError::VaultBackupNotReady);
    }
    Ok(SysCfgBackupReceipt {
        snapshot_id: snapshot.snapshot_id,
        device_identity_hash: context.device_identity_hash.clone(),
        board_config: context.board_config.clone(),
        source_blob_sha256: snapshot.blob_sha256.clone(),
        backup_sha256: vault.stored_package_sha256.clone(),
        verified: true,
        rollback_ready: true,
    })
}

pub struct SelectedFieldMutation {
    pub key: String,
    pub requested_value: String,
}

impl fmt::Debug for SelectedFieldMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedFieldMutation")
            .field("key", &self.key)
            .field("requested_value", &"<redacted>")
            .finish()
    }
}

struct PlannedFieldMutation {
    key: String,
    class: SysCfgFieldClass,
    before_value: String,
    before_hash: String,
    after_value: String,
    after_hash: String,
    print_command: EncodedCommand,
    write_command: EncodedCommand,
    rollback_command: EncodedCommand,
}

pub struct WriteTransactionPlan {
    pub session_id: Uuid,
    pub provider_id: String,
    pub device_identity_hash: String,
    pub board_config: String,
    pub backup_sha256: String,
    pub required_proofs: BTreeSet<String>,
    request: SysCfgWriteRequest,
    mutations: Vec<PlannedFieldMutation>,
}

impl WriteTransactionPlan {
    pub fn field_count(&self) -> usize {
        self.mutations.len()
    }

    pub fn field_keys(&self) -> Vec<&str> {
        self.mutations
            .iter()
            .map(|mutation| mutation.key.as_str())
            .collect()
    }
}

impl fmt::Debug for WriteTransactionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteTransactionPlan")
            .field("session_id", &self.session_id)
            .field("provider_id", &self.provider_id)
            .field("device_identity_hash", &self.device_identity_hash)
            .field("board_config", &self.board_config)
            .field("backup_sha256", &self.backup_sha256)
            .field("field_keys", &self.field_keys())
            .field("values", &"<redacted>")
            .finish()
    }
}

pub fn build_write_transaction_plan(
    serial_manifest: &SysCfgSerialProviderManifest,
    policy_manifest: &PurpleProviderManifest,
    context: &SysCfgSerialContext,
    snapshot: &SysCfgSnapshot,
    dump: &RawSysCfgDump,
    request: &SysCfgWriteRequest,
    selected: Vec<SelectedFieldMutation>,
) -> Result<WriteTransactionPlan, SysCfgSerialError> {
    validate_context(serial_manifest, context, &required_write_permissions())?;
    if !serial_manifest.supports_write {
        return Err(SysCfgSerialError::WriteCapabilityDisabled);
    }
    if request.requested_permissions != required_write_permissions() {
        return Err(SysCfgSerialError::PermissionGrantMismatch);
    }
    if request.session_id != context.session_id
        || request.provider_id != serial_manifest.provider_id
        || request.current_device_identity_hash != context.device_identity_hash
        || request.current_board_config != context.board_config
    {
        return Err(SysCfgSerialError::WriteRequestScopeMismatch);
    }
    if request.backup.snapshot_id != snapshot.snapshot_id
        || request.backup.source_blob_sha256 != dump.blob_sha256()
    {
        return Err(SysCfgSerialError::BackupBindingMismatch);
    }

    let decision = evaluate_write_request(policy_manifest, snapshot, request);
    if !decision.approved {
        return Err(SysCfgSerialError::WritePolicyBlocked(decision.blockers));
    }
    if selected.len() != request.changes.len() {
        return Err(SysCfgSerialError::SelectedMutationMismatch);
    }

    let selected_by_key: BTreeMap<String, String> = selected
        .into_iter()
        .map(|mutation| (mutation.key, mutation.requested_value))
        .collect();
    if selected_by_key.len() != request.changes.len() {
        return Err(SysCfgSerialError::SelectedMutationMismatch);
    }

    let mut mutations = Vec::with_capacity(request.changes.len());
    for change in &request.changes {
        let requested_value = selected_by_key
            .get(&change.field_key)
            .ok_or_else(|| SysCfgSerialError::MissingSelectedValue(change.field_key.clone()))?;
        let field_policy = serial_manifest
            .field_catalog
            .get(&change.field_key)
            .ok_or_else(|| SysCfgSerialError::UnknownField(change.field_key.clone()))?;
        if !field_policy.writable || field_policy.class != change.class {
            return Err(SysCfgSerialError::FieldNotWritable(
                change.field_key.clone(),
            ));
        }
        let before_value = dump
            .field_value(&change.field_key)
            .ok_or_else(|| SysCfgSerialError::MissingBackupValue(change.field_key.clone()))?;
        if hash_value(before_value) != change.expected_before_hash {
            return Err(SysCfgSerialError::BeforeHashMismatch(
                change.field_key.clone(),
            ));
        }
        validate_value(
            &change.field_key,
            requested_value,
            field_policy.max_value_bytes,
        )?;
        if hash_value(requested_value) != change.requested_after_hash {
            return Err(SysCfgSerialError::AfterHashMismatch(
                change.field_key.clone(),
            ));
        }

        let print_command = encode_command(
            serial_manifest,
            &SysCfgCommand::Print {
                key: change.field_key.clone(),
            },
        )?;
        let write_command = encode_command(
            serial_manifest,
            &SysCfgCommand::Add {
                key: change.field_key.clone(),
                value: requested_value.clone(),
            },
        )?;
        let rollback_command = encode_command(
            serial_manifest,
            &SysCfgCommand::Add {
                key: change.field_key.clone(),
                value: before_value.to_owned(),
            },
        )?;
        mutations.push(PlannedFieldMutation {
            key: change.field_key.clone(),
            class: change.class.clone(),
            before_value: before_value.to_owned(),
            before_hash: change.expected_before_hash.clone(),
            after_value: requested_value.clone(),
            after_hash: change.requested_after_hash.clone(),
            print_command,
            write_command,
            rollback_command,
        });
    }

    Ok(WriteTransactionPlan {
        session_id: context.session_id,
        provider_id: serial_manifest.provider_id.clone(),
        device_identity_hash: context.device_identity_hash.clone(),
        board_config: context.board_config.clone(),
        backup_sha256: request.backup.backup_sha256.clone(),
        required_proofs: decision.required_post_write_proofs,
        request: request.clone(),
        mutations,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("serial transport error: {message}")]
pub struct SerialTransportError {
    pub message: String,
}

pub trait SerialTransport {
    fn exchange(
        &mut self,
        command: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SerialTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    VerifiedCommitted,
    FailedNoWrite,
    RolledBackVerified,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldTransactionEvidence {
    pub key: String,
    pub class: SysCfgFieldClass,
    pub before_hash: String,
    pub requested_after_hash: String,
    pub before_precondition_verified: bool,
    pub write_exchange_completed: bool,
    pub observed_after_hash: Option<String>,
    pub readback_matched: bool,
    pub rollback_attempted: bool,
    pub rollback_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteTransactionOutcome {
    pub session_id: Uuid,
    pub provider_id: String,
    pub status: TransactionStatus,
    pub fields: Vec<FieldTransactionEvidence>,
    pub verification: SysCfgWriteVerification,
    pub recovery_required: bool,
    pub failures: Vec<String>,
}

pub fn execute_write_transaction<T: SerialTransport>(
    manifest: &SysCfgSerialProviderManifest,
    plan: &WriteTransactionPlan,
    transport: &mut T,
) -> WriteTransactionOutcome {
    let mut evidence: Vec<FieldTransactionEvidence> = plan
        .mutations
        .iter()
        .map(|mutation| FieldTransactionEvidence {
            key: mutation.key.clone(),
            class: mutation.class.clone(),
            before_hash: mutation.before_hash.clone(),
            requested_after_hash: mutation.after_hash.clone(),
            before_precondition_verified: false,
            write_exchange_completed: false,
            observed_after_hash: None,
            readback_matched: false,
            rollback_attempted: false,
            rollback_verified: false,
        })
        .collect();
    let mut attempted = Vec::new();
    let mut failures = Vec::new();
    let mut observed_hashes = BTreeMap::new();

    for (index, mutation) in plan.mutations.iter().enumerate() {
        let before_response = match exchange_checked(manifest, transport, &mutation.print_command) {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!(
                    "{} precondition read failed: {error}",
                    mutation.key
                ));
                return finish_failed_transaction(
                    manifest, plan, transport, &attempted, evidence, failures,
                );
            }
        };
        let before = match parse_print_response(manifest, &mutation.key, &before_response) {
            Ok(read) => read,
            Err(error) => {
                failures.push(format!(
                    "{} precondition parse failed: {error}",
                    mutation.key
                ));
                return finish_failed_transaction(
                    manifest, plan, transport, &attempted, evidence, failures,
                );
            }
        };
        if before.value_hash() != mutation.before_hash {
            failures.push(format!("{} changed after backup", mutation.key));
            return finish_failed_transaction(
                manifest, plan, transport, &attempted, evidence, failures,
            );
        }
        evidence[index].before_precondition_verified = true;
        attempted.push(index);

        match exchange_checked(manifest, transport, &mutation.write_command) {
            Ok(response) if !response_contains_error(&response) => {
                evidence[index].write_exchange_completed = true;
            }
            Ok(_) => {
                failures.push(format!("{} write returned an error marker", mutation.key));
                return finish_failed_transaction(
                    manifest, plan, transport, &attempted, evidence, failures,
                );
            }
            Err(error) => {
                failures.push(format!("{} write exchange failed: {error}", mutation.key));
                return finish_failed_transaction(
                    manifest, plan, transport, &attempted, evidence, failures,
                );
            }
        }

        let after_response = match exchange_checked(manifest, transport, &mutation.print_command) {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{} read-back failed: {error}", mutation.key));
                return finish_failed_transaction(
                    manifest, plan, transport, &attempted, evidence, failures,
                );
            }
        };
        let after = match parse_print_response(manifest, &mutation.key, &after_response) {
            Ok(read) => read,
            Err(error) => {
                failures.push(format!("{} read-back parse failed: {error}", mutation.key));
                return finish_failed_transaction(
                    manifest, plan, transport, &attempted, evidence, failures,
                );
            }
        };
        evidence[index].observed_after_hash = Some(after.value_hash().to_owned());
        if after.value_hash() != mutation.after_hash {
            failures.push(format!("{} exact read-back mismatch", mutation.key));
            return finish_failed_transaction(
                manifest, plan, transport, &attempted, evidence, failures,
            );
        }
        evidence[index].readback_matched = true;
        observed_hashes.insert(mutation.key.clone(), after.value_hash().to_owned());
    }

    let proof = SysCfgReadbackProof {
        session_id: plan.session_id,
        device_identity_hash: plan.device_identity_hash.clone(),
        board_config: plan.board_config.clone(),
        observed_field_hashes: observed_hashes,
        transport_write_acknowledged: evidence.iter().all(|field| field.write_exchange_completed),
        rollback_package_sha256: plan.backup_sha256.clone(),
        valid: true,
    };
    let verification = verify_write_readback(&plan.request, &proof);
    if verification.verified {
        WriteTransactionOutcome {
            session_id: plan.session_id,
            provider_id: plan.provider_id.clone(),
            status: TransactionStatus::VerifiedCommitted,
            fields: evidence,
            verification,
            recovery_required: false,
            failures,
        }
    } else {
        failures.extend(verification.failures.clone());
        finish_failed_transaction(manifest, plan, transport, &attempted, evidence, failures)
    }
}

fn finish_failed_transaction<T: SerialTransport>(
    manifest: &SysCfgSerialProviderManifest,
    plan: &WriteTransactionPlan,
    transport: &mut T,
    attempted: &[usize],
    mut evidence: Vec<FieldTransactionEvidence>,
    mut failures: Vec<String>,
) -> WriteTransactionOutcome {
    if attempted.is_empty() {
        return WriteTransactionOutcome {
            session_id: plan.session_id,
            provider_id: plan.provider_id.clone(),
            status: TransactionStatus::FailedNoWrite,
            fields: evidence,
            verification: SysCfgWriteVerification {
                verified: false,
                failures: failures.clone(),
            },
            recovery_required: false,
            failures,
        };
    }

    let mut rollback_all_verified = true;
    for index in attempted.iter().rev().copied() {
        let mutation = &plan.mutations[index];
        evidence[index].rollback_attempted = true;
        let rollback_write = exchange_checked(manifest, transport, &mutation.rollback_command);
        if rollback_write
            .as_ref()
            .map(|response| response_contains_error(response))
            .unwrap_or(true)
        {
            rollback_all_verified = false;
            failures.push(format!("{} rollback write failed", mutation.key));
            continue;
        }
        let rollback_read = exchange_checked(manifest, transport, &mutation.print_command)
            .and_then(|response| parse_print_response(manifest, &mutation.key, &response));
        match rollback_read {
            Ok(read) if read.value_hash() == mutation.before_hash => {
                evidence[index].rollback_verified = true;
            }
            Ok(_) => {
                rollback_all_verified = false;
                failures.push(format!("{} rollback read-back mismatch", mutation.key));
            }
            Err(error) => {
                rollback_all_verified = false;
                failures.push(format!(
                    "{} rollback verification failed: {error}",
                    mutation.key
                ));
            }
        }
    }

    let status = if rollback_all_verified {
        TransactionStatus::RolledBackVerified
    } else {
        TransactionStatus::RecoveryRequired
    };
    WriteTransactionOutcome {
        session_id: plan.session_id,
        provider_id: plan.provider_id.clone(),
        status: status.clone(),
        fields: evidence,
        verification: SysCfgWriteVerification {
            verified: false,
            failures: failures.clone(),
        },
        recovery_required: status == TransactionStatus::RecoveryRequired,
        failures,
    }
}

pub fn read_full_snapshot<T: SerialTransport>(
    manifest: &SysCfgSerialProviderManifest,
    context: &SysCfgSerialContext,
    transport: &mut T,
) -> Result<(RawSysCfgDump, SysCfgSnapshot), SysCfgSerialError> {
    validate_context(manifest, context, &required_read_permissions())?;
    let command = encode_command(manifest, &SysCfgCommand::List)?;
    let response = exchange_checked(manifest, transport, &command)?;
    if response_contains_error(&response) {
        return Err(SysCfgSerialError::DeviceReportedError);
    }
    let dump = parse_syscfg_list(manifest, &response)?;
    let snapshot = capture_snapshot(manifest, context, &dump)?;
    Ok((dump, snapshot))
}

fn exchange_checked<T: SerialTransport>(
    manifest: &SysCfgSerialProviderManifest,
    transport: &mut T,
    command: &EncodedCommand,
) -> Result<Vec<u8>, SysCfgSerialError> {
    let response = transport
        .exchange(command.as_bytes(), manifest.max_response_bytes)
        .map_err(SysCfgSerialError::Transport)?;
    validate_response(manifest, &response)?;
    Ok(response)
}

fn validate_response(
    manifest: &SysCfgSerialProviderManifest,
    response: &[u8],
) -> Result<(), SysCfgSerialError> {
    if response.len() > manifest.max_response_bytes {
        return Err(SysCfgSerialError::ResponseTooLarge(response.len()));
    }
    if response.contains(&0) {
        return Err(SysCfgSerialError::NulInResponse);
    }
    Ok(())
}

fn split_field_line(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':').or_else(|| line.split_once('='))?;
    Some((key.trim(), value.trim()))
}

fn looks_like_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 32
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'#' || byte == b'_')
}

fn validate_key(key: &str) -> Result<(), SysCfgSerialError> {
    if looks_like_key(key) {
        Ok(())
    } else {
        Err(SysCfgSerialError::InvalidFieldKey(key.to_owned()))
    }
}

fn validate_value(key: &str, value: &str, max_value_bytes: usize) -> Result<(), SysCfgSerialError> {
    if value.is_empty()
        || value.len() > max_value_bytes
        || value.trim() != value
        || !value.is_ascii()
    {
        return Err(SysCfgSerialError::InvalidFieldValue(key.to_owned()));
    }
    if value.bytes().any(|byte| {
        byte.is_ascii_control()
            || matches!(byte, b';' | b'&' | b'|' | b'`' | b'$' | b'<' | b'>' | b'\\')
    }) {
        return Err(SysCfgSerialError::UnsafeFieldValue(key.to_owned()));
    }
    Ok(())
}

fn response_line_is_error(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("error")
        || lower.contains("failed")
        || lower.contains("unknown command")
        || lower.contains("not supported")
}

fn response_contains_error(response: &[u8]) -> bool {
    std::str::from_utf8(response)
        .map(|text| text.lines().any(response_line_is_error))
        .unwrap_or(true)
}

fn is_git_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn hash_value(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Debug, thiserror::Error)]
pub enum SysCfgSerialError {
    #[error("unsupported SysCfg serial contract version: {0}")]
    UnsupportedVersion(String),
    #[error("SysCfg serial provider identity is incomplete")]
    IncompleteProviderIdentity,
    #[error("source commit must be a full 40-character hexadecimal commit")]
    InvalidSourceCommit,
    #[error("SysCfg serial provider is missing device or transport coverage")]
    MissingCoverage,
    #[error("invalid maximum serial response size: {0}")]
    InvalidResponseLimit(usize),
    #[error("SysCfg field catalog or required backup key set is missing")]
    MissingFieldCatalog,
    #[error("SysCfg serial permission contract does not match the fixed profile")]
    PermissionContractMismatch,
    #[error("invalid value limit for field: {0}")]
    InvalidFieldLimit(String),
    #[error("field is missing a response label: {0}")]
    MissingResponseLabel(String),
    #[error("field class cannot be writable: {0}")]
    BlockedWritableClass(String),
    #[error("required backup key is absent from the field catalog")]
    UnknownRequiredBackupKey,
    #[error("write capability and writable field catalog disagree")]
    WriteCapabilityMismatch,
    #[error("SysCfg serial provider is missing mandatory proof requirements")]
    MissingMandatoryProof,
    #[error("stable policy requires a Stable SysCfg serial provider")]
    ImmatureStableProvider,
    #[error("stable policy requires a declared provider licence")]
    MissingDeclaredLicence,
    #[error("SysCfg serial provider identity mismatch")]
    ProviderIdentityMismatch,
    #[error("device identity is incomplete")]
    IncompleteDeviceIdentity,
    #[error("device product or board route is unsupported")]
    UnsupportedDeviceRoute,
    #[error("verified same-session Purple mode is required")]
    UnverifiedPurpleSession,
    #[error("granted permissions do not exactly match the operation profile")]
    PermissionGrantMismatch,
    #[error("invalid SysCfg field key: {0}")]
    InvalidFieldKey(String),
    #[error("unknown SysCfg field: {0}")]
    UnknownField(String),
    #[error("SysCfg write capability is disabled")]
    WriteCapabilityDisabled,
    #[error("SysCfg field is not writable: {0}")]
    FieldNotWritable(String),
    #[error("invalid SysCfg value for field: {0}")]
    InvalidFieldValue(String),
    #[error("unsafe command delimiter or control byte in field value: {0}")]
    UnsafeFieldValue(String),
    #[error("serial response exceeds the provider limit: {0} bytes")]
    ResponseTooLarge(usize),
    #[error("serial response contains a NUL byte")]
    NulInResponse,
    #[error("serial response is not valid UTF-8")]
    InvalidUtf8Response,
    #[error("duplicate SysCfg field in response: {0}")]
    DuplicateField(String),
    #[error("SysCfg list response contained no fields")]
    NoSysCfgFields,
    #[error("multiple values were returned for field: {0}")]
    AmbiguousFieldResponse(String),
    #[error("serial response did not contain field: {0}")]
    MissingFieldResponse(String),
    #[error("full SysCfg dump is missing mandatory backup fields")]
    IncompleteBackupDump,
    #[error("snapshot does not match the current session, device, board, or dump")]
    SnapshotScopeMismatch,
    #[error("vault receipt does not match the current snapshot")]
    VaultReceiptScopeMismatch,
    #[error("vault backup is not encrypted, durable, hash-pinned, and rollback-ready")]
    VaultBackupNotReady,
    #[error("write request does not match the current session, provider, device, or board")]
    WriteRequestScopeMismatch,
    #[error("backup is not bound to the selected snapshot and raw dump")]
    BackupBindingMismatch,
    #[error("SysCfg write policy blocked the request: {0:?}")]
    WritePolicyBlocked(Vec<String>),
    #[error("selected raw values do not match the declared field changes")]
    SelectedMutationMismatch,
    #[error("missing selected raw value for field: {0}")]
    MissingSelectedValue(String),
    #[error("backup does not contain a raw value for field: {0}")]
    MissingBackupValue(String),
    #[error("backup value hash does not match the write precondition: {0}")]
    BeforeHashMismatch(String),
    #[error("requested value hash does not match the write request: {0}")]
    AfterHashMismatch(String),
    #[error(transparent)]
    Transport(#[from] SerialTransportError),
    #[error("device returned an explicit error marker")]
    DeviceReportedError,
}
