//! Encrypted, hash-bound backup vault for completed SysCfg list captures.
//!
//! This crate performs no device or serial operation. It accepts an already
//! completed and verified `syscfg list` response, creates a hash-only snapshot,
//! encrypts and stores the raw response, reopens and decrypts the package, and
//! only then issues a rollback-ready receipt.

mod envelope;
mod key;
mod pipeline;
mod store;

pub use envelope::{EncryptedBackupReceipt, VerifiedBackupRead};
pub use key::VaultKey;
pub use pipeline::{
    capture_encrypt_verify_backup, required_backup_permissions, BackupAuthorization,
    BackupPipelineEvidence, BackupVaultRequest, CapturedSysCfgList,
};
pub use store::FileBackupVault;

pub const SYSCFG_BACKUP_VAULT_VERSION: &str = "tgcheckm8.syscfg-backup-vault.v1";
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
