use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tg_purple::SysCfgBackupReceipt;
use uuid::Uuid;

use crate::envelope::{
    open, seal, sha256_hex, EncryptedBackupReceipt, VaultMetadata, VerifiedBackupRead,
};
use crate::key::VaultKey;
use crate::pipeline::SysCfgBackupVaultError;
use crate::MAX_ENVELOPE_BYTES;

#[derive(Debug, Clone)]
pub struct FileBackupVault {
    root: PathBuf,
}

pub(crate) struct PersistedBackup {
    pub envelope_sha256: String,
    pub ciphertext_sha256: String,
    pub envelope_bytes: usize,
    pub vault_object_name_hash: String,
}

impl FileBackupVault {
    pub fn open_existing(root: impl AsRef<Path>) -> Result<Self, SysCfgBackupVaultError> {
        let root = root.as_ref();
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| SysCfgBackupVaultError::VaultRoot(error.to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SysCfgBackupVaultError::UnsafeVaultRoot);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(SysCfgBackupVaultError::InsecureVaultPermissions);
            }
        }
        let root = fs::canonicalize(root)
            .map_err(|error| SysCfgBackupVaultError::VaultRoot(error.to_string()))?;
        Ok(Self { root })
    }

    pub fn object_path_for_local_operator(&self, object_id: Uuid) -> PathBuf {
        self.root.join(object_name(object_id))
    }

    pub(crate) fn persist_verified(
        &self,
        metadata: &VaultMetadata,
        plaintext: &[u8],
        key: &VaultKey,
    ) -> Result<PersistedBackup, SysCfgBackupVaultError> {
        let sealed = seal(metadata, plaintext, key)?;
        let path = self.object_path_for_local_operator(metadata.object_id);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let write_result = (|| {
            let mut file = options
                .open(&path)
                .map_err(|error| SysCfgBackupVaultError::VaultWrite(error.to_string()))?;
            file.write_all(&sealed.bytes)
                .map_err(|error| SysCfgBackupVaultError::VaultWrite(error.to_string()))?;
            file.sync_all()
                .map_err(|error| SysCfgBackupVaultError::VaultWrite(error.to_string()))?;
            drop(file);

            let (read_metadata, verified) = self.read_path(&path, key)?;
            if &read_metadata != metadata
                || verified.plaintext_sha256 != sha256_hex(plaintext)
                || verified.bytes_for_rollback() != plaintext
            {
                return Err(SysCfgBackupVaultError::ReadbackMismatch);
            }
            Ok::<(), SysCfgBackupVaultError>(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&path);
            return Err(error);
        }

        #[cfg(unix)]
        {
            if let Ok(directory) = File::open(&self.root) {
                let _ = directory.sync_all();
            }
        }
        Ok(PersistedBackup {
            envelope_sha256: sha256_hex(&sealed.bytes),
            ciphertext_sha256: sealed.ciphertext_sha256,
            envelope_bytes: sealed.bytes.len(),
            vault_object_name_hash: sha256_hex(object_name(metadata.object_id).as_bytes()),
        })
    }

    pub fn read_for_rollback(
        &self,
        backup: &SysCfgBackupReceipt,
        encrypted: &EncryptedBackupReceipt,
        key: &VaultKey,
    ) -> Result<VerifiedBackupRead, SysCfgBackupVaultError> {
        if !backup.verified
            || !backup.rollback_ready
            || !encrypted.verified_readback
            || backup.snapshot_id != encrypted.snapshot_id
            || backup.device_identity_hash != encrypted.device_identity_hash
            || backup.board_config != encrypted.board_config
            || backup.backup_sha256 != encrypted.envelope_sha256
            || backup.source_blob_sha256 != encrypted.plaintext_sha256
            || encrypted.key_id != key.key_id()
        {
            return Err(SysCfgBackupVaultError::ReceiptScopeMismatch);
        }
        let path = self.object_path_for_local_operator(encrypted.object_id);
        let package = read_bounded_file(&path)?;
        if sha256_hex(&package) != encrypted.envelope_sha256 {
            return Err(SysCfgBackupVaultError::PackageHashMismatch);
        }
        drop(package);
        let (metadata, verified) = self.read_path(&path, key)?;
        if metadata.object_id != encrypted.object_id
            || metadata.snapshot_id != encrypted.snapshot_id
            || metadata.session_id != encrypted.session_id
            || metadata.provider_id != encrypted.provider_id
            || metadata.device_identity_hash != encrypted.device_identity_hash
            || metadata.board_config != encrypted.board_config
            || metadata.source_blob_sha256 != encrypted.plaintext_sha256
            || verified.plaintext_sha256 != backup.source_blob_sha256
            || verified.plaintext_bytes != encrypted.plaintext_bytes
        {
            return Err(SysCfgBackupVaultError::ReadbackMismatch);
        }
        Ok(verified)
    }

    fn read_path(
        &self,
        path: &Path,
        key: &VaultKey,
    ) -> Result<(VaultMetadata, VerifiedBackupRead), SysCfgBackupVaultError> {
        let package = read_bounded_file(path)?;
        open(&package, key)
    }
}

fn object_name(object_id: Uuid) -> String {
    format!("syscfg-{object_id}.tgvault")
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, SysCfgBackupVaultError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SysCfgBackupVaultError::VaultRead(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SysCfgBackupVaultError::UnsafeVaultObject);
    }
    if metadata.len() > MAX_ENVELOPE_BYTES as u64 {
        return Err(SysCfgBackupVaultError::EnvelopeTooLarge);
    }
    let file =
        File::open(path).map_err(|error| SysCfgBackupVaultError::VaultRead(error.to_string()))?;
    let mut package = Vec::new();
    file.take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut package)
        .map_err(|error| SysCfgBackupVaultError::VaultRead(error.to_string()))?;
    if package.len() > MAX_ENVELOPE_BYTES {
        return Err(SysCfgBackupVaultError::EnvelopeTooLarge);
    }
    Ok(package)
}
