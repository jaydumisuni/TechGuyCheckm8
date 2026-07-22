use std::fmt;

use zeroize::Zeroize;

use crate::pipeline::SysCfgBackupVaultError;

pub const KEY_BYTES: usize = 32;

pub struct VaultKey {
    key_id: String,
    bytes: [u8; KEY_BYTES],
}

impl VaultKey {
    pub fn from_bytes(
        key_id: impl Into<String>,
        bytes: [u8; KEY_BYTES],
    ) -> Result<Self, SysCfgBackupVaultError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        Ok(Self { key_id, bytes })
    }

    pub fn generate(key_id: impl Into<String>) -> Result<Self, SysCfgBackupVaultError> {
        let mut bytes = [0u8; KEY_BYTES];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| SysCfgBackupVaultError::RandomFailed(error.to_string()))?;
        Self::from_bytes(key_id, bytes)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultKey")
            .field("key_id", &self.key_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn validate_key_id(key_id: &str) -> Result<(), SysCfgBackupVaultError> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SysCfgBackupVaultError::InvalidKeyId);
    }
    Ok(())
}
