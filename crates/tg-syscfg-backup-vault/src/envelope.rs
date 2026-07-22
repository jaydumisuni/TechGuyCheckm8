use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::key::VaultKey;
use crate::pipeline::SysCfgBackupVaultError;
use crate::{MAX_ENVELOPE_BYTES, MAX_METADATA_BYTES, SYSCFG_BACKUP_VAULT_VERSION};

const MAGIC: &[u8; 8] = b"TGSVLT1\0";
const FORMAT_VERSION: u16 = 1;
const NONCE_BYTES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBackupReceipt {
    pub schema_version: String,
    pub object_id: Uuid,
    pub snapshot_id: Uuid,
    pub session_id: Uuid,
    pub provider_id: String,
    pub device_identity_hash: String,
    pub board_config: String,
    pub key_id: String,
    pub vault_object_name_hash: String,
    pub envelope_sha256: String,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub plaintext_bytes: usize,
    pub encrypted_bytes: usize,
    pub field_count: usize,
    pub verified_readback: bool,
}

pub struct VerifiedBackupRead {
    bytes: Vec<u8>,
    pub object_id: Uuid,
    pub plaintext_sha256: String,
    pub plaintext_bytes: usize,
}

impl VerifiedBackupRead {
    pub fn bytes_for_rollback(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for VerifiedBackupRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBackupRead")
            .field("object_id", &self.object_id)
            .field("plaintext_sha256", &self.plaintext_sha256)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for VerifiedBackupRead {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultMetadata {
    pub schema_version: String,
    pub object_id: Uuid,
    pub snapshot_id: Uuid,
    pub session_id: Uuid,
    pub provider_id: String,
    pub device_identity_hash: String,
    pub board_config: String,
    pub source_blob_sha256: String,
    pub response_sha256: String,
    pub plaintext_bytes: usize,
    pub field_count: usize,
    pub key_id: String,
}

pub(crate) struct SealedEnvelope {
    pub bytes: Vec<u8>,
    pub ciphertext_sha256: String,
}

pub(crate) fn seal(
    metadata: &VaultMetadata,
    plaintext: &[u8],
    key: &VaultKey,
) -> Result<SealedEnvelope, SysCfgBackupVaultError> {
    if plaintext.is_empty() || plaintext.len() > MAX_ENVELOPE_BYTES {
        return Err(SysCfgBackupVaultError::InvalidPlaintextSize(
            plaintext.len(),
        ));
    }
    let metadata_bytes = serde_json::to_vec(metadata)
        .map_err(|error| SysCfgBackupVaultError::Metadata(error.to_string()))?;
    if metadata_bytes.is_empty() || metadata_bytes.len() > MAX_METADATA_BYTES {
        return Err(SysCfgBackupVaultError::InvalidMetadataSize(
            metadata_bytes.len(),
        ));
    }

    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| SysCfgBackupVaultError::RandomFailed(error.to_string()))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes())
        .map_err(|_| SysCfgBackupVaultError::InvalidKey)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &metadata_bytes,
            },
        )
        .map_err(|_| SysCfgBackupVaultError::EncryptionFailed)?;
    let bytes = encode(&nonce, &metadata_bytes, &ciphertext)?;
    Ok(SealedEnvelope {
        bytes,
        ciphertext_sha256: sha256_hex(&ciphertext),
    })
}

pub(crate) fn open(
    package: &[u8],
    key: &VaultKey,
) -> Result<(VaultMetadata, VerifiedBackupRead), SysCfgBackupVaultError> {
    let decoded = decode(package)?;
    let metadata: VaultMetadata = serde_json::from_slice(decoded.metadata)
        .map_err(|error| SysCfgBackupVaultError::Metadata(error.to_string()))?;
    if metadata.schema_version != SYSCFG_BACKUP_VAULT_VERSION || metadata.key_id != key.key_id() {
        return Err(SysCfgBackupVaultError::MetadataScopeMismatch);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes())
        .map_err(|_| SysCfgBackupVaultError::InvalidKey)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&decoded.nonce),
            Payload {
                msg: decoded.ciphertext,
                aad: decoded.metadata,
            },
        )
        .map_err(|_| SysCfgBackupVaultError::AuthenticationFailed)?;
    if plaintext.len() != metadata.plaintext_bytes
        || sha256_hex(&plaintext) != metadata.source_blob_sha256
    {
        plaintext.zeroize();
        return Err(SysCfgBackupVaultError::ReadbackMismatch);
    }
    let verified = VerifiedBackupRead {
        object_id: metadata.object_id,
        plaintext_sha256: metadata.source_blob_sha256.clone(),
        plaintext_bytes: plaintext.len(),
        bytes: plaintext,
    };
    Ok((metadata, verified))
}

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}

fn encode(
    nonce: &[u8; NONCE_BYTES],
    metadata: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SysCfgBackupVaultError> {
    let metadata_len =
        u32::try_from(metadata.len()).map_err(|_| SysCfgBackupVaultError::EnvelopeTooLarge)?;
    let ciphertext_len =
        u64::try_from(ciphertext.len()).map_err(|_| SysCfgBackupVaultError::EnvelopeTooLarge)?;
    let capacity = MAGIC
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(NONCE_BYTES))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(metadata.len()))
        .and_then(|value| value.checked_add(ciphertext.len()))
        .ok_or(SysCfgBackupVaultError::EnvelopeTooLarge)?;
    if capacity > MAX_ENVELOPE_BYTES {
        return Err(SysCfgBackupVaultError::EnvelopeTooLarge);
    }
    let mut envelope = Vec::with_capacity(capacity);
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    envelope.extend_from_slice(nonce);
    envelope.extend_from_slice(&metadata_len.to_le_bytes());
    envelope.extend_from_slice(&ciphertext_len.to_le_bytes());
    envelope.extend_from_slice(metadata);
    envelope.extend_from_slice(ciphertext);
    Ok(envelope)
}

struct DecodedEnvelope<'a> {
    nonce: [u8; NONCE_BYTES],
    metadata: &'a [u8],
    ciphertext: &'a [u8],
}

fn decode(package: &[u8]) -> Result<DecodedEnvelope<'_>, SysCfgBackupVaultError> {
    let header_len = MAGIC.len() + 2 + NONCE_BYTES + 4 + 8;
    if package.len() < header_len || package.len() > MAX_ENVELOPE_BYTES {
        return Err(SysCfgBackupVaultError::InvalidEnvelope);
    }
    if &package[..MAGIC.len()] != MAGIC {
        return Err(SysCfgBackupVaultError::InvalidEnvelope);
    }
    let mut cursor = MAGIC.len();
    let version = u16::from_le_bytes([package[cursor], package[cursor + 1]]);
    cursor += 2;
    if version != FORMAT_VERSION {
        return Err(SysCfgBackupVaultError::UnsupportedEnvelopeVersion(version));
    }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&package[cursor..cursor + NONCE_BYTES]);
    cursor += NONCE_BYTES;
    let metadata_len = u32::from_le_bytes(
        package[cursor..cursor + 4]
            .try_into()
            .map_err(|_| SysCfgBackupVaultError::InvalidEnvelope)?,
    ) as usize;
    cursor += 4;
    let ciphertext_len = usize::try_from(u64::from_le_bytes(
        package[cursor..cursor + 8]
            .try_into()
            .map_err(|_| SysCfgBackupVaultError::InvalidEnvelope)?,
    ))
    .map_err(|_| SysCfgBackupVaultError::InvalidEnvelope)?;
    cursor += 8;
    if metadata_len == 0 || metadata_len > MAX_METADATA_BYTES {
        return Err(SysCfgBackupVaultError::InvalidEnvelope);
    }
    let metadata_end = cursor
        .checked_add(metadata_len)
        .ok_or(SysCfgBackupVaultError::InvalidEnvelope)?;
    let ciphertext_end = metadata_end
        .checked_add(ciphertext_len)
        .ok_or(SysCfgBackupVaultError::InvalidEnvelope)?;
    if ciphertext_end != package.len() {
        return Err(SysCfgBackupVaultError::InvalidEnvelope);
    }
    Ok(DecodedEnvelope {
        nonce,
        metadata: &package[cursor..metadata_end],
        ciphertext: &package[metadata_end..ciphertext_end],
    })
}
