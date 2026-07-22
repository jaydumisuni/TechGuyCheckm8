use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const JOURNAL_SCHEMA_VERSION: &str = "tgcheckm8.journal.v1";
pub const MAX_JOURNAL_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub schema_version: String,
    pub session_id: Uuid,
    pub sequence: u64,
    pub event_type: String,
    pub payload: BTreeMap<String, String>,
    pub previous_hash: Option<String>,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalVerification {
    pub entries: usize,
    pub last_sequence: u64,
    pub last_hash: Option<String>,
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    session_id: Uuid,
    next_sequence: u64,
    previous_hash: Option<String>,
}

impl Journal {
    pub fn open(root: impl AsRef<Path>, session_id: Uuid) -> Result<Self, JournalError> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(JournalError::ExpectedDirectory(root));
        }

        let session_dir = root.join(session_id.to_string());
        fs::create_dir_all(&session_dir)?;
        let session_dir = session_dir.canonicalize()?;
        if !session_dir.starts_with(&root) {
            return Err(JournalError::PathEscape(session_dir));
        }

        let path = session_dir.join("events.jsonl");
        reject_symlink(&path)?;
        let existing = if path.exists() {
            Some(verify_file(&path)?)
        } else {
            None
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        let canonical_file = path.canonicalize()?;
        if !canonical_file.starts_with(&root) {
            return Err(JournalError::PathEscape(canonical_file));
        }

        let (next_sequence, previous_hash) = existing
            .map(|verification| {
                (
                    verification.last_sequence.saturating_add(1),
                    verification.last_hash,
                )
            })
            .unwrap_or((1, None));

        Ok(Self {
            path: canonical_file,
            file,
            session_id,
            next_sequence,
            previous_hash,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(
        &mut self,
        event_type: impl Into<String>,
        payload: BTreeMap<String, String>,
    ) -> Result<JournalEntry, JournalError> {
        let event_type = event_type.into();
        if event_type.trim().is_empty() {
            return Err(JournalError::MissingEventType);
        }

        let hash = compute_hash(
            self.session_id,
            self.next_sequence,
            &event_type,
            &payload,
            self.previous_hash.as_deref(),
        )?;
        let entry = JournalEntry {
            schema_version: JOURNAL_SCHEMA_VERSION.to_owned(),
            session_id: self.session_id,
            sequence: self.next_sequence,
            event_type,
            payload,
            previous_hash: self.previous_hash.clone(),
            hash,
        };
        let encoded = serde_json::to_vec(&entry)?;
        if encoded.len() > MAX_JOURNAL_LINE_BYTES {
            return Err(JournalError::LineTooLarge(encoded.len()));
        }
        self.file.write_all(&encoded)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;

        self.next_sequence = self.next_sequence.saturating_add(1);
        self.previous_hash = Some(entry.hash.clone());
        Ok(entry)
    }
}

pub fn verify_file(path: impl AsRef<Path>) -> Result<JournalVerification, JournalError> {
    let path = path.as_ref();
    reject_symlink(path)?;
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut expected_sequence = 1_u64;
    let mut previous_hash: Option<String> = None;
    let mut entries = 0_usize;

    while let Some(line) = read_bounded_line(&mut reader, MAX_JOURNAL_LINE_BYTES)? {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let entry: JournalEntry = serde_json::from_slice(&line)?;
        if entry.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalError::UnsupportedVersion(entry.schema_version));
        }
        if entry.sequence != expected_sequence {
            return Err(JournalError::SequenceMismatch {
                expected: expected_sequence,
                actual: entry.sequence,
            });
        }
        if entry.previous_hash != previous_hash {
            return Err(JournalError::PreviousHashMismatch {
                sequence: entry.sequence,
            });
        }
        let calculated = compute_hash(
            entry.session_id,
            entry.sequence,
            &entry.event_type,
            &entry.payload,
            entry.previous_hash.as_deref(),
        )?;
        if calculated != entry.hash {
            return Err(JournalError::HashMismatch {
                sequence: entry.sequence,
            });
        }

        expected_sequence = expected_sequence.saturating_add(1);
        previous_hash = Some(entry.hash);
        entries = entries.saturating_add(1);
    }

    Ok(JournalVerification {
        entries,
        last_sequence: expected_sequence.saturating_sub(1),
        last_hash: previous_hash,
    })
}

#[derive(Serialize)]
struct HashMaterial<'a> {
    schema_version: &'static str,
    session_id: Uuid,
    sequence: u64,
    event_type: &'a str,
    payload: &'a BTreeMap<String, String>,
    previous_hash: Option<&'a str>,
}

fn compute_hash(
    session_id: Uuid,
    sequence: u64,
    event_type: &str,
    payload: &BTreeMap<String, String>,
    previous_hash: Option<&str>,
) -> Result<String, JournalError> {
    let material = HashMaterial {
        schema_version: JOURNAL_SCHEMA_VERSION,
        session_id,
        sequence,
        event_type,
        payload,
        previous_hash,
    };
    let encoded = serde_json::to_vec(&material)?;
    let digest = Sha256::digest(encoded);
    Ok(to_hex(&digest))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn reject_symlink(path: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(JournalError::SymlinkRejected(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(JournalError::Io(error)),
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, JournalError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > limit {
            return Err(JournalError::LineTooLarge(
                line.len().saturating_add(take),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline.is_some() {
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("expected a directory: {0}")]
    ExpectedDirectory(PathBuf),
    #[error("journal path escaped its approved root: {0}")]
    PathEscape(PathBuf),
    #[error("journal symlinks are rejected: {0}")]
    SymlinkRejected(PathBuf),
    #[error("journal event type is required")]
    MissingEventType,
    #[error("journal line exceeds the maximum size: {0} bytes")]
    LineTooLarge(usize),
    #[error("unsupported journal version: {0}")]
    UnsupportedVersion(String),
    #[error("journal sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("journal previous hash mismatch at sequence {sequence}")]
    PreviousHashMismatch { sequence: u64 },
    #[error("journal hash mismatch at sequence {sequence}")]
    HashMismatch { sequence: u64 },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
