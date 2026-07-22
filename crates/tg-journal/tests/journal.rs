use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use tg_journal::{verify_file, Journal, JournalError, MAX_JOURNAL_LINE_BYTES};
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tg-journal-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn appended_entries_form_a_verified_hash_chain() {
    let root = TestDirectory::new();
    let session = Uuid::new_v4();
    let mut journal = Journal::open(&root.0, session).unwrap();
    let first = journal
        .append(
            "session_started",
            BTreeMap::from([("mode".to_owned(), "normal".to_owned())]),
        )
        .unwrap();
    let second = journal
        .append(
            "route_selected",
            BTreeMap::from([("route".to_owned(), "fixture".to_owned())]),
        )
        .unwrap();
    let path = journal.path().to_path_buf();
    drop(journal);

    assert_eq!(first.sequence, 1);
    assert_eq!(second.sequence, 2);
    assert_eq!(second.previous_hash.as_deref(), Some(first.hash.as_str()));
    let verified = verify_file(path).unwrap();
    assert_eq!(verified.session_id, Some(session));
    assert_eq!(verified.entries, 2);
    assert_eq!(verified.last_sequence, 2);
    assert_eq!(verified.last_hash, Some(second.hash));
}

#[test]
fn journal_reopens_at_the_next_verified_sequence() {
    let root = TestDirectory::new();
    let session = Uuid::new_v4();
    let path = {
        let mut journal = Journal::open(&root.0, session).unwrap();
        journal
            .append("first", BTreeMap::new())
            .expect("first append");
        journal.path().to_path_buf()
    };

    let mut reopened = Journal::open(&root.0, session).unwrap();
    let second = reopened.append("second", BTreeMap::new()).unwrap();
    drop(reopened);

    assert_eq!(second.sequence, 2);
    assert_eq!(verify_file(path).unwrap().entries, 2);
}

#[test]
fn only_one_writer_can_own_a_session_journal() {
    let root = TestDirectory::new();
    let session = Uuid::new_v4();
    let first = Journal::open(&root.0, session).unwrap();

    assert!(matches!(
        Journal::open(&root.0, session),
        Err(JournalError::WriterLockExists(_))
    ));
    drop(first);
    assert!(Journal::open(&root.0, session).is_ok());
}

#[test]
fn payload_tampering_is_detected() {
    let root = TestDirectory::new();
    let session = Uuid::new_v4();
    let path = {
        let mut journal = Journal::open(&root.0, session).unwrap();
        journal
            .append("session_started", BTreeMap::new())
            .unwrap();
        journal.path().to_path_buf()
    };

    let content = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        content.replace("session_started", "session_stopped"),
    )
    .unwrap();
    assert!(matches!(
        verify_file(path),
        Err(JournalError::HashMismatch { sequence: 1 })
    ));
}

#[test]
fn entries_from_different_sessions_cannot_share_a_chain() {
    let root = TestDirectory::new();
    let first_path = {
        let mut journal = Journal::open(&root.0, Uuid::new_v4()).unwrap();
        journal.append("first", BTreeMap::new()).unwrap();
        journal.path().to_path_buf()
    };
    let second_path = {
        let mut journal = Journal::open(&root.0, Uuid::new_v4()).unwrap();
        journal.append("second", BTreeMap::new()).unwrap();
        journal.path().to_path_buf()
    };
    let combined = root.0.join("combined.jsonl");
    fs::write(
        &combined,
        format!(
            "{}{}",
            fs::read_to_string(first_path).unwrap(),
            fs::read_to_string(second_path).unwrap()
        ),
    )
    .unwrap();

    assert!(matches!(
        verify_file(combined),
        Err(JournalError::SessionMismatch)
    ));
}

#[test]
fn oversized_journal_line_is_rejected() {
    let root = TestDirectory::new();
    let path = root.0.join("oversized.jsonl");
    fs::write(&path, vec![b'x'; MAX_JOURNAL_LINE_BYTES + 1]).unwrap();

    assert!(matches!(
        verify_file(path),
        Err(JournalError::LineTooLarge(size)) if size > MAX_JOURNAL_LINE_BYTES
    ));
}

#[test]
fn empty_event_type_is_rejected_before_write() {
    let root = TestDirectory::new();
    let mut journal = Journal::open(&root.0, Uuid::new_v4()).unwrap();
    assert!(matches!(
        journal.append("   ", BTreeMap::new()),
        Err(JournalError::MissingEventType)
    ));
    drop(journal);
}

#[cfg(unix)]
#[test]
fn journal_file_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let root = TestDirectory::new();
    let session = Uuid::new_v4();
    let session_dir = root.0.join(session.to_string());
    fs::create_dir_all(&session_dir).unwrap();
    let target = root.0.join("target.jsonl");
    fs::write(&target, b"").unwrap();
    symlink(&target, session_dir.join("events.jsonl")).unwrap();

    assert!(matches!(
        Journal::open(&root.0, session),
        Err(JournalError::SymlinkRejected(_))
    ));
}
