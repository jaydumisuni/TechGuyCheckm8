use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use tg_process::{
    run_supervised, ProcessError, ProcessPolicy, ProcessSpec, TerminationReason,
};
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tg-process-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn worker_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tg-sim-worker"))
}

fn policy(work: &TestDirectory, timeout: Duration, capture: usize) -> ProcessPolicy {
    let executable_root = worker_binary().parent().unwrap().to_path_buf();
    ProcessPolicy::new(
        vec![executable_root],
        work.0.clone(),
        timeout,
        Duration::from_millis(5),
        capture,
        capture,
    )
    .unwrap()
}

fn spec(work: &TestDirectory, scenario: &str) -> ProcessSpec {
    ProcessSpec {
        executable: worker_binary(),
        args: vec![format!("--scenario={scenario}")],
        environment: BTreeMap::new(),
        working_directory: work.0.clone(),
    }
}

#[test]
fn successful_worker_is_waited_and_pipes_are_joined() {
    let work = TestDirectory::new();
    let outcome = run_supervised(
        &policy(&work, Duration::from_secs(2), 16 * 1024),
        &spec(&work, "success"),
    )
    .unwrap();

    assert_eq!(outcome.termination, TerminationReason::Exited);
    assert_eq!(outcome.status_code, Some(0));
    assert!(outcome.success);
    assert!(outcome.cleanup.verified());
    assert!(outcome.stdout.utf8_lossy().contains("completed"));
}

#[test]
fn nonzero_worker_exit_is_not_success() {
    let work = TestDirectory::new();
    let outcome = run_supervised(
        &policy(&work, Duration::from_secs(2), 16 * 1024),
        &spec(&work, "failure"),
    )
    .unwrap();

    assert_eq!(outcome.termination, TerminationReason::Exited);
    assert_eq!(outcome.status_code, Some(7));
    assert!(!outcome.success);
    assert!(outcome.stderr.utf8_lossy().contains("fixture_failure"));
    assert!(outcome.cleanup.verified());
}

#[test]
fn hung_worker_is_killed_at_deadline_and_cleaned() {
    let work = TestDirectory::new();
    let mut spec = spec(&work, "hang");
    spec.args.push("--sleep-ms=5000".to_owned());
    let outcome = run_supervised(
        &policy(&work, Duration::from_millis(100), 16 * 1024),
        &spec,
    )
    .unwrap();

    assert_eq!(outcome.termination, TerminationReason::TimeoutKilled);
    assert!(!outcome.success);
    assert!(outcome.elapsed_millis < 2_000);
    assert!(outcome.cleanup.verified());
    assert!(outcome.stdout.utf8_lossy().contains("started"));
}

#[test]
fn stdout_and_stderr_are_bounded_without_deadlock() {
    let work = TestDirectory::new();
    let mut spec = spec(&work, "spam");
    spec.args.push("--bytes=65536".to_owned());
    let outcome = run_supervised(
        &policy(&work, Duration::from_secs(2), 1024),
        &spec,
    )
    .unwrap();

    assert!(outcome.success);
    assert_eq!(outcome.stdout.bytes.len(), 1024);
    assert_eq!(outcome.stderr.bytes.len(), 1024);
    assert_eq!(outcome.stdout.total_bytes, 65_536);
    assert_eq!(outcome.stderr.total_bytes, 65_536);
    assert!(outcome.stdout.truncated);
    assert!(outcome.stderr.truncated);
}

#[test]
fn child_receives_only_explicit_environment() {
    let work = TestDirectory::new();
    let mut spec = spec(&work, "environment");
    spec.environment
        .insert("TGCHECKM8_ALLOWED".to_owned(), "visible".to_owned());
    let outcome =
        run_supervised(&policy(&work, Duration::from_secs(2), 16 * 1024), &spec).unwrap();

    let line = outcome.stdout.utf8_lossy();
    let payload: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(payload["allowed"], "visible");
    assert_eq!(payload["path_present"], false);
    assert_eq!(payload["unexpected_present"], false);
}

#[test]
fn executable_outside_approved_root_is_rejected() {
    let work = TestDirectory::new();
    let unrelated_root = TestDirectory::new();
    let policy = ProcessPolicy::new(
        vec![unrelated_root.0.clone()],
        work.0.clone(),
        Duration::from_secs(1),
        Duration::from_millis(5),
        1024,
        1024,
    )
    .unwrap();

    assert!(matches!(
        run_supervised(&policy, &spec(&work, "success")),
        Err(ProcessError::ExecutableOutsideApprovedRoot(_))
    ));
}

#[test]
fn working_directory_outside_approved_root_is_rejected() {
    let approved_work = TestDirectory::new();
    let outside_work = TestDirectory::new();
    let mut spec = spec(&approved_work, "success");
    spec.working_directory = outside_work.0.clone();

    assert!(matches!(
        run_supervised(
            &policy(&approved_work, Duration::from_secs(1), 1024),
            &spec
        ),
        Err(ProcessError::WorkingDirectoryOutsideApprovedRoot(_))
    ));
}

#[test]
fn invalid_environment_key_is_rejected_before_spawn() {
    let work = TestDirectory::new();
    let mut spec = spec(&work, "success");
    spec.environment
        .insert("BAD=KEY".to_owned(), "value".to_owned());

    assert!(matches!(
        run_supervised(&policy(&work, Duration::from_secs(1), 1024), &spec),
        Err(ProcessError::InvalidEnvironmentKey(key)) if key == "BAD=KEY"
    ));
}
