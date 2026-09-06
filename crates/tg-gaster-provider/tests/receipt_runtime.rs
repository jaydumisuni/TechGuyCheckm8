use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tg_gaster_provider::{
    execute_action, required_permissions, sha256_file, GasterAction, GasterExecutionRequest,
    GasterPwnPlan,
};
use tg_process::{ProcessPolicy, TerminationReason};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    executable: PathBuf,
    plan: GasterPwnPlan,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn fixture(script: &str) -> Fixture {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("tg-gaster-receipt-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create temp root");
    let executable = root.join("gaster");
    fs::write(&executable, script).expect("write fixture");
    let mut permissions = fs::metadata(&executable).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).expect("chmod fixture");

    let executable_sha256 = sha256_file(Path::new(&executable)).expect("hash fixture");
    let plan = GasterPwnPlan {
        session_id: Uuid::new_v4(),
        engine_id: "apple.gaster.a8-a11".to_owned(),
        normalized_cpid: "8015".to_owned(),
        executable_sha256,
        actions: vec![GasterAction::Pwn, GasterAction::Reset],
        requested_permissions: required_permissions(),
        required_proofs: BTreeSet::new(),
    };

    Fixture {
        root,
        executable,
        plan,
    }
}

#[cfg(unix)]
fn policy(fixture: &Fixture, timeout: Duration, capture_limit: usize) -> ProcessPolicy {
    ProcessPolicy::new(
        vec![fixture.root.clone()],
        fixture.root.clone(),
        timeout,
        Duration::from_millis(2),
        capture_limit,
        capture_limit,
    )
    .expect("process policy")
}

#[cfg(unix)]
#[test]
fn runtime_receipt_proves_capture_bounds_and_truncation() {
    let fixture = fixture(
        "#!/bin/sh\nprintf '0123456789abcdef\\n'\nprintf 'fedcba9876543210\\n' >&2\nexit 0\n",
    );
    let policy = policy(&fixture, Duration::from_secs(5), 8);

    let receipt = execute_action(
        &policy,
        &GasterExecutionRequest {
            plan: &fixture.plan,
            action: GasterAction::Pwn,
            executable: fixture.executable.clone(),
            working_directory: fixture.root.clone(),
        },
    )
    .expect("bounded Gaster receipt");

    assert_eq!(receipt.termination, TerminationReason::Exited);
    assert_eq!(receipt.timeout_millis, 5_000);
    assert_eq!(receipt.max_stdout_bytes, 8);
    assert_eq!(receipt.max_stderr_bytes, 8);
    assert!(receipt.stdout_bytes > receipt.max_stdout_bytes);
    assert!(receipt.stderr_bytes > receipt.max_stderr_bytes);
    assert!(receipt.stdout_truncated);
    assert!(receipt.stderr_truncated);
}

#[cfg(unix)]
#[test]
fn timeout_receipt_proves_kill_and_cleanup() {
    let fixture = fixture("#!/bin/sh\nsleep 1\nexit 0\n");
    let policy = policy(&fixture, Duration::from_millis(20), 64);

    let receipt = execute_action(
        &policy,
        &GasterExecutionRequest {
            plan: &fixture.plan,
            action: GasterAction::Pwn,
            executable: fixture.executable.clone(),
            working_directory: fixture.root.clone(),
        },
    )
    .expect("timeout remains a durable receipt");

    assert_eq!(receipt.termination, TerminationReason::TimeoutKilled);
    assert_eq!(receipt.timeout_millis, 20);
    assert!(!receipt.process_success);
    assert!(receipt.cleanup_verified);
}
