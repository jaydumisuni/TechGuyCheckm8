use tg_runtime::{RegisterOutcome, RunState, RuntimeError, RuntimeLedger};
use uuid::Uuid;

#[test]
fn duplicate_session_key_returns_existing_run() {
    let mut ledger = RuntimeLedger::default();
    let session = Uuid::new_v4();
    let first = ledger
        .register_run(session, "worker-a", "stage:1")
        .unwrap();
    let second = ledger
        .register_run(session, "worker-a", "stage:1")
        .unwrap();

    let RegisterOutcome::Created(first) = first else {
        panic!("expected created run");
    };
    assert_eq!(second, RegisterOutcome::Existing(first));
    assert_eq!(ledger.run_count(), 1);
}

#[test]
fn same_key_in_different_sessions_is_not_deduplicated() {
    let mut ledger = RuntimeLedger::default();
    ledger
        .register_run(Uuid::new_v4(), "worker-a", "stage:1")
        .unwrap();
    ledger
        .register_run(Uuid::new_v4(), "worker-a", "stage:1")
        .unwrap();

    assert_eq!(ledger.run_count(), 2);
}

#[test]
fn another_session_cannot_cancel_run() {
    let mut ledger = RuntimeLedger::default();
    let session = Uuid::new_v4();
    let RegisterOutcome::Created(run) = ledger
        .register_run(session, "worker-a", "stage:1")
        .unwrap()
    else {
        unreachable!();
    };

    assert_eq!(
        ledger.request_cancel(run.run_id, Uuid::new_v4()),
        Err(RuntimeError::SessionMismatch)
    );
}

#[test]
fn cancellation_requires_worker_acknowledgement() {
    let mut ledger = RuntimeLedger::default();
    let session = Uuid::new_v4();
    let RegisterOutcome::Created(run) = ledger
        .register_run(session, "worker-a", "stage:1")
        .unwrap()
    else {
        unreachable!();
    };
    ledger.mark_active(run.run_id, "worker-a").unwrap();
    let requested = ledger.request_cancel(run.run_id, session).unwrap();
    assert_eq!(requested.state, RunState::CancellationRequested);

    assert_eq!(
        ledger.complete(run.run_id, "worker-a"),
        Err(RuntimeError::InvalidTransition {
            from: RunState::CancellationRequested,
            to: RunState::Completed,
        })
    );
    let cancelled = ledger
        .acknowledge_cancel(run.run_id, "worker-a")
        .unwrap();
    assert_eq!(cancelled.state, RunState::Cancelled);
}

#[test]
fn wrong_worker_cannot_complete_or_acknowledge() {
    let mut ledger = RuntimeLedger::default();
    let session = Uuid::new_v4();
    let RegisterOutcome::Created(run) = ledger
        .register_run(session, "worker-a", "stage:1")
        .unwrap()
    else {
        unreachable!();
    };
    ledger.mark_active(run.run_id, "worker-a").unwrap();

    assert_eq!(
        ledger.complete(run.run_id, "worker-b"),
        Err(RuntimeError::WorkerMismatch)
    );
}

#[test]
fn terminal_run_cannot_be_reopened() {
    let mut ledger = RuntimeLedger::default();
    let session = Uuid::new_v4();
    let RegisterOutcome::Created(run) = ledger
        .register_run(session, "worker-a", "stage:1")
        .unwrap()
    else {
        unreachable!();
    };
    ledger.mark_active(run.run_id, "worker-a").unwrap();
    ledger.complete(run.run_id, "worker-a").unwrap();

    assert_eq!(
        ledger.mark_active(run.run_id, "worker-a"),
        Err(RuntimeError::TerminalRun(RunState::Completed))
    );
}
