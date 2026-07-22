use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Pending,
    Active,
    CancellationRequested,
    Cancelled,
    Completed,
    Failed,
}

impl RunState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Cancelled | Self::Completed | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: Uuid,
    pub session_id: Uuid,
    pub worker_id: String,
    pub idempotency_key: String,
    pub state: RunState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    Created(RunRecord),
    Existing(RunRecord),
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeLedger {
    runs: BTreeMap<Uuid, RunRecord>,
    idempotency: BTreeMap<(Uuid, String), Uuid>,
}

impl RuntimeLedger {
    pub fn register_run(
        &mut self,
        session_id: Uuid,
        worker_id: impl Into<String>,
        idempotency_key: impl Into<String>,
    ) -> Result<RegisterOutcome, RuntimeError> {
        let worker_id = worker_id.into();
        let idempotency_key = idempotency_key.into();
        if worker_id.trim().is_empty() {
            return Err(RuntimeError::MissingWorkerIdentity);
        }
        if idempotency_key.trim().is_empty() {
            return Err(RuntimeError::MissingIdempotencyKey);
        }

        let scoped_key = (session_id, idempotency_key.clone());
        if let Some(run_id) = self.idempotency.get(&scoped_key) {
            let record = self
                .runs
                .get(run_id)
                .cloned()
                .ok_or(RuntimeError::LedgerCorruption)?;
            return Ok(RegisterOutcome::Existing(record));
        }

        let record = RunRecord {
            run_id: Uuid::new_v4(),
            session_id,
            worker_id,
            idempotency_key,
            state: RunState::Pending,
        };
        self.idempotency.insert(scoped_key, record.run_id);
        self.runs.insert(record.run_id, record.clone());
        Ok(RegisterOutcome::Created(record))
    }

    pub fn mark_active(
        &mut self,
        run_id: Uuid,
        worker_id: &str,
    ) -> Result<RunRecord, RuntimeError> {
        self.transition(run_id, worker_id, RunState::Pending, RunState::Active)
    }

    pub fn request_cancel(
        &mut self,
        run_id: Uuid,
        session_id: Uuid,
    ) -> Result<RunRecord, RuntimeError> {
        let record = self
            .runs
            .get_mut(&run_id)
            .ok_or(RuntimeError::RunNotFound)?;
        if record.session_id != session_id {
            return Err(RuntimeError::SessionMismatch);
        }
        match record.state.clone() {
            RunState::Pending | RunState::Active => {
                record.state = RunState::CancellationRequested;
                Ok(record.clone())
            }
            RunState::CancellationRequested => Ok(record.clone()),
            _ => Err(RuntimeError::TerminalRun(record.state.clone())),
        }
    }

    pub fn acknowledge_cancel(
        &mut self,
        run_id: Uuid,
        worker_id: &str,
    ) -> Result<RunRecord, RuntimeError> {
        self.transition(
            run_id,
            worker_id,
            RunState::CancellationRequested,
            RunState::Cancelled,
        )
    }

    pub fn complete(&mut self, run_id: Uuid, worker_id: &str) -> Result<RunRecord, RuntimeError> {
        self.transition(run_id, worker_id, RunState::Active, RunState::Completed)
    }

    pub fn fail(&mut self, run_id: Uuid, worker_id: &str) -> Result<RunRecord, RuntimeError> {
        let record = self
            .runs
            .get_mut(&run_id)
            .ok_or(RuntimeError::RunNotFound)?;
        if record.worker_id != worker_id {
            return Err(RuntimeError::WorkerMismatch);
        }
        if record.state.is_terminal() {
            return Err(RuntimeError::TerminalRun(record.state.clone()));
        }
        record.state = RunState::Failed;
        Ok(record.clone())
    }

    pub fn get(&self, run_id: Uuid) -> Option<&RunRecord> {
        self.runs.get(&run_id)
    }

    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    fn transition(
        &mut self,
        run_id: Uuid,
        worker_id: &str,
        expected: RunState,
        next: RunState,
    ) -> Result<RunRecord, RuntimeError> {
        let record = self
            .runs
            .get_mut(&run_id)
            .ok_or(RuntimeError::RunNotFound)?;
        if record.worker_id != worker_id {
            return Err(RuntimeError::WorkerMismatch);
        }
        if record.state != expected {
            if record.state.is_terminal() {
                return Err(RuntimeError::TerminalRun(record.state.clone()));
            }
            return Err(RuntimeError::InvalidTransition {
                from: record.state.clone(),
                to: next,
            });
        }
        record.state = next;
        Ok(record.clone())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("worker identity is required")]
    MissingWorkerIdentity,
    #[error("idempotency key is required")]
    MissingIdempotencyKey,
    #[error("run was not found")]
    RunNotFound,
    #[error("run belongs to another session")]
    SessionMismatch,
    #[error("run belongs to another worker")]
    WorkerMismatch,
    #[error("run is terminal in state {0:?}")]
    TerminalRun(RunState),
    #[error("invalid run transition from {from:?} to {to:?}")]
    InvalidTransition { from: RunState, to: RunState },
    #[error("idempotency index references a missing run")]
    LedgerCorruption,
}
