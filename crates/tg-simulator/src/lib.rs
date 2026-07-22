use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tg_contracts::{
    EvidenceClass, EvidenceRecord, RedactionClass, StageResult, CONTRACT_VERSION,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    Success,
    Timeout,
    Disconnect,
    IdentityMismatch,
    CleanupFailure,
    CancellationHonored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationInput {
    pub session_id: Uuid,
    pub stage_id: String,
    pub worker_id: String,
    pub expected_device_identity_hash: String,
    pub observed_device_identity_hash: String,
    pub scenario: Scenario,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationOutcome {
    pub result: StageResult,
    pub events: Vec<String>,
    pub evidence: Vec<EvidenceRecord>,
    pub cleanup_verified: bool,
}

pub fn simulate(input: &SimulationInput) -> SimulationOutcome {
    if input.expected_device_identity_hash != input.observed_device_identity_hash
        || input.scenario == Scenario::IdentityMismatch
    {
        return SimulationOutcome {
            result: StageResult::IdentityMismatch,
            events: vec!["identity_mismatch".to_owned(), "execution_blocked".to_owned()],
            evidence: vec![evidence(
                input,
                1,
                EvidenceClass::Observation,
                "identity-observer",
                false,
                [("identity_match", "false")],
            )],
            cleanup_verified: true,
        };
    }

    match input.scenario {
        Scenario::Success => SimulationOutcome {
            result: StageResult::SuccessVerified,
            events: vec![
                "stage_started".to_owned(),
                "stage_completed".to_owned(),
                "cleanup_completed".to_owned(),
            ],
            evidence: vec![
                evidence(
                    input,
                    1,
                    EvidenceClass::Execution,
                    &input.worker_id,
                    true,
                    [("worker_exit", "success")],
                ),
                evidence(
                    input,
                    2,
                    EvidenceClass::Transition,
                    "transport-observer",
                    true,
                    [("transition_confirmed", "true")],
                ),
                evidence(
                    input,
                    3,
                    EvidenceClass::Recovery,
                    "cleanup-observer",
                    true,
                    [("cleanup_verified", "true")],
                ),
            ],
            cleanup_verified: true,
        },
        Scenario::Timeout => SimulationOutcome {
            result: StageResult::RecoveryRequired,
            events: vec!["stage_started".to_owned(), "stage_timeout".to_owned()],
            evidence: vec![evidence(
                input,
                1,
                EvidenceClass::Execution,
                &input.worker_id,
                false,
                [("timeout", "true")],
            )],
            cleanup_verified: false,
        },
        Scenario::Disconnect => SimulationOutcome {
            result: StageResult::DeviceDisconnected,
            events: vec![
                "stage_started".to_owned(),
                "device_disconnected".to_owned(),
            ],
            evidence: vec![evidence(
                input,
                1,
                EvidenceClass::Observation,
                "transport-observer",
                true,
                [("connected", "false")],
            )],
            cleanup_verified: false,
        },
        Scenario::CleanupFailure => SimulationOutcome {
            result: StageResult::RecoveryRequired,
            events: vec![
                "stage_started".to_owned(),
                "stage_completed".to_owned(),
                "cleanup_failed".to_owned(),
            ],
            evidence: vec![
                evidence(
                    input,
                    1,
                    EvidenceClass::Execution,
                    &input.worker_id,
                    true,
                    [("worker_exit", "success")],
                ),
                evidence(
                    input,
                    2,
                    EvidenceClass::Recovery,
                    "cleanup-observer",
                    false,
                    [("cleanup_verified", "false")],
                ),
            ],
            cleanup_verified: false,
        },
        Scenario::CancellationHonored => SimulationOutcome {
            result: StageResult::Cancelled,
            events: vec![
                "stage_started".to_owned(),
                "cancellation_requested".to_owned(),
                "cancellation_acknowledged".to_owned(),
                "cleanup_completed".to_owned(),
            ],
            evidence: vec![
                evidence(
                    input,
                    1,
                    EvidenceClass::Execution,
                    &input.worker_id,
                    true,
                    [("cancel_acknowledged", "true")],
                ),
                evidence(
                    input,
                    2,
                    EvidenceClass::Recovery,
                    "cleanup-observer",
                    true,
                    [("cleanup_verified", "true")],
                ),
            ],
            cleanup_verified: true,
        },
        Scenario::IdentityMismatch => unreachable!("handled before scenario dispatch"),
    }
}

fn evidence<const N: usize>(
    input: &SimulationInput,
    sequence: u64,
    class: EvidenceClass,
    source: &str,
    valid: bool,
    values: [(&str, &str); N],
) -> EvidenceRecord {
    EvidenceRecord {
        schema_version: CONTRACT_VERSION.to_owned(),
        evidence_id: Uuid::new_v4(),
        session_id: input.session_id,
        stage_id: input.stage_id.clone(),
        sequence,
        class,
        source: source.to_owned(),
        collector_version: "tg-simulator/0.1.0".to_owned(),
        device_identity_hash: Some(input.observed_device_identity_hash.clone()),
        values: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>(),
        artifact_hashes: BTreeMap::new(),
        valid,
        redaction_class: RedactionClass::DeviceSensitive,
        supersedes: Vec::new(),
        contradicts: Vec::new(),
    }
}
