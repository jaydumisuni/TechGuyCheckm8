use std::collections::BTreeSet;

use tg_contracts::{EvidenceClass, StageResult};
use tg_evidence::{evaluate_final_proof, ProofRequirement};
use tg_simulator::{simulate, Scenario, SimulationInput};
use uuid::Uuid;

fn input(scenario: Scenario) -> SimulationInput {
    SimulationInput {
        session_id: Uuid::new_v4(),
        stage_id: "fixture-stage".to_owned(),
        worker_id: "fixture-worker".to_owned(),
        expected_device_identity_hash: "device-a".to_owned(),
        observed_device_identity_hash: "device-a".to_owned(),
        scenario,
    }
}

fn requirement(id: &str, class: EvidenceClass, disallowed: &[&str]) -> ProofRequirement {
    ProofRequirement {
        requirement_id: id.to_owned(),
        stage_id: "fixture-stage".to_owned(),
        class,
        minimum_valid_records: 1,
        disallowed_sources: disallowed.iter().map(|value| (*value).to_owned()).collect(),
    }
}

#[test]
fn success_has_independent_execution_transition_and_cleanup_proof() {
    let outcome = simulate(&input(Scenario::Success));
    assert_eq!(outcome.result, StageResult::SuccessVerified);
    assert!(outcome.cleanup_verified);

    let proof = evaluate_final_proof(
        &[
            requirement("execution", EvidenceClass::Execution, &[]),
            requirement("transition", EvidenceClass::Transition, &["fixture-worker"]),
            requirement("cleanup", EvidenceClass::Recovery, &[]),
        ],
        &outcome.evidence,
    );
    assert!(proof.passed);
}

#[test]
fn identity_mismatch_blocks_execution() {
    let mut input = input(Scenario::Success);
    input.observed_device_identity_hash = "device-b".to_owned();
    let outcome = simulate(&input);

    assert_eq!(outcome.result, StageResult::IdentityMismatch);
    assert!(!outcome.events.contains(&"stage_started".to_owned()));
    assert_eq!(
        outcome.events,
        vec![
            "identity_mismatch".to_owned(),
            "execution_blocked".to_owned()
        ]
    );
}

#[test]
fn timeout_requires_recovery_instead_of_success() {
    let outcome = simulate(&input(Scenario::Timeout));
    assert_eq!(outcome.result, StageResult::RecoveryRequired);
    assert!(!outcome.cleanup_verified);
}

#[test]
fn disconnect_is_distinct_from_worker_failure() {
    let outcome = simulate(&input(Scenario::Disconnect));
    assert_eq!(outcome.result, StageResult::DeviceDisconnected);
    assert!(outcome.events.contains(&"device_disconnected".to_owned()));
}

#[test]
fn cleanup_failure_overrides_successful_worker_exit() {
    let outcome = simulate(&input(Scenario::CleanupFailure));
    assert_eq!(outcome.result, StageResult::RecoveryRequired);
    assert!(!outcome.cleanup_verified);
    assert!(outcome.events.contains(&"stage_completed".to_owned()));
    assert!(outcome.events.contains(&"cleanup_failed".to_owned()));
}

#[test]
fn cancellation_is_verified_and_cleaned() {
    let outcome = simulate(&input(Scenario::CancellationHonored));
    assert_eq!(outcome.result, StageResult::Cancelled);
    assert!(outcome.cleanup_verified);
    assert!(outcome
        .events
        .contains(&"cancellation_acknowledged".to_owned()));
}

#[test]
fn requirement_helper_uses_set_semantics() {
    let proof = requirement(
        "transition",
        EvidenceClass::Transition,
        &["worker", "worker"],
    );
    assert_eq!(
        proof.disallowed_sources,
        BTreeSet::from(["worker".to_owned()])
    );
}
