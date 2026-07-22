use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{EvidenceClass, EvidenceRecord, RedactionClass};
use tg_evidence::{evaluate_final_proof, ProofRequirement};
use uuid::Uuid;

fn evidence(stage: &str, class: EvidenceClass, source: &str) -> EvidenceRecord {
    EvidenceRecord {
        schema_version: "tgcheckm8.contracts.v1".to_owned(),
        evidence_id: Uuid::new_v4(),
        session_id: Uuid::nil(),
        stage_id: stage.to_owned(),
        sequence: 1,
        class,
        source: source.to_owned(),
        collector_version: "fixture".to_owned(),
        device_identity_hash: Some("same-device".to_owned()),
        values: BTreeMap::new(),
        artifact_hashes: BTreeMap::new(),
        valid: true,
        redaction_class: RedactionClass::DeviceSensitive,
        supersedes: Vec::new(),
        contradicts: Vec::new(),
    }
}

fn requirement(minimum: usize) -> ProofRequirement {
    ProofRequirement {
        requirement_id: "pwned-dfu-proof".to_owned(),
        stage_id: "pwned_dfu".to_owned(),
        class: EvidenceClass::Transition,
        minimum_valid_records: minimum,
        disallowed_sources: BTreeSet::new(),
    }
}

#[test]
fn one_worker_record_cannot_satisfy_two_source_requirement() {
    let decision = evaluate_final_proof(
        &[requirement(2)],
        &[evidence(
            "pwned_dfu",
            EvidenceClass::Transition,
            "exploit-worker",
        )],
    );

    assert!(!decision.passed);
    assert_eq!(decision.missing.len(), 1);
}

#[test]
fn independent_sources_satisfy_requirement() {
    let decision = evaluate_final_proof(
        &[requirement(2)],
        &[
            evidence("pwned_dfu", EvidenceClass::Transition, "exploit-worker"),
            evidence("pwned_dfu", EvidenceClass::Transition, "usb-observer"),
        ],
    );

    assert!(decision.passed);
    assert!(decision.missing.is_empty());
    assert!(decision.blockers.is_empty());
}

#[test]
fn contradiction_blocks_final_proof() {
    let first = evidence("pwned_dfu", EvidenceClass::Transition, "exploit-worker");
    let mut second = evidence("pwned_dfu", EvidenceClass::Transition, "usb-observer");
    second.contradicts.push(first.evidence_id);

    let decision = evaluate_final_proof(&[requirement(2)], &[first, second]);

    assert!(!decision.passed);
    assert_eq!(decision.blockers.len(), 1);
}

#[test]
fn disallowed_executor_source_does_not_count_as_independent_proof() {
    let mut requirement = requirement(1);
    requirement
        .disallowed_sources
        .insert("exploit-worker".to_owned());

    let decision = evaluate_final_proof(
        &[requirement],
        &[evidence(
            "pwned_dfu",
            EvidenceClass::Transition,
            "exploit-worker",
        )],
    );

    assert!(!decision.passed);
}
