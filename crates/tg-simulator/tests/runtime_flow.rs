use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{
    EngineManifest, EvidenceClass, FailureBehavior, Maturity, Permission, Provenance, StageResult,
    CONTRACT_VERSION,
};
use tg_evidence::{evaluate_final_proof, ProofRequirement};
use tg_leases::{LeaseManager, LeaseOwner, ResourceKey, ResourceKind};
use tg_protocol::{
    ConnectFrame, Method, PeerRole, ProtocolGuard, RequestFrame, WireFrame, PROTOCOL_VERSION,
};
use tg_runtime::{RegisterOutcome, RunState, RuntimeLedger};
use tg_simulator::{simulate, Scenario, SimulationInput};
use tg_worker::{validate_worker_hello, WorkerExpectation, WorkerHello};
use uuid::Uuid;

fn set<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn manifest() -> EngineManifest {
    EngineManifest {
        schema_version: CONTRACT_VERSION.to_owned(),
        engine_id: "fixture-engine".to_owned(),
        version: "1.0.0".to_owned(),
        maturity: Maturity::SimulationTested,
        capabilities: set(["stage.execute".to_owned(), "stage.cancel".to_owned()]),
        requested_permissions: set([Permission::ProcessSpawn]),
        supported_hosts: set(["linux".to_owned()]),
        executes_external_code: true,
        requires_network: false,
        modifies_device: false,
        provenance: Provenance {
            source_repository: "owner/repo".to_owned(),
            source_commit: "0123456789abcdef".to_owned(),
            source_release: None,
            licence: "MIT".to_owned(),
            local_patch_hash: None,
            build_recipe_hash: None,
            artifact_hashes: BTreeMap::new(),
        },
        proof_requirements: set([
            "stage-execution".to_owned(),
            "stage-transition".to_owned(),
            "stage-cleanup".to_owned(),
        ]),
        failure_behavior: FailureBehavior::StopAndRecover,
    }
}

fn worker_hello() -> WorkerHello {
    WorkerHello {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        worker_id: "fixture-worker".to_owned(),
        engine_id: "fixture-engine".to_owned(),
        engine_version: "1.0.0".to_owned(),
        capabilities: set(["stage.execute".to_owned(), "stage.cancel".to_owned()]),
        requested_permissions: set([Permission::ProcessSpawn]),
        host_platform: "linux".to_owned(),
        host_architecture: "x86_64".to_owned(),
        provenance_digest: "sha256:fixture".to_owned(),
    }
}

fn requirements() -> Vec<ProofRequirement> {
    vec![
        ProofRequirement {
            requirement_id: "execution".to_owned(),
            stage_id: "fixture-stage".to_owned(),
            class: EvidenceClass::Execution,
            minimum_valid_records: 1,
            disallowed_sources: BTreeSet::new(),
        },
        ProofRequirement {
            requirement_id: "transition".to_owned(),
            stage_id: "fixture-stage".to_owned(),
            class: EvidenceClass::Transition,
            minimum_valid_records: 1,
            disallowed_sources: set(["fixture-worker".to_owned()]),
        },
        ProofRequirement {
            requirement_id: "cleanup".to_owned(),
            stage_id: "fixture-stage".to_owned(),
            class: EvidenceClass::Recovery,
            minimum_valid_records: 1,
            disallowed_sources: BTreeSet::new(),
        },
    ]
}

#[test]
fn full_simulated_success_releases_resources_after_final_proof() {
    let session_id = Uuid::new_v4();
    let accepted = validate_worker_hello(
        &worker_hello(),
        &manifest(),
        &WorkerExpectation {
            expected_provenance_digest: "sha256:fixture".to_owned(),
            allowed_host_architectures: set(["x86_64".to_owned()]),
        },
    )
    .unwrap();

    let mut protocol = ProtocolGuard::default();
    protocol
        .accept(&WireFrame::Connect(ConnectFrame {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            peer_id: accepted.worker_id.clone(),
            role: PeerRole::Worker,
            capabilities: accepted.capabilities.clone(),
            requested_permissions: accepted.granted_permission_ceiling.clone(),
        }))
        .unwrap();
    protocol
        .accept(&WireFrame::Request(RequestFrame {
            request_id: Uuid::new_v4(),
            session_id,
            method: Method::ExecuteStage,
            idempotency_key: Some("fixture-stage:1".to_owned()),
            params: BTreeMap::new(),
        }))
        .unwrap();

    let mut runs = RuntimeLedger::default();
    let RegisterOutcome::Created(run) = runs
        .register_run(session_id, &accepted.worker_id, "fixture-stage:1")
        .unwrap()
    else {
        unreachable!();
    };
    runs.mark_active(run.run_id, &accepted.worker_id).unwrap();

    let owner = LeaseOwner {
        session_id,
        worker_id: accepted.worker_id.clone(),
        run_id: run.run_id,
    };
    let resources = set([
        ResourceKey {
            kind: ResourceKind::Session,
            stable_id: session_id.to_string(),
        },
        ResourceKey {
            kind: ResourceKind::Device,
            stable_id: "device-a".to_owned(),
        },
        ResourceKey {
            kind: ResourceKind::Usb,
            stable_id: "port-1".to_owned(),
        },
    ]);
    let mut leases = LeaseManager::default();
    let grant = leases.acquire(resources, owner.clone(), 0, 10).unwrap();

    let outcome = simulate(&SimulationInput {
        session_id,
        stage_id: "fixture-stage".to_owned(),
        worker_id: accepted.worker_id.clone(),
        expected_device_identity_hash: "device-a".to_owned(),
        observed_device_identity_hash: "device-a".to_owned(),
        scenario: Scenario::Success,
    });
    let proof = evaluate_final_proof(&requirements(), &outcome.evidence);

    assert_eq!(outcome.result, StageResult::SuccessVerified);
    assert!(proof.passed);
    let completed = runs.complete(run.run_id, &accepted.worker_id).unwrap();
    assert_eq!(completed.state, RunState::Completed);
    leases.release(grant.lease_id, &owner).unwrap();
    assert_eq!(leases.active_resource_count(), 0);
}

#[test]
fn identity_mismatch_never_produces_final_proof() {
    let session_id = Uuid::new_v4();
    let outcome = simulate(&SimulationInput {
        session_id,
        stage_id: "fixture-stage".to_owned(),
        worker_id: "fixture-worker".to_owned(),
        expected_device_identity_hash: "device-a".to_owned(),
        observed_device_identity_hash: "device-b".to_owned(),
        scenario: Scenario::Success,
    });
    let proof = evaluate_final_proof(&requirements(), &outcome.evidence);

    assert_eq!(outcome.result, StageResult::IdentityMismatch);
    assert!(!proof.passed);
    assert!(!proof.missing.is_empty());
}
