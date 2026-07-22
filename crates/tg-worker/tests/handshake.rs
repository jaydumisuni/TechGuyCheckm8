use std::collections::{BTreeMap, BTreeSet};

use tg_contracts::{
    EngineManifest, FailureBehavior, Maturity, Permission, Provenance, CONTRACT_VERSION,
};
use tg_protocol::PROTOCOL_VERSION;
use tg_worker::{
    validate_worker_hello, WorkerExpectation, WorkerHandshakeError, WorkerHello,
};

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
        proof_requirements: BTreeSet::new(),
        failure_behavior: FailureBehavior::StopAndRecover,
    }
}

fn hello() -> WorkerHello {
    WorkerHello {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        worker_id: "worker-1".to_owned(),
        engine_id: "fixture-engine".to_owned(),
        engine_version: "1.0.0".to_owned(),
        capabilities: set(["stage.execute".to_owned(), "stage.cancel".to_owned()]),
        requested_permissions: set([Permission::ProcessSpawn]),
        host_platform: "linux".to_owned(),
        host_architecture: "x86_64".to_owned(),
        provenance_digest: "sha256:fixture".to_owned(),
    }
}

fn expectation() -> WorkerExpectation {
    WorkerExpectation {
        expected_provenance_digest: "sha256:fixture".to_owned(),
        allowed_host_architectures: set(["x86_64".to_owned()]),
    }
}

#[test]
fn exact_worker_handshake_is_accepted() {
    let accepted = validate_worker_hello(&hello(), &manifest(), &expectation()).unwrap();
    assert_eq!(accepted.worker_id, "worker-1");
    assert_eq!(accepted.engine_id, "fixture-engine");
}

#[test]
fn extra_permission_is_rejected() {
    let mut hello = hello();
    hello.requested_permissions.insert(Permission::UsbWrite);

    assert_eq!(
        validate_worker_hello(&hello, &manifest(), &expectation()),
        Err(WorkerHandshakeError::PermissionMismatch)
    );
}

#[test]
fn capability_drift_is_rejected() {
    let mut hello = hello();
    hello.capabilities.remove("stage.cancel");

    assert_eq!(
        validate_worker_hello(&hello, &manifest(), &expectation()),
        Err(WorkerHandshakeError::CapabilityMismatch)
    );
}

#[test]
fn provenance_mismatch_is_rejected() {
    let mut hello = hello();
    hello.provenance_digest = "sha256:other".to_owned();

    assert_eq!(
        validate_worker_hello(&hello, &manifest(), &expectation()),
        Err(WorkerHandshakeError::ProvenanceMismatch)
    );
}

#[test]
fn host_architecture_mismatch_is_rejected() {
    let mut hello = hello();
    hello.host_architecture = "arm64".to_owned();

    assert_eq!(
        validate_worker_hello(&hello, &manifest(), &expectation()),
        Err(WorkerHandshakeError::UnsupportedHost)
    );
}
