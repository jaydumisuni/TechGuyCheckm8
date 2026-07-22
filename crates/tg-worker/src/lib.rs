use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tg_contracts::{EngineManifest, Permission};
use tg_protocol::PROTOCOL_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerHello {
    pub protocol_version: String,
    pub worker_id: String,
    pub engine_id: String,
    pub engine_version: String,
    pub capabilities: BTreeSet<String>,
    pub requested_permissions: BTreeSet<Permission>,
    pub host_platform: String,
    pub host_architecture: String,
    pub provenance_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerExpectation {
    pub expected_provenance_digest: String,
    pub allowed_host_architectures: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedWorker {
    pub worker_id: String,
    pub engine_id: String,
    pub engine_version: String,
    pub capabilities: BTreeSet<String>,
    pub granted_permission_ceiling: BTreeSet<Permission>,
}

pub fn validate_worker_hello(
    hello: &WorkerHello,
    manifest: &EngineManifest,
    expectation: &WorkerExpectation,
) -> Result<AcceptedWorker, WorkerHandshakeError> {
    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(WorkerHandshakeError::UnsupportedProtocol(
            hello.protocol_version.clone(),
        ));
    }
    if hello.worker_id.trim().is_empty() {
        return Err(WorkerHandshakeError::MissingWorkerIdentity);
    }
    if hello.engine_id != manifest.engine_id || hello.engine_version != manifest.version {
        return Err(WorkerHandshakeError::EngineIdentityMismatch);
    }
    if hello.capabilities != manifest.capabilities {
        return Err(WorkerHandshakeError::CapabilityMismatch);
    }
    if hello.requested_permissions != manifest.requested_permissions {
        return Err(WorkerHandshakeError::PermissionMismatch);
    }
    if !manifest.supported_hosts.contains(&hello.host_platform)
        || !expectation
            .allowed_host_architectures
            .contains(&hello.host_architecture)
    {
        return Err(WorkerHandshakeError::UnsupportedHost);
    }
    if hello.provenance_digest != expectation.expected_provenance_digest
        || hello.provenance_digest.trim().is_empty()
    {
        return Err(WorkerHandshakeError::ProvenanceMismatch);
    }

    Ok(AcceptedWorker {
        worker_id: hello.worker_id.clone(),
        engine_id: hello.engine_id.clone(),
        engine_version: hello.engine_version.clone(),
        capabilities: hello.capabilities.clone(),
        granted_permission_ceiling: hello.requested_permissions.clone(),
    })
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkerHandshakeError {
    #[error("unsupported worker protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("worker identity is required")]
    MissingWorkerIdentity,
    #[error("worker engine identity or version does not match the selected manifest")]
    EngineIdentityMismatch,
    #[error("worker capabilities do not exactly match the selected manifest")]
    CapabilityMismatch,
    #[error("worker permissions do not exactly match the selected manifest")]
    PermissionMismatch,
    #[error("worker host platform or architecture is unsupported")]
    UnsupportedHost,
    #[error("worker provenance digest does not match the staged executable")]
    ProvenanceMismatch,
}
