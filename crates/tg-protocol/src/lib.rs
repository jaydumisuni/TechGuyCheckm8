use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tg_contracts::Permission;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "tgcheckm8.protocol.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Operator,
    Worker,
    Observer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectFrame {
    pub protocol_version: String,
    pub peer_id: String,
    pub role: PeerRole,
    pub capabilities: BTreeSet<String>,
    pub requested_permissions: BTreeSet<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Health,
    Prepare,
    ExecuteStage,
    Cancel,
    Recover,
    CollectEvidence,
    Cleanup,
}

impl Method {
    pub fn has_side_effects(&self) -> bool {
        !matches!(self, Self::Health | Self::CollectEvidence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestFrame {
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub method: Method,
    pub idempotency_key: Option<String>,
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolErrorPayload {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseFrame {
    pub request_id: Uuid,
    pub ok: bool,
    pub result: BTreeMap<String, String>,
    pub error: Option<ProtocolErrorPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    WorkerReady,
    StageStarted,
    Progress,
    EvidenceProduced,
    CancellationRequested,
    CancellationAcknowledged,
    CleanupStarted,
    CleanupCompleted,
    WorkerFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFrame {
    pub session_id: Uuid,
    pub run_id: Option<Uuid>,
    pub sequence: u64,
    pub kind: EventKind,
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireFrame {
    Connect(ConnectFrame),
    Request(RequestFrame),
    Response(ResponseFrame),
    Event(EventFrame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    AwaitingConnect,
    Connected { peer_id: String, role: PeerRole },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolGuard {
    state: ConnectionState,
}

impl Default for ProtocolGuard {
    fn default() -> Self {
        Self {
            state: ConnectionState::AwaitingConnect,
        }
    }
}

impl ProtocolGuard {
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn accept(&mut self, frame: &WireFrame) -> Result<(), ProtocolError> {
        match (&self.state, frame) {
            (ConnectionState::AwaitingConnect, WireFrame::Connect(connect)) => {
                validate_connect(connect)?;
                self.state = ConnectionState::Connected {
                    peer_id: connect.peer_id.clone(),
                    role: connect.role.clone(),
                };
                Ok(())
            }
            (ConnectionState::AwaitingConnect, _) => Err(ProtocolError::ConnectRequired),
            (ConnectionState::Connected { .. }, WireFrame::Connect(_)) => {
                Err(ProtocolError::AlreadyConnected)
            }
            (ConnectionState::Connected { .. }, WireFrame::Request(request)) => {
                validate_request(request)
            }
            (ConnectionState::Connected { .. }, _) => Ok(()),
        }
    }
}

pub fn validate_connect(connect: &ConnectFrame) -> Result<(), ProtocolError> {
    if connect.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(
            connect.protocol_version.clone(),
        ));
    }
    if connect.peer_id.trim().is_empty() {
        return Err(ProtocolError::MissingPeerIdentity);
    }
    Ok(())
}

pub fn validate_request(request: &RequestFrame) -> Result<(), ProtocolError> {
    if request.method.has_side_effects()
        && request
            .idempotency_key
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(ProtocolError::IdempotencyRequired(request.method.clone()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("the first frame must be connect")]
    ConnectRequired,
    #[error("connection handshake was already completed")]
    AlreadyConnected,
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(String),
    #[error("peer identity is required")]
    MissingPeerIdentity,
    #[error("side-effecting method {0:?} requires an idempotency key")]
    IdempotencyRequired(Method),
}
