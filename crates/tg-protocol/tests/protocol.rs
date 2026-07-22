use std::collections::{BTreeMap, BTreeSet};

use tg_protocol::{
    ConnectFrame, ConnectionState, Method, PeerRole, ProtocolError, ProtocolGuard, RequestFrame,
    WireFrame, PROTOCOL_VERSION,
};
use uuid::Uuid;

fn connect() -> WireFrame {
    WireFrame::Connect(ConnectFrame {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        peer_id: "worker-fixture".to_owned(),
        role: PeerRole::Worker,
        capabilities: BTreeSet::new(),
        requested_permissions: BTreeSet::new(),
    })
}

fn request(method: Method, idempotency_key: Option<&str>) -> WireFrame {
    WireFrame::Request(RequestFrame {
        request_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        method,
        idempotency_key: idempotency_key.map(str::to_owned),
        params: BTreeMap::new(),
    })
}

#[test]
fn first_frame_must_be_connect() {
    let mut guard = ProtocolGuard::default();
    assert_eq!(
        guard.accept(&request(Method::Health, None)),
        Err(ProtocolError::ConnectRequired)
    );
}

#[test]
fn valid_connect_locks_peer_identity() {
    let mut guard = ProtocolGuard::default();
    guard.accept(&connect()).unwrap();

    assert_eq!(
        guard.state(),
        &ConnectionState::Connected {
            peer_id: "worker-fixture".to_owned(),
            role: PeerRole::Worker,
        }
    );
    assert_eq!(
        guard.accept(&connect()),
        Err(ProtocolError::AlreadyConnected)
    );
}

#[test]
fn side_effecting_request_requires_idempotency_key() {
    let mut guard = ProtocolGuard::default();
    guard.accept(&connect()).unwrap();

    assert_eq!(
        guard.accept(&request(Method::ExecuteStage, None)),
        Err(ProtocolError::IdempotencyRequired(Method::ExecuteStage))
    );
    assert!(guard
        .accept(&request(Method::ExecuteStage, Some("session:stage:1")))
        .is_ok());
}

#[test]
fn read_only_request_does_not_require_idempotency_key() {
    let mut guard = ProtocolGuard::default();
    guard.accept(&connect()).unwrap();

    assert!(guard.accept(&request(Method::Health, None)).is_ok());
    assert!(guard
        .accept(&request(Method::CollectEvidence, None))
        .is_ok());
}

#[test]
fn unsupported_protocol_version_is_rejected() {
    let mut guard = ProtocolGuard::default();
    let frame = WireFrame::Connect(ConnectFrame {
        protocol_version: "tgcheckm8.protocol.v99".to_owned(),
        peer_id: "worker-fixture".to_owned(),
        role: PeerRole::Worker,
        capabilities: BTreeSet::new(),
        requested_permissions: BTreeSet::new(),
    });

    assert_eq!(
        guard.accept(&frame),
        Err(ProtocolError::UnsupportedVersion(
            "tgcheckm8.protocol.v99".to_owned()
        ))
    );
}
