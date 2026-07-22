use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

use tg_gateway::{FrameCodec, GatewayError, LoopbackGateway};
use tg_protocol::{
    ConnectFrame, Method, PeerRole, RequestFrame, ResponseFrame, WireFrame, PROTOCOL_VERSION,
};
use uuid::Uuid;

fn connect_frame() -> WireFrame {
    WireFrame::Connect(ConnectFrame {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        peer_id: "local-test-client".to_owned(),
        role: PeerRole::Operator,
        capabilities: BTreeSet::new(),
        requested_permissions: BTreeSet::new(),
    })
}

fn health_request() -> RequestFrame {
    RequestFrame {
        request_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        method: Method::Health,
        idempotency_key: None,
        params: BTreeMap::new(),
    }
}

#[test]
fn non_loopback_bind_is_rejected_before_listening() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let result = LoopbackGateway::bind(address, 1024, Duration::from_secs(1));
    assert!(matches!(result, Err(GatewayError::NonLoopbackBind(value)) if value == address));
}

#[test]
fn frame_codec_round_trips_wire_frames() {
    let codec = FrameCodec::new(4096).unwrap();
    let frame = connect_frame();
    let mut bytes = Vec::new();
    codec.write_frame(&mut bytes, &frame).unwrap();
    let decoded = codec.read_frame(&mut Cursor::new(bytes)).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn oversized_declared_frame_is_rejected_without_allocation() {
    let codec = FrameCodec::new(32).unwrap();
    let mut bytes = Cursor::new(100_u32.to_be_bytes().to_vec());
    let result = codec.read_frame(&mut bytes);
    assert!(matches!(
        result,
        Err(GatewayError::FrameTooLarge {
            size: 100,
            limit: 32
        })
    ));
}

#[test]
fn malformed_json_frame_is_rejected() {
    let codec = FrameCodec::new(1024).unwrap();
    let payload = b"not-json";
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    assert!(matches!(
        codec.read_frame(&mut Cursor::new(bytes)),
        Err(GatewayError::Json(_))
    ));
}

#[test]
fn loopback_gateway_validates_handshake_and_correlates_response() {
    let gateway = LoopbackGateway::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        16 * 1024,
        Duration::from_secs(2),
    )
    .unwrap();
    let address = gateway.local_addr().unwrap();
    let server = thread::spawn(move || {
        gateway
            .serve_one(|request| ResponseFrame {
                request_id: request.request_id,
                ok: true,
                result: BTreeMap::from([("status".to_owned(), "ready".to_owned())]),
                error: None,
            })
            .unwrap()
    });

    let codec = FrameCodec::new(16 * 1024).unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let request = health_request();
    codec.write_frame(&mut client, &connect_frame()).unwrap();
    codec
        .write_frame(&mut client, &WireFrame::Request(request.clone()))
        .unwrap();
    let response = codec.read_frame(&mut client).unwrap();

    let WireFrame::Response(response) = response else {
        panic!("expected response frame");
    };
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.result.get("status").map(String::as_str), Some("ready"));

    let exchange = server.join().unwrap();
    assert_eq!(exchange.peer_id, "local-test-client");
    assert!(exchange.peer.ip().is_loopback());
    assert_eq!(exchange.request, request);
}

#[test]
fn handler_cannot_reply_to_another_request_id() {
    let gateway = LoopbackGateway::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        16 * 1024,
        Duration::from_secs(2),
    )
    .unwrap();
    let address = gateway.local_addr().unwrap();
    let server = thread::spawn(move || {
        gateway.serve_one(|_| ResponseFrame {
            request_id: Uuid::new_v4(),
            ok: true,
            result: BTreeMap::new(),
            error: None,
        })
    });

    let codec = FrameCodec::new(16 * 1024).unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let request = health_request();
    codec.write_frame(&mut client, &connect_frame()).unwrap();
    codec
        .write_frame(&mut client, &WireFrame::Request(request))
        .unwrap();

    let result = server.join().unwrap();
    assert!(matches!(result, Err(GatewayError::ResponseRequestMismatch)));
}
