use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use tg_gateway::{FrameCodec, LoopbackGateway};
use tg_journal::{verify_file, Journal};
use tg_protocol::{
    ConnectFrame, Method, PeerRole, RequestFrame, ResponseFrame, WireFrame, PROTOCOL_VERSION,
};
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tg-gateway-audit-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn accepted_health_request_is_committed_to_verified_session_journal() {
    let root = TestDirectory::new();
    let session_id = Uuid::new_v4();
    let root_for_server = root.0.clone();
    let gateway = LoopbackGateway::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        16 * 1024,
        Duration::from_secs(2),
    )
    .unwrap();
    let address = gateway.local_addr().unwrap();
    let server = thread::spawn(move || {
        gateway
            .serve_one(|request| {
                let mut journal = Journal::open(&root_for_server, request.session_id).unwrap();
                journal
                    .append(
                        "gateway_request_accepted",
                        BTreeMap::from([
                            ("method".to_owned(), format!("{:?}", request.method)),
                            ("request_id".to_owned(), request.request_id.to_string()),
                        ]),
                    )
                    .unwrap();
                ResponseFrame {
                    request_id: request.request_id,
                    ok: true,
                    result: BTreeMap::from([("status".to_owned(), "ready".to_owned())]),
                    error: None,
                }
            })
            .unwrap()
    });

    let codec = FrameCodec::new(16 * 1024).unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    codec
        .write_frame(
            &mut client,
            &WireFrame::Connect(ConnectFrame {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                peer_id: "audit-client".to_owned(),
                role: PeerRole::Operator,
                capabilities: BTreeSet::new(),
                requested_permissions: BTreeSet::new(),
            }),
        )
        .unwrap();
    let request = RequestFrame {
        request_id: Uuid::new_v4(),
        session_id,
        method: Method::Health,
        idempotency_key: None,
        params: BTreeMap::new(),
    };
    codec
        .write_frame(&mut client, &WireFrame::Request(request.clone()))
        .unwrap();
    let WireFrame::Response(response) = codec.read_frame(&mut client).unwrap() else {
        panic!("expected response");
    };
    assert!(response.ok);
    assert_eq!(response.request_id, request.request_id);
    server.join().unwrap();

    let path = root
        .0
        .join(session_id.to_string())
        .join("events.jsonl");
    let verified = verify_file(path).unwrap();
    assert_eq!(verified.session_id, Some(session_id));
    assert_eq!(verified.entries, 1);
    assert_eq!(verified.last_sequence, 1);
}
