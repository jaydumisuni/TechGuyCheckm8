use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use tg_protocol::{ConnectionState, ProtocolGuard, RequestFrame, ResponseFrame, WireFrame};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameCodec {
    max_frame_bytes: usize,
}

impl FrameCodec {
    pub fn new(max_frame_bytes: usize) -> Result<Self, GatewayError> {
        if max_frame_bytes == 0 || max_frame_bytes > u32::MAX as usize {
            return Err(GatewayError::InvalidFrameLimit);
        }
        Ok(Self { max_frame_bytes })
    }

    pub fn write_frame<W: Write>(
        &self,
        writer: &mut W,
        frame: &WireFrame,
    ) -> Result<(), GatewayError> {
        let payload = serde_json::to_vec(frame)?;
        if payload.is_empty() || payload.len() > self.max_frame_bytes {
            return Err(GatewayError::FrameTooLarge {
                size: payload.len(),
                limit: self.max_frame_bytes,
            });
        }
        let length = u32::try_from(payload.len()).map_err(|_| GatewayError::FrameTooLarge {
            size: payload.len(),
            limit: self.max_frame_bytes,
        })?;
        writer.write_all(&length.to_be_bytes())?;
        writer.write_all(&payload)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_frame<R: Read>(&self, reader: &mut R) -> Result<WireFrame, GatewayError> {
        let mut length_bytes = [0_u8; 4];
        reader.read_exact(&mut length_bytes)?;
        let size = u32::from_be_bytes(length_bytes) as usize;
        if size == 0 || size > self.max_frame_bytes {
            return Err(GatewayError::FrameTooLarge {
                size,
                limit: self.max_frame_bytes,
            });
        }
        let mut payload = vec![0_u8; size];
        reader.read_exact(&mut payload)?;
        Ok(serde_json::from_slice(&payload)?)
    }
}

#[derive(Debug)]
pub struct LoopbackGateway {
    listener: TcpListener,
    codec: FrameCodec,
    io_timeout: Duration,
}

impl LoopbackGateway {
    pub fn bind(
        address: SocketAddr,
        max_frame_bytes: usize,
        io_timeout: Duration,
    ) -> Result<Self, GatewayError> {
        if !address.ip().is_loopback() {
            return Err(GatewayError::NonLoopbackBind(address));
        }
        if io_timeout.is_zero() {
            return Err(GatewayError::InvalidTimeout);
        }
        let listener = TcpListener::bind(address)?;
        Ok(Self {
            listener,
            codec: FrameCodec::new(max_frame_bytes)?,
            io_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, GatewayError> {
        Ok(self.listener.local_addr()?)
    }

    pub fn serve_one<F>(&self, handler: F) -> Result<GatewayExchange, GatewayError>
    where
        F: FnOnce(&RequestFrame) -> ResponseFrame,
    {
        let (mut stream, peer) = self.listener.accept()?;
        if !peer.ip().is_loopback() {
            return Err(GatewayError::NonLoopbackPeer(peer));
        }
        configure_stream(&stream, self.io_timeout)?;

        let mut guard = ProtocolGuard::default();
        let connect = self.codec.read_frame(&mut stream)?;
        guard.accept(&connect)?;
        let peer_id = match guard.state() {
            ConnectionState::Connected { peer_id, .. } => peer_id.clone(),
            ConnectionState::AwaitingConnect => return Err(GatewayError::HandshakeIncomplete),
        };

        let request_frame = self.codec.read_frame(&mut stream)?;
        guard.accept(&request_frame)?;
        let request = match request_frame {
            WireFrame::Request(request) => request,
            _ => return Err(GatewayError::RequestRequired),
        };
        let response = handler(&request);
        if response.request_id != request.request_id {
            return Err(GatewayError::ResponseRequestMismatch);
        }
        self.codec
            .write_frame(&mut stream, &WireFrame::Response(response.clone()))?;

        Ok(GatewayExchange {
            peer_id,
            peer,
            request,
            response,
        })
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), GatewayError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayExchange {
    pub peer_id: String,
    pub peer: SocketAddr,
    pub request: RequestFrame,
    pub response: ResponseFrame,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway bind must be loopback-only: {0}")]
    NonLoopbackBind(SocketAddr),
    #[error("gateway rejected a non-loopback peer: {0}")]
    NonLoopbackPeer(SocketAddr),
    #[error("frame size {size} is invalid or exceeds limit {limit}")]
    FrameTooLarge { size: usize, limit: usize },
    #[error("frame limit must be between 1 and u32::MAX")]
    InvalidFrameLimit,
    #[error("I/O timeout must be greater than zero")]
    InvalidTimeout,
    #[error("gateway handshake did not reach connected state")]
    HandshakeIncomplete,
    #[error("the post-handshake frame must be a request")]
    RequestRequired,
    #[error("handler response request ID does not match the request")]
    ResponseRequestMismatch,
    #[error(transparent)]
    Protocol(#[from] tg_protocol::ProtocolError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
