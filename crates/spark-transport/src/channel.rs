//! WebSocket framing over whatever stream the routing layer produced.
//!
//! `docs/protocol.md` §6: WebSocket over TLS, binary frames. This is the framing;
//! the stream underneath it has already been through [`crate::Transport::open`],
//! which decided whether it went direct or through Tor and, if through Tor,
//! negotiated SOCKS5 on its own circuit.
//!
//! The layering only works because everything here is synchronous and generic
//! over `Read + Write`. A stream is a stream, so TCP, TLS-over-TCP and
//! TLS-over-SOCKS5 all compose without any of them knowing about the others.
//! Making this async would have meant the SOCKS5 negotiation knowing about the
//! runtime, and the routing decision leaking into every layer above it.
//!
//! A thread per connection is the cost. For a first server and a verification
//! harness that is the right trade; if it stops being one, this is the seam where
//! that changes, and nothing above it needs to know.

use spark_wire::{Frame, Operation, WireError};
use std::io::{Read, Write};

/// A framed connection to one service.
pub struct Channel<S: Read + Write> {
    ws: tungstenite::WebSocket<S>,
    next_id: u32,
}

impl<S: Read + Write> Channel<S> {
    /// Take the client side of a WebSocket handshake over `stream`.
    ///
    /// `url` is what the server sees in the request line. It carries no identity —
    /// there is nothing to put in it, and a path that varied per account would
    /// hand the server the correlation the rest of the design removes.
    pub fn connect(stream: S, url: &str) -> Result<Self, ChannelError> {
        let (ws, _) = tungstenite::client::client_with_config(
            url,
            stream,
            Some(
                tungstenite::protocol::WebSocketConfig::default()
                    .max_message_size(Some(spark_wire::MAX_FRAME))
                    .max_frame_size(Some(spark_wire::MAX_FRAME)),
            ),
        )
        .map_err(|_| ChannelError::Handshake)?;
        Ok(Self { ws, next_id: 1 })
    }

    /// Take the server side.
    pub fn accept(stream: S) -> Result<Self, ChannelError> {
        let ws = tungstenite::accept_with_config(
            stream,
            Some(
                tungstenite::protocol::WebSocketConfig::default()
                    .max_message_size(Some(spark_wire::MAX_FRAME))
                    .max_frame_size(Some(spark_wire::MAX_FRAME)),
            ),
        )
        .map_err(|_| ChannelError::Handshake)?;
        Ok(Self { ws, next_id: 1 })
    }

    /// Send a request and wait for the response that matches it.
    ///
    /// Responses carrying a different `req_id` are discarded rather than returned
    /// to the wrong caller. On one connection with one caller that cannot happen;
    /// checking anyway is what stops it becoming possible when it can.
    pub fn call<Q, R>(&mut self, req: &Q) -> Result<R, ChannelError>
    where
        Q: serde::Serialize + Operation,
        R: serde::de::DeserializeOwned + Operation,
    {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.send(&Frame::encode(id, req)?)?;
        loop {
            let f = self.recv()?;
            if f.req_id == id {
                return Ok(f.body::<R>()?);
            }
        }
    }

    /// Read one frame.
    pub fn recv(&mut self) -> Result<Frame, ChannelError> {
        loop {
            match self.ws.read().map_err(|_| ChannelError::Closed)? {
                tungstenite::Message::Binary(b) => return Ok(Frame::from_bytes(&b)?),
                tungstenite::Message::Close(_) => return Err(ChannelError::Closed),
                // Text frames are not part of this protocol. Ignoring them rather
                // than erroring keeps a proxy that injects keepalives from looking
                // like an attack.
                _ => continue,
            }
        }
    }

    /// Send raw bytes as one binary message.
    ///
    /// For [`crate::paced`], which puts a cover frame on the wire rather than a
    /// protocol frame: under cover traffic the unit of transmission is the slot,
    /// and the protocol frame rides inside it.
    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<(), ChannelError> {
        self.ws
            .send(tungstenite::Message::Binary(bytes.to_vec().into()))
            .map_err(|_| ChannelError::Closed)
    }

    /// Read one binary message as raw bytes.
    pub fn recv_raw(&mut self) -> Result<Vec<u8>, ChannelError> {
        loop {
            match self.ws.read().map_err(|_| ChannelError::Closed)? {
                tungstenite::Message::Binary(b) => return Ok(b.to_vec()),
                tungstenite::Message::Close(_) => return Err(ChannelError::Closed),
                _ => continue,
            }
        }
    }

    /// Write one frame.
    pub fn send(&mut self, f: &Frame) -> Result<(), ChannelError> {
        self.ws
            .send(tungstenite::Message::Binary(f.to_bytes().into()))
            .map_err(|_| ChannelError::Closed)
    }

    /// Answer one request with `reply`, preserving its `req_id`.
    pub fn reply<R: serde::Serialize + Operation>(
        &mut self,
        req_id: u32,
        reply: &R,
    ) -> Result<(), ChannelError> {
        self.send(&Frame::encode(req_id, reply)?)
    }

    /// Close politely.
    pub fn close(&mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}

/// Why a channel operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChannelError {
    /// The WebSocket handshake failed.
    Handshake,
    /// The connection is gone.
    Closed,
    /// A frame did not encode or decode.
    Wire(WireError),
}

impl From<WireError> for ChannelError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handshake => f.write_str("could not open the connection"),
            Self::Closed => f.write_str("the connection closed"),
            Self::Wire(e) => write!(f, "{e}"),
        }
    }
}
impl core::error::Error for ChannelError {}
