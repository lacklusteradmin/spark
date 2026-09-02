//! The wire format. `docs/protocol.md` §6.
//!
//! layer 2, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. The format is a pure
//! function of its arguments, so every property below is checkable without a
//! socket, which is the point of separating it from the transport that carries it.
//!
//! ```text
//! frame := req_id: u32le || opcode: u8 || payload
//! ```
//!
//! `req_id` correlates responses on one connection and is never persisted.
//! `opcode` identifies the operation, so a server can reject one it does not know
//! before decoding anything an attacker chose. The payload is the postcard
//! encoding of the request or response itself.
//!
//! The opcode duplicates postcard's own variant tag, which is deliberate rather
//! than an oversight: dispatching before deserializing is worth a byte, and a
//! test asserts the two never disagree, so the duplication cannot rot.
//!
//! # Why these types are not the servers' types
//!
//! A server's `Request` is its implementation. This is the protocol. Keeping them
//! apart means each server writes its own conversion, and a change to either side
//! shows up as a change to that conversion rather than silently becoming the new
//! protocol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod content;
pub mod issuer;
pub mod keyring;

use serde::{Serialize, de::DeserializeOwned};

/// The largest frame that will be encoded or accepted.
///
/// A media chunk is a whole file, so this is generous. It exists to bound what a
/// peer can make a server allocate, which is the only reason a limit is here at
/// all — `Spark-spec.md` F7 caps an *account* at 128 MB, and that is enforced by
/// quota, not by framing.
pub const MAX_FRAME: usize = 16 << 20;

/// Bytes before the payload: `req_id` and `opcode`.
pub const HEADER: usize = 5;

/// One message on the wire.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    /// Correlates a response with its request. Never persisted by anyone.
    pub req_id: u32,
    /// Which operation.
    pub op: u8,
    /// The postcard-encoded body.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Build a frame around an encodable body.
    pub fn encode<T: Serialize + Operation>(req_id: u32, body: &T) -> Result<Self, WireError> {
        let payload = postcard::to_allocvec(body).map_err(|_| WireError::Encode)?;
        if HEADER + payload.len() > MAX_FRAME {
            return Err(WireError::TooLarge);
        }
        Ok(Self {
            req_id,
            op: body.op(),
            payload,
        })
    }

    /// The bytes to put on the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER + self.payload.len());
        v.extend_from_slice(&self.req_id.to_le_bytes());
        v.push(self.op);
        v.extend_from_slice(&self.payload);
        v
    }

    /// Parse a frame received from a peer.
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        if b.len() < HEADER {
            return Err(WireError::Truncated);
        }
        if b.len() > MAX_FRAME {
            return Err(WireError::TooLarge);
        }
        Ok(Self {
            req_id: u32::from_le_bytes(b[..4].try_into().expect("4 bytes")),
            op: b[4],
            payload: b[HEADER..].to_vec(),
        })
    }

    /// Decode the body.
    ///
    /// Checks that the opcode agrees with what the payload actually decoded to. A
    /// frame whose header advertises one operation and whose body is another is
    /// rejected rather than silently trusted — the header is what a server
    /// dispatched on.
    pub fn body<T: DeserializeOwned + Operation>(&self) -> Result<T, WireError> {
        let v: T = postcard::from_bytes(&self.payload).map_err(|_| WireError::Malformed)?;
        if v.op() != self.op {
            return Err(WireError::OpcodeMismatch);
        }
        Ok(v)
    }
}

/// A wire type that knows its own opcode.
pub trait Operation {
    /// The opcode identifying this operation.
    fn op(&self) -> u8;
}

/// Why a frame would not encode or decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// Shorter than a header.
    Truncated,
    /// Larger than [`MAX_FRAME`].
    TooLarge,
    /// The payload is not what the opcode says it is.
    Malformed,
    /// The header's opcode and the decoded body disagree.
    OpcodeMismatch,
    /// The body could not be encoded.
    Encode,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("frame is shorter than its header"),
            Self::TooLarge => f.write_str("frame is too large"),
            Self::Malformed => f.write_str("frame body did not decode"),
            Self::OpcodeMismatch => f.write_str("frame opcode does not match its body"),
            Self::Encode => f.write_str("could not encode frame body"),
        }
    }
}
impl core::error::Error for WireError {}

/// Proof that the caller holds the key behind an address.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Auth {
    /// The keyring address.
    pub addr: [u8; 32],
    /// The public key it was derived from.
    pub key: [u8; 32],
    /// A signature over the current challenge. A `Vec` because serde stops
    /// deriving arrays at 32; the length is checked where it is used.
    pub sig: Vec<u8>,
}
