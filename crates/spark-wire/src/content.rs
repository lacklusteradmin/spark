//! The content service's protocol. `docs/protocol.md` §6.2.
//!
//! **No operation here carries an identity.** Writes carry a blind token; reads
//! carry nothing at all. That is visible from the shape of these types, which is
//! the fastest way to check the claim.

use crate::Operation;
use serde::{Deserialize, Serialize};
use spark_crypto::{Token, TokenClaim};

/// A request to the content service.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Req {
    /// Store a chunk, authorised by a blind token.
    Put {
        /// The claimed name.
        name: [u8; 32],
        /// The sealed chunk.
        chunk: Vec<u8>,
        /// What the token authorises.
        claim: TokenClaim,
        /// The issuer's signature over that claim.
        token: Token,
    },
    /// Fetch a chunk.
    Get {
        /// The name, which with the key is the whole capability.
        name: [u8; 32],
    },
    /// Ask whether a name exists.
    Head {
        /// The name.
        name: [u8; 32],
    },
    /// Return a receipt.
    Release {
        /// The chunk.
        name: [u8; 32],
        /// The receipt issued at upload.
        receipt: [u8; 32],
        /// Refund denomination, checked against the original receipt.
        size_class: u8,
        /// Client-blinded refund claim; the store cannot recognize the redeemed serial.
        blinded: Vec<u8>,
    },
    /// Delete a room chunk outright, at dissolve.
    Delete {
        /// The chunk.
        name: [u8; 32],
        /// Independent write capability, never derivable from the room read key.
        receipt: [u8; 32],
    },
    /// Obtain the public refund key for a denomination.
    GetRefundKey(u8),
}

impl Operation for Req {
    fn op(&self) -> u8 {
        match self {
            Req::Put { .. } => 0,
            Req::Get { .. } => 1,
            Req::Head { .. } => 2,
            Req::Release { .. } => 3,
            Req::Delete { .. } => 4,
            Req::GetRefundKey(_) => 5,
        }
    }
}

/// A response from the content service.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Resp {
    /// Stored.
    Stored {
        /// Opaque, random, and held only by the uploader.
        receipt: [u8; 32],
    },
    /// The chunk bytes.
    Chunk(Vec<u8>),
    /// Whether a name exists.
    Exists(bool),
    /// Released.
    Released {
        /// Whether the bytes were freed.
        freed: bool,
        /// A blinded refund voucher.
        voucher: Vec<u8>,
    },
    /// Deleted.
    Deleted,
    /// Refused.
    Refused(Refusal),
    /// DER-encoded public refund key.
    RefundKey(Vec<u8>),
}

impl Operation for Resp {
    fn op(&self) -> u8 {
        match self {
            Resp::Stored { .. } => 0,
            Resp::Chunk(_) => 1,
            Resp::Exists(_) => 2,
            Resp::Released { .. } => 3,
            Resp::Deleted => 4,
            Resp::Refused(_) => 5,
            Resp::RefundKey(_) => 6,
        }
    }
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Refusal {
    /// A chunk already exists under that name. Write-once.
    NameTaken,
    /// The claimed name does not match the chunk.
    NameMismatch,
    /// The bytes are not a well-formed chunk.
    Malformed,
    /// That token serial has already been spent.
    TokenSpent,
    /// The token does not verify under the issuer's key.
    BadToken,
    /// The chunk is larger than the token's size class allows.
    TooLarge,
    /// No such name.
    NotFound,
    /// The receipt does not match any holder of that chunk.
    BadReceipt,
    /// Media is freed by receipt count, not by deletion.
    NotDeletable,
}
