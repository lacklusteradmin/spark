//! The issuer's protocol. `docs/protocol.md` §6.3.
//!
//! **There is no listing operation, and there must not be one.** `Spark-spec.md`
//! F5: names resolve but are not browsable. Enumeration is prevented by the shape
//! of this enum, not by a filter on an endpoint someone could later relax.

use crate::Operation;
use serde::{Deserialize, Serialize};
use spark_crypto::{Token, VoucherClaim};

/// A request to the issuer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Req {
    /// Resolve one exact name.
    Resolve {
        /// The exact name. No prefix, no pattern.
        name: String,
        /// Non-authoritative date hint; the server uses its own clock.
        today: u32,
    },
    /// Buy a voucher against a settled payment.
    Purchase {
        /// The blinded voucher claim.
        blinded: Vec<u8>,
        /// A reference to a settled payment.
        payment: Vec<u8>,
        /// What the buyer says they paid.
        amount: u64,
    },
    /// Register a name.
    Register {
        /// The exact name.
        name: String,
        /// The holder's public identity: signing key then KEM key.
        key: Vec<u8>,
        /// The unblinded voucher claim.
        claim: VoucherClaim,
        /// Its signature.
        voucher: Token,
        /// Non-authoritative date hint; ignored for expiry.
        today: u32,
    },
    /// Renew a name.
    Renew {
        /// The name.
        name: String,
        /// The voucher claim.
        claim: VoucherClaim,
        /// Its signature.
        voucher: Token,
        /// Non-authoritative date hint; ignored for expiry.
        today: u32,
    },
    /// Move a name to a key the current holder signs for.
    Transfer {
        /// The name.
        name: String,
        /// The new holder's public identity.
        new_key: Vec<u8>,
        /// The current holder's signature.
        sig: Vec<u8>,
    },
    /// The voucher-signing public key for a provisioned price.
    GetIssuerKey(u64),
    /// Read the current transfer challenge.
    TransferChallenge(String),
}

impl Operation for Req {
    fn op(&self) -> u8 {
        match self {
            Req::TransferChallenge(_) => 6,
            Req::Resolve { .. } => 0,
            Req::Purchase { .. } => 1,
            Req::Register { .. } => 2,
            Req::Renew { .. } => 3,
            Req::Transfer { .. } => 4,
            Req::GetIssuerKey(_) => 5,
        }
    }
}

/// A response from the issuer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Resp {
    /// The public identity holding a name, or nothing.
    ///
    /// A miss and a hit are the same shape: anything that made them
    /// distinguishable would be a probe oracle.
    Resolved(Option<Vec<u8>>),
    /// A blind signature over a voucher claim.
    Signed(Vec<u8>),
    /// Registered.
    Registered,
    /// Renewed, through the given day.
    Renewed(u32),
    /// Transferred. The old key appears nowhere afterwards.
    Transferred,
    /// The voucher-signing public key.
    IssuerKey(Vec<u8>),
    /// Refused.
    Refused(Refusal),
    /// Current transfer challenge, if the name exists.
    TransferChallenge(Option<[u8; 32]>),
}

impl Operation for Resp {
    fn op(&self) -> u8 {
        match self {
            Resp::TransferChallenge(_) => 7,
            Resp::Resolved(_) => 0,
            Resp::Signed(_) => 1,
            Resp::Registered => 2,
            Resp::Renewed(_) => 3,
            Resp::Transferred => 4,
            Resp::IssuerKey(_) => 5,
            Resp::Refused(_) => 6,
        }
    }
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Refusal {
    /// The name is held by someone else.
    Taken,
    /// No such name.
    Unknown,
    /// The signature does not verify under the current holder's key.
    BadSignature,
    /// That voucher has already been spent.
    VoucherSpent,
    /// The voucher does not verify.
    BadVoucher,
    /// The voucher does not buy what is being asked for.
    WrongGrant,
    /// That payment has already been exchanged.
    PaymentSpent,
    /// The amount does not match the price table.
    Underpaid,
    /// The name is not in the sellable format.
    BadName,
}
