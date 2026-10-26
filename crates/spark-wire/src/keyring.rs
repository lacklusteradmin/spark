//! The keyring service's protocol. `docs/protocol.md` §6.1.
//!
//! The only service that knows an account-shaped identifier exists, which is why
//! every operation here except two carries [`Auth`].

use crate::{Auth, Operation};
use serde::{Deserialize, Serialize};

/// A request to the keyring service.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Req {
    /// The challenge this address must sign right now.
    Challenge {
        /// The keyring address.
        addr: [u8; 32],
    },
    /// Fetch the sealed snapshot.
    GetSnapshot(Auth),
    /// Fetch the deltas written after it.
    GetDeltas(Auth),
    /// Append a delta.
    PutDelta(Auth, Vec<u8>),
    /// Replace the snapshot.
    PutSnapshot(Auth, Vec<u8>, (Option<[u8; 32]>, u32), Vec<[u8; 32]>),
    /// Read quota.
    GetQuota(Auth),
    /// Exchange quota for blind signatures over already-blinded claims.
    WithdrawTokens {
        /// Who is paying.
        auth: Auth,
        /// One blinded message per token.
        blinded: Vec<Vec<u8>>,
        /// The size class each token authorises.
        size_class: u8,
    },
    /// Credit a refund voucher.
    CreditRefund(Auth, spark_crypto::TokenClaim, spark_crypto::Token),
    /// Leave a request using an opaque permit explicitly issued by the recipient.
    PutRequest {
        /// Where to leave it.
        addr: [u8; 32],
        /// The sealed request.
        blob: Vec<u8>,
        /// A recipient-issued 32-byte inbox permit.
        permit: Vec<u8>,
    },
    /// Read the tray.
    GetRequests(Auth),
    /// Discard one request, accepted or declined alike.
    DropRequest(Auth, u32),
    /// The token issuer's public key. Unauthenticated: it is public.
    GetIssuerKey(u8),
    /// Replace the bounded list of opaque contact authorization hashes.
    SetContacts(Auth, Vec<[u8; 32]>),
}

impl Operation for Req {
    fn op(&self) -> u8 {
        match self {
            Req::Challenge { .. } => 0,
            Req::GetSnapshot(_) => 1,
            Req::GetDeltas(_) => 2,
            Req::PutDelta(..) => 3,
            Req::PutSnapshot(..) => 4,
            Req::GetQuota(_) => 5,
            Req::WithdrawTokens { .. } => 6,
            Req::CreditRefund(..) => 7,
            Req::PutRequest { .. } => 8,
            Req::GetRequests(_) => 9,
            Req::DropRequest(..) => 10,
            Req::GetIssuerKey(_) => 11,
            Req::SetContacts(..) => 12,
        }
    }
}

/// A response from the keyring service.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Resp {
    /// The challenge to sign.
    Challenge([u8; 32]),
    /// A sealed snapshot, or nothing for a new account.
    Snapshot(Option<Vec<u8>>),
    /// Sealed deltas, in write order.
    Deltas(Vec<Vec<u8>>),
    /// A delta was appended.
    Appended {
        /// Its index.
        index: u32,
        /// Whether the client should now write a fresh snapshot.
        compact: bool,
    },
    /// A snapshot was written.
    SnapshotWritten,
    /// Current quota.
    Quota {
        /// Bytes held.
        used: u64,
        /// Bytes allowed.
        limit: u64,
    },
    /// Blind signatures, still blinded.
    Tokens(Vec<Vec<u8>>),
    /// The issuer's public key, DER-encoded.
    IssuerKey(Vec<u8>),
    /// A refund was credited.
    Credited,
    /// A request was accepted for delivery. Returned whether or not the tray was
    /// full and whether or not the address exists.
    RequestTaken,
    /// The tray, oldest first.
    Requests(Vec<(u32, Vec<u8>)>),
    /// A request was discarded.
    RequestDropped,
    /// Refused.
    Refused(Refusal),
}

impl Operation for Resp {
    fn op(&self) -> u8 {
        match self {
            Resp::Challenge(_) => 0,
            Resp::Snapshot(_) => 1,
            Resp::Deltas(_) => 2,
            Resp::Appended { .. } => 3,
            Resp::SnapshotWritten => 4,
            Resp::Quota { .. } => 5,
            Resp::Tokens(_) => 6,
            Resp::IssuerKey(_) => 7,
            Resp::Credited => 8,
            Resp::RequestTaken => 9,
            Resp::Requests(_) => 10,
            Resp::RequestDropped => 11,
            Resp::Refused(_) => 12,
        }
    }
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Refusal {
    /// The signature did not verify against the current challenge.
    BadAuth,
    /// The address is not the hash of the presented key.
    AddrMismatch,
    /// The bytes are not a well-formed chunk.
    Malformed,
    /// The withdrawal would exceed this key's quota.
    OverQuota,
    /// That refund voucher has already been credited.
    VoucherSpent,
}

impl Req {
    /// Mutable authentication proof, absent on public operations.
    pub fn auth_mut(&mut self) -> Option<&mut Auth> {
        match self {
            Self::GetSnapshot(a)
            | Self::GetDeltas(a)
            | Self::PutDelta(a, _)
            | Self::PutSnapshot(a, ..)
            | Self::GetQuota(a)
            | Self::WithdrawTokens { auth: a, .. }
            | Self::CreditRefund(a, ..)
            | Self::GetRequests(a)
            | Self::DropRequest(a, _)
            | Self::SetContacts(a, _) => Some(a),
            _ => None,
        }
    }
    /// Canonical request transcript, including operation, body, address, nonce and challenge.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut request = self.clone();
        if let Some(auth) = request.auth_mut() {
            auth.sig.clear();
        }
        let mut bytes = b"spark/v2/keyring-request".to_vec();
        bytes.extend(postcard::to_allocvec(&request).expect("wire request encoding"));
        bytes
    }
}
