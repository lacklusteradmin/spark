//! room keys, chunk list, receipts, upload list.
//!
//! layer 2, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence.
//!
//! The keyring is the outer layer of the envelope (`Spark-spec.md` F2). Read it
//! as a chain, because that chain is the whole recovery story:
//!
//! ```text
//! mnemonic ──HKDF──▶ keyring_key ──▶ [sealed keyring blob at addr]
//!                                          │
//!                                          ├─▶ room_root ──▶ room chunk keys ──▶ history
//!                                          └─▶ receipts, uploads, tokens, names
//! ```
//!
//! The server holds both ciphertext layers and can open neither. Nothing else
//! contributes: there is no device key and no escrow share, which is exactly why
//! losing the seed loses everything.
//!
//! **Storage is by `addr`, not by chunk name.** The keyring is the one object
//! whose location is derived from an identity, which is why it lives on a
//! different service from the account-free content store.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod delta;
pub mod model;

pub use delta::Delta;
pub use model::{ChunkClass, HeldName, Receipt, Room, RoomId, SerLane, SerName, Upload};

use serde::{Deserialize, Serialize};
use spark_chunk::{Chunk, ChunkError, Kind, LaneId};
use spark_crypto::{Nonce, Secret};

/// The keyring format version.
pub const VERSION: u16 = 1;

/// Plaintext tag marking a sealed snapshot.
///
/// Snapshots and deltas are both `Kind::Keyring` chunks, and postcard is not
/// self-describing — without a tag, a delta's bytes could decode as a keyring and
/// produce silent garbage rather than an error.
pub const TAG_SNAPSHOT: u8 = 1;
/// Plaintext tag marking a sealed delta.
pub const TAG_DELTA: u8 = 2;

/// Deltas allowed to accumulate before the client writes a fresh snapshot.
///
/// Keeps an ordinary write small — appending one delta rather than rewriting the
/// whole keyring. The count is visible to the server, which is listed as open
/// question §9.4 in the protocol.
pub const COMPACT_AFTER: usize = 64;

/// Everything an account knows that is not derivable from the seed.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Keyring {
    /// Format version, checked on open.
    pub version: u16,
    /// Rooms this account is in.
    pub rooms: Vec<Room>,
    /// Everything uploaded and still charged against quota.
    pub uploads: Vec<Upload>,
    /// Unspent blind storage tokens.
    pub tokens: Vec<Vec<u8>>,
    /// Names held, with their paid-until dates.
    pub names: Vec<HeldName>,
    /// Contact requests awaiting a decision.
    pub pending: Vec<String>,
}

impl Keyring {
    /// An empty keyring for a brand-new account.
    pub fn new() -> Self {
        Self {
            version: VERSION,
            ..Default::default()
        }
    }

    /// Look a room up.
    pub fn room(&self, id: RoomId) -> Option<&Room> {
        self.rooms.iter().find(|r| r.id == id)
    }

    /// The highest sequence seen in one lane of a room, if any.
    pub fn head(&self, id: RoomId, lane: LaneId) -> Option<u64> {
        let l = SerLane::from(lane);
        self.room(id)?
            .heads
            .iter()
            .find(|(k, _)| *k == l)
            .map(|(_, s)| *s)
    }

    /// Total bytes this account currently holds, which is what quota measures.
    ///
    /// Viewing and receiving are free, so nobody can drain an allowance by
    /// posting a large video (`Spark-spec.md` F7).
    pub fn bytes_held(&self) -> u64 {
        self.uploads.iter().map(|u| u.size).sum()
    }

    /// Apply one change.
    pub fn apply(&mut self, d: &Delta) {
        d.apply_to(self);
    }

    /// Encode, tagged, without sealing.
    fn encode(&self) -> Vec<u8> {
        let mut v = vec![TAG_SNAPSHOT];
        v.extend_from_slice(
            &postcard::to_allocvec(self).expect("keyring is a plain serializable struct"),
        );
        v
    }

    /// Seal the whole keyring as a snapshot chunk.
    ///
    /// The nonce is a parameter and must be fresh: the keyring is mutable, so
    /// unlike room chunks it cannot derive one (`docs/protocol.md` §3.3).
    pub fn seal_snapshot(&self, key: &Secret<32>, nonce: &Nonce) -> Chunk {
        Chunk::seal(Kind::Keyring, key, nonce, &self.encode())
    }

    /// Open a snapshot chunk.
    pub fn open_snapshot(chunk: &Chunk, key: &Secret<32>) -> Result<Self, KeyringError> {
        if chunk.kind()? != Kind::Keyring {
            return Err(KeyringError::WrongKind);
        }
        let plain = chunk.open(key)?;
        let (tag, body) = plain.split_first().ok_or(KeyringError::Malformed)?;
        if *tag != TAG_SNAPSHOT {
            return Err(KeyringError::WrongKind);
        }
        let k: Keyring = postcard::from_bytes(body).map_err(|_| KeyringError::Malformed)?;
        if k.version != VERSION {
            return Err(KeyringError::UnknownVersion(k.version));
        }
        Ok(k)
    }

    /// Restore from a snapshot plus the deltas written after it.
    ///
    /// This is the recovery path in one function: everything after the seed.
    pub fn restore(
        snapshot: &Chunk,
        deltas: &[Chunk],
        key: &Secret<32>,
    ) -> Result<Self, KeyringError> {
        let mut k = Self::open_snapshot(snapshot, key)?;
        for c in deltas {
            k.apply(&Delta::open(c, key)?);
        }
        Ok(k)
    }
}

impl core::fmt::Debug for Keyring {
    /// Shape only, never contents. A keyring holds every room root this account
    /// has; a derived `Debug` would print all of them into whatever log called it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("version", &self.version)
            .field("rooms", &self.rooms.len())
            .field("uploads", &self.uploads.len())
            .field("tokens", &self.tokens.len())
            .field("names", &self.names.len())
            .field("pending", &self.pending.len())
            .field("bytes_held", &self.bytes_held())
            .finish_non_exhaustive()
    }
}

/// Why a keyring operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyringError {
    /// The chunk did not authenticate, or its header would not parse.
    Chunk(ChunkError),
    /// A chunk of the wrong kind was passed where a keyring was expected.
    WrongKind,
    /// Decrypted, but the bytes are not a keyring.
    Malformed,
    /// A keyring format this build does not know.
    UnknownVersion(u16),
}

impl From<ChunkError> for KeyringError {
    fn from(e: ChunkError) -> Self {
        Self::Chunk(e)
    }
}

impl core::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Chunk(e) => write!(f, "{e}"),
            Self::WrongKind => f.write_str("not a keyring chunk"),
            Self::Malformed => f.write_str("keyring did not decode"),
            Self::UnknownVersion(v) => write!(f, "unknown keyring version {v}"),
        }
    }
}
impl core::error::Error for KeyringError {}
