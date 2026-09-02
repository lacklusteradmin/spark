//! Append-only changes to a keyring.
//!
//! An ordinary write appends one sealed delta rather than rewriting the whole
//! keyring, which keeps a routine change small on a blob that only grows.

use crate::model::{HeldName, Room, RoomId, SerName, Upload};
use crate::{Keyring, KeyringError};
use serde::{Deserialize, Serialize};
use spark_chunk::{Chunk, Kind};
use spark_crypto::{Nonce, Secret};

/// One change to a keyring.
///
/// Every variant is idempotent under replay: a delta applied twice leaves the
/// same state. Deltas are fetched from a server that may return them more than
/// once, and there is no transaction to roll back to.
#[derive(Clone, Serialize, Deserialize)]
pub enum Delta {
    /// Join or replace a room.
    UpsertRoom(Room),
    /// Leave a room. Its chunks are handled separately; this only forgets the key.
    ForgetRoom(RoomId),
    /// Start a new generation, because membership changed.
    ///
    /// Kept as its own delta rather than folded into `UpsertRoom`: losing a past
    /// generation loses that stretch of history permanently, so adding one must
    /// never be able to overwrite the ones before it.
    OpenGeneration {
        /// Which room.
        room: RoomId,
        /// The generation.
        generation: crate::Generation,
    },
    /// Record the MLS provider's serialized storage, for the whole account.
    ///
    /// Opaque bytes; this crate does not interpret MLS.
    SetMlsState(Vec<u8>),
    /// Claim the next slot in this account's own lane, before sealing anything
    /// into it.
    ///
    /// Separate from `AdvanceHead` because they are different cursors: this one
    /// says "I am about to write here", the other says "I have read this far".
    ReserveSlot {
        /// Which room.
        room: RoomId,
        /// Which generation.
        epoch: u64,
        /// The slot being claimed. Applied as a maximum, so a replayed delta
        /// cannot hand the slot back out.
        seq: u64,
    },
    /// Record an upload and the receipt that releases it.
    AddUpload(Upload),
    /// Release an upload, refunding quota.
    ReleaseUpload(SerName),
    /// Store unspent blind tokens.
    AddTokens(Vec<Vec<u8>>),
    /// Spend one token.
    SpendToken(Vec<u8>),
    /// Record or renew a held name.
    UpsertName(HeldName),
    /// Drop a lapsed name. Quota stays with the key that paid.
    DropName(String),
    /// A contact request arrived.
    AddPending(String),
    /// A contact request was accepted or declined.
    RemovePending(String),
}

impl Delta {
    /// Seal one delta.
    pub fn seal(&self, key: &Secret<32>, nonce: &Nonce) -> Chunk {
        let mut body = vec![crate::TAG_DELTA];
        body.extend_from_slice(
            &postcard::to_allocvec(self).expect("delta is a plain serializable enum"),
        );
        Chunk::seal(Kind::Keyring, key, nonce, &body)
    }

    /// Open one delta.
    pub fn open(chunk: &Chunk, key: &Secret<32>) -> Result<Self, KeyringError> {
        if chunk.kind()? != Kind::Keyring {
            return Err(KeyringError::WrongKind);
        }
        let plain = chunk.open(key)?;
        let (tag, body) = plain.split_first().ok_or(KeyringError::Malformed)?;
        if *tag != crate::TAG_DELTA {
            return Err(KeyringError::WrongKind);
        }
        postcard::from_bytes(body).map_err(|_| KeyringError::Malformed)
    }

    pub(crate) fn apply_to(&self, k: &mut Keyring) {
        match self {
            Delta::UpsertRoom(r) => {
                k.rooms.retain(|x| x.id != r.id);
                k.rooms.push(r.clone());
            }
            Delta::ForgetRoom(id) => k.rooms.retain(|r| r.id != *id),
            Delta::OpenGeneration { room, generation } => {
                if let Some(r) = k.rooms.iter_mut().find(|r| r.id == *room) {
                    // Idempotent, and never destructive: a replayed delta must not
                    // drop the generation already recorded for that epoch.
                    if !r.generations.iter().any(|g| g.epoch == generation.epoch) {
                        r.generations.push(generation.clone());
                        r.generations.sort_by_key(|g| g.epoch);
                    }
                }
            }
            Delta::ReserveSlot { room, epoch, seq } => {
                if let Some(r) = k.rooms.iter_mut().find(|r| r.id == *room)
                    && let Some(g) = r.generations.iter_mut().find(|g| g.epoch == *epoch)
                {
                    // A maximum: a replayed delta must not hand a claimed slot
                    // back out, which would be a reused nonce.
                    g.my_next = g.my_next.max(*seq + 1);
                }
            }
            Delta::SetMlsState(state) => k.mls_state = Some(state.clone()),
            Delta::AddUpload(u) => {
                k.uploads.retain(|x| x.name != u.name);
                k.uploads.push(u.clone());
            }
            Delta::ReleaseUpload(n) => k.uploads.retain(|u| u.name != *n),
            Delta::AddTokens(t) => {
                for tok in t {
                    if !k.tokens.contains(tok) {
                        k.tokens.push(tok.clone());
                    }
                }
            }
            Delta::SpendToken(t) => k.tokens.retain(|x| x != t),
            Delta::UpsertName(n) => {
                k.names.retain(|x| x.name != n.name);
                k.names.push(n.clone());
            }
            Delta::DropName(n) => k.names.retain(|x| x.name != *n),
            Delta::AddPending(p) => {
                if !k.pending.contains(p) {
                    k.pending.push(p.clone());
                }
            }
            Delta::RemovePending(p) => k.pending.retain(|x| x != p),
        }
    }
}

/// Ergonomics for the common `SerName` conversion at call sites.
impl From<&Upload> for SerName {
    fn from(u: &Upload) -> Self {
        u.name
    }
}
