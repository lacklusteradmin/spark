//! Room log chunks: keyed naming, random nonces, append-only.
//!
//! `docs/protocol.md` §3.2. Content-derived names would let an outsider compute
//! the name of a guessed sentence and test whether it exists — files are hard to
//! guess, sentences are not (`Spark-spec.md` F7). So room chunk names are an HMAC
//! under a room secret, which the store cannot verify and an outsider cannot
//! compute.

use crate::chunk::{Chunk, ChunkError};
use crate::header::Kind;
use crate::lane::LaneId;
use crate::name::ChunkName;
use spark_crypto::{Nonce, Secret, expand, hmac_sha256_parts};
use zeroize::Zeroizing;

/// Domain separator for room chunk names.
pub const NAME_INFO: &[u8] = b"spark/v1/room/name";
/// Domain separator for room chunk keys.
pub const KEY_INFO: &[u8] = b"spark/v1/room/key";

/// The MLS exporter secret for one archived room generation.
/// Past generation secrets are retained in the encrypted keyring for recovery.
pub type RoomRoot = Secret<32>;

/// Signature context bound to the canonical MLS group ID and generation secret.
/// Including the group ID prevents a shared historical root being transplanted
/// into an unrelated group's invitation and used to replay its signed messages.
pub fn signature_context(group_id: &[u8], root: &RoomRoot) -> [u8; 32] {
    spark_crypto::sha256_parts(&[b"spark/v1/archive-context", group_id, root.expose()])
}

/// A position in a room's log.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Slot {
    /// Which lane.
    pub lane: LaneId,
    /// Position within that lane, from zero.
    pub seq: u64,
}

impl Slot {
    /// A slot.
    pub fn new(lane: LaneId, seq: u64) -> Self {
        Self { lane, seq }
    }
    /// The next slot in the same lane.
    pub fn next(self) -> Self {
        Self {
            lane: self.lane,
            seq: self.seq + 1,
        }
    }
    fn suffix(&self) -> [u8; 24] {
        let mut s = [0u8; 24];
        s[..16].copy_from_slice(self.lane.as_bytes());
        s[16..].copy_from_slice(&self.seq.to_be_bytes());
        s
    }
}

/// The slot's keyed address, with its high bit set for the room namespace.
///
/// Computable by anyone holding `root` — which is how a member finds the next
/// message without the server telling them anything (`docs/protocol.md` §5.2).
pub fn name(root: &RoomRoot, slot: Slot) -> ChunkName {
    let mut name = hmac_sha256_parts(root, &[NAME_INFO, &slot.suffix()]);
    name[0] |= 0x80;
    ChunkName::new(name)
}

fn schedule(root: &RoomRoot, slot: Slot) -> Secret<32> {
    let s = slot.suffix();
    let mut key_info = KEY_INFO.to_vec();
    key_info.extend_from_slice(&s);
    expand::<32>(root, &key_info)
}

/// Seal a log entry using a fresh random nonce supplied by the caller.
/// Slot collisions and restored cursors must never reuse an AEAD nonce.
pub fn seal(root: &RoomRoot, slot: Slot, nonce: &Nonce, plaintext: &[u8]) -> (ChunkName, Chunk) {
    let key = schedule(root, slot);
    (
        name(root, slot),
        Chunk::seal(Kind::RoomLog, &key, nonce, plaintext),
    )
}

/// Open one entry of a room's log.
pub fn open(root: &RoomRoot, slot: Slot, chunk: &Chunk) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
    let key = schedule(root, slot);
    chunk.open(&key)
}
