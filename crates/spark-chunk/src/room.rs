//! Room log chunks: keyed naming, derived nonces, append-only.
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
/// Domain separator for room chunk nonces.
pub const NONCE_INFO: &[u8] = b"spark/v1/room/nonce";

/// A room's long-lived secret.
///
/// **Not** an MLS exporter secret. Exporter secrets rotate every epoch, and
/// history has to stay addressable across every epoch the room has ever had. This
/// value is generated once at room creation, distributed inside MLS, and
/// re-shared to joiners — the one mechanism `Spark-spec.md` F4 flags as sitting
/// outside MLS's guarantees, deliberately confined to this single value.
pub type RoomRoot = Secret<32>;

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

/// The name a slot's chunk is stored under.
///
/// Computable by anyone holding `root` — which is how a member finds the next
/// message without the server telling them anything (`docs/protocol.md` §5.2).
pub fn name(root: &RoomRoot, slot: Slot) -> ChunkName {
    ChunkName::new(hmac_sha256_parts(root, &[NAME_INFO, &slot.suffix()]))
}

fn schedule(root: &RoomRoot, slot: Slot) -> (Secret<32>, Nonce) {
    let s = slot.suffix();
    let mut key_info = KEY_INFO.to_vec();
    key_info.extend_from_slice(&s);
    let mut nonce_info = NONCE_INFO.to_vec();
    nonce_info.extend_from_slice(&s);
    (
        expand::<32>(root, &key_info),
        *expand::<24>(root, &nonce_info).expose(),
    )
}

/// Seal one entry of a room's log.
///
/// The nonce is derived from `(lane, seq)`, which is safe **only** because each
/// slot is written once. Two rules enforce that, and neither lives here:
///
/// * the content store is write-once per name, so no stored chunk is ever
///   overwritten under a reused nonce;
/// * the client must durably record "seq N consumed" *before* calling this.
///   Encrypt-then-record loses to a crash between the two.
pub fn seal(root: &RoomRoot, slot: Slot, plaintext: &[u8]) -> (ChunkName, Chunk) {
    let (key, nonce) = schedule(root, slot);
    (
        name(root, slot),
        Chunk::seal(Kind::RoomLog, &key, &nonce, plaintext),
    )
}

/// Open one entry of a room's log.
pub fn open(root: &RoomRoot, slot: Slot, chunk: &Chunk) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
    let (key, _) = schedule(root, slot);
    chunk.open(&key)
}
