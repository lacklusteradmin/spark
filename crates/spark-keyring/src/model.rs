//! What a keyring holds. `docs/protocol.md` §8.

use serde::{Deserialize, Serialize};
use spark_chunk::{ChunkName, Kind, LaneId, RoomRoot};

/// A room's local identifier. Client-side only; no server ever sees it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct RoomId(pub [u8; 16]);

/// An opaque receipt returned by the content store on upload.
///
/// Returning it releases the chunk and refunds quota. **These must survive
/// recovery**: a lost receipt strands a chunk forever (`Spark-spec.md` F7).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Receipt(pub [u8; 32]);

/// One generation of a room's archive.
///
/// The archive secret is the MLS exporter secret for an epoch, so it rotates on
/// every membership change. That is what makes removal remove read access: a
/// member who never reaches the next epoch cannot derive the next generation's
/// root, so later chunk names are not merely unreadable to them but uncomputable.
///
/// Every past generation must be kept. They cannot be re-derived after the fact —
/// that is MLS forward secrecy — so losing one loses that stretch of history
/// permanently, for its owner as much as for anyone else.
#[derive(Clone, Serialize, Deserialize)]
pub struct Generation {
    /// Authenticated identity roster for this archive generation.
    pub members: Vec<[u8; 32]>,
    /// The MLS epoch this generation corresponds to.
    pub epoch: u64,
    /// The archive secret every chunk name and key in this generation derives from.
    pub root: RoomRoot,
    /// The next sequence this account will *write* in its own lane.
    ///
    /// Persisted before anything is sealed at that slot (`docs/protocol.md` §3.2).
    /// This is the *only* cursor the keyring holds, and deliberately so.
    ///
    /// There is no read cursor here. One was tried and removed: the keyring is for
    /// what cannot be re-derived, and how far an account has read can always be
    /// re-derived by reading. Worse, persisting it breaks the thing the whole
    /// design is for — a restored client resumes from a cursor while holding none
    /// of the messages behind it, and never fetches them. Keeping it out also
    /// keeps the keyring smaller, which is the growth W4 correlates on.
    pub my_next: u64,
}

/// One room, as this account knows it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Room {
    /// Local identifier.
    pub id: RoomId,
    /// Every generation, oldest first. Reading history means walking all of them.
    pub generations: Vec<Generation>,
    /// Which MLS group this room is.
    ///
    /// The group *state* is one blob for the whole account (`Keyring::mls_state`),
    /// because that is how the MLS provider stores it. This is the handle that
    /// picks this room out of it.
    pub mls_group_id: Vec<u8>,
    /// What the user calls this room. Local only.
    pub display_name: String,
    /// This account's own message lane.
    pub my_lane: SerLane,
}

/// A [`LaneId`] in a form serde can carry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct SerLane(pub [u8; 16]);

impl From<LaneId> for SerLane {
    fn from(l: LaneId) -> Self {
        Self(*l.as_bytes())
    }
}
impl From<SerLane> for LaneId {
    fn from(s: SerLane) -> Self {
        LaneId::from_bytes(s.0)
    }
}

/// A [`ChunkName`] in a form serde can carry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct SerName(pub [u8; 32]);

impl From<ChunkName> for SerName {
    fn from(n: ChunkName) -> Self {
        Self(*n.as_bytes())
    }
}
impl From<SerName> for ChunkName {
    fn from(s: SerName) -> Self {
        ChunkName::new(s.0)
    }
}

/// Which store a receipt belongs to. Media and room chunks are freed by different
/// mechanisms and must not be confused (`Spark-build-notes.md` §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ChunkClass {
    /// Freed when its receipt count reaches zero.
    Media,
    /// Freed by outright deletion at dissolve.
    RoomLog,
}

impl From<ChunkClass> for Kind {
    fn from(c: ChunkClass) -> Self {
        match c {
            ChunkClass::Media => Kind::Media,
            ChunkClass::RoomLog => Kind::RoomLog,
        }
    }
}

/// One thing this account uploaded and still holds quota against.
#[derive(Clone, Serialize, Deserialize)]
pub struct Upload {
    /// Where it lives.
    pub name: SerName,
    /// The receipt that releases it.
    pub receipt: Receipt,
    /// Bytes charged. Uploads are charged in full even when the chunk already
    /// existed: a discount would let anyone probe what Spark holds.
    pub size: u64,
    /// Which free mechanism applies.
    pub class: ChunkClass,
    /// The room it was shared into, if this account can still see that room.
    ///
    /// `None` means "unknown", never "unused". The client shows it as unknown and
    /// **does not** offer to clean it up: "no room references this" is
    /// indistinguishable from "a room references this but I left it".
    pub room: Option<RoomId>,
}

/// A name this account holds.
#[derive(Clone, Serialize, Deserialize)]
pub struct HeldName {
    /// The name itself.
    pub name: String,
    /// Days since the epoch, after which the 10-day grace period starts.
    pub paid_until_day: u32,
}

/// A user-approved contact. Keys and permits stay inside the encrypted keyring.
#[derive(Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Local display name.
    pub name: String,
    /// Authenticated signing identity.
    pub sign: [u8; 32],
    /// Recipient encryption key.
    pub kem: [u8; 32],
    /// Secret allowing this contact to write to our inbox.
    pub receive_permit: [u8; 32],
    /// Secret this contact gave us for their inbox.
    pub send_permit: Option<[u8; 32]>,
}

/// Durable refund state; all fields live only in the encrypted keyring.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingRefund {
    /// Original upload receipt.
    pub receipt: Receipt,
    /// Blind refund claim.
    pub claim: spark_crypto::TokenClaim,
    /// Verification key pinned at operation creation.
    pub issuer: Vec<u8>,
    /// Secret unblinding state for this exact operation.
    pub blinding: spark_crypto::blind::SavedBlinding,
}

/// One upload journaled before withdrawing quota or writing content.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingUpload {
    /// Chunk destination.
    pub name: SerName,
    /// Exact ciphertext to resend.
    pub chunk: Vec<u8>,
    /// Routing class.
    pub class: ChunkClass,
    /// Local room reference.
    pub room: Option<RoomId>,
    /// Token claim, hidden from the keyring server by blinding.
    pub claim: spark_crypto::TokenClaim,
    /// Pinned denomination key.
    pub issuer: Vec<u8>,
    /// Secret recovery state, inside the encrypted keyring only.
    pub blinding: spark_crypto::blind::SavedBlinding,
}
