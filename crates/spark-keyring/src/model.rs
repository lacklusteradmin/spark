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
    /// The MLS epoch this generation corresponds to.
    pub epoch: u64,
    /// The archive secret every chunk name and key in this generation derives from.
    pub root: RoomRoot,
    /// The highest sequence seen in each lane, as `(lane, seq)` sorted by lane.
    pub heads: Vec<(SerLane, u64)>,
}

/// One room, as this account knows it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Room {
    /// Local identifier.
    pub id: RoomId,
    /// Every generation, oldest first. Reading history means walking all of them.
    pub generations: Vec<Generation>,
    /// The serialized MLS group state, so a restored client can rejoin the live
    /// conversation rather than only read the archive.
    pub mls_state: Option<Vec<u8>>,
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
