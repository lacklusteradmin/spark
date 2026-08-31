//! Lanes: the split that lets a room be append-only *and* have a total order.
//!
//! `docs/protocol.md` §4. `Spark-spec.md` F7 says simultaneous senders never
//! collide; F4 says simultaneous dismissals are ordered by the server. Both are
//! true, of different lanes.

use spark_crypto::{VerifyingKey, sha256_parts};

/// Lane identifier length in bytes.
pub const LANE_LEN: usize = 16;

/// Which lane of a room's namespace a chunk belongs to.
///
/// A `LaneId` is never sent to a server. It appears only inside an HMAC keyed by
/// the secret room root, so the names it produces are indistinguishable from
/// random.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LaneId([u8; LANE_LEN]);

/// Domain separator for message lane derivation.
pub const LANE_PREFIX: &[u8] = b"spark/v1/lane";

impl LaneId {
    /// The single commit lane. Totally ordered, arbitrated by the store's
    /// write-once rule; carries MLS handshake messages only.
    pub const COMMIT: LaneId = LaneId([0u8; LANE_LEN]);

    /// One member's message lane.
    ///
    /// Keyed by identity public key rather than MLS leaf index. Leaf indices are
    /// recycled when members leave, so two different members could occupy leaf 3
    /// in different epochs and collide on one lane.
    pub fn message(sign_pub: &VerifyingKey) -> Self {
        let h = sha256_parts(&[LANE_PREFIX, sign_pub.as_bytes()]);
        let mut id = [0u8; LANE_LEN];
        id[0] = 1;
        id[1..].copy_from_slice(&h[..LANE_LEN - 1]);
        Self(id)
    }

    /// Whether this is the commit lane.
    pub fn is_commit(&self) -> bool {
        *self == Self::COMMIT
    }

    /// The raw bytes, as fed to the name and key derivations.
    pub fn as_bytes(&self) -> &[u8; LANE_LEN] {
        &self.0
    }

    /// Wrap raw bytes.
    pub fn from_bytes(b: [u8; LANE_LEN]) -> Self {
        Self(b)
    }
}
