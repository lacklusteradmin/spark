//! Vector clocks. `docs/protocol.md` §5.
//!
//! Signed causal observations used for ordering. A peer's claimed sequence is
//! never a trusted allocation size or an unbounded discovery target.

use serde::{Deserialize, Serialize};
use spark_chunk::LaneId;
use std::collections::BTreeMap;

/// The heads a writer had seen, per lane.
///
/// `BTreeMap`, not `HashMap`: the encoding has to be canonical, because it goes
/// inside a chunk that other clients compare against their own.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Clock(BTreeMap<[u8; 16], u64>);

impl Clock {
    /// An empty clock: nothing seen.
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest sequence seen in a lane, or `None` if the lane is unknown.
    ///
    /// `None` and `Some(0)` are different: sequence numbers start at zero, so a
    /// lane whose first chunk has been seen is not the same as one never heard of.
    pub fn get(&self, lane: LaneId) -> Option<u64> {
        self.0.get(lane.as_bytes()).copied()
    }

    /// Record having seen a lane at a sequence. Monotonic: a later observation
    /// never rewinds a lane.
    pub fn observe(&mut self, lane: LaneId, seq: u64) {
        let e = self.0.entry(*lane.as_bytes()).or_insert(seq);
        *e = (*e).max(seq);
    }

    /// Every lane this clock knows about.
    pub fn lanes(&self) -> impl Iterator<Item = LaneId> + '_ {
        self.0.keys().map(|b| LaneId::from_bytes(*b))
    }

    /// Whether this clock has seen everything `other` has.
    pub fn dominates(&self, other: &Clock) -> bool {
        other
            .0
            .iter()
            .all(|(l, s)| self.0.get(l).is_some_and(|m| m >= s))
    }

    /// Take the element-wise maximum.
    pub fn merge(&mut self, other: &Clock) {
        for (l, s) in &other.0 {
            let e = self.0.entry(*l).or_insert(*s);
            *e = (*e).max(*s);
        }
    }

    /// Whether this clock shows that `(lane, seq)` had already been written.
    pub fn has_seen(&self, lane: LaneId, seq: u64) -> bool {
        self.get(lane).is_some_and(|s| s >= seq)
    }

    /// How many lanes are recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing has been seen.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
