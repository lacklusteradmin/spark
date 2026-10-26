//! The outbox reserves a persistent write cursor before constructing a message.
//! Random room nonces provide cryptographic safety even if a stale client collides;
//! reservations prevent ordinary crash recovery from deliberately retrying old slots.

use spark_chunk::{LaneId, Slot};
use spark_keyring::{Delta, RoomId};

/// Proof that a slot was reserved before anything was encrypted for it.
///
/// Not `Clone` and not `Copy`: a reservation is spent by sealing, and reusing one
/// is an unintended write to an already reserved slot.
#[derive(Debug)]
pub struct Reservation {
    slot: Slot,
}

impl Reservation {
    /// The slot this reservation covers.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Consume the reservation, yielding the slot to seal at.
    pub fn consume(self) -> Slot {
        self.slot
    }
}

/// Tracks the next unused sequence in this client's own lane.
#[derive(Clone, Debug)]
pub struct Outbox {
    room: RoomId,
    epoch: u64,
    lane: LaneId,
    next: u64,
}

impl Outbox {
    /// Start an outbox at the head this account has already written, in one
    /// generation. Sequence numbers restart at zero in each generation, because
    /// the chunk names derive from that generation's root.
    ///
    /// `next` comes from the restored keyring, so a client that crashed after
    /// reserving but before sealing resumes past the reserved slot rather than
    /// reusing it. A failed write may leave a gap.
    pub fn new(room: RoomId, epoch: u64, lane: LaneId, next: u64) -> Self {
        Self {
            room,
            epoch,
            lane,
            next,
        }
    }

    /// The next sequence that would be handed out.
    pub fn next_seq(&self) -> u64 {
        self.next
    }

    /// Reserve the next slot.
    ///
    /// Returns the reservation **and** the keyring delta recording it. The caller
    /// must persist the delta before sealing; the two are returned together so
    /// there is no version of this call that yields one without the other.
    pub fn reserve(&mut self) -> (Reservation, Delta) {
        let slot = Slot::new(self.lane, self.next);
        self.next += 1;
        // A write cursor, not a read cursor. Advancing the read head here would
        // make this client skip its own message when it next syncs.
        let delta = Delta::ReserveSlot {
            room: self.room,
            epoch: self.epoch,
            seq: slot.seq,
        };
        (Reservation { slot }, delta)
    }

    /// Give up on a reserved slot without reusing it.
    ///
    /// Deliberately does not decrement. A slot whose delta may already have been
    /// written cannot be handed out again, and gaps still require bounded probing during synchronization.
    pub fn abandon(&mut self, r: Reservation) -> Slot {
        r.consume()
    }
}
