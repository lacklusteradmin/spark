//! The outbox, which exists to make one rule impossible to get wrong.
//!
//! `docs/protocol.md` §3.2: a room chunk's nonce is derived from `(lane, seq)`,
//! which is safe **only** because each slot is written once. Two rules enforce
//! that. The content store's write-once is one. The other is local:
//!
//! > The client MUST durably record "seq N consumed" **before** encrypting at
//! > seq N. Encrypt-then-record loses to a crash between the two, which would let
//! > a retry produce a second ciphertext under one nonce.
//!
//! A comment saying so would be a comment. Instead, [`Outbox::reserve`] hands back
//! a [`Reservation`] that cannot be constructed any other way, and sealing takes
//! one by value. The only way to seal is to have reserved first, and the only way
//! to reserve is through a call that returns the delta the caller must persist.

use spark_chunk::{LaneId, Slot};
use spark_keyring::{Delta, RoomId, SerLane};

/// Proof that a slot was reserved before anything was encrypted for it.
///
/// Not `Clone` and not `Copy`: a reservation is spent by sealing, and reusing one
/// is exactly the nonce reuse this type exists to prevent.
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
    /// reusing it. Losing one slot is the correct trade against reusing a nonce.
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
        let delta = Delta::AdvanceHead {
            room: self.room,
            epoch: self.epoch,
            lane: SerLane::from(self.lane),
            seq: slot.seq,
        };
        (Reservation { slot }, delta)
    }

    /// Give up on a reserved slot without reusing it.
    ///
    /// Deliberately does not decrement. A slot whose delta may already have been
    /// written cannot be handed out again, and a gap in a lane is harmless: the
    /// vector clock records what exists, not what was intended.
    pub fn abandon(&mut self, r: Reservation) -> Slot {
        r.consume()
    }
}
