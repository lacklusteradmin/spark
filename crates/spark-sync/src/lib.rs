//! lane merge, vector clocks, the total order, and the outbox.
//!
//! layer 3, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence.
//!
//! Two things live here, and they are the two halves of `docs/protocol.md` §5:
//!
//! * **The total order.** Every client must compute the same history from the
//!   same chunks, with no server ordering anything. [`total_order`] is that
//!   function, and it is pure — which is only possible because payloads stay
//!   opaque bytes at this layer. Interpreting an MLS message needs a provider,
//!   and a provider is I/O.
//! * **The outbox.** Sealing a room chunk under a derived nonce is safe only if
//!   each slot is written once. [`Outbox::reserve`] makes the ordering a type
//!   rule rather than a comment: sealing needs a [`Reservation`], and reserving
//!   hands back the keyring delta that must be persisted first.
//!
//! What is *not* here: fetching. Deciding what to request is trivial once the
//! clock is known, and doing it is I/O.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod clock;
pub mod entry;
pub mod order;
pub mod outbox;

pub use clock::Clock;
pub use entry::{Entry, EntryError, Payload};
pub use order::{by_lane, total_order};
pub use outbox::{Outbox, Reservation};

use spark_chunk::{LaneId, Slot};

/// The slots a client should try to fetch next.
///
/// Requests are issued **one name each**, never batched. Batching names into one
/// request would tell the store that those names belong together, which is the
/// correlation `docs/protocol.md` D-A exists to avoid, reintroduced one layer
/// down. The cost is request amplification proportional to room size, listed as
/// open question §9.2.
pub fn plan(known: &Clock, lanes: &[LaneId], probe_ahead: u64) -> Vec<Slot> {
    let mut out = Vec::new();
    for &lane in lanes {
        let next = known.get(lane).map_or(0, |s| s + 1);
        for seq in next..next + probe_ahead.max(1) {
            out.push(Slot::new(lane, seq));
        }
    }
    out
}
