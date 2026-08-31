//! chunk format, envelope encryption, naming.
//!
//! layer 1, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence.
//!
//! Implements `docs/protocol.md` §3 and §4. The two naming schemes are the point
//! of the crate, and they are deliberately different:
//!
//! | | Media | Room log |
//! |---|---|---|
//! | Name | `SHA-256(chunk)` | `HMAC(room_root, lane ‖ seq)` |
//! | Store can verify the name | yes | no |
//! | Outsider can compute the name | given the file | never |
//! | Deduplicates | server-wide | not at all |
//!
//! Files are hard to guess, sentences are not. Content-derived names for room
//! chunks would let anyone test whether a guessed sentence exists.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod chunk;
pub mod header;
pub mod lane;
pub mod media;
pub mod name;
pub mod room;

pub use chunk::{Chunk, ChunkError};
pub use header::{HEADER_LEN, Header, HeaderError, Kind};
pub use lane::{LANE_LEN, LaneId};
pub use name::ChunkName;
pub use room::{RoomRoot, Slot};
