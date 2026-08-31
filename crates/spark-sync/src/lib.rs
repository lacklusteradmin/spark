//! lane merge, vector clocks, total order, conflict resolution.
//!
//! layer 3, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here
//! is testable with no server in existence.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Placeholder. Stage 1 ships the skeleton and the invariant harness; this
/// crate is implemented in its own stage (see `Spark-build-notes.md` §5).
pub const STAGE: &str = "1-skeleton";
