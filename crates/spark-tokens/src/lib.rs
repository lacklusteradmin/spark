//! blind-token withdrawal/spend protocol, refund vouchers, quota ledger.
//!
//! layer 3, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here
//! is testable with no server in existence.
//!
//! Takes a transport from the caller rather than owning one. §9.3 of the
//! protocol is about withdrawal *timing*, which is spark-transport's problem;
//! keeping the two apart is what makes that question answerable on its own.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Placeholder. Stage 1 ships the skeleton and the invariant harness; this
/// crate is implemented in its own stage (see `Spark-build-notes.md` §5).
pub const STAGE: &str = "1-skeleton";
