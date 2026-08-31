//! UniFFI bindings. No logic.
//!
//! layer 6, zone `boundary` — see `docs/layering.toml`.
//!
//! Above the FFI line: no cryptography, no protocol logic. Bindings only.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Placeholder. Stage 1 ships the skeleton and the invariant harness; this
/// crate is implemented in its own stage (see `Spark-build-notes.md` §5).
pub const STAGE: &str = "1-skeleton";
