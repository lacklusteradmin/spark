//! SHA-256. The only hash function in Spark.
//!
//! It is already the MLS cipher suite's hash (`..._SHA256_...`), so using it for
//! addresses and content naming too keeps the primitive set at one. A second hash
//! function would need a decision record, not a convenience argument.

use sha2::{Digest, Sha256};

/// A 32-byte digest.
pub type Digest32 = [u8; 32];

/// SHA-256 of one buffer.
pub fn sha256(data: &[u8]) -> Digest32 {
    Sha256::digest(data).into()
}

/// SHA-256 over several buffers, as if concatenated.
///
/// Callers must make the encoding unambiguous themselves — a fixed-length prefix
/// or a domain separator. This function will happily hash `("ab", "c")` and
/// `("a", "bc")` to the same digest, which is the caller's problem to prevent.
pub fn sha256_parts(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
