//! HMAC-SHA256, used to name room chunks.
//!
//! Room chunk names must not be derived from content: an outsider could then
//! compute the name of a guessed sentence and test whether it exists
//! (`Spark-spec.md` F7). Keying the name derivation under a room secret is what
//! prevents that, so this is a naming primitive, not an authentication one.

use crate::secret::Secret;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 over several buffers, as if concatenated.
///
/// As with [`crate::hash::sha256_parts`], the caller is responsible for making
/// the encoding unambiguous. Every caller in Spark uses fixed-length fields.
pub fn hmac_sha256_parts(key: &Secret<32>, parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key.expose())
        .expect("HMAC accepts a key of any length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}
