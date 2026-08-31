//! HKDF-SHA256, split into extract and expand exactly as RFC 5869 has them.
//!
//! Spark derives every key from one seed, so the derivation path *is* the
//! identity. Both halves are exposed separately rather than through a single
//! convenience function, because `docs/protocol.md` §2 specifies them separately
//! and the two must stay auditable against that text.

use crate::secret::Secret;
use hkdf::Hkdf;
use sha2::Sha256;

/// A pseudorandom key: the output of HKDF-Extract.
pub type Prk = Secret<32>;

/// HKDF-Extract. `salt` is the domain separator, `ikm` the input key material.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Prk {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    Secret::new(out)
}

/// HKDF-Expand into a fixed-size secret.
///
/// # Panics
/// If `N` exceeds HKDF's 255 * 32 byte output limit, which is a programming error
/// rather than a runtime condition.
pub fn expand<const N: usize>(prk: &Prk, info: &[u8]) -> Secret<N> {
    let hk = Hkdf::<Sha256>::from_prk(prk.expose()).expect("PRK is exactly 32 bytes");
    let mut out = Secret::<N>::zeroed();
    hk.expand(info, out.expose_mut())
        .expect("output length within HKDF limit");
    out
}
