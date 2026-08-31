//! XChaCha20-Poly1305, the AEAD sealing every chunk.
//!
//! Chosen over AES-256-GCM for its 24-byte nonce: `docs/protocol.md` §3.2 derives
//! room chunk nonces rather than storing them, and a 96-bit nonce leaves too
//! little room to do that without a birthday-bound argument.

use crate::secret::Secret;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// An AEAD nonce. Never reused under one key — see `docs/protocol.md` §3.2.
pub type Nonce = [u8; NONCE_LEN];

/// Seal `plaintext`, authenticating `aad` alongside it.
pub fn seal(key: &Secret<32>, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.expose().into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers")
}

/// Open a sealed buffer.
///
/// The plaintext is returned zeroizing: a decrypted chunk is the thing the whole
/// design exists to keep out of memory dumps.
pub fn open(
    key: &Secret<32>,
    nonce: &Nonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    XChaCha20Poly1305::new(key.expose().into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| AeadError::NotAuthentic)
}

/// The only failure an AEAD reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AeadErrorMarker;

/// Why opening failed.
///
/// Deliberately one variant. Distinguishing "wrong key" from "tampered
/// ciphertext" would hand an attacker an oracle, and there is nothing a caller
/// could usefully do differently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AeadError {
    /// The key is wrong, the nonce is wrong, the AAD is wrong, or the bytes were
    /// modified. Which one, this will not say.
    NotAuthentic,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("chunk did not authenticate")
    }
}
impl core::error::Error for AeadError {}
