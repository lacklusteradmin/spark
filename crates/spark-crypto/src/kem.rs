//! X25519, used to wrap per-room data keys under the identity key.

use crate::secret::Secret;

/// An X25519 secret derived from the seed.
pub struct KemSecret(x25519_dalek::StaticSecret);

/// The public half.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KemPublic([u8; 32]);

impl KemSecret {
    /// Build from 32 bytes of derived key material.
    ///
    /// `StaticSecret::from` clamps the scalar, so two different derived byte
    /// strings can produce one secret. That is inherent to X25519 and is why the
    /// derived bytes, not the clamped scalar, are what the test vectors pin.
    pub fn from_secret(s: &Secret<32>) -> Self {
        Self(x25519_dalek::StaticSecret::from(*s.expose()))
    }

    /// The public half.
    pub fn public(&self) -> KemPublic {
        KemPublic(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }

    /// Diffie-Hellman against a peer's public key.
    pub fn diffie_hellman(&self, peer: &KemPublic) -> Secret<32> {
        let shared = self
            .0
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer.0));
        Secret::new(*shared.as_bytes())
    }
}

impl core::fmt::Debug for KemSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemSecret(redacted)")
    }
}

impl KemPublic {
    /// The 32 public bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Parse from bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}
