//! Ed25519, as used for the identity key and the MLS credential.

use crate::secret::Secret;
use ed25519_dalek::{Signer, Verifier};

/// A signing key derived from the seed.
pub struct SigningKey(ed25519_dalek::SigningKey);

/// The public half. Safe to publish; it is what `addr` is derived from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyingKey([u8; 32]);

/// A detached Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature([u8; 64]);

impl SigningKey {
    /// Build from 32 bytes of derived key material.
    pub fn from_secret(s: &Secret<32>) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(s.expose()))
    }

    /// The public half.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().to_bytes())
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(redacted)")
    }
}

impl VerifyingKey {
    /// The 32 public bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse from bytes. Rejects keys that are not valid points.
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, SignatureError> {
        ed25519_dalek::VerifyingKey::from_bytes(b)
            .map(|k| Self(k.to_bytes()))
            .map_err(|_| SignatureError::MalformedKey)
    }

    /// Verify a signature over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SignatureError> {
        let k = ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| SignatureError::MalformedKey)?;
        k.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig.0))
            .map_err(|_| SignatureError::BadSignature)
    }
}

impl Signature {
    /// The 64 signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    /// Parse from bytes.
    pub fn from_bytes(b: [u8; 64]) -> Self {
        Self(b)
    }
}

/// Why a signature operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureError {
    /// The key bytes are not a valid Ed25519 point.
    MalformedKey,
    /// The signature does not verify under this key.
    BadSignature,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedKey => f.write_str("malformed Ed25519 key"),
            Self::BadSignature => f.write_str("signature did not verify"),
        }
    }
}
impl core::error::Error for SignatureError {}
