//! Sealing and opening. Everything else in this crate decides *which key*.

use crate::header::{HEADER_LEN, Header, HeaderError, Kind};
use spark_crypto::{AeadError, Nonce, Secret, aead};
use zeroize::Zeroizing;

/// A sealed chunk: header followed by ciphertext.
///
/// This is the only object either store holds, and it is opaque to both.
#[derive(Clone, PartialEq, Eq)]
pub struct Chunk(Vec<u8>);

impl Chunk {
    /// Seal `plaintext` under `key`.
    ///
    /// The caller chooses the nonce, because the three chunk kinds choose it
    /// differently: media derives it (§3.1); room logs and keyrings draw it
    /// at random (§3.2, §3.3). Making it a parameter keeps this crate deterministic
    /// and puts the nonce-uniqueness argument where it belongs — at the call site
    /// that can actually make it.
    pub fn seal(kind: Kind, key: &Secret<32>, nonce: &Nonce, plaintext: &[u8]) -> Self {
        let header = Header {
            kind,
            nonce: *nonce,
        };
        let aad = header.to_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + spark_crypto::TAG_LEN);
        out.extend_from_slice(&aad);
        out.extend_from_slice(&aead::seal(key, nonce, &aad, plaintext));
        Self(out)
    }

    /// Open with `key`.
    ///
    /// Fails identically for a wrong key, a wrong kind, and modified bytes. The
    /// header is the AAD, so a chunk relabelled from `Media` to `Keyring` in
    /// transit will not authenticate.
    pub fn open(&self, key: &Secret<32>) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
        let header = Header::parse(&self.0)?;
        let aad = &self.0[..HEADER_LEN];
        Ok(aead::open(key, &header.nonce, aad, &self.0[HEADER_LEN..])?)
    }

    /// The parsed header.
    pub fn header(&self) -> Result<Header, ChunkError> {
        Ok(Header::parse(&self.0)?)
    }

    /// What this chunk claims to hold.
    pub fn kind(&self) -> Result<Kind, ChunkError> {
        Ok(self.header()?.kind)
    }

    /// The bytes as stored.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes, which is what quota is charged against.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the chunk holds no bytes at all. Never true for a sealed chunk.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse bytes received from a store.
    ///
    /// Validates the header eagerly so that a malformed chunk is rejected at the
    /// boundary rather than at some later `open`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ChunkError> {
        if bytes.len() < HEADER_LEN + spark_crypto::TAG_LEN {
            return Err(ChunkError::Header(HeaderError::TooShort));
        }
        Header::parse(&bytes)?;
        Ok(Self(bytes))
    }
}

impl core::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.header() {
            Ok(h) => write!(f, "Chunk({:?}, {} bytes, sealed)", h.kind, self.0.len()),
            Err(_) => write!(f, "Chunk(malformed, {} bytes)", self.0.len()),
        }
    }
}

/// Why a chunk operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChunkError {
    /// The header would not parse.
    Header(HeaderError),
    /// The chunk did not authenticate under this key.
    NotAuthentic,
}

impl From<HeaderError> for ChunkError {
    fn from(e: HeaderError) -> Self {
        Self::Header(e)
    }
}
impl From<AeadError> for ChunkError {
    fn from(_: AeadError) -> Self {
        Self::NotAuthentic
    }
}

impl core::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header(e) => write!(f, "{e}"),
            Self::NotAuthentic => f.write_str("chunk did not authenticate"),
        }
    }
}
impl core::error::Error for ChunkError {}
