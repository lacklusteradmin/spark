//! Chunk names. The store's entire index, and for media the whole capability.

/// The 32-byte name a chunk is stored under.
///
/// For media this is `SHA-256(chunk)` and the store can verify it. For a room log
/// it is an HMAC under the room secret and the store cannot — see
/// [`crate::room`] for why that asymmetry is deliberate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkName([u8; 32]);

impl ChunkName {
    /// Wrap raw bytes.
    pub fn new(b: [u8; 32]) -> Self {
        Self(b)
    }
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Lowercase hex, as it appears on the wire.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl core::fmt::Debug for ChunkName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChunkName({})", self.to_hex())
    }
}
impl core::fmt::Display for ChunkName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}
