//! The 32-byte chunk header. Authenticated, never encrypted.
//!
//! `docs/protocol.md` §3. The header is the AAD, so `kind` and `version` cannot
//! be swapped under an attacker. Nothing else sits outside the AEAD: there is no
//! room id, no sender field, no length prefix. **A chunk carries no routing
//! information.**

use spark_crypto::{NONCE_LEN, Nonce};

/// Header length in bytes.
pub const HEADER_LEN: usize = 32;
/// Every chunk starts with these four bytes.
pub const MAGIC: [u8; 4] = *b"SPK1";
/// The only format version that exists.
pub const VERSION: u8 = 1;

/// What a chunk holds. The three kinds have different naming and different
/// lifecycles; see `Spark-build-notes.md` §4.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// A room's append-only log. Named from the room key; freed by deletion at dissolve.
    RoomLog = 1,
    /// A shared file. Named from its own bytes; freed by receipt count reaching zero.
    Media = 2,
    /// An account's keyring. Addressed by `hash(pubkey)`, never by chunk name.
    Keyring = 3,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::RoomLog),
            2 => Some(Self::Media),
            3 => Some(Self::Keyring),
            _ => None,
        }
    }
}

/// A parsed chunk header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// What the chunk holds.
    pub kind: Kind,
    /// The AEAD nonce.
    pub nonce: Nonce,
}

impl Header {
    /// Serialize to the wire form.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind as u8;
        // bytes 6..8 are flags, reserved, and stay zero
        out[8..8 + NONCE_LEN].copy_from_slice(&self.nonce);
        out
    }

    /// Parse the wire form.
    ///
    /// A non-zero flags field is an error rather than something to ignore: a
    /// reserved field that decoders skip is a reserved field that can never be
    /// used for anything.
    pub fn parse(b: &[u8]) -> Result<Self, HeaderError> {
        if b.len() < HEADER_LEN {
            return Err(HeaderError::TooShort);
        }
        if b[0..4] != MAGIC {
            return Err(HeaderError::BadMagic);
        }
        if b[4] != VERSION {
            return Err(HeaderError::UnknownVersion(b[4]));
        }
        let kind = Kind::from_byte(b[5]).ok_or(HeaderError::UnknownKind(b[5]))?;
        if b[6] != 0 || b[7] != 0 {
            return Err(HeaderError::ReservedFlagsSet);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&b[8..8 + NONCE_LEN]);
        Ok(Self { kind, nonce })
    }
}

/// Why a header would not parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderError {
    /// Fewer than [`HEADER_LEN`] bytes.
    TooShort,
    /// Does not begin with [`MAGIC`].
    BadMagic,
    /// A format version this build does not know.
    UnknownVersion(u8),
    /// A chunk kind this build does not know.
    UnknownKind(u8),
    /// The reserved flags field was not zero.
    ReservedFlagsSet,
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("chunk shorter than its header"),
            Self::BadMagic => f.write_str("not a Spark chunk"),
            Self::UnknownVersion(v) => write!(f, "unknown chunk version {v}"),
            Self::UnknownKind(k) => write!(f, "unknown chunk kind {k}"),
            Self::ReservedFlagsSet => f.write_str("reserved header flags were set"),
        }
    }
}
impl core::error::Error for HeaderError {}
