//! Convergent encryption: one file always produces one byte-identical chunk.
//!
//! `docs/protocol.md` §3.1. This is what makes "a photo twenty people sent costs
//! one copy" true (`Spark-spec.md` F7) without the store ever holding a key.

use crate::chunk::{Chunk, ChunkError};
use crate::header::Kind;
use crate::name::ChunkName;
use spark_crypto::{Nonce, Secret, expand, extract, sha256};
use zeroize::Zeroizing;

/// Domain separator for the media key schedule.
pub const MEDIA_SALT: &[u8] = b"spark/v1/media";

/// Derive the key and nonce a given file will always be sealed under.
fn schedule(plaintext: &[u8]) -> (Secret<32>, Nonce) {
    let prk = extract(MEDIA_SALT, &sha256(plaintext));
    (
        expand::<32>(&prk, b"key"),
        *expand::<24>(&prk, b"nonce").expose(),
    )
}

/// Seal a file.
///
/// Returns the name it is stored under, the key needed to read it, and the chunk.
/// The pair `(name, key)` is the whole read capability; the store never sees the
/// second half.
pub fn seal(plaintext: &[u8]) -> (ChunkName, Secret<32>, Chunk) {
    let (key, nonce) = schedule(plaintext);
    let chunk = Chunk::seal(Kind::Media, &key, &nonce, plaintext);
    (name_of(&chunk), key, chunk)
}

/// The name a media chunk is stored under: the hash of the finished chunk.
///
/// Hashing the *chunk* rather than the plaintext lets the content store verify a
/// write matches its claimed name while holding no key at all. That closes name
/// squatting: nobody can claim a name they cannot produce bytes for.
pub fn name_of(chunk: &Chunk) -> ChunkName {
    ChunkName::new(sha256(chunk.as_bytes()))
}

/// Open a media chunk with its key.
pub fn open(chunk: &Chunk, key: &Secret<32>) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
    chunk.open(key)
}

/// Recover the read capability for a file you already hold.
///
/// Used when re-sharing a file into another room without re-uploading it.
pub fn capability(plaintext: &[u8]) -> (ChunkName, Secret<32>) {
    let (name, key, _) = seal(plaintext);
    (name, key)
}
