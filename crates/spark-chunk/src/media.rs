//! Convergent encryption: one file always produces one byte-identical chunk.
//!
//! `docs/protocol.md` §3.1. This is what makes "a photo twenty people sent costs
//! one copy" true (`Spark-spec.md` F7) without the store ever holding a key.

use crate::chunk::{Chunk, ChunkError};
use crate::header::Kind;
use crate::name::ChunkName;
use crate::scrub::Scrubbed;
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
///
/// Takes a [`Scrubbed`], which has no constructor other than
/// [`crate::scrub::scrub`]. "GPS EXIF cannot survive a send" is therefore a
/// property of the type system: there is no way to reach this function with a
/// file whose metadata was not stripped, and no call site that has to remember.
pub fn seal(file: &Scrubbed) -> (ChunkName, Secret<32>, Chunk) {
    seal_raw(file.as_bytes())
}

/// Seal bytes that are not a file: a serialized structure, a room log entry.
///
/// Separate from [`seal`] on purpose. Anything a *user* chose to send goes
/// through the scrubber; this is for bytes Spark itself produced, which have no
/// container metadata because Spark did not put any there.
pub fn seal_raw(plaintext: &[u8]) -> (ChunkName, Secret<32>, Chunk) {
    let (key, nonce) = schedule(plaintext);
    let chunk = Chunk::seal(Kind::Media, &key, &nonce, plaintext);
    (name_of(&chunk), key, chunk)
}

/// The media address: SHA-256 of the finished chunk with its high bit cleared.
///
/// Hashing the *chunk* rather than the plaintext lets the content store verify a
/// write matches its claimed name while holding no key at all. That closes name
/// squatting: nobody can claim a name they cannot produce bytes for.
pub fn name_of(chunk: &Chunk) -> ChunkName {
    let mut name = sha256(chunk.as_bytes());
    name[0] &= 0x7f;
    ChunkName::new(name)
}

/// Open a media chunk with its key.
pub fn open(chunk: &Chunk, key: &Secret<32>) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
    chunk.open(key)
}

/// Recover the read capability for a file you already hold.
///
/// Used when re-sharing a file into another room without re-uploading it. Takes
/// the scrubbed form, because that is what was uploaded — the original still has
/// its metadata and would hash to a different name.
pub fn capability(file: &Scrubbed) -> (ChunkName, Secret<32>) {
    capability_raw(file.as_bytes())
}

/// As [`capability`], for bytes Spark produced itself.
pub fn capability_raw(plaintext: &[u8]) -> (ChunkName, Secret<32>) {
    let (name, key, _) = seal_raw(plaintext);
    (name, key)
}
