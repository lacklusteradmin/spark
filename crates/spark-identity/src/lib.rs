//! seed -> keypair, deterministic derivation, key migration.
//!
//! layer 1, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence.
//!
//! This crate implements `docs/protocol.md` §2 and nothing else. The derivation
//! path is the account: change a byte of an `info` string and every existing user
//! loses their history. The constants below are therefore public, pinned by test
//! vectors in `tests/vectors.json`, and are not to be edited without a migration
//! plan.
//!
//! **At-rest storage is deliberately absent.** It is named in build-notes §5
//! stage 2, but it cannot live here: a `pure` crate has no filesystem, and with
//! no passphrase decided (`docs/protocol.md` §9.1) there is nothing to encrypt a
//! stored seed *under*. That makes it a platform-keystore question, not a
//! cryptographic one, and it lands with `spark-client`. What this crate
//! guarantees instead is that nothing needs storing: every key is reproducible
//! from the mnemonic alone.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod reach;

use spark_crypto::{
    KemPublic, KemSecret, Mnemonic, MnemonicError, Prk, Secret, Signature, SignatureError,
    SigningKey, VerifyingKey, expand, extract, sha256_parts,
};

/// HKDF-Extract salt. The root of the whole derivation tree.
pub const ROOT_SALT: &[u8] = b"spark/v1/root";
/// HKDF-Expand info for the Ed25519 identity key.
pub const INFO_SIGN: &[u8] = b"spark/v1/identity/ed25519";
/// HKDF-Expand info for the X25519 identity key.
pub const INFO_KEM: &[u8] = b"spark/v1/identity/x25519";
/// HKDF-Expand info for the keyring blob's AEAD key.
pub const INFO_KEYRING: &[u8] = b"spark/v1/keyring/aead";
/// Domain separator hashed ahead of the public key to produce [`Addr`].
pub const ADDR_PREFIX: &[u8] = b"spark/v1/keyring/addr";

/// The keyring address: the only account-shaped identifier any server sees.
///
/// Derived from the public key rather than being it, so holding an `Addr` does
/// not hand an observer a verification key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr([u8; 32]);

impl Addr {
    /// Wrap raw bytes, for an address that arrived over the wire.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Lowercase hex, as it appears on the wire.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl core::fmt::Debug for Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Addr({})", self.to_hex())
    }
}
impl core::fmt::Display for Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Everything about an identity that is safe to publish.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicIdentity {
    /// Ed25519 verification key. Signs messages and the MLS credential.
    pub sign: VerifyingKey,
    /// X25519 public key. Wraps per-room data keys.
    pub kem: KemPublic,
}

impl PublicIdentity {
    /// The keyring address for this identity.
    pub fn addr(&self) -> Addr {
        Addr(sha256_parts(&[ADDR_PREFIX, self.sign.as_bytes()]))
    }
}

/// A full identity, derived from a seed.
///
/// There is exactly one way to construct this: from a mnemonic, or from the seed
/// that mnemonic expands to. That is the shape gate 2 requires — "no code path
/// recovers an identity without it" — and the invariant harness checks it by
/// reading this file, so a second constructor cannot be added quietly.
pub struct Identity {
    sign: SigningKey,
    kem: KemSecret,
    keyring: Secret<32>,
}

impl Identity {
    /// Derive from a mnemonic.
    pub fn from_mnemonic(m: &Mnemonic) -> Self {
        Self::from_seed(&m.to_seed())
    }

    /// Derive from the 64-byte BIP-39 seed.
    ///
    /// This is `docs/protocol.md` §2 verbatim. Read the two side by side before
    /// touching either.
    pub fn from_seed(seed: &spark_crypto::Seed) -> Self {
        let root: Prk = extract(ROOT_SALT, seed.expose());
        Self {
            sign: SigningKey::from_secret(&expand::<32>(&root, INFO_SIGN)),
            kem: KemSecret::from_secret(&expand::<32>(&root, INFO_KEM)),
            keyring: expand::<32>(&root, INFO_KEYRING),
        }
    }

    /// Parse a mnemonic and derive in one step.
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        Ok(Self::from_mnemonic(&Mnemonic::parse(phrase)?))
    }

    /// The public half.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            sign: self.sign.verifying_key(),
            kem: self.kem.public(),
        }
    }

    /// This identity's keyring address.
    pub fn addr(&self) -> Addr {
        self.public().addr()
    }

    /// Sign a message with the identity key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign.sign(msg)
    }

    /// Verify a signature made by this identity.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SignatureError> {
        self.public().sign.verify(msg, sig)
    }

    /// The AEAD key sealing this account's keyring blob.
    pub fn keyring_key(&self) -> &Secret<32> {
        &self.keyring
    }

    /// Diffie-Hellman against a peer, for wrapping room data keys.
    pub fn diffie_hellman(&self, peer: &KemPublic) -> Secret<32> {
        self.kem.diffie_hellman(peer)
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The address is public and makes logs useful; nothing else appears.
        write!(f, "Identity({})", self.addr())
    }
}
