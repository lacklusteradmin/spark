//! HKDF, XChaCha20-Poly1305, SHA-256, Ed25519, BIP-39, blind-signature client.
//!
//! layer 0, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence.
//!
//! Thin wrappers over audited implementations, and nothing else. Build-notes §1
//! forbids custom cryptography, so this crate contains no algorithm — only the
//! type discipline that keeps key material from leaking through `Debug`, `==`,
//! or a forgotten `drop`.
//!
//! Every primitive named in `docs/protocol.md` §1 is now here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aead;
pub mod blind;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod mac;
pub mod mnemonic;
pub mod secret;
pub mod sign;

pub use aead::{AeadError, NONCE_LEN, Nonce, TAG_LEN};
pub use blind::{BlindError, IssuerKey, IssuerPublic, Token, TokenClaim};
pub use hash::{Digest32, sha256, sha256_parts};
pub use kdf::{Prk, expand, extract};
pub use kem::{KemPublic, KemSecret};
pub use mac::hmac_sha256_parts;
pub use mnemonic::{Mnemonic, MnemonicError, Seed};
pub use secret::Secret;
pub use sign::{Signature, SignatureError, SigningKey, VerifyingKey};
