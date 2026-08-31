//! BIP-39, 24 words. The seed phrase *is* the account (`Spark-spec.md` F3).
//!
//! **Entropy arrives as a parameter, never from a syscall inside this crate.**
//! Two reasons. This crate is `pure`, so it stays deterministic and its tests
//! need no environment. And the entropy source for an account that can never be
//! recovered is worth naming explicitly at the call site rather than inheriting
//! from whatever `getrandom` resolves to on a given platform.

use crate::secret::Secret;
use zeroize::Zeroizing;

/// A 24-word BIP-39 mnemonic.
pub struct Mnemonic(bip39::Mnemonic);

/// The 64-byte seed a mnemonic expands to.
pub type Seed = Secret<64>;

/// Spark requires 24 words: 256 bits of entropy.
pub const WORD_COUNT: usize = 24;
/// Bytes of entropy behind a 24-word mnemonic.
pub const ENTROPY_BYTES: usize = 32;

impl Mnemonic {
    /// Build from caller-supplied entropy.
    ///
    /// The caller is responsible for this being 32 bytes from a cryptographically
    /// secure source. Everything the account will ever hold rests on it.
    pub fn from_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Self {
        Self(
            bip39::Mnemonic::from_entropy(entropy)
                .expect("32 bytes is a valid BIP-39 entropy size"),
        )
    }

    /// Parse a mnemonic a user typed back in.
    ///
    /// Rejects anything that is not exactly 24 words, including valid 12-word
    /// BIP-39 phrases: accepting a shorter phrase would silently halve the
    /// entropy behind an unrecoverable account.
    pub fn parse(phrase: &str) -> Result<Self, MnemonicError> {
        let m =
            bip39::Mnemonic::parse_normalized(phrase.trim()).map_err(|_| MnemonicError::Invalid)?;
        if m.word_count() != WORD_COUNT {
            return Err(MnemonicError::WrongWordCount(m.word_count()));
        }
        Ok(Self(m))
    }

    /// The 24 words, space-separated. Zeroized when dropped.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.words().collect::<Vec<_>>().join(" "))
    }

    /// Expand to the 64-byte seed.
    ///
    /// The passphrase is empty and not a parameter. `docs/protocol.md` §9.1 lists
    /// adding one as open; exposing it here before that is decided would let a
    /// caller create accounts that a later, decided derivation cannot reproduce.
    pub fn to_seed(&self) -> Seed {
        Secret::new(self.0.to_seed_normalized(""))
    }
}

impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mnemonic(redacted)")
    }
}

/// Why a mnemonic was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MnemonicError {
    /// Not a valid BIP-39 phrase: bad word, or bad checksum.
    Invalid,
    /// Valid BIP-39, but not the 24 words Spark requires.
    WrongWordCount(usize),
}

impl core::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid => f.write_str("not a valid BIP-39 mnemonic"),
            Self::WrongWordCount(n) => write!(f, "expected {WORD_COUNT} words, got {n}"),
        }
    }
}
impl core::error::Error for MnemonicError {}
