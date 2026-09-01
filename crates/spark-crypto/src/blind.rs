//! RFC 9474 blind RSA signatures, over an audited implementation.
//!
//! One primitive serves two jobs (`Spark-build-notes.md` §3): storage tokens and
//! payment vouchers. Both need the same shape — a server signs something it
//! cannot read, and later verifies the result without being able to link it to
//! the signing.
//!
//! ```text
//! client                              server
//!   blind(msg) ──── blind_message ────▶ blind_sign
//!                 ◀─── blind_sig ─────
//!   finalize  ──▶ signature
//!                 ─────── spend ──────▶ verify   (cannot link to the signing)
//! ```
//!
//! **Entropy is a parameter**, as everywhere below the I/O line. The RNG comes
//! from the caller; nothing here reaches for one.

use blind_rsa_signatures as brs;

/// The modulus size. RFC 9474 requires at least 2048 bits.
pub const MODULUS_BITS: usize = 2048;

/// Re-exported so callers need no direct dependency to supply entropy.
/// The RNG traits, re-exported so callers need no direct dependency to supply
/// entropy. Everything here takes an RNG rather than reaching for one.
pub use brs::reexports::rand::{CryptoRng, TryCryptoRng, TryRng};

/// RFC 9474's `RSABSSA-SHA384-PSS-Randomized`. The randomized variant is the one
/// to use when the same message might be submitted twice: it prevents the issuer
/// from recognising a repeat.
type Kp = brs::KeyPair<brs::Sha384, brs::PSS, brs::Randomized>;
type Pk = brs::PublicKey<brs::Sha384, brs::PSS, brs::Randomized>;

/// The issuer's key pair. Server side only.
pub struct IssuerKey(Kp);

/// The issuer's public key, which every client needs.
#[derive(Clone)]
pub struct IssuerPublic(Pk);

/// What a client keeps between blinding and finalizing.
///
/// Not `Clone`: reusing the blinding secret across two signings would let the
/// issuer link them, which is the one thing this construction exists to prevent.
pub struct Blinding {
    pub(crate) inner: brs::BlindingResult,
}

/// A finished token: the signature and what is needed to verify it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Token {
    /// The unblinded signature.
    pub sig: Vec<u8>,
    /// The per-message randomizer RFC 9474 requires for this variant.
    pub randomizer: [u8; 32],
}

impl IssuerKey {
    /// Generate an issuer key. Server-side setup, done once.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, BlindError> {
        Kp::generate(rng, MODULUS_BITS)
            .map(Self)
            .map_err(|_| BlindError::Crypto)
    }

    /// The public half.
    pub fn public(&self) -> IssuerPublic {
        IssuerPublic(self.0.pk.clone())
    }

    /// Sign a blinded message.
    ///
    /// The issuer learns nothing about what it signed. That is what lets the
    /// keyring service charge quota for a token while the content service, which
    /// later sees it spent, cannot tell which account drew it.
    pub fn blind_sign(&self, blind_message: &[u8]) -> Result<Vec<u8>, BlindError> {
        self.0
            .sk
            .blind_sign(blind_message)
            .map(|s| s.0)
            .map_err(|_| BlindError::Crypto)
    }
}

impl IssuerPublic {
    /// Blind a message before asking for a signature.
    pub fn blind<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<(Vec<u8>, Blinding), BlindError> {
        let r = self.0.blind(rng, msg).map_err(|_| BlindError::Crypto)?;
        Ok((r.blind_message.0.clone(), Blinding { inner: r }))
    }

    /// Unblind a signature into a spendable token.
    pub fn finalize(&self, b: Blinding, blind_sig: &[u8], msg: &[u8]) -> Result<Token, BlindError> {
        let randomizer = b
            .inner
            .msg_randomizer
            .map(|r| r.0)
            .ok_or(BlindError::Crypto)?;
        let sig = self
            .0
            .finalize(&brs::BlindSignature(blind_sig.to_vec()), &b.inner, msg)
            .map_err(|_| BlindError::Crypto)?;
        Ok(Token {
            sig: sig.0,
            randomizer,
        })
    }

    /// Verify a spent token.
    pub fn verify(&self, token: &Token, msg: &[u8]) -> Result<(), BlindError> {
        self.0
            .verify(
                &brs::Signature(token.sig.clone()),
                Some(brs::MessageRandomizer(token.randomizer)),
                msg,
            )
            .map_err(|_| BlindError::NotAuthentic)
    }

    /// Serialize for distribution to clients.
    pub fn to_der(&self) -> Result<Vec<u8>, BlindError> {
        self.0.to_der().map_err(|_| BlindError::Crypto)
    }

    /// Parse a distributed public key.
    pub fn from_der(der: &[u8]) -> Result<Self, BlindError> {
        Pk::from_der(der).map(Self).map_err(|_| BlindError::Crypto)
    }
}

/// Why a blind-signature operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlindError {
    /// The token does not verify under this issuer key.
    NotAuthentic,
    /// The underlying implementation refused. Deliberately opaque: the variants
    /// distinguish parameter mistakes that a caller cannot act on differently.
    Crypto,
}

impl core::fmt::Display for BlindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAuthentic => f.write_str("token did not verify"),
            Self::Crypto => f.write_str("blind signature operation failed"),
        }
    }
}
impl core::error::Error for BlindError {}

// ------------------------------------------------------------ storage tokens

/// A token's message: a random serial and the size it authorises.
///
/// The size travels *inside* the signed message so the content store can check
/// that an upload fits what was paid for, without learning anything about who
/// paid. Size classes are coarse powers of two and are the same for everyone, so
/// they identify nobody; a token that carried an exact byte count would be far
/// closer to a fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TokenClaim {
    /// Chosen by the client, never by the issuer. The issuer never sees it.
    pub serial: [u8; 32],
    /// `log2` of the largest chunk this token authorises.
    pub size_class: u8,
}

impl TokenClaim {
    /// The smallest class that fits `bytes`.
    pub fn class_for(bytes: u64) -> u8 {
        let mut c = 10u8; // 1 KiB floor: nothing smaller is worth its own class
        while c < 40 && (1u64 << c) < bytes {
            c += 1;
        }
        c
    }

    /// The largest chunk this class permits.
    pub fn max_bytes(&self) -> u64 {
        1u64 << self.size_class
    }

    /// The bytes the issuer signs.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = b"spark/v1/token".to_vec();
        v.extend_from_slice(&self.serial);
        v.push(self.size_class);
        v
    }
}
