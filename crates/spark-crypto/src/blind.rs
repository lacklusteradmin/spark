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

// ---------------------------------------------------------- payment vouchers

/// What a voucher entitles its holder to.
///
/// The same primitive as a storage token, a different claim. `Spark-build-notes.md`
/// §3: "One primitive serves storage tokens and payment vouchers."
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grant {
    /// Months of a name, at a tier.
    ///
    /// Two tiers because the fee has two jobs that pull apart (`Spark-spec.md` D1):
    /// basic names are near-free so that blind tokens hide people in a crowd, and
    /// premium names carry a real price and fund the service. Both unlock full
    /// quota, so the paywall gates desirability rather than entry.
    NameMonths {
        /// How many months.
        months: u8,
        /// `true` for a premium name.
        premium: bool,
    },
    /// Permanent storage, as a size class.
    ///
    /// "Storage is bought once and kept forever. No expiry, no renewal" (F9).
    Storage {
        /// `log2` of the bytes granted.
        size_class: u8,
    },
}

/// A voucher's message: a serial the buyer chose and what it entitles them to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VoucherClaim {
    /// Chosen by the buyer. The issuer never sees it — that is the point.
    pub serial: [u8; 32],
    /// What was bought.
    pub grant: Grant,
}

impl VoucherClaim {
    /// The bytes the issuer signs.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = b"spark/v1/voucher".to_vec();
        v.extend_from_slice(&self.serial);
        match self.grant {
            Grant::NameMonths { months, premium } => {
                v.extend_from_slice(&[1, months, premium as u8]);
            }
            Grant::Storage { size_class } => v.extend_from_slice(&[2, size_class, 0]),
        }
        v
    }

    /// What the issuer must be paid for this grant, in whatever unit the price
    /// table uses.
    ///
    /// `Spark-spec.md` D9: "Premium pricing scales with scarcity [...] a price
    /// table rather than a design question." This is the table, kept here so the
    /// buyer and the issuer compute the same number from the same code.
    pub fn price(&self) -> u64 {
        match self.grant {
            Grant::NameMonths { months, premium } => {
                (if premium { 500 } else { 5 }) * months as u64
            }
            Grant::Storage { size_class } => 1u64 << size_class.saturating_sub(20),
        }
    }
}

// ------------------------------------------------------------ key rotation

/// The signing key a service currently uses, and the one before it.
///
/// Bounds the blast radius of RUSTSEC-2023-0071: a recovered key mints only until
/// the next rotation, rather than forever. Pacing (see [`crate::pace`]) is the
/// control; this is what limits the damage if it turns out to be insufficient.
///
/// The previous key stays *verifiable* but not *signing*, so tokens drawn before
/// a rotation keep working for one more period. Without that, rotating would
/// invalidate every unspent token a user was holding.
///
/// **No epoch travels in the token.** A verifier tries each accepted key. Putting
/// an epoch in the signed claim would work and would be cheaper to verify, but it
/// would also partition tokens into an anonymity set per epoch, stamped on the
/// token itself. Two verifications is a small price for not doing that.
pub struct KeySet {
    current: IssuerKey,
    previous: Option<IssuerPublic>,
    generation: u32,
}

impl KeySet {
    /// Start with one key.
    pub fn new(current: IssuerKey) -> Self {
        Self {
            current,
            previous: None,
            generation: 0,
        }
    }

    /// The key to sign with.
    pub fn signing(&self) -> &IssuerKey {
        &self.current
    }

    /// How many times this set has rotated. Operational, not protocol: it appears
    /// in no message and identifies nobody.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Retire the current key in favour of `next`.
    ///
    /// The retired key can still verify; only the one before *it* stops being
    /// accepted. So a token is good for at least one full rotation period after
    /// it was drawn.
    pub fn rotate(&mut self, next: IssuerKey) {
        self.previous = Some(self.current.public());
        self.current = next;
        self.generation += 1;
    }

    /// Every key a verifier should accept, newest first.
    pub fn accepted(&self) -> Vec<IssuerPublic> {
        let mut v = vec![self.current.public()];
        v.extend(self.previous.clone());
        v
    }
}

/// Verify a token against any of the keys a service currently accepts.
///
/// Tries every key rather than stopping at a match, so the work done does not
/// depend on which key signed — the same reasoning as [`crate::pace`], applied to
/// the verifier instead of the signer.
pub fn verify_any(keys: &[IssuerPublic], token: &Token, msg: &[u8]) -> Result<(), BlindError> {
    let mut ok = false;
    for k in keys {
        ok |= k.verify(token, msg).is_ok();
    }
    if ok {
        Ok(())
    } else {
        Err(BlindError::NotAuthentic)
    }
}
