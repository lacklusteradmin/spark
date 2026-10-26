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

#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SavedSecret(Vec<u8>);
impl SavedSecret {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Secret state for retrying exactly one blind-signature operation after a crash.
/// Persist only inside authenticated encryption. Never log this value.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SavedBlinding {
    message: Vec<u8>,
    secret: SavedSecret,
    randomizer: [u8; 32],
}

impl Blinding {
    /// Persist this operation's unblinding state inside the encrypted keyring.
    pub fn save(&self) -> SavedBlinding {
        SavedBlinding {
            message: self.inner.blind_message.0.clone(),
            secret: SavedSecret::new(self.inner.secret.0.clone()),
            randomizer: self.inner.msg_randomizer.unwrap().0,
        }
    }
}
impl SavedBlinding {
    /// Recreate the same operation, never a new issuance.
    pub fn restore(&self) -> Blinding {
        Blinding {
            inner: brs::BlindingResult {
                blind_message: brs::BlindMessage(self.message.clone()),
                secret: brs::Secret(self.secret.expose().to_vec()),
                msg_randomizer: Some(brs::MessageRandomizer(self.randomizer)),
            },
        }
    }
    /// Exact bytes required for an idempotent retry.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// A finished token: the signature and what is needed to verify it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// Export the private issuer key for an operator-only durable vault.
    pub fn secret_der(&self) -> Result<Vec<u8>, BlindError> {
        self.0.sk.to_der().map_err(|_| BlindError::Crypto)
    }
    /// Restore a private issuer key from an operator-only vault.
    pub fn from_secret_der(bytes: &[u8]) -> Result<Self, BlindError> {
        let sk = brs::SecretKey::from_der(bytes).map_err(|_| BlindError::Crypto)?;
        let pk = sk.public_key().map_err(|_| BlindError::Crypto)?;
        Ok(Self(Kp { sk, pk }))
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
    ///
    /// # Why this is not `blind_rsa_signatures::SecretKey::blind_sign`
    ///
    /// That call would route the private exponentiation through the `rsa` crate,
    /// which is not constant-time: RUSTSEC-2023-0071, the Marvin Attack. The
    /// advisory has `patched = []` and names exactly one workaround — "avoid using
    /// the `rsa` crate in settings where attackers are able to observe timing
    /// information". Two Spark servers do precisely that, on input the attacker
    /// chose, over the network.
    ///
    /// So the one operation that touches the private key is done here instead,
    /// against `crypto_bigint`'s constant-time modular exponentiation. Everything
    /// else about RFC 9474 — the PSS encoding, the blinding, the unblinding, the
    /// verification — stays in `blind-rsa-signatures`, because none of it touches
    /// a secret and all of it is fiddly to get right. The bytes are identical
    /// either way; `signing_matches_the_reference_implementation` is what holds
    /// that to account.
    pub fn blind_sign(&self, blind_message: &[u8]) -> Result<Vec<u8>, BlindError> {
        let c = self.0.sk.components();
        let (n, e) = (c.n(), c.e());
        let sig = ct::modexp(blind_message, &c.d(), &n)?;

        // Re-encrypt and compare, which is what the reference implementation does
        // too. It converts a fault — injected, or mine — from a signature that
        // silently leaks into a request that fails. Through the public path, whose
        // ladder is bounded by e's 17 bits rather than the modulus's 2048: running
        // it constant-time would double the cost of signing to hide a number that
        // is printed in the public key.
        let back = ct::public_modexp(&sig, &e, &n)?;
        if back != blind_message {
            return Err(BlindError::Crypto);
        }
        Ok(sig)
    }
}

/// The private-key operation, in constant time.
///
/// RFC 9474 §5: signing a blinded message is `s = m^d mod n` and nothing else —
/// the blinded message arrives already PSS-encoded by the client, so there is no
/// padding step on this side and no branch that could depend on the key.
mod ct {
    use super::BlindError;
    use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
    use crypto_bigint::{BoxedUint, Odd};

    /// Re-encode a big-endian integer in exactly `len` bytes.
    ///
    /// `None` if it does not fit. Left-pads a short one, and drops a leading run of
    /// zeroes only after confirming with a branch-free fold that it *is* all zeroes.
    fn narrow(be: &[u8], len: usize) -> Option<Vec<u8>> {
        if be.len() <= len {
            let mut out = vec![0u8; len];
            out[len - be.len()..].copy_from_slice(be);
            return Some(out);
        }
        let (high, low) = be.split_at(be.len() - len);
        let any = high.iter().fold(0u8, |a, b| a | b);
        (any == 0).then(|| low.to_vec())
    }

    /// `base^exp mod modulus`, with every operand at the modulus's precision.
    ///
    /// Precision, not bit length, is what sets the number of squarings — see
    /// `crypto_bigint`'s note that `exponent_bits` leaks in the time pattern. Every
    /// operand is widened to the modulus's precision here, so the work done is a
    /// function of the key *size*, which is public, and not of the key.
    pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, BlindError> {
        // `None` means "use the full precision", which is what makes the work a
        // function of the key size rather than of the key.
        pow(base, exp, modulus, None)
    }

    /// `base^exp mod modulus` for a *public* exponent.
    ///
    /// Bounded by the exponent's actual bit length instead of the modulus's
    /// precision, which leaks that length in the time pattern — and is fine,
    /// because the only exponent passed here is `e`, which ships in the public key.
    /// The difference is not cosmetic: at full precision this would do 2048
    /// squarings for a 17-bit exponent and double the cost of signing.
    pub fn public_modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, BlindError> {
        let bits = BoxedUint::from_be_slice_vartime(exp).bits();
        pow(base, exp, modulus, Some(bits.max(1)))
    }

    fn pow(
        base: &[u8],
        exp: &[u8],
        modulus: &[u8],
        exp_bits: Option<u32>,
    ) -> Result<Vec<u8>, BlindError> {
        let n = BoxedUint::from_be_slice_vartime(modulus);
        let bits = n.bits_precision();
        let n = Odd::new(n).into_option().ok_or(BlindError::Crypto)?;

        // An even modulus has no Montgomery form, and a base at or above the
        // modulus is not a signable message. Both are properties of the key and of
        // a well-formed request, not of any secret, so rejecting them early leaks
        // nothing.
        if base.len() != modulus.len() {
            return Err(BlindError::Crypto);
        }
        let m = BoxedUint::from_be_slice(base, bits).map_err(|_| BlindError::Crypto)?;
        if m >= *n.as_ref() {
            return Err(BlindError::Crypto);
        }

        // The private exponent arrives wider than the modulus — the `rsa` crate computes it at
        // extended precision and hands back every byte of that representation, 384
        // for a 2048-bit key. It is numerically below the modulus, so the extra
        // bytes are zero; narrowing to the modulus width is what keeps the ladder
        // at 2048 squarings rather than 3072.
        //
        // Checked rather than assumed, and with an OR-fold rather than a search:
        // a truncation that silently dropped a set bit would produce a signature
        // that verifies for nobody, and finding that from the outside is much
        // harder than refusing here.
        let e = narrow(exp, modulus.len()).ok_or(BlindError::Crypto)?;
        let e = BoxedUint::from_be_slice(&e, bits).map_err(|_| BlindError::Crypto)?;
        let params = BoxedMontyParams::new(n);
        let m = BoxedMontyForm::new(m, &params);
        let s = match exp_bits {
            None => m.pow(&e),
            Some(b) => m.pow_bounded_exp(&e, b),
        }
        .retrieve();

        // Left-padded to the modulus length, which RFC 9474 requires and which a
        // short big-endian encoding would silently break.
        let mut out = vec![0u8; modulus.len()];
        let be = s.to_be_bytes();
        let n = be.len().min(out.len());
        out[modulus.len() - n..].copy_from_slice(&be[be.len() - n..]);
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::narrow;

        /// The case the signing tests cannot reach.
        ///
        /// For a well-formed key the bytes above the modulus width are zero, so
        /// dropping them unchecked gives the same signature and every test still
        /// passes. The check earns its place only on input that does not fit —
        /// a different key size, or a library that changes how it stores `d` —
        /// where the alternative is a silently wrong exponent and signatures that
        /// verify for nobody.
        #[test]
        fn a_value_too_wide_to_fit_is_refused_rather_than_truncated() {
            assert_eq!(narrow(&[0, 0, 1, 2], 2), Some(vec![1, 2]), "zero padding");
            assert_eq!(narrow(&[1, 2], 4), Some(vec![0, 0, 1, 2]), "left-padded");
            assert_eq!(narrow(&[7, 7], 2), Some(vec![7, 7]), "exact width");
            assert_eq!(narrow(&[], 2), Some(vec![0, 0]), "empty");

            assert_eq!(narrow(&[1, 0, 0], 2), None, "a set bit above the width");
            // The last byte of the discarded run, which an off-by-one in the split
            // would let through.
            assert_eq!(narrow(&[0, 1, 9, 9], 2), None, "a set bit at the boundary");
        }
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenClaim {
    /// Chosen by the client, never by the issuer. The issuer never sees it.
    pub serial: [u8; 32],
    /// `log2` of the largest chunk this token authorises.
    pub size_class: u8,
}

impl TokenClaim {
    /// Refund claims use a separate domain as well as a separate mint.
    pub fn refund_message(&self) -> Vec<u8> {
        let mut v = b"spark/v1/refund".to_vec();
        v.extend_from_slice(&self.serial);
        v.push(self.size_class);
        v
    }

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
            Grant::Storage {
                size_class: 20..=40,
            } => {
                let Grant::Storage { size_class } = self.grant else {
                    unreachable!()
                };
                1u64 << (size_class - 20)
            }
            Grant::Storage { .. } => 0,
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

    /// Serialize private and retired public key state for an operator-only vault.
    pub fn secret_bytes(&self) -> Result<Vec<u8>, BlindError> {
        let private = self.current.secret_der()?;
        let previous = self
            .previous
            .as_ref()
            .map(IssuerPublic::to_der)
            .transpose()?
            .unwrap_or_default();
        let mut out = self.generation.to_be_bytes().to_vec();
        out.extend_from_slice(&(private.len() as u32).to_be_bytes());
        out.extend_from_slice(&private);
        out.extend_from_slice(&previous);
        Ok(out)
    }
    /// Restore a complete signing/verification generation from its private vault.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, BlindError> {
        if bytes.len() < 8 || bytes.len() > 16384 {
            return Err(BlindError::Crypto);
        }
        let generation = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let private = bytes
            .get(8..8usize.checked_add(len).ok_or(BlindError::Crypto)?)
            .ok_or(BlindError::Crypto)?;
        let previous = &bytes[8 + len..];
        Ok(Self {
            current: IssuerKey::from_secret_der(private)?,
            previous: if previous.is_empty() {
                None
            } else {
                Some(IssuerPublic::from_der(previous)?)
            },
            generation,
        })
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
