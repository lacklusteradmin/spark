//! blind-token withdrawal/spend protocol, refund vouchers, quota ledger.
//!
//! layer 3, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence.
//!
//! Takes a transport from the caller rather than owning one. §9.3 of the protocol
//! is about withdrawal *timing*, which is spark-transport's problem; keeping the
//! two apart is what makes that question answerable on its own.
//!
//! What this crate is for: the client half of the dance is easy to get subtly
//! wrong, and getting it wrong is silent. Reusing a blinding secret, or reusing a
//! serial, hands the issuer the link the whole construction exists to break. So
//! the sequence is expressed as types that can only be used in the right order.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use spark_crypto::blind::Blinding;
use spark_crypto::blind::CryptoRng;
use spark_crypto::{BlindError, IssuerPublic, Token, TokenClaim};

/// A withdrawal in progress: blinded messages sent, signatures not yet back.
///
/// Not `Clone`. Each blinding secret is good for exactly one signature, and
/// reusing one would let the issuer link two tokens.
pub struct Withdrawal {
    claims: Vec<TokenClaim>,
    blindings: Vec<Blinding>,
}

/// A token ready to spend: what it claims, and the proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Spendable {
    /// The serial and size class the issuer signed.
    pub claim: TokenClaim,
    /// The unblinded signature.
    pub token: Token,
}

/// Begin a withdrawal.
///
/// `serials` come from the caller, as entropy does everywhere below the I/O line.
/// **They must be unpredictable**: the serial is what the content store records,
/// so a guessable one lets someone else burn the token before it is spent.
pub fn begin<R: CryptoRng + ?Sized>(
    issuer: &IssuerPublic,
    rng: &mut R,
    serials: &[[u8; 32]],
    size_class: u8,
) -> Result<(Vec<Vec<u8>>, Withdrawal), BlindError> {
    let mut blinded = Vec::with_capacity(serials.len());
    let mut claims = Vec::with_capacity(serials.len());
    let mut blindings = Vec::with_capacity(serials.len());
    for s in serials {
        let claim = TokenClaim {
            serial: *s,
            size_class,
        };
        let (bm, b) = issuer.blind(rng, &claim.encode())?;
        blinded.push(bm);
        claims.push(claim);
        blindings.push(b);
    }
    Ok((blinded, Withdrawal { claims, blindings }))
}

/// Finish a withdrawal with the issuer's blind signatures.
///
/// Consumes the [`Withdrawal`], so the blinding secrets cannot be used twice.
pub fn finish(
    issuer: &IssuerPublic,
    w: Withdrawal,
    blind_sigs: &[Vec<u8>],
) -> Result<Vec<Spendable>, BlindError> {
    if blind_sigs.len() != w.claims.len() {
        return Err(BlindError::Crypto);
    }
    let mut out = Vec::with_capacity(blind_sigs.len());
    for ((claim, blinding), sig) in w.claims.into_iter().zip(w.blindings).zip(blind_sigs) {
        let token = issuer.finalize(blinding, sig, &claim.encode())?;
        out.push(Spendable { claim, token });
    }
    Ok(out)
}

/// What a chunk of this size costs, as a size class.
pub fn class_for(bytes: u64) -> u8 {
    TokenClaim::class_for(bytes)
}
