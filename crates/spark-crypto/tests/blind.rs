//! RFC 9474 blind signatures: the property, not the round trip.

use spark_crypto::blind::*;

/// A deterministic RNG, so these tests do not depend on an environment.
/// Entropy is a parameter everywhere below the I/O line; this is what that buys.
///
/// xorshift64*, which is not cryptographic and does not need to be: the point is
/// that these tests give the same answer on every machine. Production supplies a
/// real one from `spark-client`, above the I/O line.
struct Fixed(u64);

impl rc::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for c in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        Ok(())
    }
}
impl rc::TryCryptoRng for Fixed {}

mod rc {
    pub use blind_rsa_signatures::reexports::rand::{TryCryptoRng, TryRng};
}

#[test]
fn a_token_verifies_without_the_issuer_learning_what_it_signed() {
    let mut rng = Fixed(1);
    let issuer = IssuerKey::generate(&mut rng).expect("keygen");
    let pk = issuer.public();

    let msg = b"a storage token";
    let (blind_message, blinding) = pk.blind(&mut rng, msg).expect("blind");

    // The issuer sees only the blinded form.
    assert!(
        !blind_message.windows(msg.len()).any(|w| w == msg),
        "the message was visible to the issuer"
    );

    let blind_sig = issuer.blind_sign(&blind_message).expect("sign");
    let token = pk.finalize(blinding, &blind_sig, msg).expect("finalize");
    assert!(pk.verify(&token, msg).is_ok());

    // And the finished signature is not the blinded one the issuer saw.
    assert_ne!(
        token.sig, blind_sig,
        "the issuer could recognise its own output"
    );
}

#[test]
fn a_token_does_not_verify_for_a_different_message() {
    let mut rng = Fixed(2);
    let issuer = IssuerKey::generate(&mut rng).expect("keygen");
    let pk = issuer.public();
    let (bm, b) = pk.blind(&mut rng, b"one").expect("blind");
    let token = pk
        .finalize(b, &issuer.blind_sign(&bm).unwrap(), b"one")
        .unwrap();

    assert_eq!(
        pk.verify(&token, b"two").unwrap_err(),
        BlindError::NotAuthentic
    );
}

#[test]
fn a_token_does_not_verify_under_another_issuer() {
    let mut rng = Fixed(3);
    let a = IssuerKey::generate(&mut rng).expect("keygen a");
    let b = IssuerKey::generate(&mut rng).expect("keygen b");
    let (bm, bl) = a.public().blind(&mut rng, b"m").unwrap();
    let token = a
        .public()
        .finalize(bl, &a.blind_sign(&bm).unwrap(), b"m")
        .unwrap();

    assert!(a.public().verify(&token, b"m").is_ok());
    assert_eq!(
        b.public().verify(&token, b"m").unwrap_err(),
        BlindError::NotAuthentic
    );
}

#[test]
fn two_tokens_for_one_message_are_unlinkable() {
    // The randomized variant, and the reason for it: an issuer asked to sign the
    // same message twice must not be able to tell that it did.
    let mut rng = Fixed(4);
    let issuer = IssuerKey::generate(&mut rng).expect("keygen");
    let pk = issuer.public();

    let (bm1, b1) = pk.blind(&mut rng, b"same").unwrap();
    let (bm2, b2) = pk.blind(&mut rng, b"same").unwrap();
    assert_ne!(bm1, bm2, "the issuer saw two identical blinded messages");

    let t1 = pk
        .finalize(b1, &issuer.blind_sign(&bm1).unwrap(), b"same")
        .unwrap();
    let t2 = pk
        .finalize(b2, &issuer.blind_sign(&bm2).unwrap(), b"same")
        .unwrap();
    assert_ne!(t1.sig, t2.sig);
    assert_ne!(t1.randomizer, t2.randomizer);
    assert!(pk.verify(&t1, b"same").is_ok() && pk.verify(&t2, b"same").is_ok());
}

#[test]
fn a_public_key_round_trips_for_distribution() {
    let mut rng = Fixed(5);
    let issuer = IssuerKey::generate(&mut rng).expect("keygen");
    let der = issuer.public().to_der().expect("der");
    let parsed = IssuerPublic::from_der(&der).expect("parse");

    let (bm, b) = parsed.blind(&mut rng, b"m").unwrap();
    let token = parsed
        .finalize(b, &issuer.blind_sign(&bm).unwrap(), b"m")
        .unwrap();
    assert!(issuer.public().verify(&token, b"m").is_ok());
}

/// The Marvin fix, held to account.
///
/// `blind_sign` no longer calls `blind-rsa-signatures`, because that call routes
/// the private exponentiation through the `rsa` crate, which is not constant-time
/// (RUSTSEC-2023-0071). It does the exponentiation itself against a constant-time
/// bignum instead. The obvious risk in doing that is getting the arithmetic subtly
/// wrong, so: the same key, the same blinded message, both implementations, and
/// the bytes have to be equal.
///
/// Equality is the right assertion rather than "both verify". RSA signing is
/// deterministic in `(m, d, n)` — the `rsa` crate's internal base blinding is
/// undone before it returns — so any difference at all is a bug, and a test that
/// only checked verification would pass on an implementation that agreed by
/// accident on well-formed input and diverged on an edge.
#[test]
fn signing_matches_the_reference_implementation() {
    use blind_rsa_signatures as brs;

    let issuer = IssuerKey::generate(&mut Fixed(7)).expect("key");
    let pk = issuer.public();

    // The reference implementation over the same key: `IssuerKey::generate` is a
    // thin wrapper on this call, and the RNG is deterministic, so the same seed
    // gives the same modulus and the same private exponent. The first assertion
    // below would fail loudly if that ever stopped being true.
    let reference: brs::KeyPair<brs::Sha384, brs::PSS, brs::Randomized> =
        brs::KeyPair::generate(&mut Fixed(7), MODULUS_BITS).expect("reference key");
    assert_eq!(
        reference.pk.to_der().expect("their der"),
        pk.to_der().expect("our der"),
        "the two keys are not the same key, so comparing signatures proves nothing"
    );

    for (i, msg) in [b"a".as_slice(), b"", &[0xFF; 300]].iter().enumerate() {
        let (blind_message, _b) = pk.blind(&mut Fixed(100 + i as u64), msg).expect("blind");

        let ours = issuer.blind_sign(&blind_message).expect("ours");
        let theirs = reference
            .sk
            .blind_sign(&blind_message)
            .expect("reference")
            .0;

        assert_eq!(
            ours, theirs,
            "constant-time signing disagreed with the reference on message {i}"
        );
        assert_eq!(
            ours.len(),
            MODULUS_BITS / 8,
            "signature was not modulus-length"
        );
    }
}

/// A signature whose leading byte is zero.
///
/// The one place a hand-rolled big-endian encoding goes wrong: `to_be_bytes` on a
/// bignum drops leading zeroes, so a signature numerically smaller than 2^2040
/// comes back short and every verifier rejects it. Roughly 1 in 256 signatures.
/// Searched for rather than hoped for.
#[test]
fn a_short_signature_is_still_padded_to_the_modulus() {
    let issuer = IssuerKey::generate(&mut Fixed(11)).expect("key");
    let pk = issuer.public();

    let mut found = false;
    for i in 0..600u64 {
        let (bm, b) = pk.blind(&mut Fixed(i), b"pad").expect("blind");
        let sig = issuer.blind_sign(&bm).expect("sign");
        assert_eq!(
            sig.len(),
            MODULUS_BITS / 8,
            "signature {i} was not modulus-length"
        );
        if sig[0] == 0 {
            found = true;
            // And it still unblinds and verifies, which is what a truncated
            // encoding would have broken.
            let token = pk.finalize(b, &sig, b"pad").expect("finalize");
            pk.verify(&token, b"pad").expect("verify");
            break;
        }
    }
    assert!(
        found,
        "no leading-zero signature turned up in 600 tries; the case went unchecked"
    );
}

/// Input the signer must refuse.
///
/// Not a formality: `m >= n` has no unique signature, and a blinded message of the
/// wrong length would be silently zero-extended into a different number.
#[test]
fn a_malformed_blinded_message_is_refused() {
    let issuer = IssuerKey::generate(&mut Fixed(13)).expect("key");
    let bytes = MODULUS_BITS / 8;

    assert!(
        issuer.blind_sign(&vec![0xAA; bytes - 1]).is_err(),
        "short message signed"
    );
    assert!(
        issuer.blind_sign(&vec![0xAA; bytes + 1]).is_err(),
        "long message signed"
    );
    // All-ones is larger than any 2048-bit modulus.
    assert!(
        issuer.blind_sign(&vec![0xFF; bytes]).is_err(),
        "a message above the modulus signed"
    );
}
