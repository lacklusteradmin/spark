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
