//! Shared helpers for the gate tests.
//!
//! Each integration test is its own binary and compiles this module separately,
//! so anything one binary does not use is dead code *in that binary*. That is a
//! property of how Rust builds tests, not a sign of anything unused.
#![allow(dead_code)]

/// A deterministic RNG. Entropy is a parameter below the I/O line, and this is
/// what that buys: tests that give the same answer on every machine.
pub struct Fixed(pub u64);
impl spark_crypto::blind::TryRng for Fixed {
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
impl spark_crypto::blind::TryCryptoRng for Fixed {}

/// One issuer key per test binary: RSA keygen is slow, and no test here is about
/// the issuer's key generation.
pub fn issuer() -> &'static spark_crypto::IssuerKey {
    static K: std::sync::OnceLock<spark_crypto::IssuerKey> = std::sync::OnceLock::new();
    K.get_or_init(|| spark_crypto::IssuerKey::generate(&mut Fixed(42)).expect("keygen"))
}

/// Draw a 1 MiB fixture token, the denomination provisioned for this test issuer.
pub fn token(serial: u8, bytes: u64) -> (spark_crypto::TokenClaim, spark_crypto::Token) {
    assert!(
        bytes <= 1 << 20,
        "fixture exceeds the provisioned denomination"
    );
    let claim = spark_crypto::TokenClaim {
        serial: [serial; 32],
        size_class: 20,
    };
    let pk = issuer().public();
    let (bm, b) = pk
        .blind(&mut Fixed(serial as u64 + 7), &claim.encode())
        .expect("blind");
    let sig = issuer().blind_sign(&bm).expect("sign");
    (
        claim,
        pk.finalize(b, &sig, &claim.encode()).expect("finalize"),
    )
}

/// Test-only settlement stub; production uses a rejecting adapter by default.
pub struct TestPayments;
impl spark_issuer::PaymentVerifier for TestPayments {
    fn verify(&self, payment: &[u8], amount: u64, _: &[u8]) -> bool {
        !payment.is_empty() && amount > 0
    }
}

/// An issuer service with its own voucher-signing key.
pub fn name_issuer() -> spark_issuer::Issuer {
    spark_issuer::Issuer::new(
        spark_store::Db::new(),
        spark_crypto::IssuerKey::generate(&mut Fixed(77)).expect("keygen"),
    )
    .with_payment_verifier(std::sync::Arc::new(TestPayments))
    .with_day_clock(std::sync::Arc::new(|| 20_000))
}

/// Buy a voucher through the real blind dance.
pub fn buy_voucher(
    is: &spark_issuer::Issuer,
    serial: u8,
    grant: spark_crypto::Grant,
    payment: &[u8],
) -> (spark_crypto::VoucherClaim, spark_crypto::Token) {
    let claim = spark_crypto::VoucherClaim {
        serial: [serial; 32],
        grant,
    };
    if is.signing_public_for(claim.price()).is_none() {
        is.provision_price(
            claim.price(),
            spark_crypto::IssuerKey::generate(&mut Fixed(
                u64::from_le_bytes(
                    spark_crypto::sha256(&is.signing_public().to_der().unwrap())[..8]
                        .try_into()
                        .unwrap(),
                )
                .wrapping_add(claim.price()),
            ))
            .unwrap(),
        );
    }
    let pk = is.signing_public_for(claim.price()).unwrap();
    let (blinded, b) = pk
        .blind(&mut Fixed(serial as u64 + 1), &claim.encode())
        .expect("blind");
    let spark_issuer::Response::Signed(sig) = is.handle(spark_issuer::Request::Purchase {
        blinded,
        payment: payment.to_vec(),
        amount: claim.price(),
    }) else {
        panic!("purchase refused")
    };
    (
        claim,
        pk.finalize(b, &sig, &claim.encode()).expect("finalize"),
    )
}

/// Exercise the complete anonymous refund dance, including client-side unblinding.
pub fn release(
    cs: &spark_content_server::Content,
    name: [u8; 32],
    receipt: [u8; 32],
    size_class: u8,
) -> (
    spark_content_server::Response,
    spark_crypto::TokenClaim,
    Option<spark_crypto::Token>,
) {
    use spark_content_server::{Request, Response};
    let Response::RefundKey(der) = cs.handle(Request::GetRefundKey(size_class)) else {
        panic!("refund key")
    };
    let pk = spark_crypto::IssuerPublic::from_der(&der).unwrap();
    let claim = spark_crypto::TokenClaim {
        serial: spark_crypto::sha256(&receipt),
        size_class,
    };
    let msg = claim.refund_message();
    let (blinded, b) = pk.blind(&mut Fixed(71), &msg).unwrap();
    let response = cs.handle(Request::Release {
        name,
        receipt,
        size_class,
        blinded,
    });
    let token = match &response {
        Response::Released { voucher, .. } => Some(pk.finalize(b, voucher, &msg).unwrap()),
        _ => None,
    };
    (response, claim, token)
}
