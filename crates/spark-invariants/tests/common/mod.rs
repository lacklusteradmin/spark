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

/// Draw one real token for `bytes`, through the full blind dance.
pub fn token(serial: u8, bytes: u64) -> (spark_crypto::TokenClaim, spark_crypto::Token) {
    let claim = spark_crypto::TokenClaim {
        serial: [serial; 32],
        size_class: spark_tokens::class_for(bytes),
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
