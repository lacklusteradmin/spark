//! Shared test helpers.
//!
//! Each integration test is its own binary and compiles this separately, so
//! anything one binary does not use is dead code in that binary.
#![allow(dead_code)]

/// A deterministic RNG, so these tests do not depend on an environment.
/// Entropy is a parameter everywhere below the I/O line; this is what that buys.
///
/// xorshift64*, which is not cryptographic and does not need to be: the point is
/// that these tests give the same answer on every machine. Production supplies a
/// real one from `spark-client`, above the I/O line.
pub struct Fixed(pub u64);

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
