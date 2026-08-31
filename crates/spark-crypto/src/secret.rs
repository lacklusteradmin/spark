//! A byte array that wipes itself on drop and refuses to be printed.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret key material.
///
/// The inner bytes are reachable only through [`Secret::expose`], so every place
/// that handles raw key material says so at the call site. `Debug` prints the
/// length and nothing else: a secret that reaches a log is a secret that has left
/// the process.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Take ownership of key material.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Every caller of this is worth reading twice.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// A zeroed secret, for filling in before derivation writes over it.
    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// Mutable access, for a KDF writing its output in place.
    pub(crate) fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{N}>(redacted)")
    }
}

/// Constant-time equality. Secrets are never compared with `==`.
impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}
impl<const N: usize> Eq for Secret<N> {}
