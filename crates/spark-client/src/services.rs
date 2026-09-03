//! What the client needs from the three services, and nothing more.
//!
//! A trait rather than a dependency on the server crates, for two reasons that
//! both matter.
//!
//! The layering one: `spark-client` sits in the client's half of the graph and
//! must not reach into the servers'. Only `spark-cli`, at the top, wires the two
//! together.
//!
//! The design one: this is the complete list of what a client asks of a server.
//! It is short, and it is meant to stay short — every method here is a thing the
//! services learn. Reading it is the fastest way to check that claim.

use spark_crypto::{Token, TokenClaim};
pub use spark_transport::Class;

/// Proof that the caller holds the key behind an address.
#[derive(Clone, Debug)]
pub struct Auth {
    /// The keyring address.
    pub addr: [u8; 32],
    /// The public key it was derived from.
    pub key: [u8; 32],
    /// A signature over the current challenge.
    pub sig: [u8; 64],
}

/// What went wrong. Deliberately coarse: a client cannot act differently on most
/// of the distinctions a server could draw, and drawing them here would invite
/// the servers to report more than they should.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServiceError {
    /// The service refused.
    Refused,
    /// Nothing there.
    NotFound,
    /// The service could not be reached.
    Unreachable,
}

impl core::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused => f.write_str("the service refused"),
            Self::NotFound => f.write_str("not found"),
            Self::Unreachable => f.write_str("could not reach the service"),
        }
    }
}
impl core::error::Error for ServiceError {}

/// The keyring service. The only one that knows an account exists.
pub trait KeyringService {
    /// The challenge this address must sign right now.
    fn challenge(&self, addr: &[u8; 32]) -> [u8; 32];
    /// Fetch the sealed keyring snapshot.
    fn snapshot(&self, auth: &Auth) -> Result<Option<Vec<u8>>, ServiceError>;
    /// Fetch the deltas written after it.
    fn deltas(&self, auth: &Auth) -> Result<Vec<Vec<u8>>, ServiceError>;
    /// Append a delta.
    fn put_delta(&self, auth: &Auth, chunk: &[u8]) -> Result<(), ServiceError>;
    /// Replace the snapshot, dropping the deltas it subsumes.
    fn put_snapshot(&self, auth: &Auth, chunk: &[u8]) -> Result<(), ServiceError>;
    /// The token issuer's public key, DER-encoded.
    fn issuer_key(&self) -> Result<Vec<u8>, ServiceError>;
    /// Exchange quota for blind signatures over already-blinded claims.
    fn withdraw(
        &self,
        auth: &Auth,
        blinded: &[Vec<u8>],
        size_class: u8,
    ) -> Result<Vec<Vec<u8>>, ServiceError>;
    /// Leave a contact request for an address. Unauthenticated by design.
    fn put_request(&self, addr: &[u8; 32], blob: &[u8], token: &[u8]) -> Result<(), ServiceError>;
    /// Read this account's contact requests.
    fn requests(&self, auth: &Auth) -> Result<Vec<(u32, Vec<u8>)>, ServiceError>;
    /// Discard one, accepted or declined alike.
    fn drop_request(&self, auth: &Auth, index: u32) -> Result<(), ServiceError>;
}

/// The content service. No accounts, ever.
///
/// Every method takes a traffic [`Class`], because this is the one service whose
/// requests fall on both sides of `Spark-spec.md` D2's default mode: room-log
/// chunks are text and go over Tor, media chunks are bulk and go direct. A single
/// connection here would force one routing decision for both, and the mixed mode
/// would be impossible to offer.
///
/// It is an argument rather than something inferred from the chunk, for the same
/// reason it is one in `Transport::open`: a request whose class nobody decided is
/// a request routed by accident, and the accident is always media escaping in a
/// mode the user believed covered it.
pub trait ContentService {
    /// Store a chunk, authorised by a blind token.
    fn put(
        &self,
        class: Class,
        name: &[u8; 32],
        chunk: &[u8],
        claim: TokenClaim,
        token: &Token,
    ) -> Result<[u8; 32], ServiceError>;
    /// Fetch a chunk. Carries no identity.
    fn get(&self, class: Class, name: &[u8; 32]) -> Result<Option<Vec<u8>>, ServiceError>;
    /// Return a receipt, freeing the chunk at zero holders.
    fn release(
        &self,
        class: Class,
        name: &[u8; 32],
        receipt: &[u8; 32],
    ) -> Result<Vec<u8>, ServiceError>;
}

/// The issuer. Blind, and never browsable.
pub trait IssuerService {
    /// Resolve one exact name to a public identity.
    fn resolve(&self, name: &str, today: u32) -> Result<Option<[u8; 64]>, ServiceError>;
}

/// Everything a client talks to.
///
/// Implemented for references too, so one deployment can serve several clients in
/// one process — which is exactly what the CLI's demo does.
pub trait Services {
    /// The keyring service.
    fn keyring(&self) -> &dyn KeyringService;
    /// The content service.
    fn content(&self) -> &dyn ContentService;
    /// The issuer.
    fn issuer(&self) -> &dyn IssuerService;
}

impl<T: Services + ?Sized> Services for &T {
    fn keyring(&self) -> &dyn KeyringService {
        (**self).keyring()
    }
    fn content(&self) -> &dyn ContentService {
        (**self).content()
    }
    fn issuer(&self) -> &dyn IssuerService {
        (**self).issuer()
    }
}
