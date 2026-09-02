//! A [`Services`] implementation that speaks the wire protocol.
//!
//! The counterpart to `wiring::Local`. Same client above it, same server logic
//! below it, a network in between — which is the point: if the client behaves
//! differently against these two, one of them is wrong.
//!
//! Each service gets its own connection because each is a separate trust domain.
//! Sharing one would let a single operator see all three sides of a session
//! whatever the code intended.

use spark_client::{Auth, ContentService, IssuerService, KeyringService, ServiceError, Services};
use spark_crypto::{Token, TokenClaim};
use spark_transport::{Channel, ChannelError, Pin};
use spark_wire::{content, issuer, keyring};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

fn io(_: ChannelError) -> ServiceError {
    ServiceError::Unreachable
}

/// A TLS-wrapped TCP connection.
type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// One connection, used one call at a time.
///
/// The mutex is what makes `&self` enough for the [`Services`] traits. A request
/// and its response are one exchange on one connection, so they cannot interleave.
struct Conn(Mutex<Channel<Tls>>);

impl Conn {
    fn open(addr: &str, tls: Arc<rustls::ClientConfig>) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        // The name is a formality: the verifier checks the pinned key and ignores
        // the name entirely, because a pin is a statement about which key rather
        // than about what it is called.
        let name = rustls_pki_types::ServerName::try_from("spark.local")
            .map_err(|_| std::io::Error::other("bad server name"))?;
        let conn = rustls::ClientConnection::new(tls, name)
            .map_err(|e| std::io::Error::other(format!("tls: {e}")))?;
        let stream = rustls::StreamOwned::new(conn, stream);

        let url = format!("wss://{addr}/");
        Channel::connect(stream, &url)
            .map(|c| Self(Mutex::new(c)))
            .map_err(|_| std::io::Error::other("handshake failed"))
    }

    fn call<Q, R>(&self, req: &Q) -> Result<R, ServiceError>
    where
        Q: serde::Serialize + spark_wire::Operation,
        R: serde::de::DeserializeOwned + spark_wire::Operation,
    {
        self.0
            .lock()
            .map_err(|_| ServiceError::Unreachable)?
            .call(req)
            .map_err(io)
    }
}

/// The three services, over the network.
pub struct Remote {
    keyring: Conn,
    content: Conn,
    issuer: Conn,
}

impl Remote {
    /// Connect to a deployment, accepting only servers holding a pinned key.
    ///
    /// `pins` is not optional and cannot be empty: a client with nothing pinned
    /// would have nothing to check, and the shape that permits that is the shape
    /// someone later "fixes" by falling back to the WebPKI.
    pub fn connect(
        keyring: &str,
        content: &str,
        issuer: &str,
        pins: &[Pin],
    ) -> std::io::Result<Self> {
        let tls = Arc::new(
            spark_transport::tls::client_config(pins.to_vec())
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        Ok(Self {
            keyring: Conn::open(keyring, tls.clone())?,
            content: Conn::open(content, tls.clone())?,
            issuer: Conn::open(issuer, tls)?,
        })
    }
}

fn wire_auth(a: &Auth) -> spark_wire::Auth {
    spark_wire::Auth {
        addr: a.addr,
        key: a.key,
        sig: a.sig.to_vec(),
    }
}

impl KeyringService for Remote {
    fn challenge(&self, addr: &[u8; 32]) -> [u8; 32] {
        match self.keyring.call(&keyring::Req::Challenge { addr: *addr }) {
            Ok(keyring::Resp::Challenge(c)) => c,
            // A challenge that cannot be fetched becomes one that will not verify,
            // which is the same outcome and one fewer error path in every caller.
            _ => [0; 32],
        }
    }
    fn snapshot(&self, auth: &Auth) -> Result<Option<Vec<u8>>, ServiceError> {
        match self
            .keyring
            .call(&keyring::Req::GetSnapshot(wire_auth(auth)))?
        {
            keyring::Resp::Snapshot(s) => Ok(s),
            _ => Err(ServiceError::Refused),
        }
    }
    fn deltas(&self, auth: &Auth) -> Result<Vec<Vec<u8>>, ServiceError> {
        match self
            .keyring
            .call(&keyring::Req::GetDeltas(wire_auth(auth)))?
        {
            keyring::Resp::Deltas(d) => Ok(d),
            _ => Err(ServiceError::Refused),
        }
    }
    fn put_delta(&self, auth: &Auth, chunk: &[u8]) -> Result<(), ServiceError> {
        match self
            .keyring
            .call(&keyring::Req::PutDelta(wire_auth(auth), chunk.to_vec()))?
        {
            keyring::Resp::Appended { .. } => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
    fn put_snapshot(&self, auth: &Auth, chunk: &[u8]) -> Result<(), ServiceError> {
        match self
            .keyring
            .call(&keyring::Req::PutSnapshot(wire_auth(auth), chunk.to_vec()))?
        {
            keyring::Resp::SnapshotWritten => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
    fn issuer_key(&self) -> Result<Vec<u8>, ServiceError> {
        match self.keyring.call(&keyring::Req::GetIssuerKey)? {
            keyring::Resp::IssuerKey(k) => Ok(k),
            _ => Err(ServiceError::Refused),
        }
    }
    fn withdraw(
        &self,
        auth: &Auth,
        blinded: &[Vec<u8>],
        size_class: u8,
    ) -> Result<Vec<Vec<u8>>, ServiceError> {
        match self.keyring.call(&keyring::Req::WithdrawTokens {
            auth: wire_auth(auth),
            blinded: blinded.to_vec(),
            size_class,
        })? {
            keyring::Resp::Tokens(t) => Ok(t),
            _ => Err(ServiceError::Refused),
        }
    }
    fn put_request(&self, addr: &[u8; 32], blob: &[u8], token: &[u8]) -> Result<(), ServiceError> {
        match self.keyring.call(&keyring::Req::PutRequest {
            addr: *addr,
            blob: blob.to_vec(),
            token: token.to_vec(),
        })? {
            keyring::Resp::RequestTaken => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
    fn requests(&self, auth: &Auth) -> Result<Vec<(u32, Vec<u8>)>, ServiceError> {
        match self
            .keyring
            .call(&keyring::Req::GetRequests(wire_auth(auth)))?
        {
            keyring::Resp::Requests(r) => Ok(r),
            _ => Err(ServiceError::Refused),
        }
    }
    fn drop_request(&self, auth: &Auth, index: u32) -> Result<(), ServiceError> {
        match self
            .keyring
            .call(&keyring::Req::DropRequest(wire_auth(auth), index))?
        {
            keyring::Resp::RequestDropped => Ok(()),
            _ => Err(ServiceError::Refused),
        }
    }
}

impl ContentService for Remote {
    fn put(
        &self,
        name: &[u8; 32],
        chunk: &[u8],
        claim: TokenClaim,
        token: &Token,
    ) -> Result<[u8; 32], ServiceError> {
        match self.content.call(&content::Req::Put {
            name: *name,
            chunk: chunk.to_vec(),
            claim,
            token: token.clone(),
        })? {
            content::Resp::Stored { receipt } => Ok(receipt),
            _ => Err(ServiceError::Refused),
        }
    }
    fn get(&self, name: &[u8; 32]) -> Result<Option<Vec<u8>>, ServiceError> {
        match self.content.call(&content::Req::Get { name: *name })? {
            content::Resp::Chunk(b) => Ok(Some(b)),
            content::Resp::Refused(content::Refusal::NotFound) => Ok(None),
            _ => Err(ServiceError::Refused),
        }
    }
    fn release(&self, name: &[u8; 32], receipt: &[u8; 32]) -> Result<Vec<u8>, ServiceError> {
        match self.content.call(&content::Req::Release {
            name: *name,
            receipt: *receipt,
        })? {
            content::Resp::Released { voucher, .. } => Ok(voucher),
            _ => Err(ServiceError::Refused),
        }
    }
}

impl IssuerService for Remote {
    fn resolve(&self, name: &str, today: u32) -> Result<Option<[u8; 64]>, ServiceError> {
        match self.issuer.call(&issuer::Req::Resolve {
            name: name.to_string(),
            today,
        })? {
            issuer::Resp::Resolved(k) => Ok(k.and_then(|v| v.try_into().ok())),
            _ => Err(ServiceError::Refused),
        }
    }
}

impl Services for Remote {
    fn keyring(&self) -> &dyn KeyringService {
        self
    }
    fn content(&self) -> &dyn ContentService {
        self
    }
    fn issuer(&self) -> &dyn IssuerService {
        self
    }
}
