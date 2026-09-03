//! A [`Services`] implementation that speaks the wire protocol.
//!
//! layer 6, zone `io` — see `docs/layering.toml`.
//!
//! # Why this is its own crate
//!
//! It was a module inside `spark-cli` until `spark-ffi` needed it, which is when
//! the arrangement stopped working. `spark-cli` is a binary with no lib target,
//! and it links all three servers — so the only client that could reach a network
//! was the one compiled into the same binary as the servers it talked to. A mobile
//! client cannot depend on that, and nothing above the FFI line may implement the
//! wire protocol itself, which would leave it with no way to connect at all.
//!
//! The counterpart to `spark-cli`'s `wiring::Local`. Same client above it, same server logic
//! below it, a network in between — which is the point: if the client behaves
//! differently against these two, one of them is wrong.
//!
//! Each service gets its own connection because each is a separate trust domain.
//! Sharing one would let a single operator see all three sides of a session
//! whatever the code intended.
//!
//! # Why the content service gets two
//!
//! Its requests fall on both sides of `Spark-spec.md` D2's default mode: room-log
//! chunks are text and go over Tor, media chunks are bulk and go direct. One
//! connection would force a single routing decision for both, and the mixed mode
//! could not be offered at all.
//!
//! # Everything goes through `Transport`
//!
//! Not through `TcpStream` directly. That is the whole point of this module now:
//! before this, the routing, the SOCKS5 and the traffic classes existed and passed
//! their own gate while the real client connected straight out — so the Tor
//! setting was a switch that did nothing, which is the failure
//! `Spark-build-notes.md` §1 names outright.

pub mod session;
pub use session::{Config, FileHandle, Note, Room, Session, SessionError};

use spark_client::{Auth, ContentService, IssuerService, KeyringService, ServiceError, Services};
use spark_crypto::{Token, TokenClaim};
use spark_transport::{
    Channel, ChannelError, Class, Mode, Paced, Pin, RealTicker, TcpConnector, Transport,
    TransportError,
};
use spark_wire::{content, issuer, keyring};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

fn io(_: ChannelError) -> ServiceError {
    ServiceError::Unreachable
}

/// A TLS-wrapped connection, over whatever the routing layer produced.
type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// Whether this client transmits on a fixed schedule.
///
/// `Spark-spec.md` F12's cover traffic, as a decision rather than a default — for
/// the same reason `mode` is one. It costs real latency: a request waits for the
/// next slot, which is a minute away. A client that turned that on without being
/// asked would be a client that felt broken, and a client that could never turn it
/// on would be one where F12 is a paragraph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cover {
    /// Transmit when there is something to say, and not otherwise.
    Off,
    /// Transmit one uniform frame per slot, dummy or not.
    ///
    /// The interval is carried rather than fixed so the paced path can be tested
    /// against a real deployment: at F12's minute, one exchange takes a minute, so
    /// a test of it would never be written and the path would go unexercised —
    /// which is how `Transport` came to be dead code the first time. Use
    /// [`Cover::DEFAULT`] anywhere a person is waiting; a shorter interval narrows
    /// the window an observer has to average over.
    Every(std::time::Duration),
}

impl Cover {
    /// `Spark-spec.md` F12: one transmission a minute.
    pub const DEFAULT: Self = Self::Every(std::time::Duration::from_secs(
        spark_transport::hysteria::INTERVAL_SECS,
    ));
}

/// A connection's framing, which is what pacing changes.
enum Framing {
    /// Boxed only to keep the two variants a similar size; a `Channel` is over a
    /// kilobyte and `Paced` is a pointer, and this enum lives behind a mutex
    /// anyway.
    Plain(Box<Channel<Tls>>),
    /// One uniform frame per slot. The ticker is the real 60-second one; the tests
    /// that check the *shape* of this use `Immediate` against a `Paced` they build
    /// themselves, because a test that waited out real slots would take an hour.
    Paced(Box<Paced<Tls, RealTicker>>),
}

/// One connection, used one call at a time.
///
/// The mutex is what makes `&self` enough for the [`Services`] traits. A request
/// and its response are one exchange on one connection, so they cannot interleave.
struct Conn {
    framing: Mutex<Framing>,
    /// The class this connection carries, fixed when it was opened.
    ///
    /// Held rather than passed per call: the class decided the route, so letting a
    /// caller name a different one at call time would let the two disagree.
    class: Class,
    /// Requests this connection has actually carried.
    ///
    /// On the connection, not on the class argument. Counting the argument would
    /// measure what the caller asked for rather than where the request went, and
    /// a `content_for` that returned the wrong connection would go unnoticed —
    /// which is what the first version of this did.
    calls: AtomicU64,
}

impl Conn {
    fn open(
        transport: &Transport<TcpConnector>,
        class: Class,
        addr: &str,
        tls: Arc<rustls::ClientConfig>,
        cover: Cover,
    ) -> std::io::Result<Self> {
        let (host, port) = split(addr)?;
        // Through the routing layer, which decides direct or Tor from the class
        // and, if Tor, negotiates SOCKS5 on a circuit of its own. TLS wraps the
        // result: doing it before would mean handshaking with the proxy.
        let stream = transport.open(class, host, port).map_err(|e| match e {
            TransportError::Direct => std::io::Error::other("could not connect"),
            TransportError::Socks(s) => std::io::Error::other(s.to_string()),
        })?;
        // The name is a formality: the verifier checks the pinned key and ignores
        // the name entirely, because a pin is a statement about which key rather
        // than about what it is called.
        let name = rustls_pki_types::ServerName::try_from("spark.local")
            .map_err(|_| std::io::Error::other("bad server name"))?;
        let conn = rustls::ClientConnection::new(tls, name)
            .map_err(|e| std::io::Error::other(format!("tls: {e}")))?;
        let stream = rustls::StreamOwned::new(conn, stream);

        let url = format!("wss://{addr}/");
        let ch = Channel::connect(stream, &url)
            .map_err(|_| std::io::Error::other("handshake failed"))?;
        // Media is never paced, whatever was asked for. A one-minute cadence over a
        // photo is not a slower photo, and `Hysteria::enqueue` refuses the class
        // outright — so a `Paced` here would be a connection that cannot carry what
        // it was opened to carry.
        let framing = match cover {
            Cover::Every(i) if class != Class::Media => {
                Framing::Paced(Box::new(Paced::new(ch, RealTicker::every(i))))
            }
            _ => Framing::Plain(Box::new(ch)),
        };
        Ok(Self {
            framing: Mutex::new(framing),
            class,
            calls: AtomicU64::new(0),
        })
    }

    fn call<Q, R>(&self, req: &Q) -> Result<R, ServiceError>
    where
        Q: serde::Serialize + spark_wire::Operation,
        R: serde::de::DeserializeOwned + spark_wire::Operation,
    {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut framing = self.framing.lock().map_err(|_| ServiceError::Unreachable)?;
        match &mut *framing {
            Framing::Plain(c) => c.call(req).map_err(io),
            Framing::Paced(p) => p.call(self.class, req).map_err(io),
        }
    }

    /// How many requests this connection has carried.
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    /// Slots this connection has transmitted on. Zero if it is not paced.
    fn slots(&self) -> u64 {
        match &*self.framing.lock().expect("framing") {
            Framing::Plain(_) => 0,
            Framing::Paced(p) => p.slots(),
        }
    }
}

/// Split `host:port`, which is how a service address is written.
fn split(addr: &str) -> std::io::Result<(&str, u16)> {
    let (h, p) = addr
        .rsplit_once(':')
        .ok_or_else(|| std::io::Error::other("addr needs a port"))?;
    let port: u16 = p.parse().map_err(|_| std::io::Error::other("bad port"))?;
    Ok((h, port))
}

/// The three services, over the network.
pub struct Remote {
    transport: Transport<TcpConnector>,
    keyring: Conn,
    /// Room-log chunks. Text class, so Tor in the default mode.
    content_text: Conn,
    /// Media chunks. Bulk, so direct in the default mode — and that is the
    /// exposure D2 accepts, not an oversight.
    content_media: Conn,
    issuer: Conn,
}

impl Remote {
    /// Connect to a deployment.
    ///
    /// `pins` is not optional and cannot be empty: a client with nothing pinned
    /// would have nothing to check, and the shape that permits that is the shape
    /// someone later "fixes" by falling back to the WebPKI.
    ///
    /// `mode` is not optional either, and there is deliberately no convenience
    /// constructor that picks one. There was — it defaulted to `TextOverTor` — and
    /// it is gone: the entire point of routing through `Transport` is that how much
    /// goes over Tor is a decision, and an API that makes it for you silently is
    /// how it stopped being one the first time. `cover` is spelled out for the same
    /// reason, and costs more when wrong: it trades a minute of latency per request
    /// for hiding when the client had something to say.
    pub fn connect_via(
        keyring: &str,
        content: &str,
        issuer: &str,
        pins: &[Pin],
        mode: Mode,
        cover: Cover,
        proxy: (String, u16),
    ) -> std::io::Result<Self> {
        let tls = Arc::new(
            spark_transport::tls::client_config(pins.to_vec())
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        let transport = Transport::new(mode, proxy, TcpConnector);
        Ok(Self {
            keyring: Conn::open(&transport, Class::Control, keyring, tls.clone(), cover)?,
            content_text: Conn::open(&transport, Class::Text, content, tls.clone(), cover)?,
            content_media: Conn::open(&transport, Class::Media, content, tls.clone(), cover)?,
            issuer: Conn::open(&transport, Class::Control, issuer, tls, cover)?,
            transport,
        })
    }

    /// Every connection this client has opened, and whether it went over Tor.
    ///
    /// Not diagnostics: this is how "always-on shows zero direct connections" is
    /// checkable of the *client* rather than of the routing layer in isolation.
    pub fn ledger(&self) -> &spark_transport::Ledger {
        self.transport.ledger()
    }

    /// Slots this client has transmitted on, across every paced connection.
    ///
    /// The counterpart to [`Remote::ledger`], and for the same reason: without it,
    /// a `Cover` that was accepted and then quietly dropped on the floor passes
    /// every test, because a paced session and an unpaced one carry the same
    /// messages. That is how `Transport` came to be a setting that did nothing for
    /// three stages, and the fix there was the same — make the client say what it
    /// actually did, not what it was told to do.
    ///
    /// Zero on a `Cover::Off` client, since nothing is on a schedule to count.
    pub fn cover_slots(&self) -> u64 {
        self.keyring.slots()
            + self.content_text.slots()
            + self.content_media.slots()
            + self.issuer.slots()
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

impl Remote {
    /// The connection carrying a class of chunk traffic.
    fn content_for(&self, class: Class) -> &Conn {
        match class {
            Class::Media => &self.content_media,
            // Control never carries chunks, but a class nobody handled would be
            // routed by whichever arm came first, which is exactly the accident
            // requiring the argument was meant to prevent.
            Class::Text | Class::Control => &self.content_text,
        }
    }

    /// How many chunk requests each content connection actually carried:
    /// `(text, media)`.
    pub fn content_calls(&self) -> (u64, u64) {
        (self.content_text.calls(), self.content_media.calls())
    }
}

impl ContentService for Remote {
    fn put(
        &self,
        class: Class,
        name: &[u8; 32],
        chunk: &[u8],
        claim: TokenClaim,
        token: &Token,
    ) -> Result<[u8; 32], ServiceError> {
        match self.content_for(class).call(&content::Req::Put {
            name: *name,
            chunk: chunk.to_vec(),
            claim,
            token: token.clone(),
        })? {
            content::Resp::Stored { receipt } => Ok(receipt),
            _ => Err(ServiceError::Refused),
        }
    }
    fn get(&self, class: Class, name: &[u8; 32]) -> Result<Option<Vec<u8>>, ServiceError> {
        match self
            .content_for(class)
            .call(&content::Req::Get { name: *name })?
        {
            content::Resp::Chunk(b) => Ok(Some(b)),
            content::Resp::Refused(content::Refusal::NotFound) => Ok(None),
            _ => Err(ServiceError::Refused),
        }
    }
    fn release(
        &self,
        class: Class,
        name: &[u8; 32],
        receipt: &[u8; 32],
    ) -> Result<Vec<u8>, ServiceError> {
        match self.content_for(class).call(&content::Req::Release {
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
