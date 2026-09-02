//! WebSocket/TLS, SOCKS5 per traffic class, Hysteria scheduler.
//!
//! layer 4, zone `io` — see `docs/layering.toml`.
//!
//! The only crate below `spark-client` that is allowed to touch the network.
//! Everything beneath it is `pure`, which is what lets gates 2 through 8 run with
//! no server in existence.
//!
//! # What is here, and what is not
//!
//! Here: the routing policy (`Spark-spec.md` D2), SOCKS5 with per-circuit stream
//! isolation, and a ledger of every connection opened. The ledger is not
//! diagnostics — it is how gate 9's "shows zero direct connections" is checkable
//! at all, and it is why `Connector` is a trait rather than a call to `TcpStream`.
//!
//! Also here: [`hysteria`], the fixed-schedule cover traffic of `Spark-spec.md` F12.
//!
//! Not here yet, and stated rather than implied: WebSocket framing and TLS.
//! `docs/protocol.md` §6 specifies both. Gate 9 is about *where* connections go,
//! and that is decided before a byte of TLS is written, so this ships the routing
//! and leaves the framing for the client stage.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod hysteria;
pub mod push;
pub mod route;
pub mod socks;

pub use hysteria::{Availability, Frame, Hysteria, HysteriaError, Platform, Reassembler};
pub use push::{PushDisabled, Registration, Setting, Wake};
pub use route::{Class, Mode};
pub use socks::SocksError;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Where a connection actually went.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hop {
    /// What it was carrying.
    pub class: Class,
    /// The host that was asked for.
    pub host: String,
    /// The port.
    pub port: u16,
    /// Whether it went through the proxy.
    pub via_tor: bool,
}

/// Every connection this transport has opened.
///
/// Exists so "always-on mode shows zero direct connections" is a statement about
/// observed behaviour rather than about the routing table. A test that checked
/// only `Mode::uses_tor` would pass while the code ignored it.
#[derive(Clone, Default)]
pub struct Ledger(Arc<Mutex<Vec<Hop>>>);

impl Ledger {
    /// Every hop, in order.
    pub fn hops(&self) -> Vec<Hop> {
        self.0.lock().expect("ledger lock").clone()
    }
    /// The hops that did not go through Tor.
    pub fn direct(&self) -> Vec<Hop> {
        self.hops().into_iter().filter(|h| !h.via_tor).collect()
    }
    fn record(&self, h: Hop) {
        self.0.lock().expect("ledger lock").push(h);
    }
}

/// Opens byte streams to an address. The seam the network sits behind.
pub trait Connector {
    /// The stream this connector produces.
    type Stream: Read + Write;
    /// Connect to `host:port`.
    ///
    /// For a direct hop this resolves and connects. For a proxied hop the caller
    /// passes the *proxy's* address, and the real hostname never reaches here —
    /// it goes inside the SOCKS5 request so the proxy resolves it.
    fn connect(&self, host: &str, port: u16) -> std::io::Result<Self::Stream>;
}

/// Routes connections by traffic class.
pub struct Transport<C: Connector> {
    mode: Mode,
    proxy: (String, u16),
    connector: C,
    ledger: Ledger,
    counter: Arc<std::sync::atomic::AtomicU64>,
}

impl<C: Connector> Transport<C> {
    /// A transport in `mode`, using `proxy` as the SOCKS5 endpoint.
    pub fn new(mode: Mode, proxy: (String, u16), connector: C) -> Self {
        Self {
            mode,
            proxy,
            connector,
            ledger: Ledger::default(),
            counter: Default::default(),
        }
    }

    /// The current mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The connection ledger.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Change mode.
    ///
    /// `Spark-spec.md` D2: "Switching from off to on undoes nothing, because the
    /// server already recorded the IP against the keyring label." The ledger is
    /// deliberately not cleared here — what already happened is what the client
    /// needs in order to say so.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Open a stream for one request.
    ///
    /// `class` is required rather than inferred. A request whose class nobody
    /// decided is a request routed by accident, and the accident is always the
    /// same one: media escaping in a mode the user believed covered it.
    pub fn open(&self, class: Class, host: &str, port: u16) -> Result<C::Stream, TransportError> {
        let via_tor = self.mode.uses_tor(class);
        let result = if via_tor {
            let mut s = self
                .connector
                .connect(&self.proxy.0, self.proxy.1)
                .map_err(|_| TransportError::Socks(SocksError::Io))?;
            socks::connect(&mut s, host, port, &self.isolation(class))?;
            Ok(s)
        } else {
            self.connector
                .connect(host, port)
                .map_err(|_| TransportError::Direct)
        };

        // Recorded only on success: a refused connection carried nothing, and
        // counting it as a direct hop would make the gate fail for the wrong
        // reason.
        if result.is_ok() {
            self.ledger.record(Hop {
                class,
                host: host.to_string(),
                port,
                via_tor,
            });
        }
        result
    }

    /// The isolation token for the next circuit.
    ///
    /// Per request, not per class: two fetches in the same class sharing a circuit
    /// lets an exit-side observer link them to each other. The class is included
    /// only to make a packet capture readable during development.
    fn isolation(&self, class: Class) -> String {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("{class:?}-{n}").to_lowercase()
    }
}

/// Why a connection could not be opened.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TransportError {
    /// The direct connection failed.
    Direct,
    /// The proxied connection failed.
    Socks(SocksError),
}

impl From<SocksError> for TransportError {
    fn from(e: SocksError) -> Self {
        Self::Socks(e)
    }
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Direct => f.write_str("could not connect"),
            Self::Socks(e) => write!(f, "{e}"),
        }
    }
}
impl core::error::Error for TransportError {}
