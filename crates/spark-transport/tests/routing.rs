//! Gate 9: "Always-on mode shows zero direct connections; mixed mode shows them
//! for media fetches only."
//!
//! Checked against the ledger — what the transport *did* — rather than against the
//! routing table. A test that only asked `Mode::uses_tor` would pass while the
//! code ignored it.

use spark_transport::socks::SocksError;
use spark_transport::*;
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

/// A stream that replays a canned SOCKS5 conversation and records what was
/// written to it, so the bytes on the wire can be inspected.
struct Scripted {
    reply: Cursor<Vec<u8>>,
    wrote: Arc<Mutex<Vec<u8>>>,
    sink: Sent,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reply.read(buf)
    }
}
impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.wrote.lock().unwrap().extend_from_slice(buf);
        if let Some(last) = self.sink.lock().unwrap().last_mut() {
            last.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A well-behaved SOCKS5 proxy: offers username/password, accepts, connects.
fn good_proxy_reply() -> Vec<u8> {
    let mut v = vec![0x05, 0x02]; // greeting: username/password chosen
    v.extend_from_slice(&[0x01, 0x00]); // auth accepted
    v.extend_from_slice(&[0x05, 0x00, 0x00, 0x01]); // CONNECT ok, IPv4 bound addr
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // the bound address and port
    v
}

/// Host and port of every dial the transport made.
type Dialled = Arc<Mutex<Vec<(String, u16)>>>;
/// The bytes written on each connection, one entry per connection.
type Sent = Arc<Mutex<Vec<Vec<u8>>>>;

#[derive(Clone, Default)]
struct Fake {
    dialed: Dialled,
    /// Everything the transport wrote, kept so tests can read the actual SOCKS5
    /// bytes rather than bytes the test made up itself.
    sent: Sent,
    reply: Vec<u8>,
}

impl Connector for Fake {
    type Stream = Scripted;
    fn connect(&self, host: &str, port: u16) -> std::io::Result<Scripted> {
        self.dialed.lock().unwrap().push((host.to_string(), port));
        let wrote = Arc::new(Mutex::new(Vec::new()));
        self.sent.lock().unwrap().push(Vec::new());
        Ok(Scripted {
            reply: Cursor::new(self.reply.clone()),
            wrote,
            sink: self.sent.clone(),
        })
    }
}

fn transport(mode: Mode) -> (Transport<Fake>, Dialled) {
    let f = Fake {
        dialed: Default::default(),
        sent: Default::default(),
        reply: good_proxy_reply(),
    };
    let dialed = f.dialed.clone();
    (Transport::new(mode, ("127.0.0.1".into(), 9050), f), dialed)
}

/// One of everything.
fn exercise(t: &Transport<Fake>) {
    t.open(Class::Control, "keyring.spark.invalid", 443)
        .expect("control");
    t.open(Class::Text, "content.spark.invalid", 443)
        .expect("text");
    t.open(Class::Media, "content.spark.invalid", 443)
        .expect("media");
}

#[test]
fn always_on_shows_zero_direct_connections() {
    let (t, dialed) = transport(Mode::AlwaysOn);
    exercise(&t);

    assert!(
        t.ledger().direct().is_empty(),
        "a connection escaped Tor: {:?}",
        t.ledger().direct()
    );
    assert_eq!(t.ledger().hops().len(), 3);

    // And every dial went to the proxy, never to a destination.
    for (host, port) in dialed.lock().unwrap().iter() {
        assert_eq!(
            (host.as_str(), *port),
            ("127.0.0.1", 9050),
            "a destination was dialled directly"
        );
    }
}

#[test]
fn mixed_mode_shows_direct_connections_for_media_only() {
    let (t, _) = transport(Mode::TextOverTor);
    exercise(&t);

    let direct = t.ledger().direct();
    assert_eq!(
        direct.len(),
        1,
        "expected exactly one direct hop, got {direct:?}"
    );
    assert_eq!(
        direct[0].class,
        Class::Media,
        "something other than media went direct"
    );
}

#[test]
fn always_off_routes_everything_directly() {
    let (t, dialed) = transport(Mode::AlwaysOff);
    exercise(&t);
    assert_eq!(t.ledger().direct().len(), 3);
    assert!(
        dialed
            .lock()
            .unwrap()
            .iter()
            .all(|(h, _)| h.ends_with(".invalid")),
        "a connection went to the proxy in always-off mode"
    );
}

#[test]
fn the_hostname_is_resolved_by_tor_not_locally() {
    // The most common way a Tor integration leaks, and it leaks silently:
    // resolving locally hands every lookup to the ISP's resolver, and the traffic
    // that followed was over Tor for nothing.
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let mut s = Scripted {
        reply: Cursor::new(good_proxy_reply()),
        wrote: wrote.clone(),
        sink: Default::default(),
    };
    spark_transport::socks::connect(&mut s, "content.spark.invalid", 443, "text-0").unwrap();

    let sent = wrote.lock().unwrap().clone();
    // ATYP 0x03 is "domain name". 0x01 would be an IPv4 address, meaning the
    // client resolved it.
    let connect_req = sent.windows(4).position(|w| w == [0x05, 0x01, 0x00, 0x03]);
    assert!(
        connect_req.is_some(),
        "CONNECT did not use domain-name addressing"
    );
    assert!(
        sent.windows(21).any(|w| w == b"content.spark.invalid"),
        "the hostname was not sent to the proxy"
    );
}

#[test]
fn each_request_gets_its_own_circuit() {
    // Without per-request isolation every request shares one circuit, and an
    // exit-side observer can link them to each other even without an IP. This
    // reads the credentials the transport actually sent, not ones the test made up.
    let f = Fake {
        dialed: Default::default(),
        sent: Default::default(),
        reply: good_proxy_reply(),
    };
    let sent = f.sent.clone();
    let t = Transport::new(Mode::AlwaysOn, ("127.0.0.1".into(), 9050), f);

    for _ in 0..3 {
        t.open(Class::Text, "content.spark.invalid", 443).unwrap();
    }

    // RFC 1929: 0x01, ulen, username, plen, password. Pull each username out.
    let mut users: Vec<Vec<u8>> = Vec::new();
    for conv in sent.lock().unwrap().iter() {
        let at = conv
            .windows(3)
            .position(|w| w == [0x05, 0x01, 0x02])
            .expect("greeting");
        let auth = at + 3;
        assert_eq!(conv[auth], 0x01, "not an RFC 1929 auth message");
        let ulen = conv[auth + 1] as usize;
        users.push(conv[auth + 2..auth + 2 + ulen].to_vec());
    }
    assert_eq!(users.len(), 3);
    let n = users.len();
    users.sort();
    users.dedup();
    assert_eq!(
        users.len(),
        n,
        "two requests presented the same isolation credentials"
    );
}

#[test]
fn a_proxy_that_refuses_isolation_is_refused_in_turn() {
    // Falling back to no-auth would mean every request sharing one circuit while
    // the user was told otherwise. Better to fail loudly (build-notes §1: never
    // silently downgrade a privacy setting).
    let wrote = Arc::new(Mutex::new(Vec::new()));
    // 0x00 = "no authentication required", which Tor would accept but which
    // gives no stream isolation.
    let mut s = Scripted {
        reply: Cursor::new(vec![0x05, 0x00]),
        wrote,
        sink: Default::default(),
    };
    assert_eq!(
        spark_transport::socks::connect(&mut s, "h.invalid", 1, "text-0").unwrap_err(),
        SocksError::NoIsolation
    );
}

#[test]
fn a_failed_connection_is_not_recorded_as_a_hop() {
    // A refused connection carried nothing. Counting it would make gate 9 fail
    // for the wrong reason, and make a real leak harder to spot in the ledger.
    struct Refusing;
    impl Connector for Refusing {
        type Stream = Cursor<Vec<u8>>;
        fn connect(&self, _: &str, _: u16) -> std::io::Result<Self::Stream> {
            Err(std::io::Error::other("refused"))
        }
    }
    let t = Transport::new(Mode::AlwaysOff, ("127.0.0.1".into(), 9050), Refusing);
    assert!(t.open(Class::Media, "h.invalid", 443).is_err());
    assert!(
        t.ledger().hops().is_empty(),
        "a failed connection was recorded"
    );
}

#[test]
fn switching_mode_does_not_erase_what_already_happened() {
    // D2: "Switching from off to on undoes nothing, because the server already
    // recorded the IP against the keyring label." The client needs the ledger in
    // order to be able to say so.
    let (mut t, _) = transport(Mode::AlwaysOff);
    t.open(Class::Control, "keyring.spark.invalid", 443)
        .unwrap();
    assert_eq!(t.ledger().direct().len(), 1);

    t.set_mode(Mode::AlwaysOn);
    t.open(Class::Control, "keyring.spark.invalid", 443)
        .unwrap();
    assert_eq!(
        t.ledger().direct().len(),
        1,
        "turning Tor on rewrote history"
    );
    assert_eq!(t.ledger().hops().len(), 2);
}

#[test]
fn the_policy_is_exhaustive_and_the_default_is_mixed() {
    assert_eq!(Mode::default(), Mode::TextOverTor);
    for class in [Class::Control, Class::Text, Class::Media] {
        assert!(Mode::AlwaysOn.uses_tor(class));
        assert!(!Mode::AlwaysOff.uses_tor(class));
    }
    assert!(Mode::TextOverTor.uses_tor(Class::Control));
    assert!(Mode::TextOverTor.uses_tor(Class::Text));
    assert!(!Mode::TextOverTor.uses_tor(Class::Media));

    // Every mode says what it costs, in the user's terms.
    for m in [Mode::AlwaysOn, Mode::AlwaysOff, Mode::TextOverTor] {
        assert!(
            m.describe().len() > 20,
            "{m:?} has no explanation for the user"
        );
    }
}

#[test]
fn a_hostname_socks5_cannot_carry_is_refused() {
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let mut s = Scripted {
        reply: Cursor::new(good_proxy_reply()),
        wrote,
        sink: Default::default(),
    };
    let long = "a".repeat(256);
    assert_eq!(
        spark_transport::socks::connect(&mut s, &long, 1, "t").unwrap_err(),
        SocksError::BadHost
    );
}
