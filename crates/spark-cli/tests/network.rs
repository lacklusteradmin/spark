//! The client over a real socket.
//!
//! Same client, same server logic, a TCP connection and the wire format of
//! `docs/protocol.md` §6 in between. The point is that it behaves identically:
//! if the client works in-process and not over the wire, one of the two is wrong,
//! and every earlier gate was testing the wrong one.

#[path = "../src/certs.rs"]
#[allow(dead_code)]
mod certs;
#[path = "../src/remote.rs"]
#[allow(dead_code)]
mod remote;
#[path = "../src/serve.rs"]
#[allow(dead_code)]
mod serve;

use remote::{Cover, Remote};
use spark_client::Client;
use spark_crypto::{IssuerKey, Mnemonic, Secret};
use spark_store::Db;
use std::sync::Arc;

struct Fixed(u64);
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

/// A deployment: three listeners and the pin a client needs to reach them.
struct Deployment {
    keyring: String,
    content: String,
    issuer: String,
    pin: spark_transport::Pin,
}

/// Stand up all three services on loopback.
fn deployment() -> Deployment {
    let keyring = Arc::new(spark_keyring_server::Keyring::new(
        Db::new(),
        Secret::new([0x5e; 32]),
        IssuerKey::generate(&mut Fixed(1)).unwrap(),
    ));
    keyring.set_minute(1);
    let content = Arc::new(spark_content_server::Content::with_keys(
        Db::new(),
        keyring.accepted_keys(),
    ));
    let issuer = Arc::new(spark_issuer::Issuer::new(
        Db::new(),
        IssuerKey::generate(&mut Fixed(2)).unwrap(),
    ));

    let id = certs::generate("spark.local").expect("server identity");
    let pin = id.pin;
    let key = rustls_pki_types::PrivateKeyDer::try_from(id.key).expect("key");
    let tls = Arc::new(spark_transport::tls::server_config(id.cert, key).expect("tls"));

    // Port 0: the OS picks, so tests can run concurrently without colliding.
    let k = serve::keyring_service("127.0.0.1:0", tls.clone(), keyring).unwrap();
    let c = serve::content_service("127.0.0.1:0", tls.clone(), content).unwrap();
    let i = serve::issuer_service("127.0.0.1:0", tls, issuer).unwrap();
    Deployment {
        keyring: k.addr.to_string(),
        content: c.addr.to_string(),
        issuer: i.addr.to_string(),
        pin,
    }
}

impl Deployment {
    /// Connect with Tor off.
    ///
    /// Explicit, because the *default* is `TextOverTor` and there is no Tor here.
    /// Defaulting these tests to "off" inside the client would be the failure
    /// `Spark-build-notes.md` §1 names: a privacy setting that quietly does less
    /// than it says. Better that the test states what it is not using.
    fn connect(&self) -> std::io::Result<Remote> {
        self.connect_with(&[self.pin])
    }
    fn connect_with(&self, pins: &[spark_transport::Pin]) -> std::io::Result<Remote> {
        Remote::connect_via(
            &self.keyring,
            &self.content,
            &self.issuer,
            pins,
            spark_transport::Mode::AlwaysOff,
            Cover::Off,
            ("127.0.0.1".into(), 0),
        )
    }
    /// Connect with cover traffic on.
    ///
    /// A short interval, not F12's minute: this runs a whole session, and the
    /// claim under test is that pacing carries real traffic correctly, not how
    /// long a slot is. `crates/spark-cli/tests/cover_traffic.rs` is what checks
    /// what the pacing actually hides.
    fn connect_paced(&self) -> std::io::Result<Remote> {
        Remote::connect_via(
            &self.keyring,
            &self.content,
            &self.issuer,
            &[self.pin],
            spark_transport::Mode::AlwaysOff,
            Cover::Every(std::time::Duration::from_millis(1)),
            ("127.0.0.1".into(), 0),
        )
    }
    /// Connect through `proxy`, with everything over Tor.
    fn connect_via_tor(&self, proxy: (String, u16)) -> std::io::Result<Remote> {
        Remote::connect_via(
            &self.keyring,
            &self.content,
            &self.issuer,
            &[self.pin],
            spark_transport::Mode::AlwaysOn,
            Cover::Off,
            proxy,
        )
    }
}

/// What the proxy was asked for: `(isolation token, destination)` per connection.
type ProxyLog = Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// A SOCKS5 proxy, enough of one to stand in for Tor.
///
/// Real enough to matter: it insists on username/password (which is how Tor gives
/// each request its own circuit), reads the destination as a *name*, resolves it
/// itself, and records what it was asked for. A test against a proxy that skipped
/// any of that would not be testing the thing that goes wrong.
fn socks5_proxy() -> (u16, ProxyLog) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: ProxyLog = Default::default();
    let log = seen.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut c) = stream else { break };
            let log = log.clone();
            std::thread::spawn(move || {
                // Greeting: the client must offer username/password (0x02).
                let mut g = [0u8; 2];
                if c.read_exact(&mut g).is_err() || g[0] != 5 {
                    return;
                }
                let mut methods = vec![0u8; g[1] as usize];
                if c.read_exact(&mut methods).is_err() || !methods.contains(&0x02) {
                    let _ = c.write_all(&[5, 0xFF]);
                    return;
                }
                let _ = c.write_all(&[5, 0x02]);

                // RFC 1929: the username is the isolation token.
                let mut h = [0u8; 2];
                if c.read_exact(&mut h).is_err() {
                    return;
                }
                let mut user = vec![0u8; h[1] as usize];
                if c.read_exact(&mut user).is_err() {
                    return;
                }
                let mut pl = [0u8; 1];
                let _ = c.read_exact(&mut pl);
                let mut pw = vec![0u8; pl[0] as usize];
                let _ = c.read_exact(&mut pw);
                let _ = c.write_all(&[1, 0]);

                // CONNECT, by domain name.
                let mut r = [0u8; 4];
                if c.read_exact(&mut r).is_err() || r[1] != 1 || r[3] != 3 {
                    return;
                }
                let mut l = [0u8; 1];
                let _ = c.read_exact(&mut l);
                let mut host = vec![0u8; l[0] as usize];
                let _ = c.read_exact(&mut host);
                let mut p = [0u8; 2];
                let _ = c.read_exact(&mut p);
                let host = String::from_utf8_lossy(&host).into_owned();
                let port = u16::from_be_bytes(p);

                log.lock().unwrap().push((
                    String::from_utf8_lossy(&user).into_owned(),
                    format!("{host}:{port}"),
                ));

                let Ok(upstream) = std::net::TcpStream::connect((host.as_str(), port)) else {
                    let _ = c.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return;
                };
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

                // Pump both ways until either end closes.
                let (mut a, mut b) = (c.try_clone().unwrap(), upstream.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut a, &mut b);
                });
                let (mut a, mut b) = (upstream, c);
                let _ = std::io::copy(&mut a, &mut b);
            });
        }
    });
    (port, seen)
}

fn phrase(e: u8) -> Mnemonic {
    Mnemonic::from_entropy(&[e; 32])
}

#[test]
fn a_conversation_works_over_the_wire() {
    let d = deployment();
    let sa = d.connect().expect("alice connects");
    let sb = d.connect().expect("bob connects");

    let mut rng = Fixed(9);
    let mut alice = Client::from_mnemonic(&phrase(1), sa).unwrap();
    let mut bob = Client::from_mnemonic(&phrase(2), sb).unwrap();

    let room = alice.create_room(&mut rng, "the crossing").unwrap();
    let kp = bob.key_package().unwrap();
    let inv = alice.invite(&mut rng, room, &kp).unwrap();
    bob.accept(&mut rng, &inv, "the crossing").unwrap();

    let script = [
        (0, "the boat leaves at six"),
        (1, "understood"),
        (0, "do not be late"),
    ];
    for (who, text) in script {
        if who == 0 {
            alice.sync(room, 3).unwrap();
            alice.send(&mut rng, room, text.as_bytes()).unwrap();
        } else {
            bob.sync(room, 3).unwrap();
            bob.send(&mut rng, room, text.as_bytes()).unwrap();
        }
    }

    let seen: Vec<String> = alice
        .sync(room, 3)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(
        seen,
        script
            .iter()
            .map(|(_, t)| t.to_string())
            .collect::<Vec<_>>()
    );

    let bobs: Vec<String> = bob
        .sync(room, 3)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(seen, bobs, "the two clients disagree over the wire");
}

#[test]
fn a_wiped_client_recovers_over_the_wire() {
    let d = deployment();
    let mut rng = Fixed(9);

    let before: Vec<String> = {
        let s = d.connect().unwrap();
        let mut a = Client::from_mnemonic(&phrase(1), s).unwrap();
        let room = a.create_room(&mut rng, "r").unwrap();
        a.send(&mut rng, room, b"the boat leaves at six").unwrap();
        a.sync(room, 3)
            .unwrap()
            .into_iter()
            .map(|m| String::from_utf8(m.body).unwrap())
            .collect()
    };

    // Everything local is gone, including the connection. Twenty-four words and a
    // network address are all that survive.
    let s = d.connect().unwrap();
    let mut restored = Client::from_mnemonic(&phrase(1), s).unwrap();
    assert_eq!(
        restored.rooms().len(),
        1,
        "the room did not come back over the wire"
    );
    let room = restored.rooms()[0].0;
    let after: Vec<String> = restored
        .sync(room, 3)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(after, before);
}

#[test]
fn a_wrong_key_is_refused_over_the_wire_too() {
    // The auth check is the server's, and it must still be the server's after the
    // request has been through a codec. A conversion that dropped or defaulted a
    // field would show up here and nowhere else.
    let d = deployment();
    let s = d.connect().unwrap();

    let alice = spark_identity::Identity::from_mnemonic(&phrase(1));
    let bob = spark_identity::Identity::from_mnemonic(&phrase(2));
    let addr = *alice.addr().as_bytes();

    use spark_client::KeyringService;
    let forged = spark_client::Auth {
        addr,
        key: *bob.public().sign.as_bytes(),
        sig: *bob.sign(&s.challenge(&addr)).as_bytes(),
    };
    assert_eq!(
        s.snapshot(&forged).unwrap_err(),
        spark_client::ServiceError::Refused
    );
}

#[test]
fn a_malformed_frame_does_not_take_the_server_down() {
    // One connection's misbehaviour ends that connection and nothing else.
    let d = deployment();
    {
        use std::io::Write;
        let mut raw = std::net::TcpStream::connect(&d.keyring).unwrap();
        let _ = raw.write_all(b"this is not a websocket handshake\r\n\r\n");
    }
    // The service is still there.
    let s = d.connect().expect("service survived a bad connection");
    let mut rng = Fixed(9);
    let mut a = Client::from_mnemonic(&phrase(3), s).unwrap();
    assert!(a.create_room(&mut rng, "still working").is_ok());
}

#[test]
fn a_client_will_not_speak_to_an_unpinned_server() {
    // The whole reason for pinning. A server presenting *any* other key — including
    // one a certificate authority would happily vouch for — is not this server.
    let d = deployment();
    let impostor = certs::generate("spark.local").expect("a different key entirely");
    assert_ne!(
        impostor.pin, d.pin,
        "the fixture generated the same key twice"
    );

    assert!(
        d.connect_with(&[impostor.pin]).is_err(),
        "a client accepted a server whose key it had not pinned"
    );
    // And with the right pin it connects, so the failure above is the pin and not
    // something else broken.
    assert!(d.connect().is_ok());
}

#[test]
fn a_client_with_nothing_pinned_is_refused_before_it_connects() {
    // "Before it connects" is the claim, and it needs checking at the config, not
    // at the socket. An empty pin set also fails during the handshake — it matches
    // nothing — so asserting only that connecting fails would pass whether the
    // check existed or not, and would keep passing if someone later "fixed" the
    // empty case by falling back to the WebPKI.
    assert_eq!(
        spark_transport::tls::client_config(vec![]).unwrap_err(),
        spark_transport::TlsError::NoPins
    );

    let d = deployment();
    assert!(
        d.connect_with(&[]).is_err(),
        "a client with no pins was allowed to connect"
    );
}

#[test]
fn presenting_the_pinned_certificate_without_holding_its_key_gets_nowhere() {
    // The half of the verifier that is not pinning: checking that the peer holds
    // the key, not merely that it can show the certificate. A certificate is
    // public, so without this an attacker who copied one off the wire would pass.
    //
    // rustls refuses to build a server that presents a certificate it has no key
    // for, which is where this particular attack dies. That is a real defence and
    // it is rustls's, not ours — worth knowing, because it means our own
    // `verify_tls*_signature` delegation cannot be exercised from here.
    let victim = certs::generate("spark.local").unwrap();
    let attacker = certs::generate("spark.local").unwrap();
    let wrong_key = rustls_pki_types::PrivateKeyDer::try_from(attacker.key).unwrap();

    assert!(
        spark_transport::tls::server_config(victim.cert, wrong_key).is_err(),
        "a server was built presenting a certificate it holds no key for"
    );
}

#[test]
fn a_plaintext_connection_gets_nowhere() {
    // The listener speaks TLS. A peer that opens a WebSocket directly is talking to
    // a handshake it cannot complete, and gets nothing.
    let d = deployment();
    let stream = std::net::TcpStream::connect(&d.keyring).unwrap();
    assert!(
        spark_transport::Channel::connect(stream, "ws://127.0.0.1/").is_err(),
        "a plaintext client completed a WebSocket handshake against a TLS listener"
    );
    // The service is unharmed.
    assert!(d.connect().is_ok());
}

#[test]
fn a_pin_round_trips_through_its_written_form() {
    // A pin is shipped as text, so the text has to be exactly the pin.
    let id = certs::generate("spark.local").unwrap();
    let hex = id.pin.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(spark_transport::Pin::parse(&hex).unwrap(), id.pin);
    assert!(spark_transport::Pin::parse("too short").is_err());

    // Right length, wrong alphabet. Written against a fixed position rather than
    // `replace('a', ..)`, which was the previous version: the pin is a fresh random
    // key each run, so a hex without an 'a' in it left the string untouched and
    // still valid, and the test passed or failed by luck.
    let mut wrong = hex.clone();
    wrong.replace_range(0..1, "z");
    assert_eq!(wrong.len(), 64);
    assert!(spark_transport::Pin::parse(&wrong).is_err());

    // And length alone is not enough to reject on.
    assert!(spark_transport::Pin::parse(&hex[..63]).is_err());
}

#[test]
fn renewing_a_certificate_over_the_same_key_keeps_the_pin() {
    // Why the pin is of the public key rather than the certificate: routine
    // renewal must not require shipping a new pin to every client.
    let key = rcgen::KeyPair::generate().unwrap();
    let mut a = rcgen::CertificateParams::new(vec!["spark.local".into()]).unwrap();
    a.distinguished_name = rcgen::DistinguishedName::new();
    let first = a.self_signed(&key).unwrap();

    let mut b = rcgen::CertificateParams::new(vec!["spark.local".into()]).unwrap();
    b.distinguished_name = rcgen::DistinguishedName::new();
    b.serial_number = Some(rcgen::SerialNumber::from(42u64));
    let second = b.self_signed(&key).unwrap();

    assert_ne!(
        first.der().to_vec(),
        second.der().to_vec(),
        "the certificates are identical"
    );
    assert_eq!(
        spark_transport::Pin::of(first.der()).unwrap(),
        spark_transport::Pin::of(second.der()).unwrap(),
        "renewal changed the pin"
    );
}

#[test]
fn always_on_shows_zero_direct_connections_from_the_real_client() {
    // Gate 9's claim, made true of the *client* rather than of the routing layer in
    // isolation. Before the client went through `Transport`, this passed for
    // `spark-transport` while the client connected straight out — so the Tor
    // setting was a switch that did nothing.
    let d = deployment();
    let (proxy_port, seen) = socks5_proxy();
    let r = d
        .connect_via_tor(("127.0.0.1".into(), proxy_port))
        .expect("connect over the proxy");

    assert!(
        r.ledger().direct().is_empty(),
        "a connection escaped Tor: {:?}",
        r.ledger().direct()
    );
    assert_eq!(
        r.ledger().hops().len(),
        4,
        "expected one hop per service connection"
    );

    // The proxy saw every destination as a *name*, and each connection presented
    // different isolation credentials — a separate circuit each.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4, "the proxy did not carry every connection");
    let mut users: Vec<&String> = seen.iter().map(|(u, _)| u).collect();
    users.sort();
    let n = users.len();
    users.dedup();
    assert_eq!(users.len(), n, "two connections shared a circuit");

    // And the client still works through it.
    let mut rng = Fixed(9);
    let mut a = Client::from_mnemonic(&phrase(1), r).unwrap();
    let room = a.create_room(&mut rng, "over tor").unwrap();
    a.send(&mut rng, room, b"routed").unwrap();
    let seen: Vec<String> = a
        .sync(room, 3)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(seen, ["routed"]);
}

#[test]
fn the_default_mode_sends_media_direct_and_everything_else_over_tor() {
    // D2's default, and its cost: a direct media fetch ties an IP to a
    // content-derived chunk name, and therefore to identifiable content. That is
    // accepted, not overlooked — but it has to actually be *only* media.
    let d = deployment();
    let (proxy_port, _) = socks5_proxy();
    let r = Remote::connect_via(
        &d.keyring,
        &d.content,
        &d.issuer,
        &[d.pin],
        spark_transport::Mode::TextOverTor,
        Cover::Off,
        ("127.0.0.1".into(), proxy_port),
    )
    .expect("connect");

    let direct = r.ledger().direct();
    assert_eq!(
        direct.len(),
        1,
        "expected exactly one direct hop, got {direct:?}"
    );
    assert_eq!(
        direct[0].class,
        spark_transport::Class::Media,
        "something other than media went direct"
    );
}

#[test]
fn a_room_message_and_a_photo_go_on_different_connections() {
    // The claim the ledger cannot check: "media goes direct" is about *requests*,
    // and both content connections point at the same address, so counting
    // connections proves nothing about which one carried what. Routing every chunk
    // over one connection passed every other test here.
    //
    // The dangerous direction is not media taking the slow path — it is a room
    // message taking the media connection, which in the default mode goes direct.
    let d = deployment();
    let r = d.connect().unwrap();
    let mut rng = Fixed(9);

    let mut a = Client::from_mnemonic(&phrase(1), r).unwrap();
    let room = a.create_room(&mut rng, "r").unwrap();
    a.send(&mut rng, room, b"a room message").unwrap();
    let (text_after_message, media_after_message) = a.services().content_calls();
    assert!(
        text_after_message > 0,
        "a room message did not use the text connection"
    );
    assert_eq!(
        media_after_message, 0,
        "a room message used the media connection"
    );

    // A JPEG, which must take the other one.
    let mut photo = vec![0xFF, 0xD8];
    photo.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    photo.extend_from_slice(b"PIXELDATA");
    photo.extend_from_slice(&[0xFF, 0xD9]);
    a.share_file(&mut rng, room, &photo).unwrap();

    let (text, media) = a.services().content_calls();
    assert_eq!(media, 1, "a photo did not use the media connection");
    assert_eq!(
        text, text_after_message,
        "a photo also touched the text connection"
    );
}

#[test]
fn a_paced_client_holds_a_whole_conversation() {
    // The point of this one is that `Cover` is reachable at all. `Transport` spent
    // three stages passing its own tests while the real client connected straight
    // out; cover traffic could have gone the same way — a module, a gate, and no
    // caller. So: the full session, over paced connections, through the network.
    let d = deployment();
    let mut rng = Fixed(9);

    let mut alice = Client::from_mnemonic(
        &Mnemonic::from_entropy(&[11; 32]),
        d.connect_paced().expect("alice"),
    )
    .expect("alice");
    let mut bob = Client::from_mnemonic(
        &Mnemonic::from_entropy(&[12; 32]),
        d.connect_paced().expect("bob"),
    )
    .expect("bob");

    let room = alice.create_room(&mut rng, "paced").expect("room");
    let kp = bob.key_package().expect("key package");
    let inv = alice.invite(&mut rng, room, &kp).expect("invite");
    bob.accept(&mut rng, &inv, "paced").expect("accept");

    alice
        .send(&mut rng, room, b"through the cover")
        .expect("send");
    let got: Vec<String> = bob
        .sync(room, 4)
        .expect("sync")
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(
        got,
        ["through the cover"],
        "a paced client could not carry a real message"
    );

    // And media, which is never paced whatever `cover` said: `Hysteria::enqueue`
    // refuses the class outright, so a paced media connection could not carry
    // anything at all. Sharing a file is what shows that the exception is real
    // rather than a comment.
    let mut photo = vec![0xFF, 0xD8];
    photo.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    photo.extend_from_slice(b"PIXELDATA");
    photo.extend_from_slice(&[0xFF, 0xD9]);
    alice
        .share_file(&mut rng, room, &photo)
        .expect("a paced client could not share a file");

    let (text, media) = alice.services().content_calls();
    assert!(media > 0, "the media connection carried nothing");
    assert!(text > 0, "the text connection carried nothing");

    // And it was actually paced. Without this the test passes just as well when
    // `Cover` is accepted and ignored, because a paced session and an unpaced one
    // deliver the same messages — which is exactly how a routing setting that did
    // nothing survived three stages here.
    let before = alice.services().cover_slots();
    assert!(before > 0, "the client was asked to pace and did not");

    // And the count tracks transmissions rather than merely being paced: every
    // request turns at least one slot, so three more must move it by at least
    // three. A counter that reported a constant would satisfy `> 0` and prove
    // nothing.
    for _ in 0..3 {
        alice.send(&mut rng, room, b"another").expect("send");
    }
    let after = alice.services().cover_slots();
    assert!(
        after >= before + 3,
        "slots went {before} -> {after} across three requests"
    );
    let off = Client::from_mnemonic(&Mnemonic::from_entropy(&[13; 32]), d.connect().unwrap())
        .expect("unpaced");
    assert_eq!(
        off.services().cover_slots(),
        0,
        "an unpaced client turned a slot"
    );
}
