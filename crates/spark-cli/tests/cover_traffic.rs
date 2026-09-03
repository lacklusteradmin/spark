//! Cover traffic on a live connection.
//!
//! `crates/spark-transport/tests/hysteria.rs` checks the scheduler in isolation.
//! This checks that it is *connected to anything* — the same gap that had the
//! routing, the SOCKS5 and the traffic classes each passing their own gate while
//! the real client connected straight out.
//!
//! Everything here runs over the deployment's actual TLS, and the sizes observed
//! are the sizes on the socket: what a passive observer sees, ciphertext and all.
//! Measuring plaintext frames instead would be measuring our own intent.

#[path = "../src/certs.rs"]
#[allow(dead_code)]
mod certs;
#[path = "../src/serve.rs"]
#[allow(dead_code)]
mod serve;

use spark_crypto::{IssuerKey, Secret};
use spark_store::Db;
use spark_transport::hysteria::FRAME_BYTES;
use spark_transport::{Channel, Class, Immediate, Paced};
use spark_wire::keyring;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

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

/// One thing that crossed the socket, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ev {
    Sent(usize),
    Received(usize),
}

type Wire = Arc<Mutex<Vec<Ev>>>;

/// Bytes the peer sent back after each of our transmissions.
///
/// A single `read` is not a single transmission: rustls reads into a fixed buffer,
/// so one 4122-byte record arrives as 4096 + 26. That split is our buffer size, not
/// anything an observer sees. The protocol is lock-step — one frame out, one frame
/// back — so summing the reads between two writes reconstructs what the peer
/// actually sent for that slot.
fn replies(wire: &[Ev]) -> Vec<usize> {
    let mut out = Vec::new();
    for ev in wire {
        match ev {
            Ev::Sent(_) => out.push(0),
            Ev::Received(n) => *out.last_mut().expect("a reply before any request") += n,
        }
    }
    out
}

fn sends(wire: &[Ev]) -> Vec<usize> {
    wire.iter()
        .filter_map(|e| match e {
            Ev::Sent(n) => Some(*n),
            Ev::Received(_) => None,
        })
        .collect()
}

/// A TCP stream that records the size of every read and write.
///
/// It sits *under* TLS, so what it records is what crosses the wire. Not the
/// contents — those are encrypted, and a test that read them would be checking
/// something no observer can see.
struct Observed {
    inner: std::net::TcpStream,
    wire: Wire,
}

impl Read for Observed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.wire.lock().unwrap().push(Ev::Received(n));
        }
        Ok(n)
    }
}
impl Write for Observed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.wire.lock().unwrap().push(Ev::Sent(buf.len()));
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Deployment {
    addr: String,
    pin: spark_transport::Pin,
}

fn deployment() -> Deployment {
    let keyring = Arc::new(spark_keyring_server::Keyring::new(
        Db::new(),
        Secret::new([0x5e; 32]),
        IssuerKey::generate(&mut Fixed(1)).unwrap(),
    ));
    keyring.set_minute(1);
    let id = certs::generate("spark.local").expect("server identity");
    let pin = id.pin;
    let key = rustls_pki_types::PrivateKeyDer::try_from(id.key).expect("key");
    let tls = Arc::new(spark_transport::tls::server_config(id.cert, key).expect("tls"));
    let k = serve::keyring_service("127.0.0.1:0", tls, keyring).unwrap();
    Deployment {
        addr: k.addr.to_string(),
        pin,
    }
}

/// A paced connection, plus the byte sizes crossing its socket.
///
/// The recorders are cleared once the connection is up. The TLS handshake and the
/// WebSocket upgrade are a one-time setup phase that happens identically whether
/// the connection goes on to say anything or not, so leaving them in would just
/// add the same prefix to every measurement.
type Tls = rustls::StreamOwned<rustls::ClientConnection, Observed>;

fn connect(d: &Deployment) -> (Paced<Tls, Immediate>, Wire) {
    let wire: Wire = Default::default();
    let tcp = std::net::TcpStream::connect(&d.addr).unwrap();
    // So that a server which answers a dummy with silence fails the test instead of
    // hanging it. Well above the pacing interval, so it never fires on a slot that
    // is merely waiting its turn.
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let stream = Observed {
        inner: tcp,
        wire: wire.clone(),
    };
    let tls = Arc::new(spark_transport::tls::client_config(vec![d.pin]).unwrap());
    let name = rustls_pki_types::ServerName::try_from("spark.local").unwrap();
    let conn = rustls::ClientConnection::new(tls, name).unwrap();
    let ch = Channel::connect(rustls::StreamOwned::new(conn, stream), "ws://spark.local/").unwrap();
    wire.lock().unwrap().clear();
    (Paced::new(ch, Immediate), wire)
}

#[test]
fn a_paced_connection_carries_a_real_request() {
    // Before anything about indistinguishability: it has to work at all. A cover
    // stream that answered nothing would pass every test below.
    let d = deployment();
    let (mut p, _) = connect(&d);
    let r: keyring::Resp = p
        .call(Class::Control, &keyring::Req::Challenge { addr: [7; 32] })
        .unwrap();
    assert!(matches!(r, keyring::Resp::Challenge(_)));
    assert!(p.slots() >= 1);
}

#[test]
fn every_transmission_is_the_same_size_in_both_directions() {
    // `Spark-spec.md` F12: every transmission is padded to a uniform size and sent
    // to the same endpoint, since an observer who can spot a dummy by length or
    // destination gets the timing back for free.
    //
    // Both directions, because the client's cadence buys nothing if a 4 KB request
    // comes back as a reply whose length says what it was.
    let d = deployment();
    let (mut p, wire) = connect(&d);

    for _ in 0..5 {
        let _: keyring::Resp = p
            .call(Class::Control, &keyring::Req::Challenge { addr: [1; 32] })
            .unwrap();
    }

    let wire = wire.lock().unwrap().clone();
    let out = sends(&wire);
    assert!(!out.is_empty(), "nothing was transmitted");
    assert!(
        out.windows(2).all(|w| w[0] == w[1]),
        "outbound sizes varied: {out:?}"
    );
    assert!(
        out[0] >= FRAME_BYTES,
        "a transmission was smaller than one frame"
    );

    let back = replies(&wire);
    assert!(!back.is_empty(), "the server said nothing");
    assert!(
        back.windows(2).all(|w| w[0] == w[1]),
        "the server's replies varied: {back:?}"
    );
    assert!(back[0] >= FRAME_BYTES, "a reply was smaller than one frame");
}

#[test]
fn an_idle_connection_and_a_busy_one_look_the_same() {
    // The claim the whole mode exists for. One connection carries five real
    // requests; the other carries none and only turns its slots. An observer
    // counting bytes must not be able to say which was which.
    let d = deployment();

    let (mut busy, busy_wire) = connect(&d);
    for _ in 0..5 {
        let _: keyring::Resp = busy
            .call(Class::Control, &keyring::Req::Challenge { addr: [2; 32] })
            .unwrap();
    }

    let (mut idle, idle_wire) = connect(&d);
    for _ in 0..busy.slots() {
        idle.turn_slot().unwrap();
    }

    let (b, i) = (
        busy_wire.lock().unwrap().clone(),
        idle_wire.lock().unwrap().clone(),
    );
    assert!(!b.is_empty());
    assert_eq!(
        sends(&b),
        sends(&i),
        "an observer could tell the busy connection from the idle one"
    );

    // And the same of what came back: a server that answered dummies with silence
    // would make dummies recognisable, which is the client's whole cadence undone
    // from the other end.
    assert_eq!(
        replies(&b),
        replies(&i),
        "the replies gave away which connection was busy"
    );
}

#[test]
fn media_does_not_travel_in_the_stream() {
    // `Spark-spec.md` D12. A one-minute cadence over a photo is not a slower photo,
    // it is a photo that never arrives.
    let d = deployment();
    let (mut p, _) = connect(&d);
    let r: Result<keyring::Resp, _> =
        p.call(Class::Media, &keyring::Req::Challenge { addr: [3; 32] });
    assert!(r.is_err(), "media was accepted into the cover stream");
}
