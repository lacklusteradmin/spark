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

use remote::Remote;
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
    fn connect(&self) -> std::io::Result<Remote> {
        Remote::connect(&self.keyring, &self.content, &self.issuer, &[self.pin])
    }
    fn connect_with(&self, pins: &[spark_transport::Pin]) -> std::io::Result<Remote> {
        Remote::connect(&self.keyring, &self.content, &self.issuer, pins)
    }
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
    assert!(spark_transport::Pin::parse(&hex.replace('a', "zz")).is_err());
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
