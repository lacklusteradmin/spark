//! The FFI surface, against a real deployment.
//!
//! This test lives in `spark-cli` because it needs servers, and `spark-cli` is
//! where servers get wired up. What it exercises is `spark-ffi`: the same calls a
//! Swift or Kotlin app would make, in the same order, with nothing but bytes and
//! strings crossing.

#[path = "../src/certs.rs"]
#[allow(dead_code)]
mod certs;
#[path = "../src/serve.rs"]
#[allow(dead_code)]
mod serve;

use spark_crypto::{IssuerKey, Mnemonic, Secret};
use spark_ffi::{Config, Session};
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

fn deployment() -> Config {
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
    keyring.set_refund_keys(content.refund_keys());
    let issuer = Arc::new(spark_issuer::Issuer::new(
        Db::new(),
        IssuerKey::generate(&mut Fixed(2)).unwrap(),
    ));
    let id = certs::generate("spark.local").expect("server identity");
    let pin = id.pin;
    let key = rustls_pki_types::PrivateKeyDer::try_from(id.key).expect("key");
    let tls = Arc::new(spark_transport::tls::server_config(id.cert, key).expect("tls"));

    let k = serve::keyring_service("127.0.0.1:0", tls.clone(), keyring).unwrap();
    let c = serve::content_service("127.0.0.1:0", tls.clone(), content).unwrap();
    let i = serve::issuer_service("127.0.0.1:0", tls, issuer).unwrap();
    Config {
        keyring: k.addr.to_string(),
        content: c.addr.to_string(),
        issuer: i.addr.to_string(),
        pins: vec![pin.to_hex()],
        tor: "off".into(),
        cover_seconds: 0,
        proxy: "127.0.0.1:9050".into(),
    }
}

fn phrase(seed: u8) -> String {
    Mnemonic::from_entropy(&[seed; 32]).phrase().to_string()
}

#[test]
fn a_foreign_caller_holds_a_whole_conversation() {
    // Everything below crosses as String, Vec<u8> or u64. Nothing here names a
    // key, a mnemonic, an address type or an RNG — which is the point: this is
    // what the boundary zone's ban on cryptographic crates leaves a caller able
    // to do, and it has to be enough to run the product.
    let cfg = deployment();
    let alice = Session::open(&phrase(1), &cfg).expect("alice");
    let bob = Session::open(&phrase(2), &cfg).expect("bob");

    let room = alice.create_room("the crossing").expect("create");
    let kp = bob.key_package().expect("key package");
    let invitation = alice.invite(&room, &kp).expect("invite");

    // The invitation crosses as opaque bytes, which is how it would reach a
    // joiner in reality — through a channel the two people already trust.
    let joined = bob.accept(&invitation, "the crossing").expect("accept");
    assert_eq!(joined, room, "the joiner landed in a different room");

    alice.send(&room, b"from alice").expect("send");
    bob.send(&room, b"from bob").expect("send");

    // Neither send saw the other, so the two are concurrent and their order is
    // the deterministic tiebreak rather than the order they were written. What is
    // promised is that both sides agree, not that either matches wall-clock — so
    // that is what gets asserted. Sorting first would hide a disagreement, which
    // is the failure worth catching.
    let seen = bob.sync(&room, 4).expect("bob sync");
    let mine = alice.sync(&room, 4).expect("alice sync");

    let bodies = |v: &[spark_ffi::Note]| v.iter().map(|n| n.body.clone()).collect::<Vec<_>>();
    assert_eq!(
        bodies(&seen),
        bodies(&mine),
        "the two sides ordered history differently"
    );
    let mut sorted = bodies(&seen);
    sorted.sort();
    assert_eq!(
        sorted,
        [b"from alice".to_vec(), b"from bob".to_vec()],
        "a message was lost"
    );

    // Authorship, checked against something rather than against itself: both
    // parties must agree on who wrote which, and the two authors must differ. A
    // `from` field that was constant, or that echoed the reader, would fail one
    // of these.
    assert_eq!(
        seen.iter().map(|n| n.from.clone()).collect::<Vec<_>>(),
        mine.iter().map(|n| n.from.clone()).collect::<Vec<_>>(),
        "the two sides disagree about who wrote what"
    );
    assert_ne!(
        seen[0].from, seen[1].from,
        "both messages came back with one author"
    );
    assert_eq!(seen[0].from.len(), 32);

    // A file, whose capability is the only thing that comes back: the caller can
    // carry it but has nothing to construct one with.
    let mut photo = vec![0xFF, 0xD8];
    photo.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    photo.extend_from_slice(b"PIXELDATA");
    photo.extend_from_slice(&[0xFF, 0xD9]);
    let handle = alice.share_file(&room, &photo).expect("share");
    assert_eq!(handle.name.len(), 32);
    assert_eq!(handle.key.len(), 32);
    assert_eq!(bob.fetch_file(&handle).expect("fetch"), photo);

    assert_eq!(alice.rooms().unwrap().len(), 1);
    assert_eq!(alice.rooms().unwrap()[0].name, "the crossing");
    assert!(!alice.address().unwrap().is_empty());
    assert!(alice.bytes_held().unwrap() > 0);
}

#[test]
fn malformed_input_is_refused_rather_than_panicking() {
    // Everything here arrives from a foreign language with no type system in
    // common. A panic would cross the FFI, which is undefined on most toolchains,
    // so every shape mistake has to come back as an error.
    let cfg = deployment();
    let s = Session::open(&phrase(3), &cfg).expect("open");
    let room = s.create_room("r").expect("create");

    assert!(
        s.send(b"not-16-bytes", b"x").is_err(),
        "a short room id was accepted"
    );
    assert!(s.sync(&[], 1).is_err(), "an empty room id was accepted");

    // The case that distinguishes "validated" from "padded or truncated to fit".
    // A short id becomes a room that does not exist and fails either way, so it
    // proves nothing on its own; an id one byte too long, truncated, lands on a
    // room that *does* exist and the write goes somewhere the caller did not name.
    let mut too_long = room.clone();
    too_long.push(0);
    assert!(
        s.send(&too_long, b"x").is_err(),
        "an over-long room id was truncated onto a real room"
    );
    assert!(
        s.sync(&too_long, 1).is_err(),
        "an over-long room id was truncated onto a real room"
    );
    assert!(
        s.accept(b"\xff\xff\xff", "r").is_err(),
        "garbage parsed as an invitation"
    );
    assert!(
        s.fetch_file(&spark_ffi::FileHandle {
            name: vec![0; 4],
            key: vec![0; 32]
        })
        .is_err(),
        "a short chunk name was accepted"
    );
    assert!(
        s.invite(&room, b"not a key package").is_err(),
        "garbage accepted as a key package"
    );
}

#[test]
fn a_bad_configuration_is_refused_before_anything_connects() {
    let cfg = deployment();
    for (field, broken) in [
        (
            "tor",
            Config {
                tor: "maybe".into(),
                ..cfg.clone()
            },
        ),
        (
            "pins",
            Config {
                pins: vec!["nonsense".into()],
                ..cfg.clone()
            },
        ),
        (
            "proxy",
            Config {
                proxy: "no-port".into(),
                ..cfg.clone()
            },
        ),
        (
            "pins-empty",
            Config {
                pins: vec![],
                ..cfg.clone()
            },
        ),
    ] {
        assert!(
            Session::open(&phrase(4), &broken).is_err(),
            "a bad `{field}` was accepted"
        );
    }
    // And the unbroken one still works, so the loop above is not passing by
    // failing for some unrelated reason.
    assert!(Session::open(&phrase(4), &cfg).is_ok());
}
