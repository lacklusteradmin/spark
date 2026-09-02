//! The client, against real services, doing what a person would do.
//!
//! Every gate below this tests one layer. This tests that the layers add up to a
//! messenger — and, more usefully, catches the class of bug that only appears
//! once they are wired together. Both bugs found while writing it were of that
//! kind: neither layer was wrong on its own.

// The same module the binary uses, compiled into this test binary too. Parts the
// binary needs and the tests do not are dead code here, which is a fact about how
// Rust builds tests rather than about the code.
#[path = "../src/wiring.rs"]
#[allow(dead_code)]
mod wiring;

use spark_client::Client;
use spark_crypto::{IssuerKey, Mnemonic};
use wiring::Local;

/// Deterministic, so these tests give the same answer on every machine.
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

fn deployment() -> Local {
    let l = Local::new(
        IssuerKey::generate(&mut Fixed(1)).unwrap(),
        IssuerKey::generate(&mut Fixed(2)).unwrap(),
        [0x5e; 32],
    );
    l.set_minute(1);
    l
}

fn phrase(e: u8) -> Mnemonic {
    Mnemonic::from_entropy(&[e; 32])
}

/// Two accounts in a room, having said `script`.
fn conversation(s: &Local, script: &[(usize, &str)]) -> (spark_keyring::RoomId, Vec<String>) {
    let mut rng = Fixed(9);
    let mut a = Client::from_mnemonic(&phrase(1), s).unwrap();
    let mut b = Client::from_mnemonic(&phrase(2), s).unwrap();

    let room = a.create_room(&mut rng, "the crossing").unwrap();
    let kp = b.key_package().unwrap();
    let inv = a.invite(&mut rng, room, &kp).unwrap();
    b.accept(&mut rng, &inv, "the crossing").unwrap();

    for (who, text) in script {
        let c = if *who == 0 { &mut a } else { &mut b };
        // Read before writing, as a real client does: an entry's vector clock
        // records what its writer had seen.
        c.sync(room, 3).unwrap();
        c.send(&mut rng, room, text.as_bytes()).unwrap();
    }

    let view = a.sync(room, 3).unwrap();
    (
        room,
        view.into_iter()
            .map(|m| String::from_utf8(m.body).unwrap())
            .collect(),
    )
}

#[test]
fn a_conversation_arrives_in_the_order_it_was_typed() {
    // The bug this caught: `send` advanced the same cursor `sync` resumed from, so
    // each client skipped exactly its own messages. Neither the outbox nor the
    // keyring was wrong alone — a write cursor and a read cursor are different
    // things, and only wiring them together showed it.
    let s = deployment();
    let script = [
        (0, "the boat leaves at six"),
        (1, "understood"),
        (0, "do not be late"),
    ];
    let (_, view) = conversation(&s, &script);
    assert_eq!(
        view,
        script
            .iter()
            .map(|(_, t)| t.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn both_members_see_the_same_history() {
    let s = deployment();
    let script = [(0, "one"), (1, "two"), (0, "three")];
    let (room, alice_view) = conversation(&s, &script);

    let mut b = Client::from_mnemonic(&phrase(2), &s).unwrap();
    let bob_view: Vec<String> = b
        .sync(room, 3)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(alice_view, bob_view, "two members disagree about history");
}

#[test]
fn a_wiped_client_recovers_from_the_phrase_alone() {
    // The bet the whole design rests on, through the API a person would use.
    let s = deployment();
    let script = [(0, "the boat leaves at six"), (1, "understood")];
    let (room, before) = conversation(&s, &script);

    // Everything local is gone. Only twenty-four words survive.
    let mut restored = Client::from_mnemonic(&phrase(1), &s).unwrap();
    assert_eq!(restored.rooms().len(), 1, "the room did not come back");
    assert_eq!(restored.rooms()[0].0, room);

    let after: Vec<String> = restored
        .sync(room, 3)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect();
    assert_eq!(after, before, "history did not come back intact");
}

#[test]
fn the_services_hold_no_plaintext() {
    let s = deployment();
    let script = [
        (0, "the boat leaves at six"),
        (1, "understood, bringing the charts"),
    ];
    conversation(&s, &script);
    for (_, text) in script {
        assert!(
            !s.holds(text.as_bytes()),
            "plaintext `{text}` is in a service's storage"
        );
    }
    assert!(!s.holds(b"the crossing"), "the room name reached a service");
}

#[test]
fn a_shared_file_is_stripped_and_deduplicated() {
    let s = deployment();
    let mut rng = Fixed(9);
    let mut a = Client::from_mnemonic(&phrase(1), &s).unwrap();
    let room = a.create_room(&mut rng, "r").unwrap();

    // A JPEG with location data, as a phone would produce.
    let mut photo = vec![0xFF, 0xD8];
    let exif = b"Exif\x00\x00II*\x00GPSLatitude 51.5074";
    photo.extend_from_slice(&[0xFF, 0xE1]);
    photo.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    photo.extend_from_slice(exif);
    photo.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    photo.extend_from_slice(b"PIXELDATA");
    photo.extend_from_slice(&[0xFF, 0xD9]);

    let (name, key) = a.share_file(&mut rng, room, &photo).unwrap();
    assert!(
        !s.holds(b"GPSLatitude"),
        "location data reached the content store"
    );

    let back = a.fetch_file(name, &key).unwrap();
    assert!(
        back.windows(9).any(|w| w == b"PIXELDATA"),
        "the image was damaged"
    );
    assert!(
        !back.windows(11).any(|w| w == b"GPSLatitude"),
        "GPS survived the round trip"
    );
}

#[test]
fn a_file_whose_metadata_cannot_be_stripped_is_refused() {
    let s = deployment();
    let mut rng = Fixed(9);
    let mut a = Client::from_mnemonic(&phrase(1), &s).unwrap();
    let room = a.create_room(&mut rng, "r").unwrap();

    let heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00".to_vec();
    assert_eq!(
        a.share_file(&mut rng, room, &heic).unwrap_err(),
        spark_client::ClientError::Unscrubbable
    );
}

#[test]
fn a_bad_recovery_phrase_is_refused_rather_than_making_a_new_account() {
    let s = deployment();
    // Valid BIP-39, twelve words. Silently accepting it would halve the entropy
    // behind an account that can never be recovered.
    let twelve = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    assert_eq!(
        Client::open(twelve, &s).unwrap_err(),
        spark_client::ClientError::BadMnemonic
    );
    assert_eq!(
        Client::open("not a phrase", &s).unwrap_err(),
        spark_client::ClientError::BadMnemonic
    );
}
