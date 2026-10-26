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

#[test]
fn contacts_require_mutual_approval_survive_restore_and_can_be_revoked() {
    let services = deployment();
    let mut rng = Fixed(903);
    let mut a = Client::from_mnemonic(&phrase(31), &services).unwrap();
    let mut b = Client::from_mnemonic(&phrase(32), &services).unwrap();
    let b_public: [u8; 64] = [
        b.public().sign.as_bytes().as_slice(),
        b.public().kem.as_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap();
    let a_key = *a.public().sign.as_bytes();
    let b_key = *b.public().sign.as_bytes();
    assert!(b.contact_note(&mut rng, &a_key, "unsolicited").is_err());
    let a_card = a.add_contact(&mut rng, "Bob", &b_public, None).unwrap();
    let b_card = b
        .add_contact(
            &mut rng,
            "Alice",
            &a_card[..64].try_into().unwrap(),
            Some(a_card[64..].try_into().unwrap()),
        )
        .unwrap();
    a.add_contact(
        &mut rng,
        "Bob",
        &b_card[..64].try_into().unwrap(),
        Some(b_card[64..].try_into().unwrap()),
    )
    .unwrap();
    b.contact_note(&mut rng, &a_key, "approved note").unwrap();
    let mut restored = Client::from_mnemonic(&phrase(31), &services).unwrap();
    assert_eq!(restored.contacts().len(), 1);
    let notes = restored.contact_inbox().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].note, "approved note");
    assert_eq!(notes[0].from.sign, b.public().sign);
    restored.remove_contact(&mut rng, &b_key).unwrap();
    // The stale original device must not republish its old permit list.
    assert!(a.remove_contact(&mut rng, &[0; 32]).is_err());
    b.contact_note(&mut rng, &a_key, "old permit").unwrap();
    assert!(restored.contact_inbox().unwrap().is_empty());
    assert!(
        Client::from_mnemonic(&phrase(31), &services)
            .unwrap()
            .contacts()
            .is_empty()
    );
}

#[test]
fn a_real_client_redeems_a_refund_with_the_separate_content_mint() {
    let services = deployment();
    let mut rng = Fixed(904);
    let mut a = Client::from_mnemonic(&phrase(33), &services).unwrap();
    let room = a.create_room(&mut rng, "refund").unwrap();
    let png = [0xff, 0xd8, 0xff, 0xda, 0, 2, 1, 2, 3, 0xff, 0xd9];
    let (name, _) = a.share_file(&mut rng, room, &png).unwrap();
    let before = a.bytes_held();
    assert!(before > 0);
    a.release_upload(&mut rng, name).unwrap();
    assert_eq!(a.bytes_held(), 0);
    assert!(a.release_upload(&mut rng, name).is_err());
    assert_eq!(
        Client::from_mnemonic(&phrase(33), &services)
            .unwrap()
            .bytes_held(),
        0
    );
}

use spark_client::services::{
    Class, ContentService, IssuerService, KeyringService, ServiceError, Services,
};
use spark_crypto::{Token, TokenClaim};
use std::cell::{Cell, RefCell};

struct Faults<'a> {
    local: &'a Local,
    lose_put: Cell<bool>,
    lose_release: Cell<bool>,
    uploaded: RefCell<Vec<[u8; 32]>>,
    hidden: RefCell<Vec<[u8; 32]>>,
    substituted: RefCell<Option<Vec<u8>>>,
}
impl<'a> Faults<'a> {
    fn new(local: &'a Local) -> Self {
        Self {
            local,
            lose_put: Cell::new(false),
            lose_release: Cell::new(false),
            uploaded: RefCell::new(vec![]),
            hidden: RefCell::new(vec![]),
            substituted: RefCell::new(None),
        }
    }
}
impl Services for Faults<'_> {
    fn keyring(&self) -> &dyn KeyringService {
        self.local.keyring()
    }
    fn issuer(&self) -> &dyn IssuerService {
        self.local.issuer()
    }
    fn content(&self) -> &dyn ContentService {
        self
    }
}
impl ContentService for Faults<'_> {
    fn put(
        &self,
        class: Class,
        name: &[u8; 32],
        chunk: &[u8],
        claim: TokenClaim,
        token: &Token,
    ) -> Result<[u8; 32], ServiceError> {
        let receipt = self.local.content().put(class, name, chunk, claim, token)?;
        self.uploaded.borrow_mut().push(*name);
        if self.lose_put.replace(false) {
            return Err(ServiceError::Unreachable);
        }
        Ok(receipt)
    }
    fn get(&self, class: Class, name: &[u8; 32]) -> Result<Option<Vec<u8>>, ServiceError> {
        if let Some(bytes) = self.substituted.borrow().as_ref() {
            return Ok(Some(bytes.clone()));
        }
        if self.hidden.borrow().contains(name) {
            return Ok(None);
        }
        self.local.content().get(class, name)
    }
    fn refund_key(&self, class: Class, size_class: u8) -> Result<Vec<u8>, ServiceError> {
        self.local.content().refund_key(class, size_class)
    }
    fn release(
        &self,
        class: Class,
        name: &[u8; 32],
        receipt: &[u8; 32],
        size_class: u8,
        blinded: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let sig = self
            .local
            .content()
            .release(class, name, receipt, size_class, blinded)?;
        if self.lose_release.replace(false) {
            return Err(ServiceError::Unreachable);
        }
        Ok(sig)
    }
}

#[test]
fn stale_device_cannot_overwrite_newer_rooms() {
    let s = deployment();
    let mut rng = Fixed(100);
    let mut a = Client::from_mnemonic(&phrase(1), &s).unwrap();
    let mut stale = Client::from_mnemonic(&phrase(1), &s).unwrap();
    let room = a.create_room(&mut rng, "preserved").unwrap();
    assert!(stale.create_room(&mut rng, "stale overwrite").is_err());
    let recovered = Client::from_mnemonic(&phrase(1), &s).unwrap();
    assert_eq!(recovered.rooms(), vec![(room, "preserved".into())]);
}

const SMALL_JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xda, 0, 2, 1, 2, 3, 0xff, 0xd9];

#[test]
fn repeated_media_upload_retains_every_receipt_across_recovery() {
    let s = deployment();
    let mut rng = Fixed(101);
    let mut a = Client::from_mnemonic(&phrase(1), &s).unwrap();
    let room = a.create_room(&mut rng, "duplicates").unwrap();
    let (name, key) = a.share_file(&mut rng, room, SMALL_JPEG).unwrap();
    let once = a.bytes_held();
    a.share_file(&mut rng, room, SMALL_JPEG).unwrap();
    assert_eq!(a.bytes_held(), 2 * once);
    drop(a);
    let mut a = Client::from_mnemonic(&phrase(1), &s).unwrap();
    a.release_upload(&mut rng, name).unwrap();
    assert_eq!(a.bytes_held(), once);
    assert!(a.fetch_file(name, &key).is_ok());
    a.release_upload(&mut rng, name).unwrap();
    assert_eq!(a.bytes_held(), 0);
    assert!(a.fetch_file(name, &key).is_err());
}

#[test]
fn lost_refund_response_is_recoverable_from_seed() {
    let s = deployment();
    let f = Faults::new(&s);
    let mut rng = Fixed(102);
    let mut a = Client::from_mnemonic(&phrase(1), &f).unwrap();
    let room = a.create_room(&mut rng, "refund").unwrap();
    let (name, _) = a.share_file(&mut rng, room, SMALL_JPEG).unwrap();
    f.lose_release.set(true);
    assert!(a.release_upload(&mut rng, name).is_err());
    drop(a);
    let mut recovered = Client::from_mnemonic(&phrase(1), &f).unwrap();
    recovered.release_upload(&mut rng, name).unwrap();
    assert_eq!(recovered.bytes_held(), 0);
}

#[test]
fn lost_upload_response_is_recoverable_without_a_second_charge_or_message() {
    let s = deployment();
    let f = Faults::new(&s);
    let mut rng = Fixed(103);
    let mut a = Client::from_mnemonic(&phrase(1), &f).unwrap();
    let room = a.create_room(&mut rng, "upload").unwrap();
    f.lose_put.set(true);
    assert!(a.send(&mut rng, room, b"once").is_err());
    drop(a);
    let mut recovered = Client::from_mnemonic(&phrase(1), &f).unwrap();
    recovered.retry_pending_upload(&mut rng).unwrap();
    assert_eq!(
        recovered
            .sync(room, 3)
            .unwrap()
            .iter()
            .map(|m| m.body.as_slice())
            .collect::<Vec<_>>(),
        vec![b"once".as_slice()]
    );
    let held = recovered.bytes_held();
    recovered.retry_pending_upload(&mut rng).unwrap();
    assert_eq!(recovered.bytes_held(), held);
}

#[test]
fn long_gaps_and_temporarily_hidden_older_messages_are_eventually_revisited() {
    let s = deployment();
    let f = Faults::new(&s);
    let mut rng = Fixed(104);
    let mut a = Client::from_mnemonic(&phrase(1), &f).unwrap();
    let room = a.create_room(&mut rng, "gaps").unwrap();
    for i in 0..6u8 {
        a.send(&mut rng, room, &[i]).unwrap();
    }
    *f.hidden.borrow_mut() = f.uploaded.borrow()[..3].to_vec();
    assert!(a.sync(room, 2).unwrap().is_empty());
    assert_eq!(a.sync(room, 2).unwrap().len(), 3);
    f.hidden.borrow_mut().clear();
    for _ in 0..6 {
        a.sync(room, 2).unwrap();
    }
    assert_eq!(
        a.sync(room, 2)
            .unwrap()
            .iter()
            .map(|m| m.body[0])
            .collect::<Vec<_>>(),
        (0..6).collect::<Vec<u8>>()
    );
}

#[test]
fn media_fetch_rejects_authenticated_ciphertext_at_the_wrong_address() {
    let s = deployment();
    let f = Faults::new(&s);
    let mut rng = Fixed(107);
    let mut a = Client::from_mnemonic(&phrase(1), &f).unwrap();
    let room = a.create_room(&mut rng, "media integrity").unwrap();
    let (name, key) = a.share_file(&mut rng, room, SMALL_JPEG).unwrap();
    // A holder of the original convergent file knows its key. Even a valid
    // AEAD under that key is not authority to replace this content address.
    let replacement =
        spark_chunk::Chunk::seal(spark_chunk::Kind::Media, &key, &[17; 24], b"replacement");
    *f.substituted.borrow_mut() = Some(replacement.as_bytes().to_vec());
    assert_eq!(
        a.fetch_file(name, &key).unwrap_err(),
        spark_client::ClientError::Corrupt
    );
}
