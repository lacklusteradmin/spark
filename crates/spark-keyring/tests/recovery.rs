//! Gate 3: "Chunks decrypt from the seed alone via the keyring, and are inert
//! without it."
//!
//! The test is deliberately structured as two phases with a hard wall between
//! them. Phase one builds an account and hands *only* what a server would hold to
//! phase two, which starts from a mnemonic and nothing else. Anything that leaks
//! across that wall would make the test pass for the wrong reason.

use spark_chunk::{Chunk, ChunkName, LaneId, Slot, media, room};
use spark_crypto::{Mnemonic, Secret};
use spark_identity::{Addr, Identity};
use spark_keyring::*;
use std::collections::BTreeMap;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

const MESSAGES: [&str; 3] = [
    "the pigeons have landed",
    "bring the good coffee",
    "see you at the usual place",
];
const PHOTO: &[u8] = b"\x89PNG\r\n\x1a\n not really a png, but it is 40-odd bytes";

/// Everything the two services hold, and nothing else.
///
/// Note what has no field here: no member list, no sender, no room grouping, no
/// upload-to-key link. If this struct could gain such a field the design would
/// have already failed.
#[derive(Default)]
struct Servers {
    /// Keyring service: blobs addressed by `hash(pubkey)`.
    keyring: BTreeMap<String, (Chunk, Vec<Chunk>)>,
    /// Content service: an account-free map of name to bytes.
    content: BTreeMap<String, Chunk>,
}

impl Servers {
    fn put(&mut self, name: ChunkName, c: Chunk) {
        // Write-once, as the real store is (docs/protocol.md §6.2).
        assert!(
            self.content.insert(name.to_hex(), c).is_none(),
            "slot written twice"
        );
    }
    fn get(&self, name: ChunkName) -> Option<&Chunk> {
        self.content.get(&name.to_hex())
    }
    /// Every byte either service holds.
    fn all_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for (snap, deltas) in self.keyring.values() {
            v.extend_from_slice(snap.as_bytes());
            for d in deltas {
                v.extend_from_slice(d.as_bytes());
            }
        }
        for c in self.content.values() {
            v.extend_from_slice(c.as_bytes());
        }
        v
    }
}

/// Nonces the caller supplies, so the test is deterministic. Real callers pass
/// fresh randomness; the keyring cannot derive one because it is mutable.
fn nonce(n: u8) -> [u8; 24] {
    [n; 24]
}

/// Build an account, a room, some history, and one shared photo.
///
/// Returns only what a server would hold. The `Identity`, the `RoomRoot`, and the
/// plaintexts all go out of scope at the end of this function.
fn phase_one() -> (Servers, Addr) {
    let id = Identity::from_phrase(PHRASE).unwrap();
    let addr = id.addr();
    let mut servers = Servers::default();

    // A room secret. Generated once at room creation, never an MLS exporter
    // secret — history must stay addressable across every epoch (§3.2).
    let root: room::RoomRoot = Secret::new([0x5a; 32]);
    let room_id = RoomId([7; 16]);
    let lane = LaneId::message(&id.public().sign);

    // Append the history. Each slot is written exactly once, which is what makes
    // the derived nonces safe.
    for (i, m) in MESSAGES.iter().enumerate() {
        let (name, chunk) = room::seal(&root, Slot::new(lane, i as u64), m.as_bytes());
        servers.put(name, chunk);
    }

    // Share a photo. Convergent, so the name is the hash of the finished chunk.
    let (photo_name, photo_key, photo_chunk) = media::seal_raw(PHOTO);
    servers.put(photo_name, photo_chunk);

    // The keyring: a snapshot, then deltas for what happened after it.
    let mut k = Keyring::new();
    k.apply(&Delta::UpsertRoom(Room {
        id: room_id,
        generations: vec![Generation {
            epoch: 0,
            root,
            heads: vec![],
        }],
        mls_state: None,
        display_name: "usual place".into(),
        my_lane: lane.into(),
    }));
    let snapshot = k.seal_snapshot(id.keyring_key(), &nonce(1));

    let deltas = vec![
        Delta::AdvanceHead {
            room: room_id,
            epoch: 0,
            lane: lane.into(),
            seq: 2,
        }
        .seal(id.keyring_key(), &nonce(2)),
        Delta::AddUpload(Upload {
            name: photo_name.into(),
            receipt: Receipt([0xab; 32]),
            size: 512,
            class: ChunkClass::Media,
            room: Some(room_id),
        })
        .seal(id.keyring_key(), &nonce(3)),
        // The photo's read capability travels inside the room history in the real
        // protocol; here it rides in the keyring so phase two can find it without
        // MLS, which does not exist until stage 4.
        Delta::AddTokens(vec![photo_key.expose().to_vec()]).seal(id.keyring_key(), &nonce(4)),
    ];

    servers.keyring.insert(addr.to_hex(), (snapshot, deltas));
    (servers, addr)
}

#[test]
fn history_decrypts_from_the_seed_alone() {
    let (servers, expected_addr) = phase_one();

    // ---- the wall. Everything below starts from 24 words and a server. ----

    let id = Identity::from_phrase(PHRASE).unwrap();
    assert_eq!(
        id.addr(),
        expected_addr,
        "the seed alone must locate the keyring"
    );

    let (snapshot, deltas) = servers
        .keyring
        .get(&id.addr().to_hex())
        .expect("keyring at addr");
    let k = Keyring::restore(snapshot, deltas, id.keyring_key()).expect("keyring opens");

    let r = k.rooms.first().expect("the room came back");
    assert_eq!(r.display_name, "usual place");
    assert_eq!(
        k.head(r.id, r.my_lane.into()),
        Some(2),
        "lane head survived the deltas"
    );

    // Names are recomputed from the recovered room root. The server was never
    // asked what belongs to this room, and could not have answered.
    let lane: LaneId = r.my_lane.into();
    let mut recovered = Vec::new();
    // Walk every generation, oldest first: the archive is only whole if all of
    // them came back, and a generation cannot be re-derived after the fact.
    for g in &r.generations {
        let Some(head) = g
            .heads
            .iter()
            .find(|(l, _)| *l == r.my_lane)
            .map(|(_, s)| *s)
        else {
            continue;
        };
        for seq in 0..=head {
            let slot = Slot::new(lane, seq);
            let chunk = servers
                .get(room::name(&g.root, slot))
                .expect("chunk at derived name");
            let plain = room::open(&g.root, slot, chunk).expect("chunk opens");
            recovered.push(String::from_utf8(plain.to_vec()).unwrap());
        }
    }
    assert_eq!(recovered, MESSAGES, "history did not come back intact");

    // And the media, via its stored capability.
    let up = k.uploads.first().expect("upload list survived");
    let key = Secret::<32>::new(k.tokens[0].clone().try_into().unwrap());
    let photo = media::open(servers.get(ChunkName::from(up.name)).unwrap(), &key).unwrap();
    assert_eq!(&photo[..], PHOTO);
    assert_eq!(k.bytes_held(), 512, "quota accounting survived");
}

#[test]
fn everything_is_inert_without_the_seed() {
    let (servers, _) = phase_one();

    // The server's entire database yields no plaintext.
    let haystack = servers.all_bytes();
    for needle in MESSAGES.iter().map(|m| m.as_bytes()).chain([PHOTO]) {
        assert!(
            !haystack.windows(needle.len()).any(|w| w == needle),
            "plaintext found in the stored bytes"
        );
    }

    // A different seed reaches a different address, and cannot open this one.
    let other = Identity::from_mnemonic(&Mnemonic::from_entropy(&[9; 32]));
    assert!(!servers.keyring.contains_key(&other.addr().to_hex()));
    let (snapshot, deltas) = servers.keyring.values().next().unwrap();
    assert!(
        Keyring::open_snapshot(snapshot, other.keyring_key()).is_err(),
        "a wrong seed opened the keyring"
    );
    for d in deltas {
        assert!(
            Delta::open(d, other.keyring_key()).is_err(),
            "a wrong seed opened a delta"
        );
    }

    // Room chunks are inert to anyone without the room root, even someone who
    // guessed the message exactly: the name is an HMAC, not a hash of content.
    let wrong_root: room::RoomRoot = Secret::new([0x11; 32]);
    let lane = LaneId::message(&Identity::from_phrase(PHRASE).unwrap().public().sign);
    for seq in 0..MESSAGES.len() as u64 {
        let slot = Slot::new(lane, seq);
        assert!(
            servers.get(room::name(&wrong_root, slot)).is_none(),
            "guessed a room chunk name"
        );
    }

    // Even holding the right chunk, the wrong key opens nothing.
    let real_root: room::RoomRoot = Secret::new([0x5a; 32]);
    let slot = Slot::new(lane, 0);
    let chunk = servers.get(room::name(&real_root, slot)).unwrap();
    assert!(room::open(&wrong_root, slot, chunk).is_err());
}

#[test]
fn a_guessed_sentence_cannot_be_tested_against_the_store() {
    // The reason room names are keyed rather than content-derived: files are hard
    // to guess, sentences are not (Spark-spec.md F7). If room chunks were named
    // like media, this loop would find one.
    let (servers, _) = phase_one();
    for guess in MESSAGES {
        let (name, _, _) = media::seal_raw(guess.as_bytes());
        assert!(
            servers.get(name).is_none(),
            "a guessed sentence located a stored chunk"
        );
    }
}

#[test]
fn restore_is_idempotent_under_replayed_deltas() {
    // Deltas are fetched from a server that may return them more than once, and
    // there is no transaction to roll back to.
    let (servers, addr) = phase_one();
    let id = Identity::from_phrase(PHRASE).unwrap();
    let (snapshot, deltas) = &servers.keyring[&addr.to_hex()];

    let once = Keyring::restore(snapshot, deltas, id.keyring_key()).unwrap();
    let twice_input: Vec<Chunk> = deltas.iter().chain(deltas.iter()).cloned().collect();
    let twice = Keyring::restore(snapshot, &twice_input, id.keyring_key()).unwrap();

    assert_eq!(once.rooms.len(), twice.rooms.len());
    assert_eq!(once.uploads.len(), twice.uploads.len());
    assert_eq!(once.tokens.len(), twice.tokens.len());
    assert_eq!(once.bytes_held(), twice.bytes_held());
}

#[test]
fn an_out_of_order_delta_cannot_rewind_a_lane() {
    let id = Identity::from_phrase(PHRASE).unwrap();
    let room_id = RoomId([1; 16]);
    let lane = LaneId::COMMIT;
    let mut k = Keyring::new();
    k.apply(&Delta::UpsertRoom(Room {
        id: room_id,
        generations: vec![Generation {
            epoch: 0,
            root: Secret::new([3; 32]),
            heads: vec![],
        }],
        mls_state: None,
        display_name: "r".into(),
        my_lane: lane.into(),
    }));

    k.apply(&Delta::AdvanceHead {
        room: room_id,
        epoch: 0,
        lane: lane.into(),
        seq: 9,
    });
    k.apply(&Delta::AdvanceHead {
        room: room_id,
        epoch: 0,
        lane: lane.into(),
        seq: 4,
    });
    assert_eq!(
        k.head(room_id, lane),
        Some(9),
        "a late delta rewound the head"
    );

    let _ = id;
}

#[test]
fn a_delta_cannot_be_opened_as_a_snapshot() {
    // postcard is not self-describing. Without the plaintext tag, a delta's bytes
    // could decode as a keyring and produce silent garbage instead of an error.
    let id = Identity::from_phrase(PHRASE).unwrap();
    let d = Delta::DropName("x".into()).seal(id.keyring_key(), &nonce(1));
    assert_eq!(
        Keyring::open_snapshot(&d, id.keyring_key()).err(),
        Some(KeyringError::WrongKind)
    );

    let snap = Keyring::new().seal_snapshot(id.keyring_key(), &nonce(2));
    assert_eq!(
        Delta::open(&snap, id.keyring_key()).err(),
        Some(KeyringError::WrongKind)
    );
}
