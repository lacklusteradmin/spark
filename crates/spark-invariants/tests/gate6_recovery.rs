//! Gate 6 — the go/no-go, re-run against the generation model.
//!
//! > **Wipe the device, restore from seed, history matches. The server's entire
//! > database yields no plaintext and no graph edge.**
//!
//! The conversation deliberately spans a membership change, so the archive is
//! split across two generations with different roots. A restore that only walked
//! the newest generation would silently return half the history and still look
//! plausible, which is exactly the failure this arrangement is here to catch.
//!
//! `phase_one` returns only `Servers`. The identities, the MLS groups, the roots
//! and every plaintext are dropped at its closing brace; anything that leaked
//! across that boundary would make this pass for the wrong reason.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use spark_chunk::{Chunk, LaneId, Slot, room};
use spark_crypto::{Mnemonic, Secret};
use spark_identity::Identity;
use spark_keyring::{
    ChunkClass, Delta, Generation, Keyring, Receipt, Room as KeyRoom, RoomId, SerName, Upload,
};
use spark_mls::{Room, key_package, signer_for};
use spark_store::Db;
use spark_sync::{Clock, Entry, Outbox, Payload, entry::Signed, total_order};

use spark_content_server as content;
use spark_keyring_server as keyring;

mod common;
use common::{Fixed, issuer, token};

const ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon art";

/// Said before Carol joins, in the first generation.
const EARLY: [&str; 2] = ["the boat leaves at six", "understood"];
/// Said after Carol joins, in the second.
const LATE: [&str; 2] = ["carol is aboard", "then we can go"];

const ROOM: RoomId = RoomId([0x11; 16]);

struct Servers {
    keyring: keyring::Keyring,
    content: content::Content,
}

struct Client {
    id: Identity,
    provider: OpenMlsRustCrypto,
    signer: spark_mls::Signer,
}

fn sign_secret(m: &Mnemonic) -> Secret<32> {
    let root = spark_crypto::extract(spark_identity::ROOT_SALT, m.to_seed().expose());
    spark_crypto::expand::<32>(&root, spark_identity::INFO_SIGN)
}

impl Client {
    fn new(m: Mnemonic) -> Self {
        let id = Identity::from_mnemonic(&m);
        let signer = signer_for(&id, &sign_secret(&m));
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).expect("store signer");
        Self {
            id,
            provider,
            signer,
        }
    }
    fn lane(&self) -> LaneId {
        LaneId::message(&self.id.public().sign)
    }
}

fn auth(ks: &keyring::Keyring, id: &Identity) -> keyring::Auth {
    let addr = *id.addr().as_bytes();
    keyring::Auth {
        addr,
        key: *id.public().sign.as_bytes(),
        sig: *id.sign(&ks.challenge(&addr)).as_bytes(),
    }
}

/// Seal an entry into its slot and upload it under a blind token.
fn publish(
    servers: &Servers,
    root: &Secret<32>,
    slot: Slot,
    entry: &Entry,
    serial: &mut u8,
) -> (SerName, Receipt) {
    let (name, chunk) = room::seal(root, slot, &entry.encode());
    *serial += 1;
    let (claim, tok) = token(*serial, chunk.len() as u64);
    match servers.content.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim,
        token: tok,
    }) {
        content::Response::Stored { receipt } => (name.into(), Receipt(receipt)),
        r => panic!("upload refused: {r:?}"),
    }
}

/// A conversation that spans a membership change. Returns only what a server holds.
fn phase_one() -> Servers {
    let servers = Servers {
        keyring: keyring::Keyring::new(
            Db::new(),
            Secret::new([0xa1; 32]),
            spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
        ),
        content: content::Content::new(Db::new(), issuer().public()),
    };
    servers.keyring.set_minute(1);

    let alice = Client::new(Mnemonic::parse(ALICE).unwrap());
    let bob = Client::new(Mnemonic::from_entropy(&[2; 32]));
    let carol = Client::new(Mnemonic::from_entropy(&[3; 32]));

    let mut a_room = Room::create(&alice.provider, &alice.id.public().sign, &alice.signer).unwrap();
    let kp = key_package(&bob.provider, &bob.id.public().sign, &bob.signer).unwrap();
    let welcome = a_room
        .add_member(&alice.provider, &alice.signer, kp.key_package())
        .unwrap()
        .welcome
        .unwrap();
    let b_room = Room::join(&bob.provider, &welcome).unwrap();

    let mut serial = 0u8;
    let mut uploads: Vec<(SerName, Receipt)> = Vec::new();
    let mut deltas: Vec<Delta> = Vec::new();
    let mut gens: Vec<Generation> = Vec::new();

    // --- generation one: Alice and Bob ---
    let g1_epoch = a_room.generation();
    let g1_root = a_room.root(&alice.provider).unwrap();
    assert_eq!(
        b_room.root(&bob.provider).unwrap().expose(),
        g1_root.expose(),
        "members disagree on the archive root"
    );
    gens.push(Generation {
        epoch: g1_epoch,
        root: g1_root.clone(),
        my_next: 0,
    });
    deltas.push(Delta::OpenGeneration {
        room: ROOM,
        generation: Generation {
            epoch: g1_epoch,
            root: g1_root.clone(),
            my_next: 0,
        },
    });

    let mut clock = Clock::new();
    for (i, text) in EARLY.iter().enumerate() {
        let (c, ep) = if i == 0 {
            (&alice, g1_epoch)
        } else {
            (&bob, g1_epoch)
        };
        let mut ob = Outbox::new(ROOM, ep, c.lane(), 0);
        let (r, d) = ob.reserve();
        let signed = Signed::new(
            r.slot(),
            ep,
            text.as_bytes().to_vec(),
            &c.id.public().sign,
            |m| c.id.sign(m),
        );
        let e = Entry::new(r.slot(), ep, clock.clone(), Payload::Application(signed));
        let slot = r.consume();
        clock.observe(slot.lane, slot.seq);
        deltas.push(d);
        uploads.push(publish(&servers, &g1_root, slot, &e, &mut serial));
    }

    // --- Carol joins. Every member's root rotates; Carol cannot derive g1's. ---
    let kp = key_package(&carol.provider, &carol.id.public().sign, &carol.signer).unwrap();
    a_room
        .add_member(&alice.provider, &alice.signer, kp.key_package())
        .unwrap();

    let g2_epoch = a_room.generation();
    let g2_root = a_room.root(&alice.provider).unwrap();
    assert_ne!(
        g2_root.expose(),
        g1_root.expose(),
        "the root did not rotate"
    );
    gens.push(Generation {
        epoch: g2_epoch,
        root: g2_root.clone(),
        my_next: 0,
    });
    deltas.push(Delta::OpenGeneration {
        room: ROOM,
        generation: Generation {
            epoch: g2_epoch,
            root: g2_root.clone(),
            my_next: 0,
        },
    });

    let mut clock2 = Clock::new();
    for (i, text) in LATE.iter().enumerate() {
        let c = if i == 0 { &alice } else { &carol };
        let mut ob = Outbox::new(ROOM, g2_epoch, c.lane(), 0);
        let (r, d) = ob.reserve();
        let signed = Signed::new(
            r.slot(),
            g2_epoch,
            text.as_bytes().to_vec(),
            &c.id.public().sign,
            |m| c.id.sign(m),
        );
        let e = Entry::new(
            r.slot(),
            g2_epoch,
            clock2.clone(),
            Payload::Application(signed),
        );
        let slot = r.consume();
        clock2.observe(slot.lane, slot.seq);
        deltas.push(d);
        uploads.push(publish(&servers, &g2_root, slot, &e, &mut serial));
    }

    // --- keyrings ---
    for c in [&alice, &bob, &carol] {
        let mut k = Keyring::new();
        k.apply(&Delta::UpsertRoom(KeyRoom {
            id: ROOM,
            generations: vec![],
            mls_group_id: Vec::new(),
            display_name: "the crossing".into(),
            my_lane: c.lane().into(),
        }));
        // Bob left before generation two existed and never holds its root; Carol
        // joined after generation one and cannot derive it. Only Alice was present
        // for both. This is F4's re-share reduced to one list of 32-byte values.
        for d in &deltas {
            let skip = matches!(
                (&d, c.id.addr() == carol.id.addr()),
                (Delta::OpenGeneration { generation, .. }, true) if generation.epoch == g1_epoch
            );
            if !skip {
                k.apply(d);
            }
        }
        for (name, r) in &uploads {
            k.apply(&Delta::AddUpload(Upload {
                name: *name,
                receipt: *r,
                size: 300,
                class: ChunkClass::RoomLog,
                room: Some(ROOM),
            }));
        }
        let snap = k.seal_snapshot(c.id.keyring_key(), &[7; 24]);
        assert_eq!(
            servers.keyring.handle(keyring::Request::PutSnapshot(
                auth(&servers.keyring, &c.id),
                snap.as_bytes().to_vec()
            )),
            keyring::Response::SnapshotWritten
        );
    }

    servers
}

/// Everything an identity can recover from its seed and a server.
fn restore(servers: &Servers, id: &Identity) -> Vec<String> {
    let snapshot = match servers
        .keyring
        .handle(keyring::Request::GetSnapshot(auth(&servers.keyring, id)))
    {
        keyring::Response::Snapshot(Some(b)) => Chunk::from_bytes(b).expect("keyring chunk"),
        r => panic!("no keyring at addr: {r:?}"),
    };
    let k = Keyring::open_snapshot(&snapshot, id.keyring_key()).expect("keyring opens");
    let r = k.rooms.first().expect("the room came back");

    let mut entries = Vec::new();
    // Every generation, oldest first. A restore that walked only the newest would
    // return half the history and still look plausible.
    //
    // The lanes are probed forward from zero rather than read off a cursor. A
    // wiped device has no cursor — `heads` records what this account has *read*,
    // and it read nothing before the wipe. This is what `Client::sync` does.
    for g in &r.generations {
        let lanes: Vec<LaneId> = [
            LaneId::message(&Identity::from_phrase(ALICE).unwrap().public().sign),
            LaneId::message(&ident(2).public().sign),
            LaneId::message(&ident(3).public().sign),
            LaneId::COMMIT,
        ]
        .into_iter()
        .collect();
        for lane in lanes {
            let mut misses = 0;
            for seq in 0..8u64 {
                if misses >= 3 {
                    break;
                }
                let slot = Slot::new(lane, seq);
                let name = room::name(&g.root, slot);
                let content::Response::Chunk(bytes) =
                    servers.content.handle(content::Request::Get {
                        name: *name.as_bytes(),
                    })
                else {
                    misses += 1;
                    continue;
                };
                misses = 0;
                let chunk = Chunk::from_bytes(bytes).expect("chunk parses");
                let plain = room::open(&g.root, slot, &chunk).expect("chunk opens");
                entries.push(Entry::decode(&plain, slot).expect("entry decodes"));
            }
        }
    }

    total_order(entries)
        .into_iter()
        .filter_map(|e| match &e.payload {
            Payload::Application(sig) => {
                sig.verify(e.slot(), e.epoch)
                    .expect("authorship verifies after restore");
                Some(String::from_utf8(sig.body.clone()).unwrap())
            }
            _ => None,
        })
        .collect()
}

fn ident(entropy: u8) -> Identity {
    Identity::from_mnemonic(&Mnemonic::from_entropy(&[entropy; 32]))
}

#[test]
fn wipe_the_device_restore_from_seed_history_matches() {
    let servers = phase_one();

    // ---- the wall. Below here: twenty-four words and a server. ----

    let alice = Identity::from_phrase(ALICE).unwrap();
    let view = restore(&servers, &alice);

    // Ground truth, not "the two restores agree with each other": a broken total
    // order would reverse every restore identically and still look consistent.
    let expected: Vec<String> = EARLY
        .iter()
        .chain(LATE.iter())
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        view, expected,
        "history did not come back as it was written"
    );
    assert_eq!(view.len(), 4, "a generation went missing");
}

#[test]
fn a_member_who_joined_late_cannot_read_what_came_before() {
    // Carol holds only generation two's root. MLS forward secrecy is why: she was
    // not in the group when generation one's exporter secret existed, and no
    // member re-shared it to her.
    let servers = phase_one();
    let carol = restore(&servers, &ident(3));
    let late: Vec<String> = LATE.iter().map(|s| s.to_string()).collect();
    assert_eq!(carol, late, "a late joiner read pre-join history");
}

#[test]
fn the_servers_entire_database_yields_no_plaintext() {
    let servers = phase_one();
    let mut all = servers.keyring.db().all_bytes();
    all.extend_from_slice(&servers.content.db().all_bytes());
    for said in EARLY.iter().chain(LATE.iter()) {
        assert!(
            !all.windows(said.len()).any(|w| w == said.as_bytes()),
            "plaintext `{said}` survived into the servers"
        );
    }
}

#[test]
fn the_servers_entire_database_yields_no_graph_edge() {
    let servers = phase_one();
    let ids = [Identity::from_phrase(ALICE).unwrap(), ident(2), ident(3)];
    let addrs: Vec<String> = ids.iter().map(|i| i.addr().to_hex()).collect();

    let cbytes = servers.content.db().all_bytes();
    for a in &addrs {
        assert!(
            !cbytes.windows(a.len()).any(|w| w == a.as_bytes()),
            "the content service holds an address"
        );
    }
    for i in &ids {
        let pubkey = *i.public().sign.as_bytes();
        assert!(
            !cbytes.windows(32).any(|w| w == pubkey),
            "the content service holds a public key"
        );
    }

    for table in [
        keyring::T_KEYRING,
        keyring::T_DELTA,
        keyring::T_QUOTA,
        keyring::T_RATE,
    ] {
        for row in servers.keyring.db().rows(table) {
            let mut bytes = Vec::new();
            for (n, c) in &row {
                bytes.extend_from_slice(n.as_bytes());
                match c {
                    spark_store::Cell::Bytes(v) => bytes.extend_from_slice(v),
                    spark_store::Cell::Num(v) => bytes.extend_from_slice(&v.to_be_bytes()),
                    spark_store::Cell::Text(v) => bytes.extend_from_slice(v.as_bytes()),
                }
            }
            let hits = addrs
                .iter()
                .filter(|a| bytes.windows(a.len()).any(|w| w == a.as_bytes()))
                .count();
            assert!(
                hits <= 1,
                "a row in `{table}` names two accounts: that is a graph edge"
            );
        }
    }
}

#[test]
fn a_wrong_seed_recovers_nothing() {
    let servers = phase_one();
    assert!(matches!(
        servers.keyring.handle(keyring::Request::GetSnapshot(auth(
            &servers.keyring,
            &ident(200)
        ))),
        keyring::Response::Snapshot(None)
    ));
}
