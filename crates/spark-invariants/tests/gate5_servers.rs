//! Gate 5: "Permitted-knowledge tests pass against the real server."
//!
//! Stage 1 shipped `server/*-schema.toml` as hand-written declarations. That
//! closed one gap and left a bigger one: nothing tied the declaration to the
//! code. This closes it — the services are driven through a realistic session and
//! then audited on what they *actually* stored, via `Db::inventory`, which is
//! derived from writes rather than from anyone's notes.
//!
//! Three assertions, in increasing order of what they would catch:
//!
//! 1. what the servers stored is a subset of `docs/permitted-knowledge.toml`;
//! 2. the hand-written `server/*-schema.toml` matches reality, so the stage 1
//!    declarations cannot drift;
//! 3. the servers' entire contents contain no plaintext and no graph edge.

use spark_chunk::{LaneId, Slot, media, room};
use spark_crypto::{Mnemonic, Secret};
use spark_identity::Identity;
use spark_invariants::*;
use spark_keyring::{Delta, Keyring, Room, RoomId};
use spark_store::Db;

use spark_content_server as content;
use spark_issuer as issuer;
use spark_keyring_server as keyring;

const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon art";

const MESSAGES: [&str; 3] = ["meet at seven", "bring the folder", "it went fine"];
const PHOTO: &[u8] = b"\x89PNG\r\n\x1a\n pretend this is a photograph of something";
const HANDLE: &str = "riverbank";

/// Everything three services hold after one realistic session.
struct Run {
    keyring: keyring::Keyring,
    content: content::Content,
    issuer: issuer::Issuer,
}

fn nonce(n: u8) -> [u8; 24] {
    [n; 24]
}

/// Drive the real services: two accounts, a room, history, a shared photo, a
/// name purchase, a transfer, and a release.
fn exercise() -> Run {
    let alice = Identity::from_phrase(PHRASE_A).unwrap();
    let bob = Identity::from_mnemonic(&Mnemonic::from_entropy(&[2; 32]));

    let ks = keyring::Keyring::new(Db::new(), Secret::new([0xa1; 32]));
    let cs = content::Content::new(Db::new());
    let is = issuer::Issuer::new(Db::new());
    ks.set_minute(1_000_000);

    let auth = |id: &Identity| {
        let addr = *id.addr().as_bytes();
        keyring::Auth {
            addr,
            key: *id.public().sign.as_bytes(),
            sig: *id.sign(&ks.challenge(&addr)).as_bytes(),
        }
    };

    // --- the room's history goes to the content store, authorised by tokens ---
    let root: room::RoomRoot = Secret::new([0x5a; 32]);
    let lane = LaneId::message(&alice.public().sign);
    let mut token = 0u64;
    let mut next_token = || {
        token += 1;
        format!("tok-{token}").into_bytes()
    };

    for (i, m) in MESSAGES.iter().enumerate() {
        let slot = Slot::new(lane, i as u64);
        let (name, chunk) = room::seal(&root, slot, m.as_bytes());
        let r = cs.handle(content::Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            token: next_token(),
        });
        assert!(
            matches!(r, content::Response::Stored { .. }),
            "history upload refused: {r:?}"
        );
    }

    // --- a shared photo, uploaded by both accounts: one chunk, two charges ---
    let (photo_name, photo_key, photo_chunk) = media::seal(PHOTO);
    let mut receipts = Vec::new();
    for _ in 0..2 {
        match cs.handle(content::Request::Put {
            name: *photo_name.as_bytes(),
            chunk: photo_chunk.as_bytes().to_vec(),
            token: next_token(),
        }) {
            content::Response::Stored { receipt } => receipts.push(receipt),
            r => panic!("photo upload refused: {r:?}"),
        }
    }

    // --- keyrings: a snapshot and deltas for each account ---
    for id in [&alice, &bob] {
        let mut k = Keyring::new();
        k.apply(&Delta::UpsertRoom(Room {
            id: RoomId([7; 16]),
            root: Secret::new([0x5a; 32]),
            display_name: "the usual".into(),
            my_lane: lane.into(),
            heads: vec![],
        }));
        let snap = k.seal_snapshot(id.keyring_key(), &nonce(1));
        assert_eq!(
            ks.handle(keyring::Request::PutSnapshot(
                auth(id),
                snap.as_bytes().to_vec()
            )),
            keyring::Response::SnapshotWritten
        );
        let d = Delta::AdvanceHead {
            room: RoomId([7; 16]),
            lane: lane.into(),
            seq: 2,
        }
        .seal(id.keyring_key(), &nonce(2));
        assert!(matches!(
            ks.handle(keyring::Request::PutDelta(auth(id), d.as_bytes().to_vec())),
            keyring::Response::Appended { .. }
        ));
        assert!(matches!(
            ks.handle(keyring::Request::WithdrawTokens(auth(id), 4096)),
            keyring::Response::Tokens(_)
        ));
    }

    // --- a name, bought and then transferred to a key the seller never saw ---
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: HANDLE.into(),
            key: *alice.public().sign.as_bytes(),
            voucher: b"voucher-1".to_vec(),
            paid_until_day: 20_400,
        }),
        issuer::Response::Registered
    );
    let mut msg = issuer::TRANSFER_CONTEXT.to_vec();
    msg.extend_from_slice(HANDLE.as_bytes());
    msg.extend_from_slice(bob.public().sign.as_bytes());
    assert_eq!(
        is.handle(issuer::Request::Transfer {
            name: HANDLE.into(),
            new_key: *bob.public().sign.as_bytes(),
            sig: *alice.sign(&msg).as_bytes(),
        }),
        issuer::Response::Transferred
    );

    // --- one holder releases the photo; the other still holds it ---
    match cs.handle(content::Request::Release {
        name: *photo_name.as_bytes(),
        receipt: receipts[0],
    }) {
        content::Response::Released { freed, voucher } => {
            assert!(!freed, "bytes freed while another holder remains");
            assert_eq!(
                ks.handle(keyring::Request::CreditRefund(auth(&alice), voucher, 512)),
                keyring::Response::Credited
            );
        }
        r => panic!("release refused: {r:?}"),
    }
    let _ = photo_key;

    Run {
        keyring: ks,
        content: cs,
        issuer: is,
    }
}

/// `(section of permitted-knowledge.toml, declared schema file, live store)`.
fn services(run: &Run) -> Vec<(&'static str, &'static str, &Db)> {
    vec![
        (
            "keyring_service",
            "server/keyring-schema.toml",
            run.keyring.db(),
        ),
        (
            "content_service",
            "server/content-schema.toml",
            run.content.db(),
        ),
        (
            "issuer_service",
            "server/issuer-schema.toml",
            run.issuer.db(),
        ),
    ]
}

#[test]
fn the_real_servers_store_only_permitted_knowledge() {
    let run = exercise();
    let wl = whitelist(&load("docs/permitted-knowledge.toml"));

    for (service, _, db) in services(&run) {
        let inv = db.inventory();
        assert!(
            !inv.is_empty(),
            "{service} stored nothing; the session did not exercise it"
        );

        let observed = ServiceSchema {
            service: service.to_string(),
            tables: inv
                .into_iter()
                .map(|(t, f)| (t, f.into_iter().collect::<Vec<_>>()))
                .collect(),
        };
        let v = check_permitted(&observed, &wl);
        assert!(
            v.is_empty(),
            "{service} persisted knowledge it may not hold:\n  {}",
            v.join("\n  ")
        );
    }
}

#[test]
fn the_declared_schemas_match_what_the_servers_actually_store() {
    // The stage 1 declarations are hand-written, so they can drift from the code.
    // This is the only test that can catch that, and it is why gate 5 has to run
    // against a real server rather than against the declarations.
    let run = exercise();

    for (service, file, db) in services(&run) {
        let declared = service_schema(&load(file));
        assert_eq!(
            declared.service, service,
            "{file} declares the wrong service"
        );

        let live = db.inventory();
        for (table, fields) in &live {
            let Some((_, dfields)) = declared.tables.iter().find(|(t, _)| t == table) else {
                panic!("{service}: table `{table}` is written by the code but absent from {file}");
            };
            for f in fields {
                assert!(
                    dfields.contains(f),
                    "{service}: `{table}.{f}` is written by the code but absent from {file}"
                );
            }
        }
        for (table, fields) in &declared.tables {
            if let Some(lf) = live.get(table.as_str()) {
                for f in fields {
                    assert!(
                        lf.contains(f),
                        "{service}: {file} declares `{table}.{f}`, which the code never writes. \
                         A declaration nobody exercises is a declaration nobody checks."
                    );
                }
            }
        }
    }
}

#[test]
fn the_servers_hold_no_plaintext() {
    let run = exercise();
    let mut everything = run.keyring.db().all_bytes();
    everything.extend_from_slice(&run.content.db().all_bytes());
    everything.extend_from_slice(&run.issuer.db().all_bytes());

    for needle in MESSAGES.iter().map(|m| m.as_bytes()).chain([PHOTO]) {
        assert!(
            !everything.windows(needle.len()).any(|w| w == needle),
            "plaintext survived into a server's storage"
        );
    }
}

#[test]
fn no_server_holds_a_graph_edge() {
    // The strongest claim in the spec: "We can't hand over a social graph we never
    // had." Concretely — no single row may name two accounts, and no row outside
    // the keyring service may name an account at all.
    let run = exercise();
    let alice = Identity::from_phrase(PHRASE_A).unwrap();
    let bob = Identity::from_mnemonic(&Mnemonic::from_entropy(&[2; 32]));

    let addrs = [alice.addr().to_hex(), bob.addr().to_hex()];
    let keys = [
        alice.public().sign.as_bytes().to_vec(),
        bob.public().sign.as_bytes().to_vec(),
    ];

    // The content store must not know either account, in any form.
    let content_bytes = run.content.db().all_bytes();
    for a in &addrs {
        assert!(
            !content_bytes.windows(a.len()).any(|w| w == a.as_bytes()),
            "the content store holds an address"
        );
    }
    for k in &keys {
        assert!(
            !content_bytes.windows(k.len()).any(|w| w == k.as_slice()),
            "the content store holds a public key"
        );
    }

    // The keyring service knows addresses — that is its job — but no row may
    // mention two of them, which is what an edge would look like.
    for table in [
        keyring::T_KEYRING,
        keyring::T_DELTA,
        keyring::T_QUOTA,
        keyring::T_RATE,
    ] {
        for row in run.keyring.db().rows(table) {
            let mut bytes = Vec::new();
            for (name, cell) in &row {
                bytes.extend_from_slice(name.as_bytes());
                match cell {
                    spark_store::Cell::Bytes(b) => bytes.extend_from_slice(b),
                    spark_store::Cell::Num(n) => bytes.extend_from_slice(&n.to_be_bytes()),
                    spark_store::Cell::Text(s) => bytes.extend_from_slice(s.as_bytes()),
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
fn the_keyring_address_derivation_agrees_across_the_trust_boundary() {
    // spark-keyring-server duplicates the address prefix rather than depending on
    // spark-identity, which lives in the client's graph. Duplication that nothing
    // checks is duplication that drifts.
    let run = exercise();
    let alice = Identity::from_phrase(PHRASE_A).unwrap();
    assert!(
        run.keyring
            .db()
            .has(spark_keyring_server::T_KEYRING, &alice.addr().to_hex()),
        "the server derived a different address than the client did"
    );
}

#[test]
fn a_wrong_key_cannot_authenticate_against_an_address() {
    let ks = keyring::Keyring::new(Db::new(), Secret::new([0xa1; 32]));
    let alice = Identity::from_phrase(PHRASE_A).unwrap();
    let bob = Identity::from_mnemonic(&Mnemonic::from_entropy(&[2; 32]));
    let addr = *alice.addr().as_bytes();

    // Bob's key against Alice's address.
    let forged = keyring::Auth {
        addr,
        key: *bob.public().sign.as_bytes(),
        sig: *bob.sign(&ks.challenge(&addr)).as_bytes(),
    };
    assert_eq!(
        ks.handle(keyring::Request::GetSnapshot(forged)),
        keyring::Response::Refused(keyring::Refusal::AddrMismatch)
    );

    // Alice's own key, but a signature over a stale challenge.
    let stale = ks.challenge(&addr);
    ks.set_minute(99);
    let replayed = keyring::Auth {
        addr,
        key: *alice.public().sign.as_bytes(),
        sig: *alice.sign(&stale).as_bytes(),
    };
    assert_eq!(
        ks.handle(keyring::Request::GetSnapshot(replayed)),
        keyring::Response::Refused(keyring::Refusal::BadAuth)
    );
}
