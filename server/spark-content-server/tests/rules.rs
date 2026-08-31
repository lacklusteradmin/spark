//! The content service's load-bearing rules, each easy to "improve" into a leak.
//! Tested here rather than in the gate so a regression names itself.

use spark_chunk::{Chunk, Kind, LaneId, Slot, media, room};
use spark_content_server::*;
use spark_crypto::Secret;
use spark_store::Db;

fn svc() -> Content {
    Content::new(Db::new())
}
fn tok(n: u8) -> Vec<u8> {
    vec![n; 8]
}
fn hexed(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn a_name_is_write_once() {
    // The commit lane's arbitration point, and the backstop that makes derived
    // room-chunk nonces safe. A store that allowed overwrite would break the
    // AEAD, not merely the ordering.
    let c = svc();
    let root: room::RoomRoot = Secret::new([1; 32]);
    let (name, chunk) = room::seal(&root, Slot::new(LaneId::COMMIT, 0), b"first");

    assert!(matches!(
        c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            token: tok(1)
        }),
        Response::Stored { .. }
    ));
    // A second commit racing for the same slot loses and must retry at seq+1.
    assert_eq!(
        c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            token: tok(2)
        }),
        Response::Refused(Refusal::NameTaken)
    );
}

#[test]
fn two_accounts_uploading_one_file_produce_one_chunk_and_two_charges() {
    let c = svc();
    let (name, _, chunk) = media::seal(b"the same photograph");
    let mut receipts = Vec::new();
    for t in [tok(1), tok(2)] {
        match c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            token: t,
        }) {
            Response::Stored { receipt } => receipts.push(receipt),
            r => panic!("refused: {r:?}"),
        }
    }
    assert_ne!(receipts[0], receipts[1], "two holders got one receipt");
    assert_eq!(c.db().keys(T_CHUNK).len(), 1, "one file became two chunks");
    assert_eq!(
        c.db().keys(T_TOKEN).len(),
        2,
        "the second upload was not charged"
    );
}

#[test]
fn a_duplicate_upload_is_indistinguishable_from_a_fresh_one() {
    // A discount, or a distinguishable response, would let anyone probe what
    // Spark holds (build-notes §4).
    let c = svc();
    let (name, _, chunk) = media::seal(b"probe target");
    let first = c.handle(Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        token: tok(1),
    });
    let second = c.handle(Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        token: tok(2),
    });
    assert!(matches!(first, Response::Stored { .. }));
    assert!(
        matches!(second, Response::Stored { .. }),
        "a duplicate upload was answered differently: {second:?}"
    );
}

#[test]
fn a_token_cannot_be_spent_twice() {
    let c = svc();
    let (n1, _, c1) = media::seal(b"one");
    let (n2, _, c2) = media::seal(b"two");
    assert!(matches!(
        c.handle(Request::Put {
            name: *n1.as_bytes(),
            chunk: c1.as_bytes().to_vec(),
            token: tok(9)
        }),
        Response::Stored { .. }
    ));
    assert_eq!(
        c.handle(Request::Put {
            name: *n2.as_bytes(),
            chunk: c2.as_bytes().to_vec(),
            token: tok(9)
        }),
        Response::Refused(Refusal::TokenSpent)
    );
}

#[test]
fn a_forged_media_name_is_rejected_without_any_key() {
    // Hashing the finished chunk is what lets the store verify a name while
    // holding nothing. Without it, anyone could squat a name they cannot produce.
    let c = svc();
    let (name, _, _) = media::seal(b"the real file");
    let impostor = Chunk::seal(
        Kind::Media,
        &Secret::new([3; 32]),
        &[3; 24],
        b"not the real file",
    );
    assert_eq!(
        c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: impostor.as_bytes().to_vec(),
            token: tok(1)
        }),
        Response::Refused(Refusal::NameMismatch)
    );
}

#[test]
fn media_is_freed_at_zero_holders_and_room_chunks_by_deletion() {
    // "Room chunks are freed by deletion at dissolve; media chunks by receipt
    // count. They are not the same mechanism." (build-notes §4)
    let c = svc();
    let (mname, _, mchunk) = media::seal(b"shared");
    let mut rs = Vec::new();
    for t in [tok(1), tok(2)] {
        match c.handle(Request::Put {
            name: *mname.as_bytes(),
            chunk: mchunk.as_bytes().to_vec(),
            token: t,
        }) {
            Response::Stored { receipt } => rs.push(receipt),
            r => panic!("{r:?}"),
        }
    }
    match c.handle(Request::Release {
        name: *mname.as_bytes(),
        receipt: rs[0],
    }) {
        Response::Released { freed, .. } => assert!(!freed, "freed while a holder remains"),
        r => panic!("{r:?}"),
    }
    assert!(c.db().has(T_CHUNK, &hexed(mname.as_bytes())));
    match c.handle(Request::Release {
        name: *mname.as_bytes(),
        receipt: rs[1],
    }) {
        Response::Released { freed, .. } => assert!(freed, "bytes not freed at zero holders"),
        r => panic!("{r:?}"),
    }
    assert!(!c.db().has(T_CHUNK, &hexed(mname.as_bytes())));

    // Media cannot be deleted outright by one holder's say-so.
    let (m2, _, ch2) = media::seal(b"still shared");
    c.handle(Request::Put {
        name: *m2.as_bytes(),
        chunk: ch2.as_bytes().to_vec(),
        token: tok(5),
    });
    assert_eq!(
        c.handle(Request::Delete {
            name: *m2.as_bytes()
        }),
        Response::Refused(Refusal::NotDeletable)
    );

    // A room chunk is deleted outright at dissolve.
    let root: room::RoomRoot = Secret::new([1; 32]);
    let (rname, rchunk) = room::seal(&root, Slot::new(LaneId::COMMIT, 0), b"history");
    c.handle(Request::Put {
        name: *rname.as_bytes(),
        chunk: rchunk.as_bytes().to_vec(),
        token: tok(6),
    });
    assert_eq!(
        c.handle(Request::Delete {
            name: *rname.as_bytes()
        }),
        Response::Deleted
    );
    assert!(!c.db().has(T_CHUNK, &hexed(rname.as_bytes())));
}

#[test]
fn reads_carry_nothing_and_are_answered_to_anyone() {
    // The name plus the key is the whole capability. There is no session here to
    // authenticate against, which is the point.
    let c = svc();
    let (name, key, chunk) = media::seal(b"readable by anyone who knows the name");
    c.handle(Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        token: tok(1),
    });
    match c.handle(Request::Get {
        name: *name.as_bytes(),
    }) {
        Response::Chunk(b) => {
            let got = Chunk::from_bytes(b).unwrap();
            assert_eq!(
                &media::open(&got, &key).unwrap()[..],
                b"readable by anyone who knows the name"
            );
        }
        r => panic!("{r:?}"),
    }
    assert_eq!(
        c.handle(Request::Head {
            name: *name.as_bytes()
        }),
        Response::Exists(true)
    );
    assert_eq!(
        c.handle(Request::Head { name: [9; 32] }),
        Response::Exists(false)
    );
}
