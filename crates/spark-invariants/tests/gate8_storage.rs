//! Gate 8, the longest gate:
//!
//! > Two accounts uploading one file produce one chunk and two full charges; a
//! > viewer is charged nothing; a ten-member room stores one history; receipts
//! > restore from seed; dissolve deletes room chunks and spares shared media; the
//! > content store logs nothing about who; GPS EXIF cannot survive a send.

use spark_chunk::{Chunk, LaneId, Slot, media, room, scrub};
use spark_crypto::{Mnemonic, Secret};
use spark_identity::Identity;
use spark_keyring::{
    ChunkClass, Delta, Generation, Keyring, Receipt, Room as KeyRoom, RoomId, SerName, Upload,
};
use spark_store::Db;

use spark_content_server as content;
use spark_keyring_server as keyring;

mod common;
use common::{Fixed, issuer, token};

const ROOM: RoomId = RoomId([5; 16]);

fn ident(e: u8) -> Identity {
    Identity::from_mnemonic(&Mnemonic::from_entropy(&[e; 32]))
}

fn auth(ks: &keyring::Keyring, id: &Identity) -> keyring::Auth {
    let addr = *id.addr().as_bytes();
    keyring::Auth {
        addr,
        key: *id.public().sign.as_bytes(),
        sig: *id.sign(&ks.challenge(&addr)).as_bytes(),
    }
}

/// Draw a token through the real blind dance, spend it, and return the outcome.
///
/// This is the whole point of the construction in one function: `who` pays at the
/// keyring service, which signs bytes it cannot read; the content service checks
/// a signature that tells it nothing about `who`.
fn upload(
    ks: &keyring::Keyring,
    cs: &content::Content,
    who: &Identity,
    serial: u8,
    name: &spark_chunk::ChunkName,
    chunk: &Chunk,
) -> content::Response {
    let pk = ks.issuer_public();
    let class = spark_tokens::class_for(chunk.len() as u64);
    let (blinded, w) =
        spark_tokens::begin(&pk, &mut Fixed(serial as u64 + 3), &[[serial; 32]], class)
            .expect("blind");
    let keyring::Response::Tokens(sigs) = ks.handle(keyring::Request::WithdrawTokens {
        auth: auth(ks, who),
        blinded,
        size_class: class,
    }) else {
        panic!("withdrawal refused")
    };
    let spendable = spark_tokens::finish(&pk, w, &sigs).expect("finalize");
    cs.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim: spendable[0].claim,
        token: spendable[0].token.clone(),
    })
}

/// A photo with location data in it, as a phone would produce.
fn photo(tag: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    let mut exif = b"Exif\x00\x00II*\x00".to_vec();
    exif.extend_from_slice(b"GPSLatitude 51.5074 ");
    exif.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(&[0xFF, 0xE1]);
    v.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(&exif);
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    v.extend_from_slice(b"THE-SAME-PICTURE-BYTES");
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

// ---------------- one file, one chunk, two full charges; a viewer pays nothing

#[test]
fn two_accounts_uploading_one_file_produce_one_chunk_and_two_full_charges() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let cs = content::Content::new(Db::new(), issuer().public());
    let (alice, bob, viewer) = (ident(1), ident(2), ident(3));

    // Two phones, the same picture, different EXIF. Scrubbing before hashing is
    // what makes these one chunk rather than two.
    let a_file = scrub::scrub(&photo("camera-A")).unwrap();
    let b_file = scrub::scrub(&photo("camera-B")).unwrap();
    let (name, key, chunk) = media::seal(&a_file);
    assert_eq!(
        media::capability(&b_file).0,
        name,
        "the same picture became two chunks"
    );

    let mut receipts = Vec::new();
    for (i, who) in [&alice, &bob].into_iter().enumerate() {
        match upload(&ks, &cs, who, i as u8 + 1, &name, &chunk) {
            content::Response::Stored { receipt } => receipts.push((who.addr(), Receipt(receipt))),
            r => panic!("upload {i} refused: {r:?}"),
        }
    }

    assert_eq!(
        cs.db().keys(content::T_CHUNK).len(),
        1,
        "one file, two chunks"
    );
    assert_ne!(receipts[0].1, receipts[1].1, "two holders got one receipt");

    // Both were charged in full. A discount for the second would let anyone probe
    // what Spark holds (build-notes §4). The charge is the token's size class,
    // which is what the client paid for and what the store enforces.
    let class_bytes = 1u64 << spark_tokens::class_for(chunk.len() as u64);
    for who in [&alice, &bob] {
        let keyring::Response::Quota { used, .. } =
            ks.handle(keyring::Request::GetQuota(auth(&ks, who)))
        else {
            panic!()
        };
        assert_eq!(used, class_bytes, "an uploader was not charged in full");
    }

    // A viewer fetches the file and is charged nothing. Reads carry no identity,
    // so there is nobody to charge even in principle.
    let content::Response::Chunk(bytes) = cs.handle(content::Request::Get {
        name: *name.as_bytes(),
    }) else {
        panic!("read refused")
    };
    let got = media::open(&Chunk::from_bytes(bytes).unwrap(), &key).unwrap();
    assert!(
        got.windows(9).any(|w| w == b"THE-SAME-"),
        "the viewer got the wrong bytes"
    );

    let keyring::Response::Quota { used, .. } =
        ks.handle(keyring::Request::GetQuota(auth(&ks, &viewer)))
    else {
        panic!()
    };
    assert_eq!(used, 0, "a viewer was charged");
}

// ------------------------------------------- a ten-member room stores one history

#[test]
fn a_ten_member_room_stores_one_history() {
    let cs = content::Content::new(Db::new(), issuer().public());
    let root: room::RoomRoot = Secret::new([0x5a; 32]);
    let lane = LaneId::message(&ident(1).public().sign);

    // One member writes twenty messages. The other nine read them; nothing about
    // the room's size appears in what is stored.
    for seq in 0..20u64 {
        let (name, chunk) =
            room::seal(&root, Slot::new(lane, seq), format!("msg {seq}").as_bytes());
        let (c, t) = token(seq as u8, chunk.len() as u64);
        cs.handle(content::Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            claim: c,
            token: t,
        });
    }

    assert_eq!(
        cs.db().keys(content::T_CHUNK).len(),
        20,
        "history was stored more than once"
    );

    // Ten members each read the whole history. Storage does not move.
    for _ in 0..10 {
        for seq in 0..20u64 {
            let name = room::name(&root, Slot::new(lane, seq));
            assert!(matches!(
                cs.handle(content::Request::Get {
                    name: *name.as_bytes()
                }),
                content::Response::Chunk(_)
            ));
        }
    }
    assert_eq!(
        cs.db().keys(content::T_CHUNK).len(),
        20,
        "reading changed what is stored"
    );
}

// ----------------------------------------------------- receipts restore from seed

#[test]
fn receipts_restore_from_seed() {
    // A lost receipt strands a chunk forever (F7), so this is not bookkeeping —
    // it is the difference between reclaimable space and space gone for good.
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let cs = content::Content::new(Db::new(), issuer().public());
    let alice = ident(1);

    let file = scrub::scrub(&photo("x")).unwrap();
    let (name, _, chunk) = media::seal(&file);
    let (c, t) = token(1, chunk.len() as u64);
    let content::Response::Stored { receipt } = cs.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim: c,
        token: t,
    }) else {
        panic!()
    };

    let mut k = Keyring::new();
    k.apply(&Delta::AddUpload(Upload {
        name: name.into(),
        receipt: Receipt(receipt),
        size: chunk.len() as u64,
        class: ChunkClass::Media,
        room: Some(ROOM),
    }));
    let snap = k.seal_snapshot(alice.keyring_key(), &[9; 24]);
    ks.handle(keyring::Request::PutSnapshot(
        auth(&ks, &alice),
        snap.as_bytes().to_vec(),
    ));

    // ---- wipe. Only the mnemonic survives. ----

    let restored_id = Identity::from_mnemonic(&Mnemonic::from_entropy(&[1; 32]));
    let keyring::Response::Snapshot(Some(b)) =
        ks.handle(keyring::Request::GetSnapshot(auth(&ks, &restored_id)))
    else {
        panic!("no keyring")
    };
    let k2 =
        Keyring::open_snapshot(&Chunk::from_bytes(b).unwrap(), restored_id.keyring_key()).unwrap();
    let up = k2.uploads.first().expect("the upload list survived");

    // The restored receipt still releases the chunk, which is the whole point.
    match cs.handle(content::Request::Release {
        name: *spark_chunk::ChunkName::from(up.name).as_bytes(),
        receipt: up.receipt.0,
    }) {
        content::Response::Released { freed, .. } => {
            assert!(freed, "a restored receipt did not free")
        }
        r => panic!("release refused: {r:?}"),
    }
}

// ------------------------ dissolve deletes room chunks and spares shared media

#[test]
fn dissolve_deletes_room_chunks_and_spares_shared_media() {
    // "Room chunks are freed by deletion at dissolve; media chunks by receipt
    // count. They are not the same mechanism." (build-notes §4) And spec F4: the
    // client must say so, because users will assume dissolving cleans up.
    let cs = content::Content::new(Db::new(), issuer().public());
    let root: room::RoomRoot = Secret::new([0x5a; 32]);
    let lane = LaneId::COMMIT;

    let mut room_names = Vec::new();
    for seq in 0..5u64 {
        let (name, chunk) = room::seal(&root, Slot::new(lane, seq), b"history");
        let (c, t) = token(seq as u8, chunk.len() as u64);
        cs.handle(content::Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            claim: c,
            token: t,
        });
        room_names.push(name);
    }

    // A photo shared into the room, and also held by someone outside it.
    let file = scrub::scrub(&photo("shared")).unwrap();
    let (photo_name, _, photo_chunk) = media::seal(&file);
    for holder in 100..102u8 {
        let (c, t) = token(holder, photo_chunk.len() as u64);
        cs.handle(content::Request::Put {
            name: *photo_name.as_bytes(),
            chunk: photo_chunk.as_bytes().to_vec(),
            claim: c,
            token: t,
        });
    }

    // Dissolve: the owner derives every room chunk name from the generation roots
    // in their keyring and deletes them outright.
    for n in &room_names {
        assert_eq!(
            cs.handle(content::Request::Delete {
                name: *n.as_bytes()
            }),
            content::Response::Deleted
        );
    }
    for n in &room_names {
        assert_eq!(
            cs.handle(content::Request::Head {
                name: *n.as_bytes()
            }),
            content::Response::Exists(false),
            "a room chunk survived dissolve"
        );
    }

    // The photo is untouched, and cannot be deleted by the room's owner at all.
    assert_eq!(
        cs.handle(content::Request::Head {
            name: *photo_name.as_bytes()
        }),
        content::Response::Exists(true),
        "dissolve took shared media with it"
    );
    assert_eq!(
        cs.handle(content::Request::Delete {
            name: *photo_name.as_bytes()
        }),
        content::Response::Refused(content::Refusal::NotDeletable)
    );
}

// -------------------------------------- the content store logs nothing about who

#[test]
fn the_content_store_logs_nothing_about_who() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let cs = content::Content::new(Db::new(), issuer().public());
    let ids: Vec<Identity> = (1..=4).map(ident).collect();

    let file = scrub::scrub(&photo("p")).unwrap();
    let (name, _, chunk) = media::seal(&file);
    for (i, who) in ids.iter().enumerate() {
        assert!(
            matches!(
                upload(&ks, &cs, who, i as u8 + 1, &name, &chunk),
                content::Response::Stored { .. }
            ),
            "upload {i} refused"
        );
    }

    let bytes = cs.db().all_bytes();
    for who in &ids {
        let hex = who.addr().to_hex();
        assert!(
            !bytes.windows(hex.len()).any(|w| w == hex.as_bytes()),
            "an address is stored"
        );
        let pk = *who.public().sign.as_bytes();
        assert!(
            !bytes.windows(32).any(|w| w == pk),
            "a public key is stored"
        );
    }

    // It knows there are four holders. It does not know of whom.
    let count = cs
        .db()
        .field(content::T_CHUNK, &name.to_hex(), "receipt_count")
        .and_then(|c| c.num())
        .unwrap();
    assert_eq!(
        count, 4,
        "the holder count is what the store is allowed to know"
    );
}

// -------------------------------------------- quota is refunded across the seam

#[test]
fn releasing_refunds_quota_without_relinking_the_upload() {
    // docs/protocol.md §7. If the refund voucher were cleartext it would bind
    // "this upload" to "this identity" and undo the blind token that authorised
    // the upload in the first place.
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let cs = content::Content::new(Db::new(), issuer().public());
    let alice = ident(1);

    let file = scrub::scrub(&photo("q")).unwrap();
    let (name, _, chunk) = media::seal(&file);

    let content::Response::Stored { receipt } = upload(&ks, &cs, &alice, 1, &name, &chunk) else {
        panic!("upload refused")
    };

    let size = 1u64 << spark_tokens::class_for(chunk.len() as u64);
    let keyring::Response::Quota { used, .. } =
        ks.handle(keyring::Request::GetQuota(auth(&ks, &alice)))
    else {
        panic!()
    };
    assert_eq!(used, size);

    let content::Response::Released { voucher, .. } = cs.handle(content::Request::Release {
        name: *name.as_bytes(),
        receipt,
    }) else {
        panic!()
    };
    assert_eq!(
        ks.handle(keyring::Request::CreditRefund(
            auth(&ks, &alice),
            voucher.clone(),
            size
        )),
        keyring::Response::Credited
    );
    let keyring::Response::Quota { used, .. } =
        ks.handle(keyring::Request::GetQuota(auth(&ks, &alice)))
    else {
        panic!()
    };
    assert_eq!(used, 0, "quota was not refunded");

    // A voucher spends once.
    assert_eq!(
        ks.handle(keyring::Request::CreditRefund(
            auth(&ks, &alice),
            voucher,
            size
        )),
        keyring::Response::Refused(keyring::Refusal::VoucherSpent)
    );
}

#[test]
fn an_upload_beyond_quota_is_refused() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let alice = ident(1);
    assert_eq!(
        ks.handle(keyring::Request::WithdrawTokens {
            auth: auth(&ks, &alice),
            blinded: vec![vec![0; 256]],
            size_class: 40,
        }),
        keyring::Response::Refused(keyring::Refusal::OverQuota)
    );
}

#[test]
fn the_upload_list_never_judges_what_is_unused() {
    // "No room references this" is indistinguishable from "a room references this
    // but I left it" (build-notes §4). The list records what it knows and marks
    // the rest unknown; it does not offer to tidy up.
    let mut k = Keyring::new();
    k.apply(&Delta::UpsertRoom(KeyRoom {
        id: ROOM,
        generations: vec![Generation {
            epoch: 0,
            root: Secret::new([1; 32]),
            my_next: 0,
        }],
        mls_group_id: Vec::new(),
        display_name: "r".into(),
        my_lane: LaneId::COMMIT.into(),
    }));
    k.apply(&Delta::AddUpload(Upload {
        name: SerName([1; 32]),
        receipt: Receipt([1; 32]),
        size: 100,
        class: ChunkClass::Media,
        room: Some(ROOM),
    }));
    // Shared into a room this account has since left.
    k.apply(&Delta::AddUpload(Upload {
        name: SerName([2; 32]),
        receipt: Receipt([2; 32]),
        size: 200,
        class: ChunkClass::Media,
        room: None,
    }));

    assert_eq!(
        k.bytes_held(),
        300,
        "quota counts everything held, referenced or not"
    );
    assert_eq!(k.uploads.len(), 2);

    // Leaving the room does not drop the upload, and does not change the charge.
    k.apply(&Delta::ForgetRoom(ROOM));
    assert_eq!(
        k.bytes_held(),
        300,
        "leaving a room silently released its uploads"
    );
    assert!(
        k.uploads.iter().any(|u| u.room == Some(ROOM)),
        "an upload was reclassified on leaving"
    );
}
