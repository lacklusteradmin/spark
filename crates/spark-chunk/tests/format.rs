//! The chunk format's claims, tested as claims rather than as round trips.

use spark_chunk::*;
use spark_crypto::{Secret, SigningKey, VerifyingKey};

/// A valid Ed25519 public key, without reaching for spark-identity: this crate
/// sits at the same layer, and a test-only edge is still an edge.
fn pubkey(b: u8) -> VerifyingKey {
    SigningKey::from_secret(&Secret::new([b; 32])).verifying_key()
}

fn key(b: u8) -> Secret<32> {
    Secret::new([b; 32])
}
fn root(b: u8) -> RoomRoot {
    Secret::new([b; 32])
}

#[test]
fn header_is_authenticated_not_merely_present() {
    // The header is the AAD, so a chunk relabelled in transit must not open.
    let c = Chunk::seal(Kind::Media, &key(1), &[2; 24], b"payload");
    let mut tampered = c.as_bytes().to_vec();
    tampered[5] = Kind::Keyring as u8;
    let relabelled = Chunk::from_bytes(tampered).unwrap();
    assert_eq!(
        relabelled.kind().unwrap(),
        Kind::Keyring,
        "the label did change"
    );
    assert_eq!(
        relabelled.open(&key(1)).err(),
        Some(ChunkError::NotAuthentic)
    );
}

#[test]
fn a_flipped_ciphertext_byte_does_not_open() {
    let c = Chunk::seal(Kind::RoomLog, &key(1), &[2; 24], b"payload");
    let mut t = c.as_bytes().to_vec();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert_eq!(
        Chunk::from_bytes(t).unwrap().open(&key(1)).err(),
        Some(ChunkError::NotAuthentic)
    );
}

#[test]
fn reserved_flags_are_rejected_not_ignored() {
    // A reserved field that decoders skip is a field that can never be used.
    let c = Chunk::seal(Kind::Media, &key(1), &[2; 24], b"x");
    let mut t = c.as_bytes().to_vec();
    t[6] = 0x01;
    assert_eq!(
        Chunk::from_bytes(t).err(),
        Some(ChunkError::Header(HeaderError::ReservedFlagsSet))
    );
}

#[test]
fn malformed_chunks_are_rejected_at_the_boundary() {
    assert_eq!(
        Chunk::from_bytes(vec![]).err(),
        Some(ChunkError::Header(HeaderError::TooShort))
    );
    assert_eq!(
        Chunk::from_bytes(vec![0; HEADER_LEN + 16]).err(),
        Some(ChunkError::Header(HeaderError::BadMagic))
    );
    let mut bad_version = Chunk::seal(Kind::Media, &key(1), &[0; 24], b"x")
        .as_bytes()
        .to_vec();
    bad_version[4] = 99;
    assert_eq!(
        Chunk::from_bytes(bad_version).err(),
        Some(ChunkError::Header(HeaderError::UnknownVersion(99)))
    );
}

#[test]
fn the_header_leaks_only_kind_and_nonce() {
    // "A chunk carries no routing information." Two chunks of the same kind and
    // length must be indistinguishable outside their nonce.
    let a = Chunk::seal(Kind::RoomLog, &key(1), &[0; 24], b"aaaaaaaa");
    let b = Chunk::seal(Kind::RoomLog, &key(2), &[0; 24], b"bbbbbbbb");
    assert_eq!(a.as_bytes()[..HEADER_LEN], b.as_bytes()[..HEADER_LEN]);
    assert_eq!(a.len(), b.len());
}

// ---------------------------------------------------------------- media

#[test]
fn identical_files_produce_one_identical_chunk() {
    // The whole basis of "a photo twenty people sent costs one copy".
    let (n1, k1, c1) = media::seal_raw(b"a shared photo");
    let (n2, k2, c2) = media::seal_raw(b"a shared photo");
    assert_eq!(n1, n2);
    assert_eq!(
        c1.as_bytes(),
        c2.as_bytes(),
        "convergent encryption was not deterministic"
    );
    assert_eq!(k1.expose(), k2.expose());
}

#[test]
fn different_files_do_not_collide() {
    let (a, _, _) = media::seal_raw(b"one file");
    let (b, _, _) = media::seal_raw(b"another file");
    assert_ne!(a, b);
}

#[test]
fn the_store_can_verify_a_media_name_without_any_key() {
    // Hashing the finished chunk rather than the plaintext is what closes name
    // squatting: nobody can claim a name they cannot produce bytes for.
    let (name, _, chunk) = media::seal_raw(b"contents");
    assert_eq!(media::name_of(&chunk), name);

    let impostor = Chunk::seal(Kind::Media, &key(9), &[9; 24], b"different contents");
    assert_ne!(
        media::name_of(&impostor),
        name,
        "a forged chunk claimed a taken name"
    );
}

#[test]
fn a_media_chunk_is_inert_without_its_key() {
    let (_, k, c) = media::seal_raw(b"contents");
    assert!(media::open(&c, &k).is_ok());
    assert_eq!(
        media::open(&c, &key(0)).err(),
        Some(ChunkError::NotAuthentic)
    );
}

#[test]
fn the_capability_is_recoverable_from_the_file() {
    // Re-sharing a file into another room must not need a re-upload.
    let (name, key1, _) = media::seal_raw(b"contents");
    let (name2, key2) = media::capability_raw(b"contents");
    assert_eq!(name, name2);
    assert_eq!(key1.expose(), key2.expose());
}

// ---------------------------------------------------------------- room log

#[test]
fn room_names_are_unguessable_without_the_root() {
    let slot = Slot::new(LaneId::COMMIT, 0);
    assert_ne!(room::name(&root(1), slot), room::name(&root(2), slot));
}

#[test]
fn every_slot_gets_a_distinct_name_key_and_nonce() {
    // A collision here would mean a reused nonce, which for XChaCha20-Poly1305 is
    // catastrophic rather than merely wrong.
    let r = root(5);
    let lane_a = LaneId::COMMIT;
    let lane_b = LaneId::message(&pubkey(4));

    let mut names = Vec::new();
    let mut nonces = Vec::new();
    for lane in [lane_a, lane_b] {
        for seq in 0..8u64 {
            let slot = Slot::new(lane, seq);
            names.push(room::name(&r, slot));
            let mut nonce = [0; 24];
            nonce[..16].copy_from_slice(lane.as_bytes());
            nonce[16..].copy_from_slice(&seq.to_be_bytes());
            let (_, chunk) = room::seal(&r, slot, &nonce, b"same plaintext every time");
            nonces.push(chunk.header().unwrap().nonce);
        }
    }
    let n = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), n, "two slots shared a name");
    nonces.sort();
    nonces.dedup();
    assert_eq!(nonces.len(), n, "two slots shared a nonce");
}

#[test]
fn the_same_message_at_two_slots_is_two_different_chunks() {
    // Otherwise the store could tell that a message was repeated.
    let r = root(5);
    let (_, a) = room::seal(&r, Slot::new(LaneId::COMMIT, 0), &[7; 24], b"ok");
    let (_, b) = room::seal(&r, Slot::new(LaneId::COMMIT, 1), &[7; 24], b"ok");
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn a_room_chunk_opens_only_at_its_own_slot() {
    let r = root(5);
    let slot = Slot::new(LaneId::COMMIT, 3);
    let (_, c) = room::seal(&r, slot, &[7; 24], b"payload");
    assert!(room::open(&r, slot, &c).is_ok());
    assert!(
        room::open(&r, slot.next(), &c).is_err(),
        "opened at the wrong seq"
    );
    assert!(
        room::open(&root(6), slot, &c).is_err(),
        "opened under the wrong root"
    );
}

// ---------------------------------------------------------------- lanes

#[test]
fn the_commit_lane_is_distinguishable_and_unique() {
    assert!(LaneId::COMMIT.is_commit());
    assert_eq!(LaneId::COMMIT.as_bytes()[0], 0);
}

#[test]
fn message_lanes_are_keyed_by_identity_not_by_position() {
    // Leaf indices are recycled when members leave; identity keys are not.
    let a = LaneId::message(&pubkey(1));
    let b = LaneId::message(&pubkey(2));
    assert_ne!(a, b);
    assert!(
        !a.is_commit() && !b.is_commit(),
        "a message lane collided with the commit lane"
    );
    assert_eq!(a.as_bytes()[0], 1, "message lanes are tagged");
    assert_eq!(
        a,
        LaneId::message(&pubkey(1)),
        "lane derivation is not deterministic"
    );
}
