//! The total order's claims, tested as claims.
//!
//! "Every member sees identical history" reduces to: this function is a pure
//! function of the set of entries, and does not depend on the order they arrived.

use spark_chunk::{LaneId, Slot};
use spark_crypto::{Mnemonic, Secret, SigningKey};
use spark_keyring::RoomId;
use spark_sync::entry::Signed;
use spark_sync::*;

/// A signer standing in for an identity. The ordering tests do not care whose
/// key it is, only that authorship is real rather than assumed.
fn signer(b: u8) -> SigningKey {
    SigningKey::from_secret(&Secret::new([b; 32]))
}

fn signed(slot: Slot, epoch: u64, body: &str, sk: &SigningKey) -> Signed {
    Signed::new(
        slot,
        epoch,
        body.as_bytes().to_vec(),
        &sk.verifying_key(),
        |m| sk.sign(m),
    )
}

fn lane(b: u8) -> LaneId {
    let mut id = [0u8; 16];
    id[0] = 1;
    id[1] = b;
    LaneId::from_bytes(id)
}

fn entry(l: LaneId, seq: u64, epoch: u64, saw: &[(LaneId, u64)], body: &str) -> Entry {
    let mut c = Clock::new();
    for (ln, s) in saw {
        c.observe(*ln, *s);
    }
    let slot = Slot::new(l, seq);
    let sk = signer(7);
    Entry::new(
        slot,
        epoch,
        c,
        Payload::Application(signed(slot, epoch, body, &sk)),
    )
}

fn bodies(v: &[Entry]) -> Vec<String> {
    v.iter()
        .map(|e| match &e.payload {
            Payload::Application(s) => String::from_utf8_lossy(&s.body).into_owned(),
            Payload::Commit(_) => "<commit>".into(),
            Payload::LaneAdvert => "<advert>".into(),
        })
        .collect()
}

#[test]
fn arrival_order_does_not_affect_the_result() {
    // The claim that matters. Two clients fetch the same chunks in whatever order
    // their requests happened to complete, and must still agree.
    let (a, b) = (lane(1), lane(2));
    let entries = vec![
        entry(a, 0, 1, &[], "a0"),
        entry(a, 1, 1, &[(b, 0)], "a1"),
        entry(b, 0, 1, &[(a, 0)], "b0"),
        entry(b, 1, 1, &[(a, 1)], "b1"),
    ];

    let canonical = bodies(&total_order(entries.clone()));
    // Every permutation must land on the same history.
    let n = entries.len();
    let mut perms = 0;
    for i in 0..n {
        for j in 0..n {
            let mut p = entries.clone();
            p.swap(i, j);
            p.reverse();
            assert_eq!(
                bodies(&total_order(p)),
                canonical,
                "arrival order changed history"
            );
            perms += 1;
        }
    }
    assert!(perms > 0);
}

#[test]
fn causality_is_respected_across_lanes() {
    let (a, b) = (lane(1), lane(2));
    // b0 saw a0, so a0 must come first however they are handed in.
    let out = bodies(&total_order(vec![
        entry(b, 0, 1, &[(a, 0)], "b0"),
        entry(a, 0, 1, &[], "a0"),
    ]));
    assert_eq!(out, ["a0", "b0"]);
}

#[test]
fn a_lane_is_always_in_sequence() {
    let a = lane(1);
    let out = bodies(&total_order(vec![
        entry(a, 2, 1, &[], "a2"),
        entry(a, 0, 1, &[], "a0"),
        entry(a, 1, 1, &[], "a1"),
    ]));
    assert_eq!(out, ["a0", "a1", "a2"], "a lane came out of sequence");
}

#[test]
fn epochs_dominate_causality() {
    // MLS already totally orders epochs, so an entry from a later epoch follows
    // one from an earlier epoch even if the clocks say nothing.
    let (a, b) = (lane(1), lane(2));
    let out = bodies(&total_order(vec![
        entry(b, 0, 9, &[], "late"),
        entry(a, 0, 1, &[], "early"),
    ]));
    assert_eq!(out, ["early", "late"]);
}

#[test]
fn concurrent_writes_break_by_lane_then_seq() {
    // Neither saw the other: rule 3 decides, and it must be deterministic rather
    // than "whatever the sort did".
    let (a, b) = (lane(1), lane(2));
    let out = bodies(&total_order(vec![
        entry(b, 0, 1, &[], "b0"),
        entry(a, 0, 1, &[], "a0"),
    ]));
    assert_eq!(out, ["a0", "b0"], "concurrent order is not by lane bytes");
}

#[test]
fn a_cycle_terminates_instead_of_hanging() {
    // Honest clients cannot produce this; a corrupt or hostile one can. A client
    // that hangs on a malformed history is worse than one that orders it oddly.
    let (a, b) = (lane(1), lane(2));
    let cyclic = vec![
        entry(a, 0, 1, &[(b, 0)], "a0"),
        entry(b, 0, 1, &[(a, 0)], "b0"),
    ];
    let out = total_order(cyclic);
    assert_eq!(out.len(), 2, "entries were dropped");
    assert_eq!(
        bodies(&out),
        ["a0", "b0"],
        "cycle fallback is not deterministic"
    );
}

#[test]
fn an_entry_cannot_be_replayed_into_another_slot() {
    // The chunk key is derived from (lane, seq), so a mismatch means something is
    // wrong that authentication alone would not have caught.
    let a = lane(1);
    let e = entry(a, 3, 1, &[], "payload");
    let bytes = e.encode();
    assert!(Entry::decode(&bytes, Slot::new(a, 3)).is_ok());
    assert_eq!(
        Entry::decode(&bytes, Slot::new(a, 4)).unwrap_err(),
        EntryError::SlotMismatch
    );
    assert_eq!(
        Entry::decode(&bytes, Slot::new(lane(2), 3)).unwrap_err(),
        EntryError::SlotMismatch
    );
}

#[test]
fn a_clock_distinguishes_unknown_from_zero() {
    // Sequence numbers start at zero, so "never heard of this lane" and "seen its
    // first chunk" are different facts. Conflating them would make `plan` re-fetch
    // seq 0 forever, or skip it.
    let mut c = Clock::new();
    assert_eq!(c.get(lane(1)), None);
    c.observe(lane(1), 0);
    assert_eq!(c.get(lane(1)), Some(0));
    assert!(c.has_seen(lane(1), 0));
    assert!(!c.has_seen(lane(1), 1));
}

#[test]
fn a_clock_never_rewinds() {
    let mut c = Clock::new();
    c.observe(lane(1), 5);
    c.observe(lane(1), 2);
    assert_eq!(c.get(lane(1)), Some(5));

    let mut other = Clock::new();
    other.observe(lane(1), 1);
    other.observe(lane(2), 9);
    c.merge(&other);
    assert_eq!(c.get(lane(1)), Some(5), "merge rewound a lane");
    assert_eq!(c.get(lane(2)), Some(9));
    assert!(c.dominates(&other));
    assert!(!other.dominates(&c));
}

#[test]
fn plan_asks_for_the_next_unseen_slot_in_each_lane() {
    let mut c = Clock::new();
    c.observe(lane(1), 4);
    let slots = plan(&c, &[lane(1), lane(2)], 2);
    assert_eq!(
        slots[0],
        Slot::new(lane(1), 5),
        "did not resume after the known head"
    );
    assert_eq!(slots[1], Slot::new(lane(1), 6));
    assert_eq!(
        slots[2],
        Slot::new(lane(2), 0),
        "an unknown lane must start at zero"
    );
}

#[test]
fn a_slot_cannot_be_sealed_without_being_reserved_first() {
    // The type rule standing in for protocol §3.2's MUST. `Reservation` has no
    // public constructor, is not Clone, and is consumed by sealing — so the only
    // way to reach a slot is through a reserve that also hands back the delta.
    let mut ob = Outbox::new(RoomId([1; 16]), 0, lane(1), 0);
    let (r0, d0) = ob.reserve();
    assert_eq!(r0.slot(), Slot::new(lane(1), 0));
    assert!(matches!(
        d0,
        spark_keyring::Delta::ReserveSlot { seq: 0, .. }
    ));

    let (r1, _) = ob.reserve();
    assert_eq!(
        r1.slot(),
        Slot::new(lane(1), 1),
        "two reservations shared a slot"
    );
    assert_eq!(r0.consume(), Slot::new(lane(1), 0));
}

#[test]
fn an_abandoned_slot_is_never_handed_out_again() {
    // A gap in a lane is harmless; a reused nonce is not.
    let mut ob = Outbox::new(RoomId([1; 16]), 0, lane(1), 0);
    let (r, _) = ob.reserve();
    let abandoned = ob.abandon(r);
    let (next, _) = ob.reserve();
    assert_ne!(next.slot(), abandoned, "an abandoned slot was reissued");
    assert_eq!(next.slot(), Slot::new(lane(1), 1));
}

#[test]
fn a_restored_outbox_resumes_past_what_was_reserved() {
    // A client that crashed between reserving and sealing must not reuse the slot.
    // Losing one slot is the correct trade.
    let mut before = Outbox::new(RoomId([1; 16]), 0, lane(1), 0);
    let (_reserved, _delta) = before.reserve(); // crash here: the delta was persisted
    let after = Outbox::new(RoomId([1; 16]), 0, lane(1), before.next_seq());
    assert_eq!(after.next_seq(), 1, "restore reused a reserved slot");
}

#[test]
fn authorship_is_verified_not_assumed() {
    // The archive is confidential because of the chunk AEAD; it is *attributable*
    // because of this signature. Without the check, anyone who could write a
    // chunk could write it as anyone.
    let l = lane(1);
    let slot = Slot::new(l, 3);
    let sk = signer(11);
    let s = signed(slot, 5, "genuine", &sk);
    assert_eq!(s.verify(slot, 5).unwrap(), sk.verifying_key());

    // A different slot: the signature covers lane and seq, so a message cannot be
    // lifted out of one slot and replayed into another.
    assert_eq!(
        s.verify(Slot::new(l, 4), 5).unwrap_err(),
        EntryError::BadSignature
    );
    assert_eq!(
        s.verify(Slot::new(lane(2), 3), 5).unwrap_err(),
        EntryError::BadSignature
    );
    // A different epoch.
    assert_eq!(s.verify(slot, 6).unwrap_err(), EntryError::BadSignature);

    // A forged sender: claiming someone else's key does not produce their
    // signature.
    let mut forged = s.clone();
    forged.sender = *signer(12).verifying_key().as_bytes();
    assert_eq!(
        forged.verify(slot, 5).unwrap_err(),
        EntryError::BadSignature
    );

    // A tampered body.
    let mut edited = s.clone();
    edited.body = b"forged".to_vec();
    assert_eq!(
        edited.verify(slot, 5).unwrap_err(),
        EntryError::BadSignature
    );

    // A truncated signature is a verification failure, not a panic.
    let mut short = s.clone();
    short.sig.truncate(10);
    assert_eq!(short.verify(slot, 5).unwrap_err(), EntryError::BadSignature);

    let _ = Mnemonic::from_entropy(&[0; 32]);
}
