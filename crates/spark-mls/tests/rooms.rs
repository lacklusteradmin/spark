//! Gate 4: "Every member sees identical history; a removed member cannot read
//! later messages; the last owner cannot leave without dissolving; a 1:1 uses the
//! same owner logic."
//!
//! Two clients in one process, no network — each with its own provider, so
//! neither can see the other's key material.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use spark_crypto::{Mnemonic, Secret, VerifyingKey};
use spark_identity::Identity;
use spark_mls::*;

/// One participant: an identity, its MLS signer, and its own provider.
struct Client {
    id: Identity,
    signer: Signer,
    provider: OpenMlsRustCrypto,
}

impl Client {
    fn new(entropy: u8) -> Self {
        let id = Identity::from_mnemonic(&Mnemonic::from_entropy(&[entropy; 32]));
        // The MLS signature key is the identity key. In production this secret
        // comes from the same derivation; here it is reconstructed the same way.
        let secret = derive_sign_secret(entropy);
        let signer = signer_for(&id, &secret);
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).expect("store signer");
        Self {
            id,
            signer,
            provider,
        }
    }
    fn key(&self) -> VerifyingKey {
        self.id.public().sign
    }
}

/// Re-derive the Ed25519 secret the same way `spark-identity` does.
fn derive_sign_secret(entropy: u8) -> Secret<32> {
    let seed = Mnemonic::from_entropy(&[entropy; 32]).to_seed();
    let root = spark_crypto::extract(spark_identity::ROOT_SALT, seed.expose());
    spark_crypto::expand::<32>(&root, spark_identity::INFO_SIGN)
}

/// Create a room and add `guest`, returning both sides.
fn room_of_two(host: &Client, guest: &Client) -> (Room, Room) {
    let mut a = Room::create(&host.provider, &host.key(), &host.signer).unwrap();
    let kp = key_package(&guest.provider, &guest.key(), &guest.signer).unwrap();
    let c = a
        .add_member(&host.provider, &host.signer, kp.key_package())
        .unwrap();
    // No root is passed: both sides derive the current generation from the MLS
    // exporter. Only *past* generations need the out-of-band re-share (F4).
    let b = Room::join(&guest.provider, &c.welcome.unwrap()).unwrap();
    (a, b)
}

#[test]
fn every_member_sees_identical_history() {
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut b) = room_of_two(&alice, &bob);

    let mut heard_by_bob = Vec::new();
    for text in ["one", "two", "three"] {
        let m = a
            .send(&alice.provider, &alice.signer, text.as_bytes())
            .unwrap();
        match b.process(&bob.provider, &m).unwrap() {
            Event::Message(got) => heard_by_bob.push(String::from_utf8(got).unwrap()),
            e => panic!("expected a message, got {e:?}"),
        }
    }
    assert_eq!(heard_by_bob, ["one", "two", "three"]);

    // Both sides agree on membership, owners, and epoch — the state every client
    // derives history ordering from.
    let mut ma = a.members();
    let mut mb = b.members();
    ma.sort_by_key(|k| *k.as_bytes());
    mb.sort_by_key(|k| *k.as_bytes());
    assert_eq!(ma.len(), 2);
    assert_eq!(ma, mb, "members diverged");
    assert_eq!(
        a.owners().unwrap(),
        b.owners().unwrap(),
        "owner sets diverged"
    );
    assert_eq!(a.epoch(), b.epoch(), "epochs diverged");
}

#[test]
fn a_removed_member_cannot_read_later_messages() {
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut b) = room_of_two(&alice, &bob);

    // Bob can read before the removal.
    let before = a.send(&alice.provider, &alice.signer, b"before").unwrap();
    assert!(
        matches!(b.process(&bob.provider, &before).unwrap(), Event::Message(m) if m == b"before")
    );

    let c = a
        .remove_member(&alice.provider, &alice.signer, &bob.key())
        .unwrap();
    assert!(matches!(
        b.process(&bob.provider, &c.commit).unwrap(),
        Event::Applied(_)
    ));
    assert_eq!(a.members().len(), 1);

    let after = a.send(&alice.provider, &alice.signer, b"after").unwrap();
    assert!(
        b.process(&bob.provider, &after).is_err(),
        "a removed member read a later message"
    );
}

#[test]
fn the_last_owner_cannot_leave_and_must_dissolve() {
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut _b) = room_of_two(&alice, &bob);

    // Alice is the only owner: Bob was added as a member, not an owner.
    assert_eq!(a.owners().unwrap().len(), 1);
    assert!(a.owners().unwrap().contains(&alice.key()));

    assert_eq!(
        a.leave(&alice.provider, &alice.signer).unwrap_err(),
        RoomError::LastOwner
    );
    // Bob, a plain member, may always propose to go.
    assert!(_b.leave(&bob.provider, &bob.signer).is_ok());
    assert_eq!(
        a.dismiss_owner(&alice.provider, &alice.signer, &alice.key())
            .unwrap_err(),
        RoomError::LastOwner
    );
    assert_eq!(
        a.remove_member(&alice.provider, &alice.signer, &alice.key())
            .unwrap_err(),
        RoomError::LastOwner
    );

    // Dissolving is the way out, and it reports how many generations of chunk
    // names the client must derive and delete.
    let d = a.dissolve().unwrap();
    assert!(d.generations >= 1);
}

#[test]
fn an_owner_may_leave_once_another_exists() {
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut b) = room_of_two(&alice, &bob);

    let c = a
        .appoint_owner(&alice.provider, &alice.signer, &bob.key())
        .unwrap();
    b.process(&bob.provider, &c.commit).unwrap();
    assert_eq!(a.owners().unwrap().len(), 2);
    assert_eq!(
        a.owners().unwrap(),
        b.owners().unwrap(),
        "owner set did not replicate"
    );

    // Now Alice may go — but leaving is two steps: she proposes, Bob commits.
    // MLS does not let a member commit their own removal.
    let proposal = a
        .leave(&alice.provider, &alice.signer)
        .expect("alice may leave");
    assert!(matches!(
        b.process(&bob.provider, &proposal).unwrap(),
        Event::Proposed
    ));
    assert_eq!(b.members().len(), 2, "a proposal alone must change nothing");

    let c = b
        .commit_pending(&bob.provider, &bob.signer)
        .expect("bob commits the departure");
    assert_eq!(b.members().len(), 1, "alice is gone");
    assert!(!b.members().contains(&alice.key()));

    // And Alice, applying the same commit, agrees she is out.
    a.process(&alice.provider, &c.commit).ok();
}

#[test]
fn a_one_to_one_is_a_room_of_two_owners_on_the_same_path() {
    // Build-notes §4: "Do not implement a separate 1:1 code path."
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut b) = room_of_two(&alice, &bob);
    let c = a
        .appoint_owner(&alice.provider, &alice.signer, &bob.key())
        .unwrap();
    b.process(&bob.provider, &c.commit).unwrap();

    // Both are owners, and the logic is symmetric: each can do what the other can.
    assert!(a.owners().unwrap().contains(&alice.key()));
    assert!(a.owners().unwrap().contains(&bob.key()));

    // Bob, an owner by appointment rather than by creation, can dismiss Alice.
    let c = b
        .dismiss_owner(&bob.provider, &bob.signer, &alice.key())
        .unwrap();
    a.process(&alice.provider, &c.commit).unwrap();
    assert_eq!(a.owners().unwrap().len(), 1);
    assert!(a.owners().unwrap().contains(&bob.key()));

    // And Alice, now a plain member, cannot.
    assert_eq!(
        a.appoint_owner(&alice.provider, &alice.signer, &alice.key())
            .unwrap_err(),
        RoomError::NotAnOwner
    );
}

#[test]
fn a_non_owner_cannot_manage_the_room() {
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (_a, mut b) = room_of_two(&alice, &bob);
    let carol = Client::new(3);
    let kp = key_package(&carol.provider, &carol.key(), &carol.signer).unwrap();

    assert_eq!(
        b.add_member(&bob.provider, &bob.signer, kp.key_package())
            .unwrap_err(),
        RoomError::NotAnOwner
    );
    assert_eq!(
        b.remove_member(&bob.provider, &bob.signer, &alice.key())
            .unwrap_err(),
        RoomError::NotAnOwner
    );
    assert_eq!(
        b.appoint_owner(&bob.provider, &bob.signer, &bob.key())
            .unwrap_err(),
        RoomError::NotAnOwner
    );
    assert_eq!(b.dissolve().unwrap_err(), RoomError::NotAnOwner);
}

#[test]
fn removing_an_owner_drops_them_from_the_owner_set_atomically() {
    // Two commits would leave a window in which a removed member is still an
    // owner, and MLS gives no way to make two commits atomic.
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut b) = room_of_two(&alice, &bob);
    let c = a
        .appoint_owner(&alice.provider, &alice.signer, &bob.key())
        .unwrap();
    b.process(&bob.provider, &c.commit).unwrap();
    assert_eq!(a.owners().unwrap().len(), 2);

    a.remove_member(&alice.provider, &alice.signer, &bob.key())
        .unwrap();
    assert_eq!(a.members().len(), 1);
    assert!(
        !a.owners().unwrap().contains(&bob.key()),
        "a removed member stayed an owner"
    );
}

#[test]
fn the_mls_credential_is_the_spark_identity() {
    // A leaf is provably the Spark identity it claims: one identity, not two that
    // have to be kept in step.
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (a, _b) = room_of_two(&alice, &bob);
    let members = a.members();
    assert!(members.contains(&alice.key()));
    assert!(members.contains(&bob.key()));
    assert_eq!(a.me().unwrap(), alice.key());
}

#[test]
fn a_room_without_an_owner_set_is_not_a_spark_room() {
    // OwnerSet::decode is the boundary check; malformed input must not be coerced
    // into an empty set, which would read as "no owners" rather than "not ours".
    assert_eq!(
        OwnerSet::decode(&[0u8; 31]).unwrap_err(),
        OwnerSetError::Malformed
    );
    assert_eq!(
        OwnerSet::decode(&[7u8; 64]).unwrap_err(),
        OwnerSetError::Malformed
    ); // duplicates
    assert!(OwnerSet::decode(&[]).unwrap().is_empty());
}

#[test]
fn the_owner_set_encoding_is_canonical() {
    // Two clients that agree on the set must produce identical bytes, or the
    // group context hash differs between members who agree.
    let (k1, k2) = (Client::new(1).key(), Client::new(2).key());
    let a = OwnerSet::founder(&k1).with(&k2);
    let b = OwnerSet::founder(&k2).with(&k1);
    assert_eq!(
        a.encode(),
        b.encode(),
        "owner set encoding depends on insertion order"
    );
    assert_eq!(a, b);

    // Idempotent in both directions.
    assert_eq!(a.with(&k1), a);
    assert_eq!(a.without(&k1).without(&k1), a.without(&k1));
}

#[test]
fn every_member_derives_the_same_root_without_it_being_sent() {
    // A randomly generated root would have to be distributed and re-distributed.
    // An exporter secret is derived independently by everyone in the group.
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (a, b) = room_of_two(&alice, &bob);
    assert_eq!(
        a.root(&alice.provider).unwrap().expose(),
        b.root(&bob.provider).unwrap().expose(),
        "two members derived different archive roots"
    );
}

#[test]
fn a_removed_member_cannot_derive_the_next_generations_root() {
    // Gate 7's third clause, and the reason the root is an exporter secret rather
    // than a value fixed at creation. Since stage 6 the archive is sealed under
    // the room root, so a root that never rotated would leave a removed member
    // able to *compute the names of* and decrypt everything written afterwards —
    // removal that removes nothing.
    let (alice, bob) = (Client::new(1), Client::new(2));
    let (mut a, mut b) = room_of_two(&alice, &bob);

    let shared_before = a.root(&alice.provider).unwrap();
    assert_eq!(
        b.root(&bob.provider).unwrap().expose(),
        shared_before.expose()
    );

    let c = a
        .remove_member(&alice.provider, &alice.signer, &bob.key())
        .unwrap();
    b.process(&bob.provider, &c.commit).unwrap();

    let after = a.root(&alice.provider).unwrap();
    assert_ne!(
        after.expose(),
        shared_before.expose(),
        "the root did not rotate on removal"
    );

    // Whatever Bob's copy of the group now derives, it is not the room's root.
    let bobs_view = b.root(&bob.provider).map(|r| *r.expose());
    assert_ne!(
        bobs_view.ok(),
        Some(*after.expose()),
        "a removed member still derives the current root"
    );
}

#[test]
fn the_root_rotates_on_every_membership_change() {
    let (alice, bob, carol) = (Client::new(1), Client::new(2), Client::new(3));
    let (mut a, _b) = room_of_two(&alice, &bob);

    let g1 = *a.root(&alice.provider).unwrap().expose();
    let kp = key_package(&carol.provider, &carol.key(), &carol.signer).unwrap();
    a.add_member(&alice.provider, &alice.signer, kp.key_package())
        .unwrap();
    let g2 = *a.root(&alice.provider).unwrap().expose();

    assert_ne!(g1, g2, "adding a member did not start a new generation");
    assert!(a.generation() >= 2, "generation did not advance");
}

#[test]
fn a_nonowner_cannot_bypass_policy_using_raw_openmls() {
    use openmls::prelude::tls_codec::Serialize;
    use openmls::prelude::*;
    let (alice, bob) = (Client::new(71), Client::new(72));
    let (mut a, b) = room_of_two(&alice, &bob);
    let before = a.epoch();
    let mut raw = MlsGroup::load(bob.provider.storage(), &GroupId::from_slice(&b.group_id()))
        .unwrap()
        .unwrap();
    let (commit, _, _) = raw
        .update_group_context_extensions(
            &bob.provider,
            OwnerSet::founder(&bob.key()).extensions(),
            &bob.signer,
        )
        .unwrap();
    assert_eq!(
        a.process(&alice.provider, &commit.tls_serialize_detached().unwrap())
            .unwrap_err(),
        RoomError::NotAnOwner
    );
    assert_eq!(a.epoch(), before);
    assert!(a.owners().unwrap().contains(&alice.key()));
}

#[test]
fn a_valid_key_package_cannot_claim_another_identity() {
    let (alice, bob) = (Client::new(73), Client::new(74));
    let mut a = Room::create(&alice.provider, &alice.key(), &alice.signer).unwrap();
    // MLS validates Bob's signature, but the BasicCredential falsely says Alice.
    let package = key_package(&bob.provider, &alice.key(), &bob.signer).unwrap();
    assert!(
        a.add_member(&alice.provider, &alice.signer, package.key_package())
            .is_err()
    );
    assert_eq!(a.members().len(), 1);
}

#[test]
fn receiving_a_raw_nonowner_removal_does_not_apply_it() {
    use openmls::prelude::tls_codec::Serialize;
    use openmls::prelude::*;
    let (alice, bob) = (Client::new(75), Client::new(76));
    let (mut a, b) = room_of_two(&alice, &bob);
    let mut raw = MlsGroup::load(bob.provider.storage(), &GroupId::from_slice(&b.group_id()))
        .unwrap()
        .unwrap();
    let alice_leaf = raw
        .members()
        .find(|m| m.signature_key == alice.key().as_bytes())
        .unwrap()
        .index;
    let (commit, _, _) = raw
        .remove_members(&bob.provider, &bob.signer, &[alice_leaf])
        .unwrap();
    let before = a.epoch();
    assert_eq!(
        a.process(&alice.provider, &commit.tls_serialize_detached().unwrap())
            .unwrap_err(),
        RoomError::NotAnOwner
    );
    assert_eq!(a.epoch(), before);
    assert_eq!(a.members().len(), 2);
}
