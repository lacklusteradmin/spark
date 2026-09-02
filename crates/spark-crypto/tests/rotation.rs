//! Key rotation: bounding the blast radius of a recovered signing key.

mod util;
use spark_crypto::*;
use util::Fixed;

fn key(seed: u64) -> IssuerKey {
    IssuerKey::generate(&mut Fixed(seed)).expect("keygen")
}

fn sign(k: &IssuerKey, msg: &[u8], seed: u64) -> Token {
    let pk = k.public();
    let (bm, b) = pk.blind(&mut Fixed(seed), msg).expect("blind");
    pk.finalize(b, &k.blind_sign(&bm).expect("sign"), msg)
        .expect("finalize")
}

#[test]
fn a_token_survives_one_rotation_and_not_two() {
    // Rotating must not invalidate every unspent token a user is holding, so the
    // retired key stays verifiable for one more period. The one before it does not.
    let mut set = KeySet::new(key(1));
    let old = sign(set.signing(), b"token", 11);
    assert!(verify_any(&set.accepted(), &old, b"token").is_ok());

    set.rotate(key(2));
    assert!(
        verify_any(&set.accepted(), &old, b"token").is_ok(),
        "one rotation invalidated a token already in someone's hands"
    );

    set.rotate(key(3));
    assert_eq!(
        verify_any(&set.accepted(), &old, b"token").unwrap_err(),
        BlindError::NotAuthentic,
        "a key remained accepted two rotations after it was retired"
    );
}

#[test]
fn rotation_changes_what_gets_signed_with() {
    let mut set = KeySet::new(key(1));
    let before = set.signing().public().to_der().unwrap();
    set.rotate(key(2));
    let after = set.signing().public().to_der().unwrap();
    assert_ne!(before, after, "rotation did not change the signing key");
    assert_eq!(set.generation(), 1);

    // A token minted with a recovered old key stops working after two rotations —
    // which is the bound rotation buys.
    let stolen = sign(&key(1), b"minted with a stolen key", 12);
    assert!(verify_any(&set.accepted(), &stolen, b"minted with a stolen key").is_ok());
    set.rotate(key(3));
    assert!(verify_any(&set.accepted(), &stolen, b"minted with a stolen key").is_err());
}

#[test]
fn verify_any_checks_every_key_rather_than_stopping_at_a_match() {
    // Same reasoning as the pacing: the work done must not depend on which key
    // signed, or the verifier leaks that instead.
    let mut set = KeySet::new(key(1));
    set.rotate(key(2));
    let keys = set.accepted();
    assert_eq!(keys.len(), 2);

    let by_current = sign(set.signing(), b"m", 21);
    let by_previous = sign(&key(1), b"m", 22);
    assert!(verify_any(&keys, &by_current, b"m").is_ok());
    assert!(verify_any(&keys, &by_previous, b"m").is_ok());
    assert!(verify_any(&keys, &by_current, b"other").is_err());
}

#[test]
fn a_fresh_keyset_accepts_only_its_own_key() {
    let set = KeySet::new(key(1));
    assert_eq!(set.accepted().len(), 1);
    assert_eq!(set.generation(), 0);
    let foreign = sign(&key(9), b"m", 31);
    assert!(verify_any(&set.accepted(), &foreign, b"m").is_err());
}
