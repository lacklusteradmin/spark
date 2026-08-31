//! Gate 2: "The same seed yields identical keys on a clean machine; no code path
//! recovers an identity without it."
//!
//! The first half is the frozen vectors below. The second half is structural and
//! lives in the invariant harness, which reads this crate's source — a test here
//! could only check the constructors it already knows about.

use spark_crypto::{Mnemonic, MnemonicError};
use spark_identity::*;
use std::collections::BTreeMap;

/// One `[section]` of `tests/vectors.txt`.
type Vector = BTreeMap<String, String>;

fn vectors() -> BTreeMap<String, Vector> {
    let src = include_str!("vectors.txt");
    let mut out: BTreeMap<String, Vector> = BTreeMap::new();
    let mut cur = String::new();
    for line in src.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(name) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            cur = name.to_string();
            out.insert(cur.clone(), Vector::new());
        } else if let Some((k, v)) = l.split_once(" = ") {
            out.get_mut(&cur)
                .expect("value before any [section]")
                .insert(k.into(), v.into());
        }
    }
    assert!(!out.is_empty(), "vectors.txt parsed to nothing");
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().expect("32 bytes")
}

#[test]
fn derivation_matches_frozen_vectors() {
    // If this fails, the derivation path changed and every existing account just
    // lost its history. It is not a test to update — it is a test to revert to.
    for (name, v) in vectors() {
        let m = Mnemonic::from_entropy(&unhex32(&v["entropy"]));
        assert_eq!(m.phrase().as_str(), v["phrase"], "[{name}] phrase");
        assert_eq!(hex(m.to_seed().expose()), v["seed"], "[{name}] seed");

        let id = Identity::from_mnemonic(&m);
        let p = id.public();
        assert_eq!(hex(p.sign.as_bytes()), v["sign_pub"], "[{name}] sign_pub");
        assert_eq!(hex(p.kem.as_bytes()), v["kem_pub"], "[{name}] kem_pub");
        assert_eq!(id.addr().to_hex(), v["addr"], "[{name}] addr");
        assert_eq!(
            hex(id.keyring_key().expose()),
            v["keyring_key"],
            "[{name}] keyring_key"
        );
    }
}

#[test]
fn same_seed_yields_identical_keys() {
    // The literal gate wording. Two derivations sharing no state must agree on
    // every byte, including the secret ones.
    for (name, v) in vectors() {
        let a = Identity::from_phrase(&v["phrase"]).unwrap();
        let b = Identity::from_mnemonic(&Mnemonic::from_entropy(&unhex32(&v["entropy"])));
        assert_eq!(a.public(), b.public(), "[{name}] public halves diverged");
        assert_eq!(a.addr(), b.addr(), "[{name}] addr diverged");
        assert_eq!(
            a.keyring_key(),
            b.keyring_key(),
            "[{name}] keyring key diverged"
        );
    }
}

#[test]
fn different_seeds_yield_different_keys() {
    let v = vectors();
    let a = Identity::from_phrase(&v["zero"]["phrase"]).unwrap();
    let b = Identity::from_phrase(&v["counting"]["phrase"]).unwrap();
    assert_ne!(a.addr(), b.addr());
    assert_ne!(a.public().sign, b.public().sign);
    assert_ne!(a.public().kem, b.public().kem);
    assert_ne!(a.keyring_key(), b.keyring_key());
}

#[test]
fn addr_is_derived_from_the_key_not_equal_to_it() {
    // Holding an addr must not hand an observer a verification key.
    let id = Identity::from_phrase(&vectors()["zero"]["phrase"]).unwrap();
    assert_ne!(id.addr().as_bytes(), id.public().sign.as_bytes());
}

#[test]
fn the_four_derived_keys_are_distinct() {
    // A copy-paste slip in an `info` string would make two purposes share a key
    // and nothing else would notice.
    let id = Identity::from_phrase(&vectors()["zero"]["phrase"]).unwrap();
    let p = id.public();
    let mut seen = vec![
        hex(p.sign.as_bytes()),
        hex(p.kem.as_bytes()),
        hex(id.keyring_key().expose()),
        id.addr().to_hex(),
    ];
    seen.sort();
    let n = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), n, "two derived values collided");
}

#[test]
fn info_strings_are_domain_separated() {
    // Every info string must be distinct, and none a prefix of another: HKDF
    // offers no separation beyond the bytes it is handed.
    let infos: Vec<&[u8]> = vec![INFO_SIGN, INFO_KEM, INFO_KEYRING, ADDR_PREFIX, ROOT_SALT];
    for (i, a) in infos.iter().enumerate() {
        for (j, b) in infos.iter().enumerate() {
            if i != j {
                assert!(!a.starts_with(b), "{:?} has prefix {:?}", a, b);
            }
        }
    }
}

#[test]
fn twelve_word_mnemonics_are_rejected() {
    // Valid BIP-39, half the entropy. Accepting it would silently weaken an
    // account that can never be recovered.
    let twelve = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    assert_eq!(
        Mnemonic::parse(twelve).unwrap_err(),
        MnemonicError::WrongWordCount(12)
    );
    assert_eq!(
        Identity::from_phrase(twelve).unwrap_err(),
        MnemonicError::WrongWordCount(12)
    );
}

#[test]
fn corrupt_mnemonics_are_rejected() {
    let v = vectors();
    let good = &v["zero"]["phrase"];

    // Bad checksum: last word swapped for another valid word.
    let bad_checksum = good.replace(" art", " zoo");
    assert_eq!(
        Mnemonic::parse(&bad_checksum).unwrap_err(),
        MnemonicError::Invalid
    );

    // Not a BIP-39 word at all.
    let bad_word = good.replace("art", "sparkle");
    assert_eq!(
        Mnemonic::parse(&bad_word).unwrap_err(),
        MnemonicError::Invalid
    );

    assert_eq!(Mnemonic::parse("").unwrap_err(), MnemonicError::Invalid);
}

#[test]
fn whitespace_around_a_typed_phrase_is_tolerated() {
    // A user pasting from a screenshot should not be told their account is gone.
    let v = vectors();
    let p = &v["zero"]["phrase"];
    let padded = format!("  {p}\n");
    assert_eq!(
        Identity::from_phrase(&padded).unwrap().addr(),
        Identity::from_phrase(p).unwrap().addr()
    );
}

#[test]
fn signatures_verify_and_do_not_cross_identities() {
    let v = vectors();
    let a = Identity::from_phrase(&v["zero"]["phrase"]).unwrap();
    let b = Identity::from_phrase(&v["counting"]["phrase"]).unwrap();

    let sig = a.sign(b"spark");
    assert!(a.verify(b"spark", &sig).is_ok());
    assert!(
        a.verify(b"spark ", &sig).is_err(),
        "signature verified over the wrong message"
    );
    assert!(
        b.verify(b"spark", &sig).is_err(),
        "signature verified under the wrong identity"
    );
}

#[test]
fn diffie_hellman_agrees_in_both_directions() {
    let v = vectors();
    let a = Identity::from_phrase(&v["zero"]["phrase"]).unwrap();
    let b = Identity::from_phrase(&v["counting"]["phrase"]).unwrap();
    assert_eq!(
        a.diffie_hellman(&b.public().kem),
        b.diffie_hellman(&a.public().kem)
    );
}

#[test]
fn secrets_do_not_appear_in_debug_output() {
    // A secret that reaches a log has left the process.
    let id = Identity::from_phrase(&vectors()["zero"]["phrase"]).unwrap();
    let shown = format!(
        "{id:?} {:?} {:?}",
        id.keyring_key(),
        Mnemonic::from_entropy(&[7u8; 32])
    );
    assert!(
        !shown.contains(&hex(id.keyring_key().expose())),
        "keyring key leaked via Debug"
    );
    assert!(
        !shown.contains("abandon"),
        "mnemonic words leaked via Debug"
    );
    assert!(
        shown.contains(&id.addr().to_hex()),
        "addr is public and should stay useful in logs"
    );
}
