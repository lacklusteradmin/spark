//! Gate 2, second half: "no code path recovers an identity without it."
//!
//! This lives in the harness rather than in `spark-identity` because it is a
//! claim about the crate's whole API surface. A test inside the crate could only
//! assert things about constructors it already imports.

use spark_invariants::*;

/// The only ways an `Identity` may come into existence. Adding a name here is an
/// architectural decision: it means a new path to an account exists.
const SEED_DERIVED: &[&str] = &["from_mnemonic", "from_seed", "from_phrase"];

#[test]
fn identity_is_reachable_only_from_seed_material() {
    let src = std::fs::read_to_string(repo_root().join("crates/spark-identity/src/lib.rs"))
        .expect("spark-identity/src/lib.rs");
    let v = check_identity_constructors(&src, SEED_DERIVED);
    assert!(v.is_empty(), "recovery paths found:\n  {}", v.join("\n  "));
}

#[test]
fn rejects_a_device_backup_constructor() {
    // F2: "any recovery path available to you would also be available to an
    // attacker." The fixture is what that mistake looks like in a diff.
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/broken/identity-backdoor.rs"),
    )
    .unwrap();
    let v = check_identity_constructors(&src, SEED_DERIVED);
    assert_eq!(v.len(), 1, "expected exactly one finding, got:\n{v:#?}");
    assert!(
        v[0].contains("from_device_backup"),
        "wrong finding: {}",
        v[0]
    );
}

#[test]
fn rejects_a_derive_that_rebuilds_an_identity() {
    // A derive sits on the line above the item, which is the whole reason a
    // single-line scan is not good enough here.
    let derived = "#[derive(Clone, Deserialize)]\n#[serde(deny_unknown_fields)]\n\
                   pub struct Identity { sign: SigningKey }\n";
    let v = check_identity_constructors(derived, SEED_DERIVED);
    assert!(
        v.iter().any(|x| x.contains("Deserialize")),
        "derive slipped through: {v:?}"
    );

    // The hand-written form of the same hole.
    let handwritten =
        "impl From<[u8; 32]> for Identity {\n    fn from(b: [u8; 32]) -> Self { todo!() }\n}\n";
    let v = check_identity_constructors(handwritten, SEED_DERIVED);
    assert!(
        v.iter().any(|x| x.contains("From<[u8")),
        "impl slipped through: {v:?}"
    );

    // And a derive on some *other* type must not trip it.
    let innocent = "#[derive(Deserialize)]\npub struct Envelope { addr: Addr }\n";
    assert!(check_identity_constructors(innocent, SEED_DERIVED).is_empty());
}

#[test]
fn the_derivation_vectors_are_committed_and_non_empty() {
    // The vectors are what make "identical keys on a clean machine" checkable at
    // all. If the file goes missing, derivation_matches_frozen_vectors would
    // still compile — include_str! would just fail the build — but a future
    // refactor that makes it optional should trip here first.
    let p = repo_root().join("crates/spark-identity/tests/vectors.txt");
    let s = std::fs::read_to_string(&p).expect("frozen derivation vectors are committed");
    assert!(
        s.contains("[zero]") && s.contains("[counting]"),
        "vectors.txt lost a section"
    );
    assert!(
        s.matches("addr = ").count() >= 2,
        "vectors.txt lost its addr values"
    );
}
