//! Gate 12: "Every W1–W7 threat has an implemented mitigation or a documented
//! accepted risk."
//!
//! `docs/threats.toml` is the reckoning. This file is what stops it becoming a
//! document nobody checks — every claim it makes about the code is verified
//! against the code, so a mitigation that is deleted, renamed, or never written
//! fails here rather than being discovered by someone who trusted the register.

use spark_invariants::*;
use std::collections::BTreeSet;

/// The threats `Spark-spec.md` names. Hardcoded, so that deleting one from the
/// register is a failure rather than a smaller register.
const REQUIRED: [&str; 7] = ["W1", "W2", "W3", "W4", "W5", "W6", "W7"];

struct Threat {
    id: String,
    status: String,
    mitigation: String,
    evidence: Vec<String>,
    residual: String,
    stated_to_user: String,
}

fn register() -> Vec<Threat> {
    let doc = load("docs/threats.toml");
    (0..doc.count("threat"))
        .map(|i| Threat {
            id: doc
                .str(&format!("threat[{i}].id"))
                .unwrap_or_default()
                .into(),
            status: doc
                .str(&format!("threat[{i}].status"))
                .unwrap_or_default()
                .into(),
            mitigation: doc
                .str(&format!("threat[{i}].mitigation"))
                .unwrap_or_default()
                .into(),
            evidence: doc.strs(&format!("threat[{i}].evidence")),
            residual: doc
                .str(&format!("threat[{i}].residual"))
                .unwrap_or_default()
                .into(),
            stated_to_user: doc
                .str(&format!("threat[{i}].stated_to_user"))
                .unwrap_or_default()
                .into(),
        })
        .collect()
}

#[test]
fn every_threat_the_spec_names_is_in_the_register() {
    let ids: BTreeSet<String> = register().into_iter().map(|t| t.id).collect();
    for w in REQUIRED {
        assert!(ids.contains(w), "{w} is missing from docs/threats.toml");
    }
    assert_eq!(
        ids.len(),
        REQUIRED.len(),
        "the register gained a threat: {ids:?}"
    );
}

#[test]
fn every_threat_is_resolved_one_way_or_the_other() {
    // The gate's actual wording: an implemented mitigation *or* a documented
    // accepted risk. There is deliberately no third status — a threat with no
    // answer must fail, which is the point of having a gate.
    for t in register() {
        assert!(
            t.status == "mitigated" || t.status == "accepted",
            "{}: status `{}` is neither mitigated nor accepted",
            t.id,
            t.status
        );
        assert!(
            t.mitigation.len() > 40,
            "{}: no mitigation is described",
            t.id
        );
    }
}

#[test]
fn every_mitigation_names_a_test_that_actually_exists() {
    // The register's whole value is that it can be trusted. A mitigation whose
    // proof was deleted or renamed must fail here.
    //
    // Every threat that cites evidence, not only the `mitigated` ones. An
    // `accepted` threat can still have a partial mitigation with tests behind it —
    // W2 does — and the first version of this check skipped exactly those, so
    // renaming a push test went unnoticed.
    let root = repo_root();
    for t in register() {
        if t.status == "mitigated" {
            assert!(
                !t.evidence.is_empty(),
                "{}: claims to be mitigated but names no test",
                t.id
            );
        }
        for e in &t.evidence {
            let (path, func) = e
                .split_once("::")
                .unwrap_or_else(|| panic!("{}: evidence `{e}` is not `path::test_name`", t.id));
            let src = std::fs::read_to_string(root.join(path))
                .unwrap_or_else(|_| panic!("{}: evidence names a missing file `{path}`", t.id));
            assert!(
                src.contains(&format!("fn {func}(")),
                "{}: `{path}` has no test named `{func}`",
                t.id
            );
        }
    }
}

#[test]
fn an_accepted_threat_that_cites_evidence_has_it_checked_too() {
    // W2 is accepted, and still carries a partial client-side mitigation with
    // tests. Those tests must be as real as a mitigated threat's.
    let w2 = register().into_iter().find(|t| t.id == "W2").expect("W2");
    assert_eq!(w2.status, "accepted");
    assert!(
        !w2.evidence.is_empty(),
        "W2 dropped the evidence for its partial mitigation"
    );
}

#[test]
fn every_threat_says_what_is_left_after_the_mitigation() {
    // A mitigation with no stated residual reads as "solved", and none of these
    // are. W1 is still severe in the default mode; W6 covers containers and not
    // pixels. Saying so is the difference between a threat model and a
    // reassurance.
    for t in register() {
        assert!(
            t.residual.len() > 60,
            "{}: does not say what remains after the mitigation",
            t.id
        );
    }
}

#[test]
fn every_threat_names_where_the_user_is_told() {
    // Spark's answer to several of these is "warn loudly". A warning nobody can
    // point to is not a warning.
    let root = repo_root();
    for t in register() {
        assert!(
            !t.stated_to_user.is_empty(),
            "{}: nowhere states this to the user",
            t.id
        );
        // Where it points at code, the code must exist.
        if let Some((path, item)) = t.stated_to_user.split_once("::")
            && path.ends_with(".rs")
        {
            {
                let src = std::fs::read_to_string(root.join(path)).unwrap_or_else(|_| {
                    panic!("{}: stated_to_user names a missing file `{path}`", t.id)
                });
                let last = item.rsplit("::").next().unwrap_or(item);
                assert!(
                    src.contains(last),
                    "{}: `{path}` does not contain `{last}`",
                    t.id
                );
            }
        }
    }
}

#[test]
fn the_two_severe_threats_are_still_marked_severe() {
    // W1 and W2 are the ones the spec calls severe, and neither has been solved —
    // W1 is mitigated only in always-on mode, and W2's server half does not exist.
    // If a future edit downgrades either, that should be a decision someone makes
    // on purpose.
    let doc = load("docs/threats.toml");
    for i in 0..doc.count("threat") {
        let id = doc.str(&format!("threat[{i}].id")).unwrap_or_default();
        if id == "W1" || id == "W2" {
            assert_eq!(
                doc.str(&format!("threat[{i}].severity")),
                Some("severe"),
                "{id} was downgraded from severe"
            );
        }
    }
}

#[test]
fn the_push_decision_is_recorded_rather_than_left_to_be_rediscovered() {
    // Stage 12's finding: build-notes §2 says servers may never store real-world
    // identifiers, D3 said push was on by default, and delivering a push requires
    // holding an Apple or Google token against an account. It was resolved by a
    // product decision: off by default, loud to turn on.
    //
    // The register has to keep saying both halves: what the conflict was, so
    // nobody flips the default back without meeting it, and how it was resolved,
    // so the resolution is not mistaken for engineering that removed the risk.
    let t = register().into_iter().find(|t| t.id == "W2").expect("W2");
    for phrase in [
        "real-world identifier",
        "could not hold",
        "off by default",
        "No delivery service exists yet",
    ] {
        assert!(
            t.residual.contains(phrase),
            "W2 no longer records the push decision (missing: {phrase:?})"
        );
    }

    // And the spec it cites has to agree. A register that says "off by default"
    // over a D3 that still says "on" is the contradiction this test exists for.
    let spec = std::fs::read_to_string(repo_root().join("Spark-spec.md")).expect("spec");
    let d3 = spec
        .split("### D3.")
        .nth(1)
        .and_then(|r| r.split("\n### ").next())
        .expect("D3");
    assert!(
        d3.contains("off by default"),
        "Spark-spec.md D3 does not say push is off by default"
    );
    assert!(
        !d3.contains("Push is on by default"),
        "Spark-spec.md D3 still says push is on by default"
    );
}
