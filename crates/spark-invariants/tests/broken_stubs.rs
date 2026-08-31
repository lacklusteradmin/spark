//! Gate 1, first half: "Invariant tests fail against a deliberately broken stub."
//!
//! A harness nobody has watched fail proves nothing. Each fixture in
//! `fixtures/broken` is a regression that would look reasonable in a pull request;
//! this file asserts the harness rejects it, and names the specific reason, so a
//! check cannot rot into one that passes everything.

use spark_invariants::*;
use std::collections::BTreeMap;

fn fixture(name: &str) -> toml_lite::Doc {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/broken")
        .join(name);
    toml_lite::parse(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn wl() -> Whitelist {
    whitelist(&load("docs/permitted-knowledge.toml"))
}

fn assert_mentions(violations: &[String], needle: &str) {
    assert!(
        violations.iter().any(|v| v.contains(needle)),
        "expected a violation mentioning `{needle}`, got:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn rejects_upload_to_key_link() {
    let v = check_permitted(&service_schema(&fixture("uploader-link.toml")), &wl());
    assert!(!v.is_empty(), "harness accepted an upload-to-key link");
    assert_mentions(&v, "uploader_addr");
}

#[test]
fn rejects_relationship_renamed_as_bookkeeping() {
    let v = check_permitted(&service_schema(&fixture("renamed-concept.toml")), &wl());
    assert!(!v.is_empty(), "harness accepted a room membership index");
    // Both nets should fire: the table name and the field.
    assert_mentions(&v, "room_index");
    assert_mentions(&v, "group_id");
}

#[test]
fn rejects_name_transfer_history() {
    let v = check_permitted(&service_schema(&fixture("transfer-history.toml")), &wl());
    assert!(!v.is_empty(), "harness accepted a transfer history");
    assert_mentions(&v, "transfer_history");
    assert_mentions(&v, "previous_pubkey");
}

#[test]
fn rejects_layering_regressions() {
    let doc = fixture("layering.toml");
    let decls = crate_decls(&doc);
    let rules = zone_rules(&doc);

    // What the Cargo.toml files would say after three plausible-looking commits:
    //   1. spark-chunk reaches for tokio "just for the runtime handle"
    //   2. spark-crypto depends on spark-client to reuse an error type (inversion)
    //   3. spark-ffi calls into spark-chunk directly to skip a hop
    let actual: BTreeMap<String, Vec<String>> = [
        ("spark-crypto", vec!["spark-client"]),
        ("spark-chunk", vec!["spark-crypto", "tokio"]),
        ("spark-transport", vec![]),
        ("spark-client", vec!["spark-chunk", "spark-transport"]),
        ("spark-ffi", vec!["spark-client", "spark-chunk"]),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.into_iter().map(str::to_string).collect()))
    .collect();

    // Same map for both: these fixtures declare everything as shipping.
    let v = check_layering(&decls, &actual, &actual, &rules);
    assert!(!v.is_empty(), "harness accepted three layering regressions");
    assert_mentions(&v, "depends on tokio"); // I/O below the I/O line
    assert_mentions(&v, "spark-client"); // undeclared upward dependency
    assert_mentions(&v, "cryptography above the FFI line");
}

#[test]
fn rejects_io_named_in_a_pure_crate() {
    let doc = fixture("layering.toml");
    let decls = crate_decls(&doc);
    let rules = zone_rules(&doc);

    let srcs: BTreeMap<String, Vec<(String, String)>> = [(
        "spark-chunk".to_string(),
        vec![(
            "src/lib.rs".to_string(),
            "// a comment about std::net is fine\n\
             pub fn load() { let _ = std::fs::read(\"/tmp/x\"); }\n"
                .to_string(),
        )],
    )]
    .into_iter()
    .collect();

    let v = check_pure_sources(&decls, &srcs, &rules);
    assert_eq!(
        v.len(),
        1,
        "expected exactly one hit — the comment must not count:\n{v:?}"
    );
    assert_mentions(&v, "std::fs");
    assert_mentions(&v, "src/lib.rs:2");
}

#[test]
fn parser_rejects_unsupported_syntax_rather_than_skipping_it() {
    // A manifest that silently half-parses is worse than one that fails: the rules
    // in the unparsed half would stop being enforced without anyone noticing.
    assert!(toml_lite::parse("key = 1.5").is_err(), "float accepted");
    assert!(
        toml_lite::parse("[unterminated").is_err(),
        "bad table header accepted"
    );
    assert!(
        toml_lite::parse("fields = [\"a\", \"b\"").is_err(),
        "unterminated array accepted"
    );
    assert!(
        toml_lite::parse("no equals sign here").is_err(),
        "junk line accepted"
    );
}
