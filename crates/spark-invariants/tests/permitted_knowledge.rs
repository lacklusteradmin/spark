//! Each server declares what it persists. That declaration must be a subset of
//! `docs/permitted-knowledge.toml` — the machine-readable form of build-notes §2.

use spark_invariants::*;

fn check(schema_file: &str) -> Vec<String> {
    let wl = whitelist(&load("docs/permitted-knowledge.toml"));
    check_permitted(&service_schema(&load(schema_file)), &wl)
}

#[test]
fn keyring_server_stores_only_permitted_fields() {
    let v = check("server/keyring-schema.toml");
    assert!(v.is_empty(), "keyring service:\n  {}", v.join("\n  "));
}

#[test]
fn content_server_stores_only_permitted_fields() {
    let v = check("server/content-schema.toml");
    assert!(v.is_empty(), "content service:\n  {}", v.join("\n  "));
}

#[test]
fn issuer_server_stores_only_permitted_fields() {
    let v = check("server/issuer-schema.toml");
    assert!(v.is_empty(), "issuer service:\n  {}", v.join("\n  "));
}

#[test]
fn whitelist_itself_holds_no_banned_concept() {
    // The whitelist is the thing everything else is checked against, so a mistake
    // in it is invisible to every other test here.
    let wl = whitelist(&load("docs/permitted-knowledge.toml"));
    let mut bad = Vec::new();
    for (service, fields) in &wl.services {
        assert!(
            !fields.is_empty(),
            "{service}: whitelist section is empty or misparsed"
        );
        for f in fields {
            if let Some(b) = hits_banned(f, &wl.banned) {
                bad.push(format!("{service}.{f} matches banned concept `{b}`"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "permitted-knowledge.toml contradicts itself:\n  {}",
        bad.join("\n  ")
    );
}

#[test]
fn token_matching_does_not_fire_on_innocent_names() {
    // `receipt` contains the letters of `ip`. Raw substring matching would ban the
    // content store's own receipt counter, and someone would "fix" it with an
    // allow list. Token matching is what makes the allow list unnecessary.
    let banned: Vec<String> = ["ip", "real_name", "room"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(hits_banned("receipt_count", &banned), None);
    assert_eq!(hits_banned("chunk_name", &banned), None);
    assert_eq!(hits_banned("client_ip", &banned).as_deref(), Some("ip"));
    assert_eq!(
        hits_banned("user_real_name", &banned).as_deref(),
        Some("real_name")
    );
    assert_eq!(hits_banned("room_id", &banned).as_deref(), Some("room"));
}
