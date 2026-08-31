//! The crate graph in `docs/layering.toml` is the architecture. This test is what
//! makes that sentence true rather than aspirational.

use spark_invariants::*;
use std::collections::BTreeMap;

/// Crate name -> dependency names, as the `Cargo.toml` files really have them.
type Deps = BTreeMap<String, Vec<String>>;
/// Crate name -> `(path, contents)` for every source file.
type Sources = BTreeMap<String, Vec<(String, String)>>;

/// What every workspace crate declares and contains.
struct Workspace {
    /// Every dependency section.
    all: Deps,
    /// `[dependencies]` only — what actually ships.
    shipping: Deps,
    /// Source files, for the pure-zone scan.
    sources: Sources,
}

fn workspace() -> Workspace {
    let root = repo_root();
    let mut w = Workspace {
        all: Deps::new(),
        shipping: Deps::new(),
        sources: Sources::new(),
    };

    for parent in ["crates", "server"] {
        let Ok(entries) = std::fs::read_dir(root.join(parent)) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let manifest = p.join("Cargo.toml");
            if !manifest.is_file() {
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let src = std::fs::read_to_string(&manifest).unwrap();
            w.all.insert(name.clone(), cargo_deps(&src));
            w.shipping.insert(name.clone(), cargo_shipping_deps(&src));

            if let Ok(files) = std::fs::read_dir(p.join("src")) {
                for f in files.flatten() {
                    let fp = f.path();
                    if fp.extension().is_some_and(|x| x == "rs") {
                        w.sources.entry(name.clone()).or_default().push((
                            format!("src/{}", fp.file_name().unwrap().to_string_lossy()),
                            std::fs::read_to_string(&fp).unwrap(),
                        ));
                    }
                }
            }
        }
    }
    w
}

#[test]
fn declared_graph_matches_reality() {
    let doc = load("docs/layering.toml");
    let w = workspace();
    let v = check_layering(&crate_decls(&doc), &w.all, &w.shipping, &zone_rules(&doc));
    assert!(v.is_empty(), "layering violations:\n  {}", v.join("\n  "));
}

#[test]
fn pure_crates_name_no_io() {
    let doc = load("docs/layering.toml");
    let w = workspace();
    let v = check_pure_sources(&crate_decls(&doc), &w.sources, &zone_rules(&doc));
    assert!(
        v.is_empty(),
        "I/O below the I/O line:\n  {}",
        v.join("\n  ")
    );
}

#[test]
fn dev_only_exceptions_to_the_zone_bans_are_named() {
    // The zone bans check shipping dependencies, because a crate generic over a
    // crypto provider can only be tested by supplying one. That exception is real
    // but narrow, so every instance of it is listed here by name: adding one is a
    // deliberate edit to this file, not a silent widening of the rule.
    const ALLOWED: &[(&str, &str)] = &[(
        "spark-mls",
        // Gate 4 runs two clients in one process. A provider has to come from
        // somewhere, and in production it comes from spark-client.
        "openmls_rust_crypto",
    )];

    let doc = load("docs/layering.toml");
    let rules = zone_rules(&doc);
    let w = workspace();
    let mut found = Vec::new();

    for d in crate_decls(&doc).iter().filter(|d| d.zone == "pure") {
        let all = w.all.get(&d.name).cloned().unwrap_or_default();
        let shipping = w.shipping.get(&d.name).cloned().unwrap_or_default();
        for dep in all.iter().filter(|x| !shipping.contains(x)) {
            if rules.banned_in_pure.iter().any(|b| b == dep) {
                found.push((d.name.clone(), dep.clone()));
            }
        }
    }

    let expected: Vec<(String, String)> = ALLOWED
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    found.sort();
    assert_eq!(
        found, expected,
        "the set of dev-only exceptions changed. Each one is a crate that may not \
         ship an entropy source but does use one in tests; if this is intended, add \
         it to ALLOWED with the reason."
    );
}

#[test]
fn every_workspace_member_is_declared() {
    let root = repo_root();
    let ws = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let doc = load("docs/layering.toml");
    let declared: Vec<String> = crate_decls(&doc).into_iter().map(|d| d.name).collect();

    // Only the `members = [...]` array. [workspace.dependencies] entries also
    // contain paths, and scraping those made this test read `spark-crypto" }`.
    let members = ws
        .split_once("members = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(inner, _)| inner)
        .expect("workspace Cargo.toml has no members array");

    let mut missing = Vec::new();
    for line in members.lines() {
        let l = line
            .trim()
            .trim_matches(|c| c == '"' || c == ',')
            .trim_matches('"');
        let Some((_, name)) = l.split_once('/') else {
            continue;
        };
        if !name.starts_with("spark-") || name == "spark-invariants" {
            continue;
        }
        if !declared.iter().any(|d| d == name) {
            missing.push(name.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "workspace members absent from docs/layering.toml: {missing:?}\n\
         Adding a crate is an architecture change; declare it there first."
    );
}
