//! The crate graph in `docs/layering.toml` is the architecture. This test is what
//! makes that sentence true rather than aspirational.

use spark_invariants::*;
use std::collections::BTreeMap;

/// Crate name -> dependency names, as the `Cargo.toml` files really have them.
type Deps = BTreeMap<String, Vec<String>>;
/// Crate name -> `(path, contents)` for every source file.
type Sources = BTreeMap<String, Vec<(String, String)>>;

/// Read every workspace crate's real dependencies and source files.
fn workspace() -> (Deps, Sources) {
    let root = repo_root();
    let mut deps: Deps = BTreeMap::new();
    let mut srcs: Sources = BTreeMap::new();

    for parent in ["crates", "server"] {
        let dir = root.join(parent);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let manifest = p.join("Cargo.toml");
            if !manifest.is_file() {
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            deps.insert(
                name.clone(),
                cargo_deps(&std::fs::read_to_string(&manifest).unwrap()),
            );

            let src = p.join("src");
            if let Ok(files) = std::fs::read_dir(&src) {
                for f in files.flatten() {
                    let fp = f.path();
                    if fp.extension().is_some_and(|x| x == "rs") {
                        srcs.entry(name.clone()).or_default().push((
                            format!("src/{}", fp.file_name().unwrap().to_string_lossy()),
                            std::fs::read_to_string(&fp).unwrap(),
                        ));
                    }
                }
            }
        }
    }
    (deps, srcs)
}

#[test]
fn declared_graph_matches_reality() {
    let doc = load("docs/layering.toml");
    let decls = crate_decls(&doc);
    let rules = zone_rules(&doc);
    let (deps, _) = workspace();

    let v = check_layering(&decls, &deps, &rules);
    assert!(v.is_empty(), "layering violations:\n  {}", v.join("\n  "));
}

#[test]
fn pure_crates_name_no_io() {
    let doc = load("docs/layering.toml");
    let decls = crate_decls(&doc);
    let rules = zone_rules(&doc);
    let (_, srcs) = workspace();

    let v = check_pure_sources(&decls, &srcs, &rules);
    assert!(
        v.is_empty(),
        "I/O below the I/O line:\n  {}",
        v.join("\n  ")
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
        if !name.starts_with("spark-") {
            continue;
        }
        // The harness polices the graph; it is not part of it.
        if name == "spark-invariants" {
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
