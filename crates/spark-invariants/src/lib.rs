//! The invariant harness. Runs in CI from commit 1 (`Spark-build-notes.md` §2, §6).
//!
//! Two families of rule, both deny-by-default:
//!
//! * **Layering** — the crate graph in `docs/layering.toml` is the architecture.
//!   A `Cargo.toml` that disagrees with it is a test failure, not a refactor.
//! * **Permitted knowledge** — each server declares what it persists, and that
//!   declaration must be a subset of `docs/permitted-knowledge.toml`.
//!
//! Every check is a pure function over parsed data, so the same code runs against
//! the real manifests (expecting zero violations) and against the deliberately
//! broken stubs in `fixtures/broken` (expecting specific ones). Gate 1 requires
//! that second half: a harness nobody has watched fail proves nothing.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod toml_lite;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use toml_lite::Doc;

/// Repository root, derived from this crate's manifest directory.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <root>/crates/spark-invariants")
        .to_path_buf()
}

/// Read and parse a manifest relative to the repository root.
pub fn load(rel: &str) -> Doc {
    let path = repo_root().join(rel);
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    toml_lite::parse(&src).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

// ---------------------------------------------------------------- layering

/// One crate's declared position in the graph.
#[derive(Debug, Clone)]
pub struct CrateDecl {
    /// Crate name.
    pub name: String,
    /// Layer index. A crate may depend only on strictly lower layers.
    pub layer: i64,
    /// `pure`, `io`, or `boundary`.
    pub zone: String,
    /// Workspace-internal dependencies this crate is allowed to have.
    pub deps: Vec<String>,
}

/// The zone rules from `docs/layering.toml`.
#[derive(Debug, Clone, Default)]
pub struct ZoneRules {
    /// Crates a `pure` crate may not reach, directly or through the workspace.
    pub banned_in_pure: Vec<String>,
    /// Source paths a `pure` crate may not name.
    pub banned_paths: Vec<String>,
    /// Crates a `boundary` crate may not reach.
    pub boundary_banned: Vec<String>,
}

/// Read the crate declarations out of a parsed `layering.toml`.
pub fn crate_decls(doc: &Doc) -> Vec<CrateDecl> {
    (0..doc.count("crate"))
        .map(|i| CrateDecl {
            name: doc
                .str(&format!("crate[{i}].name"))
                .unwrap_or_default()
                .to_string(),
            layer: match doc.get(&format!("crate[{i}].layer")) {
                Some(toml_lite::Value::Int(n)) => *n,
                _ => -1,
            },
            zone: doc
                .str(&format!("crate[{i}].zone"))
                .unwrap_or_default()
                .to_string(),
            deps: doc.strs(&format!("crate[{i}].deps")),
        })
        .collect()
}

/// Read the zone rules out of a parsed `layering.toml`.
pub fn zone_rules(doc: &Doc) -> ZoneRules {
    ZoneRules {
        banned_in_pure: doc.strs("io_crates.banned_in_pure"),
        banned_paths: doc.strs("pure_source.banned_paths"),
        boundary_banned: doc.strs("boundary.banned_crates"),
    }
}

/// Check the declared graph against the dependencies each `Cargo.toml` really has.
///
/// `actual` maps crate name to every dependency named in its `[dependencies]`
/// section, workspace-internal and external alike. Returns one string per
/// violation; empty means the architecture and the code agree.
/// `shipping` holds only `[dependencies]`; `actual` holds every section.
///
/// The two are used for different rules, deliberately. The workspace-graph checks
/// use `actual`, because a dev-only edge between two crates is still an edge and
/// still how a cycle gets introduced. The zone bans use `shipping`, because they
/// are about what reaches a user: a crate generic over a crypto provider can only
/// be tested by supplying one, and forbidding that would mean the provider-
/// generic design could never be exercised. Which pure crates take that exception
/// is asserted by name in `tests/layering.rs`, so adding one is a deliberate edit.
pub fn check_layering(
    decls: &[CrateDecl],
    actual: &BTreeMap<String, Vec<String>>,
    shipping: &BTreeMap<String, Vec<String>>,
    rules: &ZoneRules,
) -> Vec<String> {
    let mut v = Vec::new();
    let by_name: BTreeMap<&str, &CrateDecl> = decls.iter().map(|d| (d.name.as_str(), d)).collect();

    for d in decls {
        let Some(real) = actual.get(&d.name) else {
            v.push(format!(
                "{}: declared in layering.toml but has no Cargo.toml",
                d.name
            ));
            continue;
        };
        let real_internal: BTreeSet<&str> = real
            .iter()
            .filter(|x| by_name.contains_key(x.as_str()))
            .map(String::as_str)
            .collect();
        let declared: BTreeSet<&str> = d.deps.iter().map(String::as_str).collect();

        for extra in real_internal.difference(&declared) {
            v.push(format!(
                "{}: depends on {extra}, not declared in layering.toml",
                d.name
            ));
        }
        for missing in declared.difference(&real_internal) {
            v.push(format!(
                "{}: layering.toml declares {missing}, Cargo.toml does not",
                d.name
            ));
        }

        // A dependency on an equal or higher layer is a cycle waiting to happen.
        for dep in &declared {
            if let Some(dd) = by_name.get(dep)
                && dd.layer >= d.layer
            {
                v.push(format!(
                    "{} (layer {}) depends on {} (layer {}): dependencies must go strictly downward",
                    d.name, d.layer, dd.name, dd.layer
                ));
            }
        }

        // Zone rules.
        match d.zone.as_str() {
            "pure" => {
                for dep in shipping.get(&d.name).into_iter().flatten() {
                    if rules.banned_in_pure.iter().any(|b| b == dep) {
                        v.push(format!(
                            "{} is `pure` but depends on {dep}: that puts I/O below the I/O line",
                            d.name
                        ));
                    }
                }
                // A pure crate must also not reach I/O through another workspace crate.
                for dep in &declared {
                    if let Some(dd) = by_name.get(dep)
                        && dd.zone != "pure"
                    {
                        v.push(format!(
                            "{} is `pure` but depends on {} which is `{}`",
                            d.name, dd.name, dd.zone
                        ));
                    }
                }
            }
            "boundary" => {
                for dep in shipping.get(&d.name).into_iter().flatten() {
                    if rules.boundary_banned.iter().any(|b| b == dep) {
                        v.push(format!(
                            "{} is `boundary` but depends on {dep}: cryptography above the FFI line",
                            d.name
                        ));
                    }
                }
            }
            "io" => {}
            other => v.push(format!("{}: unknown zone `{other}`", d.name)),
        }
    }
    v
}

/// Check that no `pure` crate's source names a path that implies I/O.
///
/// `sources` maps crate name to `(file, contents)` pairs. `Cargo.toml` cannot
/// catch these: `std` is always in scope.
pub fn check_pure_sources(
    decls: &[CrateDecl],
    sources: &BTreeMap<String, Vec<(String, String)>>,
    rules: &ZoneRules,
) -> Vec<String> {
    let mut v = Vec::new();
    for d in decls.iter().filter(|d| d.zone == "pure") {
        for (file, body) in sources.get(&d.name).into_iter().flatten() {
            for banned in &rules.banned_paths {
                // Skip comment lines: prose about the rule is not a breach of it.
                for (n, line) in body.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    if code.contains(banned) {
                        v.push(format!(
                            "{}: {file}:{} names `{banned}` in a `pure` crate",
                            d.name,
                            n + 1
                        ));
                    }
                }
            }
        }
    }
    v
}

// -------------------------------------------------------- permitted knowledge

/// What a server declares it persists.
#[derive(Debug, Clone)]
pub struct ServiceSchema {
    /// Which whitelist section applies.
    pub service: String,
    /// `(table, fields)` pairs.
    pub tables: Vec<(String, Vec<String>)>,
}

/// The whitelist from `docs/permitted-knowledge.toml`.
#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    /// Allowed field names per service.
    pub services: BTreeMap<String, Vec<String>>,
    /// Concepts that may never be stored, whatever the service.
    pub banned: Vec<String>,
}

/// Read a server's declaration out of a parsed `*-schema.toml`.
pub fn service_schema(doc: &Doc) -> ServiceSchema {
    ServiceSchema {
        service: doc.str("service").unwrap_or_default().to_string(),
        tables: (0..doc.count("table"))
            .map(|i| {
                (
                    doc.str(&format!("table[{i}].name"))
                        .unwrap_or_default()
                        .to_string(),
                    doc.strs(&format!("table[{i}].fields")),
                )
            })
            .collect(),
    }
}

/// Read the whitelist out of a parsed `permitted-knowledge.toml`.
pub fn whitelist(doc: &Doc) -> Whitelist {
    let mut services = BTreeMap::new();
    for s in ["keyring_service", "content_service", "issuer_service"] {
        services.insert(s.to_string(), doc.strs(&format!("{s}.fields")));
    }
    Whitelist {
        services,
        banned: doc.strs("banned.substrings"),
    }
}

/// Split an identifier into `_`-separated tokens.
fn tokens(s: &str) -> Vec<&str> {
    s.split('_').filter(|t| !t.is_empty()).collect()
}

/// Whether `field` matches a banned concept.
///
/// Matching is on tokens, not raw substrings: `ip` matches `client_ip` but not
/// `receipt_count`. Raw substring matching would need an allow list, and every
/// entry on an allow list is a hole in this net.
pub fn hits_banned(field: &str, banned: &[String]) -> Option<String> {
    let f = tokens(field);
    for b in banned {
        let bt = tokens(b);
        if bt.is_empty() || bt.len() > f.len() {
            continue;
        }
        if f.windows(bt.len()).any(|w| w == bt.as_slice()) {
            return Some(b.clone());
        }
    }
    None
}

/// Check one server's declaration against the whitelist.
///
/// Two nets. The subset check catches a new field. The concept ban catches a
/// forbidden field renamed to look ordinary — including a table *name* that
/// encodes a relationship the server is not allowed to hold.
pub fn check_permitted(schema: &ServiceSchema, wl: &Whitelist) -> Vec<String> {
    let mut v = Vec::new();
    let Some(allowed) = wl.services.get(&schema.service) else {
        v.push(format!(
            "unknown service `{}`: not a section of permitted-knowledge.toml",
            schema.service
        ));
        return v;
    };
    for (table, fields) in &schema.tables {
        if let Some(b) = hits_banned(table, &wl.banned) {
            v.push(format!(
                "{}: table `{table}` encodes banned concept `{b}`",
                schema.service
            ));
        }
        for f in fields {
            if !allowed.iter().any(|a| a == f) {
                v.push(format!(
                    "{}: `{table}.{f}` is persisted but not permitted knowledge",
                    schema.service
                ));
            }
            if let Some(b) = hits_banned(f, &wl.banned) {
                v.push(format!(
                    "{}: `{table}.{f}` encodes banned concept `{b}`",
                    schema.service
                ));
            }
        }
    }
    v
}

// ------------------------------------------------------------------ helpers

/// Every dependency named in a `Cargo.toml`'s `[dependencies]` section.
pub fn cargo_deps(manifest: &str) -> Vec<String> {
    cargo_deps_by_section(manifest)
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

/// Only the dependencies that ship: `[dependencies]`, not dev or build.
pub fn cargo_shipping_deps(manifest: &str) -> Vec<String> {
    cargo_deps_by_section(manifest)
        .into_iter()
        .filter(|(_, sec)| sec == "dependencies")
        .map(|(d, _)| d)
        .collect()
}

/// As [`cargo_deps`], but keeping the section each dependency came from, so a
/// rule can distinguish "reaches a user" from "is used by the test suite".
pub fn cargo_deps_by_section(manifest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for line in manifest.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            section = match l {
                "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]" => {
                    l.trim_matches(['[', ']']).to_string()
                }
                _ => String::new(),
            };
            continue;
        }
        if section.is_empty() || l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, _)) = l.split_once('=') {
            // `foo.workspace = true` names the crate `foo`.
            let name = k.trim().split('.').next().unwrap_or("").trim().to_string();
            if !name.is_empty() {
                out.push((name, section.clone()));
            }
        }
    }
    out
}

// ------------------------------------------------------- identity constructors

/// Check that `Identity` can only be built from seed material.
///
/// Gate 2's second half — "no code path recovers an identity without it" — is a
/// statement about the *shape* of the API, not about any one function's
/// behaviour. A test inside `spark-identity` could only check the constructors it
/// already knows about; this reads the source and fails on a new one.
///
/// `source` is `spark-identity/src/lib.rs`. `allowed` is the constructor names
/// that legitimately take seed material. Anything else that returns an `Identity`
/// is a recovery path, whatever it is called.
pub fn check_identity_constructors(source: &str, allowed: &[&str]) -> Vec<String> {
    let mut v = Vec::new();
    let mut in_impl = false;
    let mut depth = 0i32;

    for (n, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        let trimmed = code.trim();

        if !in_impl && trimmed.starts_with("impl Identity") {
            in_impl = true;
            depth = 0;
        }
        if in_impl {
            depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            if depth <= 0 && trimmed.ends_with('}') && !trimmed.starts_with("impl") {
                in_impl = false;
            }
        }

        // A constructor is any public fn whose return type is the type itself.
        let returns_self = code.contains("-> Self")
            || code.contains("-> Identity")
            || code.contains("Result<Self")
            || code.contains("Result<Identity");
        if !(in_impl && trimmed.starts_with("pub fn") && returns_self) {
            continue;
        }
        let name = trimmed
            .trim_start_matches("pub fn")
            .trim()
            .split(['(', '<'])
            .next()
            .unwrap_or("")
            .trim();
        if !allowed.contains(&name) {
            v.push(format!(
                "spark-identity/src/lib.rs:{}: `Identity::{name}` builds an identity but is not a \
                 declared seed-derived constructor. Gate 2 requires that no code path recovers an \
                 identity without the seed.",
                n + 1
            ));
        }
    }

    // The other way in: a trait that reconstructs the struct from bytes. A derive
    // sits on the line *above* the item it applies to, so a single-line scan would
    // miss exactly the shape this is meant to catch.
    const REBUILDS: [&str; 4] = ["Deserialize", "Default", "From<[u8", "FromStr"];
    let lines: Vec<&str> = source
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect();

    for (n, code) in lines.iter().enumerate() {
        let t = code.trim();

        // `#[derive(..)]` — find the item it decorates, skipping further attributes.
        if let Some(list) = t
            .strip_prefix("#[derive(")
            .and_then(|x| x.split(')').next())
        {
            let item = lines[n + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty() && !l.starts_with('#'))
                .unwrap_or("");
            if item.contains("Identity") {
                for bad in REBUILDS {
                    if list.contains(bad) {
                        v.push(format!(
                            "spark-identity/src/lib.rs:{}: `#[derive({bad})]` on Identity \
                             reconstructs one without a seed",
                            n + 1
                        ));
                    }
                }
            }
        }

        // `impl Deserialize for Identity`, `impl From<[u8; 32]> for Identity`, ...
        if t.starts_with("impl") && t.contains("for Identity") {
            for bad in REBUILDS {
                if t.contains(bad) {
                    v.push(format!(
                        "spark-identity/src/lib.rs:{}: `impl {bad} for Identity` reconstructs one \
                         without a seed",
                        n + 1
                    ));
                }
            }
        }
    }
    v
}
