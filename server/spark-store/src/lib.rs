//! Storage that describes its own shape.
//!
//! layer 9, zone `io` — see `docs/layering.toml`.
//!
//! Stage 1 shipped `server/*-schema.toml` as hand-written declarations, checked
//! against `docs/permitted-knowledge.toml`. That closed one gap and left a bigger
//! one: nothing tied the declaration to the code. A server could persist a field
//! nobody had declared and every test would still pass.
//!
//! This closes it. Every write goes through [`Db::put`], which records the field
//! names it was handed, so [`Db::inventory`] is a report of what the server
//! *actually* stored during a run rather than what someone wrote down. Gate 5
//! compares that inventory to both the declaration and the whitelist.
//!
//! It is deliberately not a real database. Build-notes §3 calls for two
//! S3-compatible stores; this is the shape they must present, small enough that
//! the shape is auditable by reading it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// One stored value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cell {
    /// Opaque bytes. Every ciphertext in Spark is one of these.
    Bytes(Vec<u8>),
    /// A counter or a date.
    Num(u64),
    /// Text. Only names and hex addresses are ever stored as text.
    Text(String),
}

impl Cell {
    /// The bytes, for a `Bytes` cell.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Cell::Bytes(b) => Some(b),
            _ => None,
        }
    }
    /// The number, for a `Num` cell.
    pub fn num(&self) -> Option<u64> {
        match self {
            Cell::Num(n) => Some(*n),
            _ => None,
        }
    }
    /// The text, for a `Text` cell.
    pub fn text(&self) -> Option<&str> {
        match self {
            Cell::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// One record: field name to value, in declaration order.
pub type Row = Vec<(&'static str, Cell)>;

/// A key-value store whose rows carry named fields.
///
/// Cloning shares the underlying data, so a handler and a test can hold the same
/// store without the server needing to hand one out.
#[derive(Clone, Default)]
pub struct Db {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    /// `table -> key -> row`.
    rows: BTreeMap<&'static str, BTreeMap<String, Row>>,
    /// Every field name ever written, per table. Never pruned: a field that was
    /// written once and deleted was still knowledge the server held.
    seen: BTreeMap<&'static str, BTreeSet<&'static str>>,
}

impl Db {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a row, replacing any row under the same key.
    pub fn put(&self, table: &'static str, key: &str, row: Row) {
        let mut g = self.inner.lock().expect("store lock");
        let fields = g.seen.entry(table).or_default();
        for (name, _) in &row {
            fields.insert(name);
        }
        g.rows
            .entry(table)
            .or_default()
            .insert(key.to_string(), row);
    }

    /// Write a row only if the key is absent. Returns whether it was written.
    ///
    /// This is the content store's write-once rule and the commit lane's
    /// arbitration point (`docs/protocol.md` §4, §6.2), in one place so both are
    /// obviously the same mechanism.
    pub fn put_if_absent(&self, table: &'static str, key: &str, row: Row) -> bool {
        let mut g = self.inner.lock().expect("store lock");
        if g.rows.get(table).is_some_and(|t| t.contains_key(key)) {
            return false;
        }
        let fields = g.seen.entry(table).or_default();
        for (name, _) in &row {
            fields.insert(name);
        }
        g.rows
            .entry(table)
            .or_default()
            .insert(key.to_string(), row);
        true
    }

    /// Read a row.
    pub fn get(&self, table: &'static str, key: &str) -> Option<Row> {
        self.inner
            .lock()
            .expect("store lock")
            .rows
            .get(table)?
            .get(key)
            .cloned()
    }

    /// Whether a key exists.
    pub fn has(&self, table: &'static str, key: &str) -> bool {
        self.inner
            .lock()
            .expect("store lock")
            .rows
            .get(table)
            .is_some_and(|t| t.contains_key(key))
    }

    /// Delete a row. The field inventory is unaffected.
    pub fn delete(&self, table: &'static str, key: &str) {
        if let Some(t) = self.inner.lock().expect("store lock").rows.get_mut(table) {
            t.remove(key);
        }
    }

    /// Every key in a table, sorted.
    pub fn keys(&self, table: &'static str) -> Vec<String> {
        self.inner
            .lock()
            .expect("store lock")
            .rows
            .get(table)
            .map(|t| t.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Every row in a table.
    pub fn rows(&self, table: &'static str) -> Vec<Row> {
        self.inner
            .lock()
            .expect("store lock")
            .rows
            .get(table)
            .map(|t| t.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Read one field of one row.
    pub fn field(&self, table: &'static str, key: &str, field: &str) -> Option<Cell> {
        self.get(table, key)?
            .into_iter()
            .find(|(n, _)| *n == field)
            .map(|(_, v)| v)
    }

    /// Increment a numeric field, creating the row if needed.
    pub fn bump(&self, table: &'static str, key: &str, field: &'static str, by: i64, row: Row) {
        let cur = self
            .field(table, key, field)
            .and_then(|c| c.num())
            .unwrap_or(0);
        let next = if by < 0 {
            cur.saturating_sub(by.unsigned_abs())
        } else {
            cur + by as u64
        };
        let mut r: Row = self.get(table, key).unwrap_or(row);
        match r.iter_mut().find(|(n, _)| *n == field) {
            Some((_, v)) => *v = Cell::Num(next),
            None => r.push((field, Cell::Num(next))),
        }
        self.put(table, key, r);
    }

    /// What this store has actually held: `table -> fields`.
    ///
    /// This is the report gate 5 checks. It is derived from writes, so it cannot
    /// disagree with the code the way a hand-written schema can.
    pub fn inventory(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.inner
            .lock()
            .expect("store lock")
            .seen
            .iter()
            .map(|(t, f)| (t.to_string(), f.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    /// Every byte the store holds, for asserting that no plaintext survives.
    pub fn all_bytes(&self) -> Vec<u8> {
        let g = self.inner.lock().expect("store lock");
        let mut out = Vec::new();
        for table in g.rows.values() {
            for (key, row) in table {
                out.extend_from_slice(key.as_bytes());
                for (name, cell) in row {
                    out.extend_from_slice(name.as_bytes());
                    match cell {
                        Cell::Bytes(b) => out.extend_from_slice(b),
                        Cell::Num(n) => out.extend_from_slice(&n.to_be_bytes()),
                        Cell::Text(s) => out.extend_from_slice(s.as_bytes()),
                    }
                }
            }
        }
        out
    }
}
