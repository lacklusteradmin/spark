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
//! SQLite WAL transactions durably couple authorization, accounting, and replies.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod mint;

use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

/// One stored value.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
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

/// Owned rows read from durable storage.
pub type StoredRow = Vec<(String, Cell)>;

/// SQLite-backed service data. Clones share a connection and transaction lock.
#[derive(Clone)]
pub struct Db {
    connection: Arc<Mutex<Connection>>,
    operation: Arc<Mutex<()>>,
}
impl Default for Db {
    fn default() -> Self {
        Self::new()
    }
}

/// An all-or-nothing service operation. Dropping without commit rolls back.
pub struct Transaction<'a> {
    db: &'a Db,
    _operation: MutexGuard<'a, ()>,
    committed: bool,
}
impl Transaction<'_> {
    /// Make every write durable before acknowledging the operation.
    pub fn commit(mut self) -> rusqlite::Result<()> {
        self.db.connection.lock().unwrap().execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.db.connection.lock().unwrap().execute_batch("ROLLBACK");
        }
    }
}

impl Db {
    /// Ephemeral SQLite database for tests and explicitly ephemeral demos.
    pub fn new() -> Self {
        Self::initialize(Connection::open_in_memory().expect("SQLite memory"))
            .expect("SQLite schema")
    }

    /// Open a durable database. Parent directory must already exist and be private.
    pub fn open(path: &std::path::Path) -> rusqlite::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let meta = std::fs::symlink_metadata(parent)
            .map_err(|_| rusqlite::Error::InvalidPath(parent.to_owned()))?;
        if !meta.is_dir() {
            return Err(rusqlite::Error::InvalidPath(parent.to_owned()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(rusqlite::Error::InvalidPath(parent.to_owned()));
            }
        }
        // Refuse symlinks; owner-only creation precedes SQLite's open.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.is_file() {
                return Err(rusqlite::Error::InvalidPath(path.to_owned()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(rusqlite::Error::InvalidPath(path.to_owned()));
                }
            }
        } else {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .map_err(|_| rusqlite::Error::InvalidPath(path.to_owned()))?;
        }
        Self::initialize(Connection::open(path)?)
    }

    fn initialize(c: Connection) -> rusqlite::Result<Self> {
        c.busy_timeout(std::time::Duration::from_secs(15))?;
        c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS records (namespace TEXT NOT NULL, id TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(namespace,id));
            CREATE TABLE IF NOT EXISTS inventory (namespace TEXT NOT NULL, field TEXT NOT NULL, PRIMARY KEY(namespace,field));
            CREATE TABLE IF NOT EXISTS vault (id TEXT PRIMARY KEY, value BLOB NOT NULL);")?;
        Ok(Self {
            connection: Arc::new(Mutex::new(c)),
            operation: Arc::new(Mutex::new(())),
        })
    }

    /// Serialize against other connections/processes and begin a durable operation.
    pub fn transaction(&self) -> rusqlite::Result<Transaction<'_>> {
        let operation = self.operation.lock().unwrap();
        self.connection
            .lock()
            .unwrap()
            .execute_batch("BEGIN IMMEDIATE")?;
        Ok(Transaction {
            db: self,
            _operation: operation,
            committed: false,
        })
    }

    /// Load or atomically provision a service secret, outside account metadata.
    /// The database and containing directory must be restricted to the operator.
    pub fn secret(&self, name: &str, generate: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
        let c = self.connection.lock().unwrap();
        if let Some(value) = c
            .query_row("SELECT value FROM vault WHERE id=?1", [name], |r| r.get(0))
            .optional()
            .expect("vault read")
        {
            return value;
        }
        let value = generate();
        c.execute(
            "INSERT OR IGNORE INTO vault(id,value) VALUES(?1,?2)",
            params![name, value],
        )
        .expect("vault write");
        c.query_row("SELECT value FROM vault WHERE id=?1", [name], |r| r.get(0))
            .expect("vault reread")
    }

    /// Existing service secret names under a deployment-controlled prefix.
    pub fn secret_names(&self, prefix: &str) -> Vec<String> {
        let c = self.connection.lock().unwrap();
        let mut query = c.prepare("SELECT id FROM vault ORDER BY id").unwrap();
        query
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .filter(|s| s.starts_with(prefix))
            .collect()
    }

    /// Replace a provisioned service secret (use inside a transaction for rotation).
    pub fn replace_secret(&self, name: &str, value: &[u8]) {
        self.connection.lock().unwrap().execute("INSERT INTO vault(id,value) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET value=excluded.value", params![name,value]).expect("vault replace");
    }

    /// Write a row, replacing its previous value.
    pub fn put(&self, table: &'static str, key: &str, row: Row) {
        self.put_owned(
            table,
            key,
            row.into_iter().map(|(n, c)| (n.to_owned(), c)).collect(),
            false,
        );
    }
    fn put_owned(&self, table: &str, key: &str, row: StoredRow, absent: bool) -> bool {
        let bytes = postcard::to_stdvec(&row).expect("row encoding");
        let c = self.connection.lock().unwrap();
        let own = c.is_autocommit();
        if own {
            c.execute_batch("BEGIN IMMEDIATE").expect("row transaction");
        }
        let sql = if absent {
            "INSERT OR IGNORE INTO records(namespace,id,value) VALUES(?1,?2,?3)"
        } else {
            "INSERT INTO records(namespace,id,value) VALUES(?1,?2,?3) ON CONFLICT(namespace,id) DO UPDATE SET value=excluded.value"
        };
        let changed = c
            .execute(sql, params![table, key, bytes])
            .expect("row write")
            != 0;
        if changed {
            for (field, _) in row {
                c.execute(
                    "INSERT OR IGNORE INTO inventory(namespace,field) VALUES(?1,?2)",
                    params![table, field],
                )
                .expect("inventory write");
            }
        }
        if own {
            c.execute_batch("COMMIT").expect("row commit");
        }
        changed
    }
    /// Insert once; SQLite's primary key arbitrates concurrent writers.
    pub fn put_if_absent(&self, table: &'static str, key: &str, row: Row) -> bool {
        self.put_owned(
            table,
            key,
            row.into_iter().map(|(n, c)| (n.to_owned(), c)).collect(),
            true,
        )
    }
    /// Read a row.
    pub fn get(&self, table: &str, key: &str) -> Option<StoredRow> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM records WHERE namespace=?1 AND id=?2",
                params![table, key],
                |r| r.get(0),
            )
            .optional()
            .expect("row read");
        bytes.map(|b| postcard::from_bytes(&b).expect("corrupt database row"))
    }
    /// Whether the key exists.
    pub fn has(&self, table: &str, key: &str) -> bool {
        self.connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT 1 FROM records WHERE namespace=?1 AND id=?2",
                params![table, key],
                |_| Ok(()),
            )
            .optional()
            .expect("exists")
            .is_some()
    }
    /// Delete a row, retaining the inventory.
    pub fn delete(&self, table: &str, key: &str) {
        self.connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM records WHERE namespace=?1 AND id=?2",
                params![table, key],
            )
            .expect("delete");
    }
    /// Delete an expired lexicographic key range using the primary-key index.
    pub fn delete_before(&self, table: &str, end: &str) {
        self.connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM records WHERE namespace=?1 AND id<?2",
                params![table, end],
            )
            .expect("range delete");
    }
    /// All keys in sorted order.
    pub fn keys(&self, table: &str) -> Vec<String> {
        let c = self.connection.lock().unwrap();
        let mut q = c
            .prepare("SELECT id FROM records WHERE namespace=?1 ORDER BY id")
            .unwrap();
        q.query_map([table], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
    /// Read an indexed half-open key range without scanning unrelated accounts.
    pub fn keys_between(&self, table: &str, start: &str, end: &str) -> Vec<String> {
        let c = self.connection.lock().unwrap();
        let mut q = c
            .prepare("SELECT id FROM records WHERE namespace=?1 AND id>=?2 AND id<?3 ORDER BY id")
            .unwrap();
        q.query_map(params![table, start, end], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
    /// All stored rows in a table.
    pub fn rows(&self, table: &str) -> Vec<StoredRow> {
        let c = self.connection.lock().unwrap();
        let mut q = c
            .prepare("SELECT value FROM records WHERE namespace=?1 ORDER BY id")
            .unwrap();
        q.query_map([table], |r| r.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|r| postcard::from_bytes(&r.unwrap()).expect("corrupt row"))
            .collect()
    }
    /// Read a field.
    pub fn field(&self, table: &str, key: &str, field: &str) -> Option<Cell> {
        self.get(table, key)?
            .into_iter()
            .find(|(n, _)| n == field)
            .map(|(_, v)| v)
    }
    /// Change a counter; service transactions serialize the read-modify-write.
    pub fn bump(&self, table: &'static str, key: &str, field: &'static str, by: i64, row: Row) {
        let mut r = self
            .get(table, key)
            .unwrap_or_else(|| row.into_iter().map(|(n, c)| (n.to_owned(), c)).collect());
        let cur = r
            .iter()
            .find(|(n, _)| n == field)
            .and_then(|(_, v)| v.num())
            .unwrap_or(0);
        let next = if by < 0 {
            cur.saturating_sub(by.unsigned_abs())
        } else {
            cur.checked_add(by as u64).expect("counter overflow")
        };
        match r.iter_mut().find(|(n, _)| n == field) {
            Some((_, v)) => *v = Cell::Num(next),
            None => r.push((field.to_owned(), Cell::Num(next))),
        }
        self.put_owned(table, key, r, false);
    }
    /// Field inventory, excluding service-owned secrets.
    pub fn inventory(&self) -> BTreeMap<String, BTreeSet<String>> {
        let c = self.connection.lock().unwrap();
        let mut q = c
            .prepare("SELECT namespace,field FROM inventory ORDER BY namespace,field")
            .unwrap();
        let mut out = BTreeMap::<String, BTreeSet<String>>::new();
        for r in q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
        {
            let (t, f) = r.unwrap();
            out.entry(t).or_default().insert(f);
        }
        out
    }
    /// Metadata bytes for privacy tests; excludes server cryptographic secrets.
    pub fn all_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for table in self.inventory().keys() {
            for key in self.keys(table) {
                out.extend_from_slice(key.as_bytes());
                for (n, c) in self.get(table, &key).unwrap() {
                    out.extend_from_slice(n.as_bytes());
                    match c {
                        Cell::Bytes(b) => out.extend(b),
                        Cell::Text(t) => out.extend(t.as_bytes()),
                        Cell::Num(n) => out.extend(n.to_be_bytes()),
                    }
                }
            }
        }
        out
    }
}
