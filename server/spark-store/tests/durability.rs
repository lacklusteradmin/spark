use spark_store::{Cell, Db};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "spark-db-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
    fn open(&self) -> Db {
        Db::open(&self.0.join("test.sqlite")).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn commit_survives_reopen_and_abandoned_transaction_rolls_back() {
    let t = Temp::new();
    {
        let db = t.open();
        let tx = db.transaction().unwrap();
        db.put("spent", "token", vec![("used", Cell::Num(1))]);
        db.put(
            "chunks",
            "name",
            vec![("bytes", Cell::Bytes(vec![1, 2, 3]))],
        );
        tx.commit().unwrap();
        let _aborted = db.transaction().unwrap();
        db.delete("chunks", "name");
        db.put("spent", "aborted", vec![("used", Cell::Num(1))]);
    }
    let db = t.open();
    assert!(db.has("spent", "token"));
    assert!(!db.has("spent", "aborted"));
    assert_eq!(
        db.field("chunks", "name", "bytes"),
        Some(Cell::Bytes(vec![1, 2, 3]))
    );
}
#[test]
fn independent_connections_cannot_double_spend() {
    let t = Temp::new();
    let a = t.open();
    let b = t.open();
    let race = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = [a, b]
        .into_iter()
        .map(|db| {
            let race = race.clone();
            std::thread::spawn(move || {
                race.wait();
                let tx = db.transaction().unwrap();
                let won = db.put_if_absent("spent", "same-token", vec![("used", Cell::Num(1))]);
                if won {
                    db.bump("quota", "account", "used", 1, vec![]);
                }
                tx.commit().unwrap();
                won
            })
        })
        .collect();
    let wins = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap().then_some(()))
        .count();
    assert_eq!(wins, 1);
    assert_eq!(
        t.open().field("quota", "account", "used"),
        Some(Cell::Num(1))
    );
}
#[test]
fn secrets_are_stable_and_excluded_from_account_inventory() {
    let t = Temp::new();
    t.open().secret("private", || b"server-secret".to_vec());
    let db = t.open();
    assert_eq!(
        db.secret("private", || panic!("must not regenerate")),
        b"server-secret"
    );
    assert!(db.inventory().is_empty());
    assert!(db.all_bytes().is_empty());
}
#[cfg(unix)]
#[test]
fn symlink_and_world_readable_database_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let t = Temp::new();
    drop(t.open());
    let path = t.0.join("test.sqlite");
    let link = t.0.join("link.sqlite");
    symlink(&path, &link).unwrap();
    assert!(Db::open(&link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Db::open(&path).is_err());
}

#[test]
fn indexed_account_range_excludes_other_accounts_and_namespaces() {
    let db = Db::new();
    for (table, key) in [
        ("delta", "aa:0"),
        ("delta", "aa:1"),
        ("delta", "bb:0"),
        ("request", "aa:0"),
    ] {
        db.put(table, key, vec![("value", Cell::Num(1))]);
    }
    assert_eq!(db.keys_between("delta", "aa:", "aa;"), ["aa:0", "aa:1"]);
}
#[cfg(unix)]
#[test]
fn exposed_parent_directory_is_refused_before_creating_secret_files() {
    use std::os::unix::fs::PermissionsExt;
    let t = Temp::new();
    std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Db::open(&t.0.join("test.sqlite")).is_err());
    assert!(!t.0.join("test.sqlite").exists());
}
