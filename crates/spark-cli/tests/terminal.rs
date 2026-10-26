#[path = "../src/certs.rs"]
#[allow(dead_code)]
mod certs;
#[path = "../src/serve.rs"]
#[allow(dead_code)]
mod serve;

use spark_crypto::{IssuerKey, Mnemonic, Secret};
use spark_ffi::Config;
use spark_store::Db;
use std::sync::Arc;

struct Fixed(u64);
impl spark_crypto::blind::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for c in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        Ok(())
    }
}
impl spark_crypto::blind::TryCryptoRng for Fixed {}

fn deployment() -> Config {
    let keyring = Arc::new(spark_keyring_server::Keyring::new(
        Db::new(),
        Secret::new([0x5e; 32]),
        IssuerKey::generate(&mut Fixed(1)).unwrap(),
    ));
    keyring.set_minute(1);
    let content = Arc::new(spark_content_server::Content::with_keys(
        Db::new(),
        keyring.accepted_keys(),
    ));
    keyring.set_refund_keys(content.refund_keys());
    let issuer = Arc::new(spark_issuer::Issuer::new(
        Db::new(),
        IssuerKey::generate(&mut Fixed(2)).unwrap(),
    ));
    let id = certs::generate("spark.local").expect("server identity");
    let pin = id.pin;
    let key = rustls_pki_types::PrivateKeyDer::try_from(id.key).expect("key");
    let tls = Arc::new(spark_transport::tls::server_config(id.cert, key).expect("tls"));

    let k = serve::keyring_service("127.0.0.1:0", tls.clone(), keyring).unwrap();
    let c = serve::content_service("127.0.0.1:0", tls.clone(), content).unwrap();
    let i = serve::issuer_service("127.0.0.1:0", tls, issuer).unwrap();
    Config {
        keyring: k.addr.to_string(),
        content: c.addr.to_string(),
        issuer: i.addr.to_string(),
        pins: vec![pin.to_hex()],
        tor: "off".into(),
        cover_seconds: 0,
        proxy: "127.0.0.1:9050".into(),
    }
}

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "spark-terminal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_spark"))
        .args(args)
        .output()
        .unwrap()
}
fn run(args: &[&str]) -> String {
    let o = command(args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}
fn init(cfg: &Config, profile: &str, phrase: Option<&str>) {
    let mut args = vec![
        "init",
        profile,
        "--pin",
        &cfg.pins[0],
        "--tor",
        "off",
        "--keyring",
        &cfg.keyring,
        "--content",
        &cfg.content,
        "--issuer",
        &cfg.issuer,
    ];
    if let Some(file) = phrase {
        args.extend(["--phrase-file", file]);
    }
    run(&args);
}

#[test]
fn independent_processes_join_send_restart_restore_and_share() {
    let cfg = deployment();
    let tmp = Scratch::new();
    let a = tmp.path("alice");
    let b = tmp.path("bob");
    let phrase = tmp.path("recovery.txt");
    std::fs::write(&phrase, Mnemonic::from_entropy(&[72; 32]).phrase().as_str()).unwrap();
    init(&cfg, &a, Some(&phrase));
    init(&cfg, &b, None);
    let room = run(&["create", &a, "a room with spaces"]);
    run(&["send", &a, &room, "before joining"]);
    let kp = tmp.path("bob.package");
    let inv = tmp.path("bob.invitation");
    run(&["key-package", &b, &kp]);
    run(&["invite", &a, &room, &kp, &inv]);
    assert_eq!(run(&["join", &b, &inv, "a room with spaces"]), room);
    for msg in ["hello", "hello again", "你好"] {
        run(&["send", &a, &room, msg]);
    }
    run(&["send", &b, &room, "reply"]);
    let view = run(&["history", &a, &room]);
    assert_eq!(view, run(&["history", &b, &room]));
    for msg in ["before joining", "hello", "hello again", "你好", "reply"] {
        assert!(view.contains(msg));
    }
    assert_eq!(view.lines().count(), 5);
    // Fresh local profile holds only the seed and settings. No local room or
    // provider files are copied, and the recovered account can write again.
    let recovered = tmp.path("restored");
    init(&cfg, &recovered, Some(&phrase));
    assert_eq!(run(&["history", &recovered, &room]), view);
    run(&["send", &recovered, &room, "after restore"]);
    assert!(run(&["history", &b, &room]).contains("after restore"));
    let input = tmp.path("note.txt");
    std::fs::write(&input, b"attachment content").unwrap();
    let token = run(&["share", &b, &room, &input]);
    assert!(run(&["history", &a, &room]).contains(&token));
    let output = tmp.path("download.txt");
    run(&["fetch", &a, &token, &output]);
    assert_eq!(std::fs::read(&output).unwrap(), b"attachment content");
    assert!(!command(&["fetch", &a, &token, &output]).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), b"attachment content");
    let missing = format!("spark-file:{}:{}", "00".repeat(32), "00".repeat(32));
    let failed = tmp.path("missing-download.txt");
    assert!(!command(&["fetch", &a, &missing, &failed]).status.success());
    assert!(
        !Path::new(&failed).exists(),
        "failed fetch left a misleading empty file"
    );
    // Authenticated text is still untrusted terminal input.
    run(&["send", &b, &room, "escape \x1b]52;c;bad\x07"]);
    let view = run(&["history", &a, &room]);
    assert!(!view.contains('\x1b'));
    assert!(!view.contains('\x07'));
}

struct Chat(std::process::Child);
impl Drop for Chat {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn live_chat_receives_identical_messages_and_locks_its_profile() {
    let cfg = deployment();
    let tmp = Scratch::new();
    let a = tmp.path("alice");
    let b = tmp.path("bob");
    init(&cfg, &a, None);
    init(&cfg, &b, None);
    let room = run(&["create", &a, "live"]);
    let kp = tmp.path("package");
    let inv = tmp.path("invitation");
    run(&["key-package", &b, &kp]);
    run(&["invite", &a, &room, &kp, &inv]);
    run(&["join", &b, &inv, "live"]);
    let mut chat = Chat(
        Command::new(env!("CARGO_BIN_EXE_spark"))
            .args(["chat", &a, &room])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = chat.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(20))
            .unwrap()
            .contains("Room")
    );
    let busy = command(&["rooms", &a]);
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("in use"));
    for _ in 0..2 {
        run(&["send", &b, &room, "identical"]);
    }
    for _ in 0..2 {
        assert!(
            rx.recv_timeout(Duration::from_secs(20))
                .unwrap()
                .ends_with("identical")
        );
    }
    chat.0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"from live chat\n/quit\n")
        .unwrap();
    assert!(chat.0.wait().unwrap().success());
    assert!(run(&["history", &b, &room]).contains("from live chat"));
    assert!(run(&["rooms", &a]).contains(&room));
}

#[test]
fn profile_permissions_validation_and_no_overwrite() {
    let tmp = Scratch::new();
    let p = tmp.path("profile");
    let pin = "00".repeat(32);
    assert!(!command(&["init", &p, "--pin", "invalid"]).status.success());
    assert!(!Path::new(&p).exists());
    run(&["init", &p, "--pin", &pin]);
    let original = std::fs::read(Path::new(&p).join("profile.json")).unwrap();
    assert!(!command(&["init", &p, "--pin", &pin]).status.success());
    assert_eq!(
        original,
        std::fs::read(Path::new(&p).join("profile.json")).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file = Path::new(&p).join("profile.json");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let o = command(&["account", &p]);
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("permissions"));
    }
}
