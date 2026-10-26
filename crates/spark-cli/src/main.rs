//! Terminal chat client and scripted verification commands.

mod certs;
mod serve;
mod terminal;
mod wiring;

use spark_client::Client;
use spark_crypto::{IssuerKey, Mnemonic};
use wiring::Local;

/// The system RNG.
///
/// **This is the only place in the whole tree that draws entropy from the
/// operating system.** Everything below the I/O line takes entropy as a
/// parameter, precisely so that the chain terminates somewhere visible rather
/// than at a hidden syscall in a crypto routine. This is that somewhere.
///
/// The error type is `Infallible` because a failure here is not a condition to
/// handle. If the OS cannot produce randomness, every key this process would go
/// on to generate is suspect, and continuing is worse than stopping.
struct OsRandom;

impl OsRandom {
    fn fill(dst: &mut [u8]) {
        getrandom::fill(dst)
            .expect("the operating system could not produce randomness; refusing to continue");
    }
}

impl spark_crypto::blind::TryRng for OsRandom {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        Self::fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        Self::fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        Self::fill(dst);
        Ok(())
    }
}
impl spark_crypto::blind::TryCryptoRng for OsRandom {}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let code = match cmd {
        "init" | "contacts" | "contact-add" | "contact-remove" | "contact-note" | "inbox"
        | "retry-upload" | "account" | "rooms" | "create" | "key-package" | "invite" | "join"
        | "send" | "history" | "chat" | "share" | "fetch" => terminal::run(&args),
        "new" => cmd_new(),
        "demo" => cmd_demo(),
        "serve" => cmd_serve(&args[1..]),
        "remote-demo" => cmd_remote_demo(&args[1..]),
        "help" | "--help" | "-h" => {
            usage();
            0
        }
        other => {
            eprintln!("unknown command: {other}\n");
            usage();
            2
        }
    };
    std::process::exit(code);
}

fn usage() {
    terminal::usage();
    println!(
        "spark {} — diagnostic commands\n\
         \n\
           new     generate a recovery phrase and show the address it derives\n\
           demo    run two accounts through a conversation against real services,\n\
                   then print what those services were left holding\n\
           serve   run the three services on TCP and stay up\n\
                   (spark serve [keyring-port content-port issuer-port] [--data-dir DIR])\n\
           remote-demo\n\
                   the same conversation, over real sockets and the wire format\n\
                   (spark remote-demo [--cover [seconds]])\n\
                   --cover paces every transmission onto a fixed schedule, so an\n\
                   observer cannot tell when there was something to say. It is off\n\
                   by default because it is slow, and slow is the point: at the\n\
                   spec's 60s a demo of a dozen requests takes a quarter of an\n\
                   hour. Give a shorter interval to watch it work.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_new() -> i32 {
    let mut entropy = [0u8; 32];
    if getrandom::fill(&mut entropy).is_err() {
        eprintln!("could not read entropy from the operating system");
        return 1;
    }
    let m = Mnemonic::from_entropy(&entropy);
    let id = spark_identity_of(&m);

    println!("recovery phrase:\n  {}\n", m.phrase().as_str());
    println!("address the servers will see:\n  {id}\n");
    println!(
        "This phrase is the account. There is no reset and no support path:\n\
         a recovery route for you would be a recovery route for everyone else."
    );
    0
}

fn spark_identity_of(m: &Mnemonic) -> String {
    // Deriving here rather than opening a Client: `new` should not need a server.
    let root = spark_crypto::extract(spark_identity_root_salt(), m.to_seed().expose());
    let sign = spark_crypto::SigningKey::from_secret(&spark_crypto::expand::<32>(
        &root,
        b"spark/v1/identity/ed25519",
    ));
    let addr =
        spark_crypto::sha256_parts(&[b"spark/v1/keyring/addr", sign.verifying_key().as_bytes()]);
    addr.iter().map(|b| format!("{b:02x}")).collect()
}

fn spark_identity_root_salt() -> &'static [u8] {
    b"spark/v1/root"
}

fn cmd_serve(args: &[String]) -> i32 {
    let mut ports = Vec::new();
    let mut directory = std::path::PathBuf::from("spark-server-data");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--data-dir" {
            let Some(path) = args.next() else {
                eprintln!("--data-dir requires a directory");
                return 2;
            };
            directory = path.into();
        } else if let Ok(port) = arg.parse::<u16>() {
            ports.push(port);
        } else {
            eprintln!("invalid serve argument: {arg}");
            return 2;
        }
    }
    if !ports.is_empty() && ports.len() != 3 {
        eprintln!("provide all three service ports");
        return 2;
    }
    let port = |i: usize, default| ports.get(i).copied().unwrap_or(default);
    let mut rng = OsRandom;
    let setup = || -> Result<_, String> {
        if !directory.exists() {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&directory).map_err(|e| e.to_string())?;
        }
        let meta = std::fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !meta.is_dir() {
            return Err("data directory must not be a symlink".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("data directory must have mode 0700".into());
            }
        }
        let lock_path = directory.join("server.lock");
        if let Ok(meta) = std::fs::symlink_metadata(&lock_path) {
            if !meta.is_file() {
                return Err("invalid deployment lock".into());
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path).map_err(|e| e.to_string())?;
        lock.try_lock()
            .map_err(|_| "deployment directory is already in use")?;
        let open = |name| spark_store::Db::open(&directory.join(name)).map_err(|e| e.to_string());
        let databases = [
            open("keyring.sqlite")?,
            open("content.sqlite")?,
            open("issuer.sqlite")?,
        ];
        let id = certs::persistent(&open("tls.sqlite")?, "spark.local")?;
        let pin = id.pin;
        let key = rustls_pki_types::PrivateKeyDer::try_from(id.key).map_err(|e| e.to_string())?;
        let tls = std::sync::Arc::new(
            spark_transport::tls::server_config(id.cert, key).map_err(|e| e.to_string())?,
        );
        Ok((databases, tls, pin, lock))
    };
    let (databases, tls, pin, _deployment_lock) = match setup() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("durable deployment: {e}");
            return 1;
        }
    };
    let (k, c, i) = build_services_in(&mut rng, databases);

    let kl = match serve::keyring_service(&format!("127.0.0.1:{}", port(0, 9310)), tls.clone(), k) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("keyring service: {e}");
            return 1;
        }
    };
    let cl = serve::content_service(&format!("127.0.0.1:{}", port(1, 9311)), tls.clone(), c)
        .expect("content");
    let il =
        serve::issuer_service(&format!("127.0.0.1:{}", port(2, 9312)), tls, i).expect("issuer");

    println!("Durable server data: {}", directory.display());
    println!("keyring   {}", kl.addr);
    println!("content   {}", cl.addr);
    println!("issuer    {}", il.addr);
    println!("\npin       {}\n", pin.to_hex());
    println!(
        "SQLite WAL transactions and the TLS pin survive restart. Back up the private data directory. Ctrl-C to stop."
    );
    kl.join();
    0
}

/// A server identity and the pin a client needs for it.
fn server_tls() -> Result<(std::sync::Arc<rustls::ServerConfig>, spark_transport::Pin), String> {
    let id = certs::generate("spark.local")?;
    let key = rustls_pki_types::PrivateKeyDer::try_from(id.key)
        .map_err(|e| format!("private key: {e}"))?;
    let cfg = spark_transport::tls::server_config(id.cert, key).map_err(|e| e.to_string())?;
    Ok((std::sync::Arc::new(cfg), id.pin))
}

fn build_services(
    rng: &mut OsRandom,
) -> (
    std::sync::Arc<spark_keyring_server::Keyring>,
    std::sync::Arc<spark_content_server::Content>,
    std::sync::Arc<spark_issuer::Issuer>,
) {
    build_services_in(
        rng,
        [
            spark_store::Db::new(),
            spark_store::Db::new(),
            spark_store::Db::new(),
        ],
    )
}

fn build_services_in(
    rng: &mut OsRandom,
    databases: [spark_store::Db; 3],
) -> (
    std::sync::Arc<spark_keyring_server::Keyring>,
    std::sync::Arc<spark_content_server::Content>,
    std::sync::Arc<spark_issuer::Issuer>,
) {
    use std::sync::Arc;
    let [keyring_db, content_db, issuer_db] = databases;
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).expect("challenge entropy");
    let keyring = Arc::new(spark_keyring_server::Keyring::new(
        keyring_db,
        spark_crypto::Secret::new(secret),
        IssuerKey::generate(rng).expect("token key"),
    ));
    let content = Arc::new(spark_content_server::Content::with_keys(
        content_db,
        keyring.accepted_keys(),
    ));
    keyring.set_refund_keys(content.refund_keys());
    let issuer = Arc::new(spark_issuer::Issuer::new(
        issuer_db,
        IssuerKey::generate(rng).expect("voucher key"),
    ));
    (keyring, content, issuer)
}

fn cmd_remote_demo(args: &[String]) -> i32 {
    // `--cover` with no number means F12's interval, because the default has to be
    // the real one. A number after it is for watching the mechanism without waiting
    // out a quarter of an hour — it is a demo knob, not a deployment one: a shorter
    // interval narrows the window an observer has to average over.
    let cover = match args.iter().position(|a| a == "--cover") {
        None => spark_net::Cover::Off,
        Some(i) => match args.get(i + 1).map(|s| s.parse::<u64>()) {
            None => spark_net::Cover::DEFAULT,
            Some(Ok(secs)) => spark_net::Cover::Every(std::time::Duration::from_secs(secs)),
            Some(Err(_)) => {
                eprintln!("--cover takes a number of seconds, or nothing for the default");
                return 2;
            }
        },
    };
    if let spark_net::Cover::Every(i) = cover {
        println!("cover traffic on: one transmission every {}s.", i.as_secs());
        println!("this will take a while, which is the cost being demonstrated.\n");
    }
    let started = std::time::Instant::now();
    let mut rng = OsRandom;
    let (k, c, i) = build_services(&mut rng);
    let (tls, pin) = server_tls().expect("server identity");
    let kl = serve::keyring_service("127.0.0.1:0", tls.clone(), k).expect("keyring");
    let cl = serve::content_service("127.0.0.1:0", tls.clone(), c).expect("content");
    let il = serve::issuer_service("127.0.0.1:0", tls, i).expect("issuer");
    println!("services on {} {} {}", kl.addr, cl.addr, il.addr);
    println!("pinned to  {}\n", pin.to_hex());

    let conn = |who: &str| {
        // Tor off: this demo has no proxy to reach. Said explicitly, because a
        // default that quietly does less than the setting claims is the failure
        // `Spark-build-notes.md` §1 names.
        spark_net::Remote::connect_via(
            &kl.addr.to_string(),
            &cl.addr.to_string(),
            &il.addr.to_string(),
            &[pin],
            spark_transport::Mode::AlwaysOff,
            cover,
            ("127.0.0.1".into(), 9050),
        )
        .unwrap_or_else(|e| panic!("{who} could not connect: {e}"))
    };

    let mut alice =
        Client::from_mnemonic(&Mnemonic::from_entropy(&[1; 32]), conn("alice")).expect("alice");
    let mut bob =
        Client::from_mnemonic(&Mnemonic::from_entropy(&[2; 32]), conn("bob")).expect("bob");

    let room = alice.create_room(&mut rng, "the crossing").expect("room");
    let kp = bob.key_package().expect("key package");
    let inv = alice.invite(&mut rng, room, &kp).expect("invite");
    bob.accept(&mut rng, &inv, "the crossing").expect("join");

    for (who, text) in [
        (0usize, "the boat leaves at six"),
        (1, "understood, bringing the charts"),
        (0, "do not be late"),
    ] {
        if who == 0 {
            alice.sync(room, 3).expect("sync");
            alice.send(&mut rng, room, text.as_bytes()).expect("send");
        } else {
            bob.sync(room, 3).expect("sync");
            bob.send(&mut rng, room, text.as_bytes()).expect("send");
        }
    }

    let alice_key = alice.public().sign;
    for (name, msgs) in [
        ("alice", alice.sync(room, 3).expect("sync")),
        ("bob", bob.sync(room, 3).expect("sync")),
    ] {
        println!("{name} sees {} message(s):", msgs.len());
        for m in &msgs {
            let who = if m.from == alice_key {
                "alice"
            } else {
                "bob  "
            };
            println!("    {who}  {}", String::from_utf8_lossy(&m.body));
        }
        println!();
    }
    let services = alice.services();
    println!("how that traffic was routed:");
    for h in services.ledger().hops() {
        println!(
            "    {:<8} {}:{}  {}",
            format!("{:?}", h.class),
            h.host,
            h.port,
            if h.via_tor { "over Tor" } else { "direct" }
        );
    }
    let (text, media) = services.content_calls();
    println!("\n    {text} chunk request(s) on the text connection, {media} on the media one");
    let slots = services.cover_slots();
    if slots > 0 {
        println!(
            "    {slots} paced transmission(s), every one the same size, in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        println!("    (media is never paced: a slower photo is a photo that never arrives)");
    } else {
        println!("    0 paced transmissions — cover traffic was off, so the timing of");
        println!("    every request above says when there was something to say");
    }
    println!(
        "\nAll of that crossed a TCP socket, inside TLS pinned to that key, as\n\
         WebSocket binary frames in the format of docs/protocol.md §6.\n\
         \n\
         Tor is off here — there is no proxy to reach. The default mode routes\n\
         control and text through one and leaves media direct, which is why the\n\
         content service gets two connections rather than one."
    );
    0
}

fn cmd_demo() -> i32 {
    let mut rng = OsRandom;
    println!("standing up three services in this process...");
    let services = Local::new(
        IssuerKey::generate(&mut rng).expect("token key"),
        IssuerKey::generate(&mut rng).expect("voucher key"),
        [0x5e; 32],
    );
    services.set_minute(1);

    let alice_phrase = Mnemonic::from_entropy(&[1; 32]);
    let bob_phrase = Mnemonic::from_entropy(&[2; 32]);

    let mut alice = match Client::from_mnemonic(&alice_phrase, &services) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("alice: {e}");
            return 1;
        }
    };
    let mut bob = Client::from_mnemonic(&bob_phrase, &services).expect("bob");
    println!("  alice  {}", alice.addr());
    println!("  bob    {}\n", bob.addr());

    let room = alice
        .create_room(&mut rng, "the crossing")
        .expect("create room");
    let kp = bob.key_package().expect("bob key package");
    let invite = alice.invite(&mut rng, room, &kp).expect("invite");
    bob.accept(&mut rng, &invite, "the crossing")
        .expect("bob joins");
    println!(
        "room created, bob added ({} generation(s) re-shared)\n",
        invite.generations.len()
    );

    let script = [
        (0usize, "the boat leaves at six"),
        (1, "understood, bringing the charts"),
        (0, "do not be late"),
    ];
    for (who, text) in script {
        let c: &mut Client<&Local> = if who == 0 { &mut alice } else { &mut bob };
        // Read before writing, as a real client does. The vector clock in each
        // entry records what its writer had seen, so a reply that was genuinely
        // written without having read the message before it is *concurrent* with
        // it — and gets ordered by lane bytes, not by wall-clock. Skipping this
        // sync would make the transcript arrive in an order nobody typed.
        c.sync(room, 3).expect("sync before sending");
        c.send(&mut rng, room, text.as_bytes()).expect("send");
    }

    let alice_key = alice.public().sign;
    let alice_view = alice.sync(room, 3).expect("alice sync");
    let bob_view = bob.sync(room, 3).expect("bob sync");

    for (name, msgs) in [("alice", &alice_view), ("bob", &bob_view)] {
        println!("{name} sees {} message(s):", msgs.len());
        for m in msgs.iter() {
            let who = if m.from == alice_key {
                "alice"
            } else {
                "bob  "
            };
            println!("    {who}  {}", String::from_utf8_lossy(&m.body));
        }
        println!();
    }

    if alice_view != bob_view {
        println!("    DISAGREEMENT: the two clients do not see the same history\n");
    }

    let (k, ct, is) = services.stored_bytes();
    println!("what the services are left holding:");
    println!("    keyring service   {k} bytes");
    println!(
        "    content service   {ct} bytes across {} chunks",
        services.chunk_count()
    );
    println!("    issuer            {is} bytes\n");

    let mut leaked = false;
    for (_, text) in script {
        if services.holds(text.as_bytes()) {
            println!("    LEAK: {text:?} is in a server's storage");
            leaked = true;
        }
    }
    if !leaked {
        println!("    none of the three holds any of that plaintext.");
    }
    if services.holds(alice.addr().to_hex().as_bytes()) {
        println!("    (the keyring service knows alice's address — that is its job)");
    }
    i32::from(leaked)
}
