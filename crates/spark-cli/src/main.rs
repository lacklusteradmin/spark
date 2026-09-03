//! scripted verification harness. Not a user-facing product.
//!
//! layer 11, zone `boundary` — see `docs/layering.toml`.
//!
//! `Spark-build-notes.md` §5: "the CLI is for scripted verification, not for
//! users." So the commands here are not a chat interface. They stand up all three
//! services in this process, drive whole scenarios through the real client, and
//! print both what the participants see and what the servers were left holding.
//!
//! The second half is the point. Anyone can claim a messenger is private; this
//! prints the servers' entire contents and shows the plaintext is not in them.

mod certs;
mod remote;
mod serve;
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
    println!(
        "spark {} — verification harness, not a chat client\n\
         \n\
           new     generate a recovery phrase and show the address it derives\n\
           demo    run two accounts through a conversation against real services,\n\
                   then print what those services were left holding\n\
           serve   run the three services on TCP and stay up\n\
                   (spark serve [keyring-port content-port issuer-port])\n\
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
    let port = |i: usize, d: u16| args.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    let mut rng = OsRandom;
    let (k, c, i) = build_services(&mut rng);
    let (tls, pin) = match server_tls() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("could not build a server identity: {e}");
            return 1;
        }
    };

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

    println!("keyring   {}", kl.addr);
    println!("content   {}", cl.addr);
    println!("issuer    {}", il.addr);
    println!("\npin       {}\n", pin.to_hex());
    println!(
        "Three listeners, three trust domains. Running them on one machine is a\n\
         choice this command makes, not one the code assumes.\n\
         \n\
         Clients pin that key rather than asking a certificate authority. This one is\n\
         generated fresh at startup, so the pin changes every restart — right for a\n\
         harness, wrong for a deployment, which keeps its key. Ctrl-C to stop."
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
    use std::sync::Arc;
    let keyring = Arc::new(spark_keyring_server::Keyring::new(
        spark_store::Db::new(),
        spark_crypto::Secret::new([0x5e; 32]),
        IssuerKey::generate(rng).expect("token key"),
    ));
    keyring.set_minute(1);
    let content = Arc::new(spark_content_server::Content::with_keys(
        spark_store::Db::new(),
        keyring.accepted_keys(),
    ));
    let issuer = Arc::new(spark_issuer::Issuer::new(
        spark_store::Db::new(),
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
        None => remote::Cover::Off,
        Some(i) => match args.get(i + 1).map(|s| s.parse::<u64>()) {
            None => remote::Cover::DEFAULT,
            Some(Ok(secs)) => remote::Cover::Every(std::time::Duration::from_secs(secs)),
            Some(Err(_)) => {
                eprintln!("--cover takes a number of seconds, or nothing for the default");
                return 2;
            }
        },
    };
    if let remote::Cover::Every(i) = cover {
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
        remote::Remote::connect_via(
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
