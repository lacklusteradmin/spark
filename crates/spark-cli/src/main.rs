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
                   then print what those services were left holding\n",
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
