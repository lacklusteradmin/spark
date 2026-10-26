//! A profile contains credentials and connection settings; conversation state
//! stays in the encrypted server keyring. Each invocation reopens that state.
use spark_net::{Config, FileHandle, Note, Session, SessionError};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

type Result<T> = std::result::Result<T, String>;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    phrase: String,
    keyring: String,
    content: String,
    issuer: String,
    pin: String,
    tor: String,
    proxy: String,
}

impl Profile {
    fn config(&self) -> Config {
        Config {
            keyring: self.keyring.clone(),
            content: self.content.clone(),
            issuer: self.issuer.clone(),
            pins: vec![self.pin.clone()],
            tor: self.tor.clone(),
            proxy: self.proxy.clone(),
            cover_seconds: 0,
        }
    }
    fn connect(&self) -> Result<Session> {
        Session::open(&self.phrase, &self.config()).map_err(session_error)
    }
}

pub fn usage() {
    println!(
        "\
Spark — terminal chat
  init PROFILE --pin HEX [--tor text|on|off] [--phrase-file FILE]
       [--keyring HOST:PORT] [--content HOST:PORT] [--issuer HOST:PORT]
       [--proxy HOST:PORT]
  account PROFILE                    show address and storage usage
  contacts PROFILE                   list approved contacts
  contact-add PROFILE NAME CARD      approve identity/card hex; print reply card
  contact-remove PROFILE KEY         revoke a contact's signing key hex
  contact-note PROFILE KEY TEXT       send a note to an approved contact
  inbox PROFILE                      read signed notes from contacts
  retry-upload PROFILE               resume an interrupted upload
  rooms PROFILE                      list room IDs and names
  create PROFILE NAME                create a room; print its ID
  key-package PROFILE OUTPUT         export a saved invitation key package
  invite PROFILE ROOM PACKAGE OUTPUT create a confidential invitation
  join PROFILE INVITATION NAME        accept an invitation; print room ID
  send PROFILE ROOM TEXT             send text (use - to read stdin)
  history PROFILE ROOM               print the conversation
  chat PROFILE ROOM                  chat live; /quit exits, /help lists commands
  share PROFILE ROOM FILE            upload and send an attachment handle
  fetch PROFILE HANDLE OUTPUT        download an attachment without overwriting

PROFILE is a directory, ROOM is the full ID from create/rooms.
init creates an account, or restores from --phrase-file (use - for stdin).
The profile stores your recovery phrase UNENCRYPTED, with owner-only Unix
permissions. Back it up securely. Do not run one account from multiple profiles
at once. Tor defaults to text; local testing requires explicit --tor off.
The bundled serve command uses memory only: stopping it loses all server data."
    );
}

pub fn run(args: &[String]) -> i32 {
    match execute(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("spark: {}", visible(&e));
            1
        }
    }
}

fn execute(args: &[String]) -> Result<()> {
    let cmd = args[0].as_str();
    if args.get(1).is_some_and(|a| a == "--help" || a == "-h") {
        usage();
        return Ok(());
    }
    if cmd == "init" {
        return init(&args[1..]);
    }
    let expected = match cmd {
        "account" | "rooms" | "contacts" | "inbox" | "retry-upload" => 2,
        "create" | "key-package" | "history" | "chat" | "contact-remove" => 3,
        "join" | "send" | "share" | "fetch" | "contact-add" | "contact-note" => 4,
        "invite" => 5,
        _ => return Err("unknown command; run spark help".into()),
    };
    if args.len() != expected {
        return Err("wrong number of arguments; run spark help".into());
    }
    let path = Path::new(&args[1]);
    check_private(path, true)?;
    let credential = path.join("profile.json");
    check_private(&credential, false)?;
    // Advisory OS lock is released even after Ctrl-C or a crash. Keeping the
    // lock file avoids unlink/recreate races between concurrent commands.
    let lock = private_options()
        .read(true)
        .write(true)
        .create(true)
        .open(path.join("lock"))
        .map_err(io_error)?;
    lock.try_lock()
        .map_err(|_| "profile is in use; close its other Spark command first".to_string())?;
    let p: Profile = serde_json::from_slice(&read_limited(&credential, 16 * 1024)?)
        .map_err(|_| "invalid profile.json".to_string())?;
    let mut s = p.connect()?;
    let arg = args.get(2).map(String::as_str).unwrap_or("");
    match cmd {
        "account" => println!(
            "address {}\npublic {}\nstored {} bytes",
            s.address(),
            hex(&s.public_identity()),
            s.bytes_held()
        ),
        "contacts" => {
            for (name, key) in s.contacts() {
                println!("{}  {}", hex(&key), visible(&name));
            }
        }
        "contact-add" => println!(
            "{}",
            hex(&s
                .add_contact(arg, &parse_contact_hex(&args[3])?)
                .map_err(session_error)?)
        ),
        "contact-remove" => s
            .remove_contact(&parse_contact_hex(arg)?)
            .map_err(session_error)?,
        "contact-note" => s
            .contact_note(&parse_contact_hex(arg)?, &args[3])
            .map_err(session_error)?,
        "retry-upload" => s.retry_pending_upload().map_err(session_error)?,
        "inbox" => {
            for note in s.contact_inbox().map_err(session_error)? {
                print_note(&note);
            }
        }
        "rooms" => {
            for r in s.rooms() {
                println!("{}  {}", hex(&r.id), visible(&r.name));
            }
        }
        "create" => {
            nonempty(arg)?;
            println!("{}", hex(&s.create_room(arg).map_err(session_error)?));
        }
        "key-package" => {
            write_output(Path::new(arg), || {
                s.saved_key_package().map_err(session_error)
            })?;
        }
        "invite" => {
            let room = room_id(arg)?;
            let package = read_limited(Path::new(&args[3]), 1024 * 1024)?;
            write_output(Path::new(&args[4]), || {
                s.invite(&room, &package).map_err(session_error)
            })?;
            eprintln!("Invitation includes room history keys. Transfer it confidentially.");
        }
        "join" => {
            nonempty(&args[3])?;
            let bytes = read_limited(Path::new(arg), 16 * 1024 * 1024)?;
            println!(
                "{}",
                hex(&s.accept(&bytes, &args[3]).map_err(session_error)?)
            );
        }
        "send" => {
            let body = if args[3] == "-" {
                read_stdin(64 * 1024)?
            } else {
                args[3].as_bytes().to_vec()
            };
            send(&mut s, &room_id(arg)?, &body)?;
            println!("sent");
        }
        "history" => {
            for n in s.sync(&room_id(arg)?, 3).map_err(session_error)? {
                print_note(&n);
            }
        }
        "chat" => chat(&p, s, &room_id(arg)?)?,
        "share" => {
            share(&mut s, &room_id(arg)?, &args[3])?;
        }
        "fetch" => {
            let h = handle(arg)?;
            let size = write_output(Path::new(&args[3]), || {
                s.fetch_file(&h).map_err(session_error)
            })?;
            println!("saved {size} bytes");
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn init(args: &[String]) -> Result<()> {
    let path = args
        .first()
        .ok_or("expected a profile directory; run spark help")?;
    let mut opts = BTreeMap::new();
    let mut rest = args[1..].chunks_exact(2);
    for pair in &mut rest {
        if ![
            "--pin",
            "--tor",
            "--phrase-file",
            "--keyring",
            "--content",
            "--issuer",
            "--proxy",
        ]
        .contains(&pair[0].as_str())
        {
            return Err(format!("unknown option: {}", pair[0]));
        }
        if opts.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err("duplicate option".into());
        }
    }
    if !rest.remainder().is_empty() {
        return Err("every init option needs a value".into());
    }
    let pin = *opts
        .get("--pin")
        .ok_or("--pin is required; copy the server's trusted public-key pin")?;
    spark_transport::Pin::parse(pin).map_err(|_| "pin must contain 64 hexadecimal characters")?;
    let tor = opts.get("--tor").copied().unwrap_or("text");
    if !["text", "on", "off"].contains(&tor) {
        return Err("--tor must be text, on, or off".into());
    }
    let mut p = Profile {
        phrase: String::new(),
        pin: pin.into(),
        tor: tor.into(),
        keyring: opts
            .get("--keyring")
            .copied()
            .unwrap_or("127.0.0.1:9310")
            .into(),
        content: opts
            .get("--content")
            .copied()
            .unwrap_or("127.0.0.1:9311")
            .into(),
        issuer: opts
            .get("--issuer")
            .copied()
            .unwrap_or("127.0.0.1:9312")
            .into(),
        proxy: opts
            .get("--proxy")
            .copied()
            .unwrap_or("127.0.0.1:9050")
            .into(),
    };
    for address in [&p.keyring, &p.content, &p.issuer, &p.proxy] {
        let (host, port) = address
            .rsplit_once(':')
            .ok_or("addresses must be HOST:PORT")?;
        if host.is_empty() || port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
            return Err("addresses must contain a host and a port from 1 to 65535".into());
        }
    }
    let generated = !opts.contains_key("--phrase-file");
    p.phrase = if let Some(file) = opts.get("--phrase-file") {
        let bytes = if *file == "-" {
            read_stdin(4096)?
        } else {
            read_limited(Path::new(file), 4096)?
        };
        let text = String::from_utf8(bytes).map_err(|_| "recovery phrase must be UTF-8")?;
        let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
        spark_crypto::Mnemonic::parse(&normalized)
            .map_err(|_| "invalid 24-word recovery phrase")?;
        normalized
    } else {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| "could not obtain secure randomness")?;
        spark_crypto::Mnemonic::from_entropy(&entropy)
            .phrase()
            .to_string()
    };
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    #[cfg(not(unix))]
    {
        return Err("profile storage currently supports macOS and Linux only".into());
    }
    builder.create(path).map_err(io_error)?;
    let mut out = new_output(&Path::new(path).join("profile.json"))?;
    out.write_all(&serde_json::to_vec_pretty(&p).map_err(|e| e.to_string())?)
        .map_err(io_error)?;
    out.sync_all().map_err(io_error)?;
    eprintln!("Profile saved. Recovery phrase is stored unencrypted with owner-only permissions.");
    if generated {
        println!("Recovery phrase (back this up securely):\n{}", p.phrase);
    }
    println!(
        "Profile ready. Use spark account {} to connect.",
        visible(path)
    );
    Ok(())
}

fn send(s: &mut Session, room: &[u8], body: &[u8]) -> Result<()> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err("message must contain 1 to 65536 bytes".into());
    }
    s.sync(room, 3).map_err(session_error)?;
    s.send(room, body).map_err(|e| {
        format!(
            "send failed ({}) — delivery may be uncertain; check history before retrying",
            session_error(e)
        )
    })
}

fn share(s: &mut Session, room: &[u8], file: &str) -> Result<()> {
    if !s.rooms().iter().any(|r| r.id == room) {
        return Err(session_error(SessionError::NoSuchRoom));
    }
    let bytes = read_limited(Path::new(file), 128 * 1024 * 1024)?;
    let h = s.share_file(room, &bytes).map_err(session_error)?;
    let token = format!("spark-file:{}:{}", hex(&h.name), hex(&h.key));
    // Print the capability before sending so a failed send does not strand the
    // upload without any way for the user to retrieve it.
    println!("{token}");
    send(s, room, token.as_bytes())?;
    Ok(())
}

fn chat(p: &Profile, mut s: Session, room: &[u8]) -> Result<()> {
    println!(
        "Room {}. Type a message and press Enter. /help for commands.",
        hex(room)
    );
    let (tx, rx) = mpsc::sync_channel(32);
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut shown = BTreeMap::new();
    let mut connected = true;
    loop {
        if !connected {
            match p.connect() {
                Ok(new) => {
                    s = new;
                    connected = true;
                    eprintln!("reconnected");
                }
                Err(_) => { /* Retry after processing input below. */ }
            }
        }
        if connected {
            match s.sync(room, 3) {
                Ok(notes) => {
                    let mut counts = BTreeMap::new();
                    for n in notes {
                        let key = (n.generation, n.from.clone(), n.body.clone());
                        let count = counts.entry(key.clone()).or_insert(0usize);
                        *count += 1;
                        if *count > *shown.get(&key).unwrap_or(&0) {
                            print_note(&n);
                        }
                    }
                    shown = counts;
                }
                Err(SessionError::Unreachable) => {
                    connected = false;
                    eprintln!("connection lost; retrying (messages are not queued)");
                }
                Err(e) => return Err(session_error(e)),
            }
        }
        io::stdout().flush().map_err(io_error)?;
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(line)) => {
                if line == "/quit" {
                    return Ok(());
                }
                if line == "/help" {
                    println!(
                        "/quit exit; /share PATH send attachment; //TEXT send text starting with /; /help"
                    );
                    continue;
                }
                if line.trim().is_empty() {
                    continue;
                }
                if !connected {
                    eprintln!("offline: message was not sent; try again after reconnection");
                    continue;
                }
                let result = if let Some(path) = line.strip_prefix("/share ") {
                    share(&mut s, room, path)
                } else if line.starts_with('/') && !line.starts_with("//") {
                    eprintln!("unknown command; use /help or // to send a leading slash");
                    continue;
                } else {
                    send(
                        &mut s,
                        room,
                        line.strip_prefix('/')
                            .filter(|_| line.starts_with("//"))
                            .unwrap_or(&line)
                            .as_bytes(),
                    )
                };
                if let Err(e) = result {
                    eprintln!("{}", visible(&e));
                    // A failed write may have changed local state. Reopen before
                    // the next operation, and never automatically resend.
                    connected = false;
                }
            }
            Ok(Err(e)) => return Err(io_error(e)),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn session_error(e: SessionError) -> String {
    match e {
        SessionError::BadPhrase => "invalid recovery phrase",
        SessionError::BadConfig => "invalid connection configuration",
        SessionError::Unreachable => {
            "cannot reach service or request refused; check server, pin, and Tor proxy"
        }
        SessionError::NoSuchRoom => "room not found; use spark rooms PROFILE",
        SessionError::Malformed => "malformed room, invitation, or attachment handle",
        SessionError::Unscrubbable => "unsupported attachment: metadata cannot be safely removed",
        SessionError::Refused => "operation refused by the client or server",
    }
    .into()
}
fn io_error(e: io::Error) -> String {
    e.to_string()
}
fn nonempty(s: &str) -> Result<()> {
    if s.trim().is_empty() {
        Err("name cannot be empty".into())
    } else {
        Ok(())
    }
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn new_output(path: &Path) -> Result<File> {
    private_options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)
}
// Reserve the destination before a remote mutation. Remove failed downloads or
// exports so an empty placeholder cannot be mistaken for a valid artifact.
fn write_output(path: &Path, data: impl FnOnce() -> Result<Vec<u8>>) -> Result<usize> {
    let mut out = new_output(path)?;
    let result = data().and_then(|bytes| {
        out.write_all(&bytes).map_err(io_error)?;
        out.sync_all().map_err(io_error)?;
        Ok(bytes.len())
    });
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn check_private(path: &Path, directory: bool) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if meta.file_type().is_symlink()
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
    {
        return Err("profile must use regular files and a real directory, not symlinks".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("profile permissions are too broad; use chmod 700 on the directory and chmod 600 on profile.json".into());
        }
    }
    Ok(())
}
fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    limited(File::open(path).map_err(io_error)?, limit)
}
fn read_stdin(limit: usize) -> Result<Vec<u8>> {
    limited(io::stdin().lock(), limit)
}
fn limited(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut b)
        .map_err(io_error)?;
    if b.len() > limit {
        return Err(format!("input exceeds {limit} bytes"));
    }
    Ok(b)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(s: &str, len: usize) -> Result<Vec<u8>> {
    if s.len() != len * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected {} hexadecimal characters", len * 2));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".into()))
        .collect()
}
fn room_id(s: &str) -> Result<Vec<u8>> {
    unhex(s, 16)
}
fn handle(s: &str) -> Result<FileHandle> {
    let (name, key) = s
        .strip_prefix("spark-file:")
        .and_then(|s| s.split_once(':'))
        .ok_or("invalid attachment handle")?;
    Ok(FileHandle {
        name: unhex(name, 32)?,
        key: unhex(key, 32)?,
    })
}
// Room names and messages are untrusted terminal content. Never print escape
// sequences (including OSC clipboard writes), even from authenticated senders.
fn visible(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn print_note(n: &Note) {
    println!(
        "{}  {}",
        hex(&n.from),
        visible(&String::from_utf8_lossy(&n.body))
    );
}

fn parse_contact_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() > 192 || !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err("invalid contact key/card".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid contact key/card".into())
        })
        .collect()
}
