//! The FFI surface: what a Swift or Kotlin app is given.
//!
//! layer 7, zone `boundary` — see `docs/layering.toml`.
//!
//! # What this crate is not allowed to do
//!
//! No cryptography, and no dependency that does any. `docs/layering.toml`'s
//! `[boundary]` list is enforced by `spark-invariants`, and the reason is
//! reproducible builds: everything below this line is byte-identical from source,
//! and an auditor's job is bounded by where that stops. A key handled above it is
//! a key outside the audit.
//!
//! That rule is why [`spark_net::Session`] exists. `Client`'s own API is made of
//! `Mnemonic`, `Addr`, `ChunkName`, `Secret<32>` and an `R: CryptoRng` — every one
//! of them from a crate this zone may not name. The conversion to `String`,
//! `Vec<u8>` and `u64` happens below the line, and what arrives here is already
//! inert.
//!
//! # No logic
//!
//! Every function here forwards. If one of them ever needs a branch that is not
//! argument marshalling, that branch belongs in `spark-net` where it can be tested
//! without a mobile toolchain in the loop.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

uniffi::setup_scaffolding!();

/// Where the three services are, and how to reach them.
///
/// Mirrored here rather than re-exported from `spark-net`. These types are an
/// ABI: a foreign app is compiled against them, and it should not break because a
/// field moved on the Rust side. The conversion below is the seam that absorbs
/// that.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Config {
    /// `host:port` of the keyring service.
    pub keyring: String,
    /// `host:port` of the content service.
    pub content: String,
    /// `host:port` of the issuer.
    pub issuer: String,
    /// Pinned server keys, as the 64-character hex a deployment publishes.
    pub pins: Vec<String>,
    /// `"off"`, `"text"` for D2's default, or `"on"` for everything over Tor.
    pub tor: String,
    /// Seconds between transmissions, or 0 for no cover traffic.
    pub cover_seconds: u64,
    /// `host:port` of the SOCKS5 proxy, used only when `tor` is not `"off"`.
    pub proxy: String,
    /// The push warning this device's user accepted, exactly as shown, or empty.
    ///
    /// Store the text passed to `enable_push` when it succeeds, and clear it on
    /// `disable_push`. It is checked again on every open, so a warning reworded in
    /// a later release brings push up as `PushState::Stale` rather than on.
    pub push_consent: String,
}

impl From<&Config> for spark_net::Config {
    fn from(c: &Config) -> Self {
        Self {
            keyring: c.keyring.clone(),
            content: c.content.clone(),
            issuer: c.issuer.clone(),
            pins: c.pins.clone(),
            tor: c.tor.clone(),
            cover_seconds: c.cover_seconds,
            proxy: c.proxy.clone(),
            push_consent: c.push_consent.clone(),
        }
    }
}

/// One message, as a reader sees it.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Record)]
pub struct Note {
    /// The author's verifying key. Verified, not claimed.
    pub from: Vec<u8>,
    /// The text.
    pub body: Vec<u8>,
    /// Which generation of the room it belongs to.
    pub generation: u64,
}

/// A room this account is in.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Record)]
pub struct Room {
    /// Its identifier, opaque to the caller.
    pub id: Vec<u8>,
    /// Its name.
    pub name: String,
}

/// The capability to read one shared file, and nothing else.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Record)]
pub struct FileHandle {
    /// Where the chunk is stored.
    pub name: Vec<u8>,
    /// The key that opens it.
    pub key: Vec<u8>,
}

/// What went wrong.
///
/// Flat and small on purpose. A foreign caller can act on "unreachable" and on
/// "bad phrase"; it cannot act on which layer refused, and telling it more would
/// put protocol detail above the FFI line.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error, uniffi::Error)]
pub enum SessionError {
    /// The recovery phrase is not a valid 24-word mnemonic.
    #[error("the recovery phrase is not valid")]
    BadPhrase,
    /// A service address or pin could not be parsed.
    #[error("the configuration could not be parsed")]
    BadConfig,
    /// The deployment could not be reached, or refused.
    #[error("the deployment could not be reached")]
    Unreachable,
    /// No such room in this account.
    #[error("no such room")]
    NoSuchRoom,
    /// An identifier, invitation or file handle was not the right shape.
    #[error("malformed input")]
    Malformed,
    /// The file cannot be stripped of metadata, so it will not be sent.
    #[error("this file cannot be stripped of metadata, so it will not be sent")]
    Unscrubbable,
    /// Anything the client refused that the caller cannot act on differently.
    #[error("refused")]
    Refused,
    /// Push was not turned on: the text passed back was not the current warning.
    #[error("push was not turned on: show the current warning and pass back exactly what was shown")]
    WarningNotShown,
}

/// Whether this device may use push.
#[derive(Clone, Copy, PartialEq, Eq, Debug, uniffi::Enum)]
pub enum PushState {
    /// Off, which is the default. Nothing is registered with Apple or Google.
    Off,
    /// On, after the user accepted the current warning.
    On,
    /// Off, because the user accepted a warning that has since changed. Show the
    /// new one and ask again; never treat this as on.
    Stale,
}

impl From<spark_net::PushState> for PushState {
    fn from(p: spark_net::PushState) -> Self {
        match p {
            spark_net::PushState::Off => Self::Off,
            spark_net::PushState::On => Self::On,
            spark_net::PushState::Stale => Self::Stale,
        }
    }
}

/// The warning an interface must show before push can be turned on.
///
/// Display it in full and, if the user accepts, pass the same text to
/// `Session::enable_push`. Push is off by default; this is the cost of turning it
/// on, and it is meant to be read before the switch moves, not after.
#[uniffi::export]
pub fn push_warning() -> String {
    spark_net::push_warning().to_string()
}

/// What leaving push off costs, to show alongside the warning.
#[uniffi::export]
pub fn push_off_cost() -> String {
    spark_net::push_off_cost().to_string()
}

impl From<spark_net::Room> for Room {
    fn from(r: spark_net::Room) -> Self {
        Self {
            id: r.id,
            name: r.name,
        }
    }
}

impl From<spark_net::Note> for Note {
    fn from(n: spark_net::Note) -> Self {
        Self {
            from: n.from,
            body: n.body,
            generation: n.generation,
        }
    }
}

impl From<spark_net::FileHandle> for FileHandle {
    fn from(h: spark_net::FileHandle) -> Self {
        Self {
            name: h.name,
            key: h.key,
        }
    }
}

impl From<&FileHandle> for spark_net::FileHandle {
    fn from(h: &FileHandle) -> Self {
        Self {
            name: h.name.clone(),
            key: h.key.clone(),
        }
    }
}

impl From<spark_net::SessionError> for SessionError {
    fn from(e: spark_net::SessionError) -> Self {
        use spark_net::SessionError as E;
        match e {
            E::BadPhrase => Self::BadPhrase,
            E::BadConfig => Self::BadConfig,
            E::Unreachable => Self::Unreachable,
            E::NoSuchRoom => Self::NoSuchRoom,
            E::Malformed => Self::Malformed,
            E::Unscrubbable => Self::Unscrubbable,
            E::Refused => Self::Refused,
            E::WarningNotShown => Self::WarningNotShown,
        }
    }
}

/// An explicitly approved contact, containing public information only.
#[derive(Clone, uniffi::Record)]
pub struct Contact {
    /// Local display name.
    pub name: String,
    /// Signing and encryption public keys (64 bytes).
    pub identity: Vec<u8>,
}

/// An account, connected. The handle a mobile app holds.
///
/// Interior mutability because the foreign side owns this behind a shared
/// reference and cannot express `&mut`. One call at a time: a request and its
/// response are one exchange on one connection.
#[derive(uniffi::Object)]
pub struct Session {
    inner: std::sync::Mutex<spark_net::Session>,
}

/// The result type every binding sees.
pub type FfiResult<T> = Result<T, SessionError>;

#[uniffi::export]
impl Session {
    /// Open an account from its recovery phrase and connect.
    #[uniffi::constructor]
    pub fn open(phrase: &str, cfg: &Config) -> FfiResult<std::sync::Arc<Self>> {
        Ok(std::sync::Arc::new(Self {
            inner: std::sync::Mutex::new(spark_net::Session::open(phrase, &cfg.into())?),
        }))
    }
}

impl Session {
    fn with<T>(
        &self,
        f: impl FnOnce(&mut spark_net::Session) -> Result<T, spark_net::SessionError>,
    ) -> FfiResult<T> {
        // A poisoned lock means a previous call panicked. Reporting it as
        // `Refused` rather than panicking again keeps the failure on the Rust side
        // of the boundary: a panic across FFI is undefined on most toolchains.
        let mut g = self.inner.lock().map_err(|_| SessionError::Refused)?;
        f(&mut g).map_err(Into::into)
    }
}

#[uniffi::export]
impl Session {
    /// This account's address, as the text a person shares.
    pub fn address(&self) -> FfiResult<String> {
        self.with(|s| Ok(s.address()))
    }

    /// Bytes this account is currently paying to store.
    pub fn bytes_held(&self) -> FfiResult<u64> {
        self.with(|s| Ok(s.bytes_held()))
    }

    /// Every room this account is in.
    pub fn rooms(&self) -> FfiResult<Vec<Room>> {
        self.with(|s| Ok(s.rooms().into_iter().map(Into::into).collect()))
    }

    /// Create a room and return its identifier.
    pub fn create_room(&self, name: &str) -> FfiResult<Vec<u8>> {
        self.with(|s| s.create_room(name))
    }

    /// This account's key package, which someone else needs in order to invite it.
    pub fn key_package(&self) -> FfiResult<Vec<u8>> {
        self.with(|s| s.key_package())
    }

    /// Invite the holder of `key_package` into `room`.
    ///
    /// The bytes returned are secret: they carry the archive key for the room's
    /// whole history. Whatever carries them must be confidential.
    pub fn invite(&self, room: &[u8], key_package: &[u8]) -> FfiResult<Vec<u8>> {
        self.with(|s| s.invite(room, key_package))
    }

    /// Join a room from an invitation.
    pub fn accept(&self, invitation: &[u8], name: &str) -> FfiResult<Vec<u8>> {
        self.with(|s| s.accept(invitation, name))
    }

    /// Public identity for approving this account as a contact.
    pub fn public_identity(&self) -> FfiResult<Vec<u8>> {
        self.with(|s| Ok(s.public_identity()))
    }
    /// Approved contacts, restored with the encrypted keyring.
    pub fn contacts(&self) -> FfiResult<Vec<Contact>> {
        self.with(|s| {
            Ok(s.contacts()
                .into_iter()
                .map(|(name, identity)| Contact { name, identity })
                .collect())
        })
    }
    /// Explicitly approve an identity or confidential contact card, returning a reply card.
    pub fn add_contact(&self, name: &str, card: &[u8]) -> FfiResult<Vec<u8>> {
        self.with(|s| s.add_contact(name, card))
    }
    /// Remove a contact and revoke their inbox access.
    pub fn remove_contact(&self, key: &[u8]) -> FfiResult<()> {
        self.with(|s| s.remove_contact(key))
    }
    /// Send a note using a contact's inbox permission.
    pub fn contact_note(&self, key: &[u8], note: &str) -> FfiResult<()> {
        self.with(|s| s.contact_note(key, note))
    }
    /// Read only signed notes from approved contacts.
    pub fn contact_inbox(&self) -> FfiResult<Vec<Note>> {
        self.with(|s| {
            s.contact_inbox()
                .map(|notes| notes.into_iter().map(Into::into).collect())
        })
    }

    /// Send a message.
    pub fn send(&self, room: &[u8], body: &[u8]) -> FfiResult<()> {
        self.with(|s| s.send(room, body))
    }

    /// Fetch new messages.
    pub fn sync(&self, room: &[u8], probe_ahead: u64) -> FfiResult<Vec<Note>> {
        self.with(|s| {
            s.sync(room, probe_ahead)
                .map(|v| v.into_iter().map(Into::into).collect())
        })
    }

    /// Share a file, returning the capability to read it.
    pub fn share_file(&self, room: &[u8], bytes: &[u8]) -> FfiResult<FileHandle> {
        self.with(|s| s.share_file(room, bytes).map(Into::into))
    }

    /// Retry the exact pending upload after an interrupted send.
    pub fn retry_pending_upload(&self) -> FfiResult<()> {
        self.with(|s| s.retry_pending_upload())
    }

    /// Fetch a shared file by its capability.
    pub fn fetch_file(&self, handle: &FileHandle) -> FfiResult<Vec<u8>> {
        self.with(|s| s.fetch_file(&handle.into()))
    }

    /// Whether this device may use push.
    pub fn push_state(&self) -> FfiResult<PushState> {
        self.with(|s| Ok(s.push_state().into()))
    }

    /// Turn push on. `shown` must be exactly the `push_warning()` text the
    /// interface displayed; on success, store it as `Config::push_consent`.
    pub fn enable_push(&self, shown: &str) -> FfiResult<()> {
        self.with(|s| s.enable_push(shown))
    }

    /// Turn push off. Clear `Config::push_consent`.
    pub fn disable_push(&self) -> FfiResult<()> {
        self.with(|s| {
            s.disable_push();
            Ok(())
        })
    }
}
