//! The client as an application uses it: networked, and speaking in bytes.
//!
//! # Why this exists
//!
//! `docs/layering.toml` bans `spark-crypto`, `spark-identity`, `spark-chunk`,
//! `spark-keyring` and every cryptographic dependency from the `boundary` zone,
//! because once a key is handled above the FFI line reproducible builds stop
//! bounding what an auditor has to read. But `Client`'s API is made of exactly
//! those types — `Mnemonic`, `Addr`, `ChunkName`, `Secret<32>`, `RoomId`, and an
//! `R: CryptoRng` on half its methods. Nothing in the boundary zone can call it.
//!
//! So the conversion happens here, below the line, where crypto is allowed. What
//! crosses is `String`, `Vec<u8>` and `u64`. That is not a formality: a capability
//! leaving as `Vec<u8>` is a capability the Swift or Kotlin side can only carry,
//! not construct, because it has nothing to construct one with.
//!
//! # The RNG stops here too
//!
//! Entropy is a parameter everywhere below the I/O line, and this crate is `io`,
//! so this is a place that may draw it. It is drawn once per `Session` rather than
//! passed in, because the caller above the FFI line has no business choosing the
//! entropy source for key generation and no safe way to supply one.

use crate::{Cover, Remote};
use spark_client::{Client, ClientError, Invitation};
use spark_crypto::blind::{TryCryptoRng, TryRng};
use spark_keyring::RoomId;
use spark_transport::push::{self, Consent, Setting};
use spark_transport::{Mode, Pin};

/// The warning an interface must show before push can be turned on.
///
/// The interface displays this and, if the user accepts, hands the same text
/// back to [`Session::enable_push`]. It comes from here rather than from the
/// app's own strings so that there is one wording, and so that strengthening it
/// in a release reaches every interface that displays it.
pub fn push_warning() -> &'static str {
    push::ENABLE_WARNING
}

/// What leaving push off costs, to show alongside the warning.
pub fn push_off_cost() -> &'static str {
    push::OFF_COST
}

/// Whether this device may use push.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PushState {
    /// Off, which is the default. Nothing is registered with Apple or Google.
    Off,
    /// On, after the user accepted the current warning.
    On,
    /// Off, because the user accepted a warning that has since changed.
    ///
    /// Distinct from `Off` so an interface can show the new wording and ask
    /// again, rather than silently losing notifications the user chose to have.
    /// Never treated as on: consent given to a warning that no longer describes
    /// the risk is not consent to the risk as it now stands.
    Stale,
}
/// The operating-system entropy source.
///
/// The one place in the client's graph that draws rather than receives. Above it
/// is the FFI line, where there is no safe way to pass entropy in; below it every
/// signature takes an `&mut R`.
struct OsRandom;

impl OsRandom {
    /// Panics if the OS cannot produce randomness.
    ///
    /// `CryptoRng` is `TryRng<Error = Infallible>`, so there is no error to
    /// return, and that is the right shape: every alternative here is worse than
    /// stopping. Carrying on with degraded entropy generates a key that looks
    /// fine, and there is no later point at which that becomes visible.
    fn fill(dst: &mut [u8]) {
        getrandom::fill(dst)
            .expect("the operating system could not produce randomness; refusing to continue");
    }
}

impl TryRng for OsRandom {
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
impl TryCryptoRng for OsRandom {}

/// What went wrong, flattened for a caller that cannot see the type graph.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionError {
    /// The recovery phrase is not a valid 24-word mnemonic.
    BadPhrase,
    /// A service address or pin could not be parsed.
    BadConfig,
    /// The deployment could not be reached, or refused.
    Unreachable,
    /// No such room in this account.
    NoSuchRoom,
    /// A room identifier, invitation or file handle was not the right shape.
    Malformed,
    /// The file cannot be stripped of metadata, so it will not be sent.
    Unscrubbable,
    /// Anything the client refused that the caller cannot act on differently.
    Refused,
    /// Push was not turned on, because the text passed back was not the current
    /// warning. Show [`push_warning`] and pass back exactly what was shown.
    WarningNotShown,
}

impl From<ClientError> for SessionError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Service(_) => Self::Unreachable,
            ClientError::BadMnemonic => Self::BadPhrase,
            ClientError::NoSuchRoom => Self::NoSuchRoom,
            ClientError::Unscrubbable => Self::Unscrubbable,
            _ => Self::Refused,
        }
    }
}

/// Where the three services are, and how to reach them.
///
/// `tor` and `cover` are spelled out rather than defaulted, for the reason
/// `Remote::connect_via` gives: a privacy setting chosen silently by an API is one
/// nobody decided.
#[derive(Clone, Debug)]
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
    /// The push warning this device's user accepted, exactly as it was shown, or
    /// empty if they never turned push on.
    ///
    /// A device setting rather than an account one, so it lives with the app and
    /// not in the keyring: each device mints its own token, possibly tied to a
    /// different Apple or Google account, and consent on one device is not consent
    /// on another. The app stores the text it displayed when the user accepted,
    /// and clears it when they turn push off.
    ///
    /// Text rather than a flag, so that it is checked again on every open. If the
    /// warning has been reworded since, this no longer matches and push comes up
    /// [`PushState::Stale`] instead of on.
    pub push_consent: String,
}

/// One message, as a reader sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Note {
    /// The author's verifying key. Verified, not claimed.
    pub from: Vec<u8>,
    /// The text.
    pub body: Vec<u8>,
    /// Which generation of the room it belongs to.
    pub generation: u64,
}

/// A room this account is in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Room {
    /// Its identifier, opaque to the caller.
    pub id: Vec<u8>,
    /// Its name.
    pub name: String,
}

/// What `share_file` returns and `fetch_file` takes: the capability to read one
/// file, and nothing else. Opaque here because it is a key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileHandle {
    /// Where the chunk is stored.
    pub name: Vec<u8>,
    /// The key that opens it.
    pub key: Vec<u8>,
}

/// An account, connected.
pub struct Session {
    client: Client<Remote>,
    rng: OsRandom,
    /// The push setting, which can only be `On` through a [`Consent`].
    push: Setting,
    /// Whether the last consent offered was for a warning that has changed.
    push_stale: bool,
}

fn room_id(b: &[u8]) -> Result<RoomId, SessionError> {
    <[u8; 16]>::try_from(b)
        .map(RoomId)
        .map_err(|_| SessionError::Malformed)
}

impl Session {
    /// Publish the 64-byte identity to approve this account in contacts.
    pub fn public_identity(&self) -> Vec<u8> {
        let p = self.client.public();
        [p.sign.as_bytes().as_slice(), p.kem.as_bytes()].concat()
    }
    /// List approved contacts as (display name, public identity).
    pub fn contacts(&self) -> Vec<(String, Vec<u8>)> {
        self.client
            .contacts()
            .iter()
            .map(|c| {
                (
                    c.name.clone(),
                    [c.sign.as_slice(), c.kem.as_slice()].concat(),
                )
            })
            .collect()
    }
    /// Approve a public identity or a confidential 96-byte contact card; return our reply card.
    pub fn add_contact(&mut self, name: &str, card: &[u8]) -> Result<Vec<u8>, SessionError> {
        if card.len() != 64 && card.len() != 96 {
            return Err(SessionError::Malformed);
        }
        let identity = card[..64].try_into().map_err(|_| SessionError::Malformed)?;
        let permit = if card.len() == 96 {
            Some(card[64..].try_into().unwrap())
        } else {
            None
        };
        Ok(self
            .client
            .add_contact(&mut self.rng, name, &identity, permit)?)
    }
    /// Revoke a contact by its 32-byte signing key.
    pub fn remove_contact(&mut self, key: &[u8]) -> Result<(), SessionError> {
        Ok(self.client.remove_contact(
            &mut self.rng,
            &key.try_into().map_err(|_| SessionError::Malformed)?,
        )?)
    }
    /// Send a contact note, only with an explicitly exchanged permit.
    pub fn contact_note(&mut self, key: &[u8], note: &str) -> Result<(), SessionError> {
        Ok(self.client.contact_note(
            &mut self.rng,
            &key.try_into().map_err(|_| SessionError::Malformed)?,
            note,
        )?)
    }
    /// Read authenticated notes from contacts; unknown senders are discarded.
    pub fn contact_inbox(&self) -> Result<Vec<Note>, SessionError> {
        Ok(self
            .client
            .contact_inbox()?
            .into_iter()
            .map(|n| Note {
                from: n.from.sign.as_bytes().to_vec(),
                body: n.note.into_bytes(),
                generation: 0,
            })
            .collect())
    }

    /// Open an account from its recovery phrase and connect.
    pub fn open(phrase: &str, cfg: &Config) -> Result<Self, SessionError> {
        let mode = match cfg.tor.as_str() {
            "off" => Mode::AlwaysOff,
            "text" => Mode::TextOverTor,
            "on" => Mode::AlwaysOn,
            _ => return Err(SessionError::BadConfig),
        };
        let cover = match cfg.cover_seconds {
            0 => Cover::Off,
            s => Cover::Every(std::time::Duration::from_secs(s)),
        };
        let pins: Vec<Pin> = cfg
            .pins
            .iter()
            .map(|p| Pin::parse(p).map_err(|_| SessionError::BadConfig))
            .collect::<Result<_, _>>()?;
        let (host, port) = cfg.proxy.rsplit_once(':').ok_or(SessionError::BadConfig)?;
        let port: u16 = port.parse().map_err(|_| SessionError::BadConfig)?;

        let remote = Remote::connect_via(
            &cfg.keyring,
            &cfg.content,
            &cfg.issuer,
            &pins,
            mode,
            cover,
            (host.to_string(), port),
        )
        .map_err(|_| SessionError::Unreachable)?;

        // Through `Consent::acknowledge`, the same as a fresh opt-in, so a stored
        // consent cannot outlive the wording it was given to.
        let (push, push_stale) = match cfg.push_consent.as_str() {
            "" => (Setting::Off, false),
            shown => match Consent::acknowledge(shown) {
                Ok(c) => (Setting::On(c), false),
                Err(_) => (Setting::Off, true),
            },
        };

        Ok(Self {
            client: Client::open(phrase, remote)?,
            rng: OsRandom,
            push,
            push_stale,
        })
    }

    /// Whether this device may use push.
    ///
    /// Nothing registers yet, whatever this says: there is no delivery service, and
    /// minting a token nothing will consume would be the leak with none of the
    /// benefit. This is the setting a registration call will consult once there is
    /// one.
    pub fn push_state(&self) -> PushState {
        match (self.push, self.push_stale) {
            (Setting::On(_), _) => PushState::On,
            (Setting::Off, true) => PushState::Stale,
            (Setting::Off, false) => PushState::Off,
        }
    }

    /// Turn push on, after the user accepted the warning.
    ///
    /// `shown` is the text the interface displayed, which must be exactly
    /// [`push_warning`]. On success the app should store it as
    /// [`Config::push_consent`].
    pub fn enable_push(&mut self, shown: &str) -> Result<(), SessionError> {
        let consent = Consent::acknowledge(shown).map_err(|_| SessionError::WarningNotShown)?;
        self.push = Setting::On(consent);
        self.push_stale = false;
        Ok(())
    }

    /// Turn push off. The app should clear [`Config::push_consent`].
    pub fn disable_push(&mut self) {
        self.push = Setting::Off;
        self.push_stale = false;
    }

    /// This account's address, as the text a person shares.
    pub fn address(&self) -> String {
        self.client.addr().to_hex()
    }

    /// Bytes this account is currently paying to store.
    pub fn bytes_held(&self) -> u64 {
        self.client.bytes_held()
    }

    /// Every room this account is in.
    pub fn rooms(&self) -> Vec<Room> {
        self.client
            .rooms()
            .into_iter()
            .map(|(id, name)| Room {
                id: id.0.to_vec(),
                name,
            })
            .collect()
    }

    /// Create a room and return its identifier.
    pub fn create_room(&mut self, name: &str) -> Result<Vec<u8>, SessionError> {
        let id = self.client.create_room(&mut self.rng, name)?;
        Ok(id.0.to_vec())
    }

    /// This account's key package, which someone else needs in order to invite it.
    pub fn key_package(&self) -> Result<Vec<u8>, SessionError> {
        Ok(self.client.key_package()?)
    }

    /// Export a key package whose private state survives closing the session.
    pub fn saved_key_package(&mut self) -> Result<Vec<u8>, SessionError> {
        Ok(self.client.saved_key_package(&mut self.rng)?)
    }

    /// Invite the holder of `key_package` into `room`.
    ///
    /// The bytes returned carry every past generation root — the archive key for
    /// the room's whole history — so whatever moves them must be confidential.
    /// `Spark-spec.md` F4 is where that being out-of-band is accounted for.
    pub fn invite(&mut self, room: &[u8], key_package: &[u8]) -> Result<Vec<u8>, SessionError> {
        let inv = self
            .client
            .invite(&mut self.rng, room_id(room)?, key_package)?;
        postcard::to_allocvec(&inv).map_err(|_| SessionError::Refused)
    }

    /// Join a room from an invitation.
    pub fn accept(&mut self, invitation: &[u8], name: &str) -> Result<Vec<u8>, SessionError> {
        let inv: Invitation =
            postcard::from_bytes(invitation).map_err(|_| SessionError::Malformed)?;
        let id = self.client.accept(&mut self.rng, &inv, name)?;
        Ok(id.0.to_vec())
    }

    /// Send a message.
    pub fn send(&mut self, room: &[u8], body: &[u8]) -> Result<(), SessionError> {
        self.client.send(&mut self.rng, room_id(room)?, body)?;
        Ok(())
    }

    /// Fetch new messages.
    pub fn sync(&mut self, room: &[u8], probe_ahead: u64) -> Result<Vec<Note>, SessionError> {
        Ok(self
            .client
            .sync(room_id(room)?, probe_ahead)?
            .into_iter()
            .map(|m| Note {
                from: m.from.as_bytes().to_vec(),
                body: m.body,
                generation: m.generation,
            })
            .collect())
    }

    /// Share a file, returning the capability to read it.
    pub fn share_file(&mut self, room: &[u8], bytes: &[u8]) -> Result<FileHandle, SessionError> {
        let (name, key) = self
            .client
            .share_file(&mut self.rng, room_id(room)?, bytes)?;
        Ok(FileHandle {
            name: name.as_bytes().to_vec(),
            key: key.expose().to_vec(),
        })
    }

    /// Retry the exact upload interrupted by a network or process failure.
    pub fn retry_pending_upload(&mut self) -> Result<(), SessionError> {
        self.client.retry_pending_upload(&mut self.rng)?;
        Ok(())
    }

    /// Fetch a shared file by its capability.
    pub fn fetch_file(&self, h: &FileHandle) -> Result<Vec<u8>, SessionError> {
        let name = <[u8; 32]>::try_from(h.name.as_slice()).map_err(|_| SessionError::Malformed)?;
        let key = <[u8; 32]>::try_from(h.key.as_slice()).map_err(|_| SessionError::Malformed)?;
        Ok(self.client.fetch_file(
            spark_chunk::ChunkName::new(name),
            &spark_crypto::Secret::new(key),
        )?)
    }
}
