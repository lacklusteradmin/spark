//! facade, state machine, event stream.
//!
//! layer 5, zone `io` — see `docs/layering.toml`.
//!
//! Everything below this crate is implemented and tested on its own. This is
//! where the pieces become a thing a person can use: an identity that derives
//! from a mnemonic, rooms that hold their own archive secrets, a keyring that
//! survives a wiped device, tokens that pay for uploads without naming who paid.
//!
//! # What it does not do yet
//!
//! Talk to a network. [`Services`] is a trait, and the only implementation today
//! is the in-process one in `spark-cli`. `docs/protocol.md` §6 specifies WebSocket
//! over TLS, and `spark-transport` has the routing and the SOCKS5 but not the
//! framing. Stated rather than implied, as elsewhere: this crate's logic is
//! complete and exercised; its transport binding is the piece that is missing.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod services;

pub use services::{
    Auth, Class, ContentService, IssuerService, KeyringService, ServiceError, Services,
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use spark_chunk::{Chunk, ChunkName, LaneId, Slot, room, scrub};
use spark_crypto::{Mnemonic, Secret, blind::CryptoRng};
use spark_identity::Identity;
use spark_keyring::{
    ChunkClass, Delta, Generation, Keyring, Receipt, Room as KeyRoom, RoomId, Upload,
};
use spark_mls::{Room as MlsRoom, Signer, publish_key_package, signer_for};
use spark_sync::{Entry, Outbox, Payload, entry::Signed, total_order};
use std::collections::BTreeMap;

/// One message, as a reader sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    /// Who wrote it. Verified, not claimed.
    pub from: spark_crypto::VerifyingKey,
    /// The text.
    pub body: Vec<u8>,
    /// Which generation of the room it belongs to.
    pub generation: u64,
}

/// What went wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientError {
    /// A service refused or could not be reached.
    Service(ServiceError),
    /// The mnemonic is not a valid 24-word phrase.
    BadMnemonic,
    /// No such room in this account's keyring.
    NoSuchRoom,
    /// MLS refused the operation.
    Mls,
    /// The file cannot be sent because its metadata cannot be stripped.
    Unscrubbable,
    /// Quota is exhausted, or the service would not issue a token.
    NoQuota,
    /// Resume the journaled upload before starting a new send.
    PendingUpload,
    /// Local state is inconsistent with what came back.
    Corrupt,
}

impl From<ServiceError> for ClientError {
    fn from(e: ServiceError) -> Self {
        Self::Service(e)
    }
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Service(e) => write!(f, "{e}"),
            Self::BadMnemonic => f.write_str("that is not a valid 24-word recovery phrase"),
            Self::NoSuchRoom => f.write_str("no such room"),
            Self::Mls => f.write_str("the room refused that"),
            Self::Unscrubbable => {
                f.write_str("this file type may carry location data Spark cannot remove")
            }
            Self::NoQuota => f.write_str("not enough storage left"),
            Self::PendingUpload => f.write_str("retry the pending upload before sending again"),
            Self::Corrupt => f.write_str("local state does not match the server"),
        }
    }
}
impl core::error::Error for ClientError {}

/// An account, its rooms, and the services it talks to.
pub struct Client<S: Services> {
    identity: Identity,
    signer: Signer,
    provider: OpenMlsRustCrypto,
    keyring: Keyring,
    snapshot_version: (Option<[u8; 32]>, u32),
    pending_snapshot: Option<(Vec<u8>, Vec<[u8; 32]>)>,
    rooms: BTreeMap<RoomId, MlsRoom>,
    services: S,
    /// Decrypted history, per room.
    ///
    /// A running client holds the conversation it is showing; that is what a
    /// messenger is. It is plaintext in memory and is not zeroized — the room
    /// roots in the keyring are, because those unlock everything, but the messages
    /// on screen are the thing the user asked to see.
    history: BTreeMap<RoomId, Vec<Entry>>,
    scans: BTreeMap<(RoomId, u64, [u8; 16]), (u64, u64, u64)>,
}

impl<S: Services> Client<S> {
    /// Open an account from its recovery phrase.
    ///
    /// The same call whether the account is new or being restored: if a keyring
    /// exists at this address it is loaded, and if not an empty one is started.
    /// There is no separate "restore" path to get wrong, because there is nothing
    /// a restore does that opening does not.
    pub fn open(phrase: &str, services: S) -> Result<Self, ClientError> {
        let m = Mnemonic::parse(phrase).map_err(|_| ClientError::BadMnemonic)?;
        Self::from_mnemonic(&m, services)
    }

    /// As [`Client::open`], from an already-parsed mnemonic.
    pub fn from_mnemonic(m: &Mnemonic, services: S) -> Result<Self, ClientError> {
        let identity = Identity::from_mnemonic(m);
        let root = spark_crypto::extract(spark_identity::ROOT_SALT, m.to_seed().expose());
        let signer = signer_for(
            &identity,
            &spark_crypto::expand::<32>(&root, spark_identity::INFO_SIGN),
        );
        let provider = OpenMlsRustCrypto::default();
        signer
            .store(provider.storage())
            .map_err(|_| ClientError::Mls)?;

        let mut c = Self {
            identity,
            signer,
            provider,
            keyring: Keyring::new(),
            snapshot_version: (None, 0),
            pending_snapshot: None,
            rooms: BTreeMap::new(),
            services,
            history: BTreeMap::new(),
            scans: BTreeMap::new(),
        };
        c.load_keyring()?;
        c.load_mls()?;
        Ok(c)
    }

    /// The services this client talks to.
    ///
    /// Exposed so a caller can inspect what its transport actually did — the
    /// connection ledger, the per-class request counts. Claims about routing are
    /// claims about behaviour, and behaviour that cannot be observed cannot be
    /// tested.
    pub fn services(&self) -> &S {
        &self.services
    }

    /// This account's address, which is all any server ever sees of it.
    pub fn addr(&self) -> spark_identity::Addr {
        self.identity.addr()
    }

    /// This account's public identity, for someone else to reach.
    pub fn public(&self) -> spark_identity::PublicIdentity {
        self.identity.public()
    }

    /// The rooms this account is in.
    pub fn rooms(&self) -> Vec<(RoomId, String)> {
        self.keyring
            .rooms
            .iter()
            .map(|r| (r.id, r.display_name.clone()))
            .collect()
    }

    /// Bytes currently held, which is what quota measures.
    pub fn bytes_held(&self) -> u64 {
        self.keyring.bytes_held()
    }

    fn auth(&self) -> Auth<'_> {
        let addr = *self.identity.addr().as_bytes();
        Auth {
            signer: Some(&self.identity),
            addr,
            key: *self.identity.public().sign.as_bytes(),
            sig: *self
                .identity
                .sign(&self.services.keyring().challenge(&addr))
                .as_bytes(),
        }
    }

    fn load_keyring(&mut self) -> Result<(), ClientError> {
        let auth = self.auth();
        let Some(snap) = self.services.keyring().snapshot(&auth)? else {
            if !self.services.keyring().deltas(&auth)?.is_empty() {
                return Err(ClientError::Corrupt);
            }
            return Ok(()); // a new account
        };
        let snapshot_hash = spark_crypto::sha256(&snap);
        let snap = Chunk::from_bytes(snap).map_err(|_| ClientError::Corrupt)?;
        let deltas: Vec<Chunk> = self
            .services
            .keyring()
            .deltas(&auth)?
            .into_iter()
            .map(|b| Chunk::from_bytes(b).map_err(|_| ClientError::Corrupt))
            .collect::<Result<_, _>>()?;

        // A snapshot replaced between the two reads cannot be combined with its successor's deltas.
        if self
            .services
            .keyring()
            .snapshot(&auth)?
            .as_deref()
            .map(spark_crypto::sha256)
            != Some(snapshot_hash)
        {
            return Err(ClientError::Corrupt);
        }
        self.snapshot_version = (
            Some(snapshot_hash),
            deltas.len().try_into().map_err(|_| ClientError::Corrupt)?,
        );
        self.keyring = Keyring::restore(&snap, &deltas, self.identity.keyring_key())
            .map_err(|_| ClientError::Corrupt)?;
        Ok(())
    }

    /// Restore the MLS provider's storage, then reopen every room from it.
    ///
    /// This is what makes a recovered account able to *participate* rather than
    /// only read: without it the archive secrets come back but the member list
    /// does not, and a client that does not know who is in the room does not know
    /// which lanes to fetch.
    fn load_mls(&mut self) -> Result<(), ClientError> {
        let Some(blob) = self.keyring.mls_state.clone() else {
            return Ok(());
        };
        // Encoded here rather than through `MemoryStorage::serialize`, which is
        // behind the provider's `test-utils` feature. Production state should not
        // ride on a test-only API, and a `BTreeMap` gives a deterministic encoding
        // that a hand-rolled one would have to promise.
        let restored: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
            postcard::from_bytes(&blob).map_err(|_| ClientError::Corrupt)?;
        {
            let mut values = self
                .provider
                .storage()
                .values
                .write()
                .map_err(|_| ClientError::Corrupt)?;
            *values = restored.into_iter().collect();
        }
        for r in &self.keyring.rooms {
            let room = MlsRoom::load(&self.provider, &r.mls_group_id)
                .map_err(|_| ClientError::Corrupt)?
                .ok_or(ClientError::Corrupt)?;
            self.rooms.insert(r.id, room);
        }
        Ok(())
    }

    /// Persist the MLS provider's storage into the keyring.
    ///
    /// Called after anything that changes group state. Missing one leaves a
    /// recovered client unable to work out the room's membership.
    fn save_mls(&mut self) -> Result<(), ClientError> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| ClientError::Corrupt)?;
        let sorted: std::collections::BTreeMap<&Vec<u8>, &Vec<u8>> = values.iter().collect();
        let blob = postcard::to_allocvec(&sorted).map_err(|_| ClientError::Corrupt)?;
        drop(values);
        self.keyring.apply(&Delta::SetMlsState(blob));
        Ok(())
    }

    /// Write the whole keyring back, replacing any deltas.
    fn save_keyring<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), ClientError> {
        if let Some((bytes, permits)) = self.pending_snapshot.as_ref() {
            self.services.keyring().put_snapshot(
                &self.auth(),
                bytes,
                self.snapshot_version,
                permits,
            )?;
            self.snapshot_version = (Some(spark_crypto::sha256(bytes)), 0);
            self.pending_snapshot = None;
        }
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let chunk = self
            .keyring
            .seal_snapshot(self.identity.keyring_key(), &nonce);
        let permits: Vec<_> = self
            .keyring
            .contacts
            .iter()
            .map(|c| spark_crypto::sha256(&c.receive_permit))
            .collect();
        self.pending_snapshot = Some((chunk.as_bytes().to_vec(), permits.clone()));
        let auth = self.auth();
        self.services.keyring().put_snapshot(
            &auth,
            chunk.as_bytes(),
            self.snapshot_version,
            &permits,
        )?;
        self.snapshot_version = (Some(spark_crypto::sha256(chunk.as_bytes())), 0);
        self.pending_snapshot = None;
        Ok(())
    }

    /// The traffic class a chunk's requests belong to.
    ///
    /// Room history is text and goes over Tor in the default mode; media is bulk
    /// and goes direct. This is the one place the two are told apart, so it is
    /// worth reading next to `Spark-spec.md` D2's cost: a direct media fetch ties
    /// an IP to a content-derived chunk name, and therefore to identifiable
    /// content.
    fn traffic_class(c: ChunkClass) -> Class {
        match c {
            ChunkClass::RoomLog => Class::Text,
            ChunkClass::Media => Class::Media,
        }
    }

    /// Draw one storage token and spend it on a chunk.
    fn upload<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        name: ChunkName,
        chunk: &Chunk,
        class: ChunkClass,
        room: Option<RoomId>,
    ) -> Result<(), ClientError> {
        if self.keyring.pending_upload.is_some() {
            return Err(ClientError::PendingUpload);
        }
        let size_class = spark_tokens::class_for(chunk.len() as u64);
        let issuer = self.services.keyring().issuer_key(size_class)?;
        let pk = spark_crypto::IssuerPublic::from_der(&issuer).map_err(|_| ClientError::Corrupt)?;
        let mut serial = [0; 32];
        rng.fill_bytes(&mut serial);
        let claim = spark_crypto::TokenClaim { serial, size_class };
        let (_, blinding) = pk
            .blind(rng, &claim.encode())
            .map_err(|_| ClientError::Corrupt)?;
        self.keyring.pending_upload = Some(spark_keyring::model::PendingUpload {
            name: name.into(),
            chunk: chunk.as_bytes().to_vec(),
            class,
            room,
            claim,
            issuer,
            blinding: blinding.save(),
        });
        self.retry_pending_upload(rng)
    }

    /// Resume exactly the interrupted upload, including after seed recovery.
    /// Does nothing when no upload is pending. Never starts a new send.
    pub fn retry_pending_upload<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), ClientError> {
        let Some(pending) = self.keyring.pending_upload.clone() else {
            return Ok(());
        };
        self.save_keyring(rng)?;
        let pk = spark_crypto::IssuerPublic::from_der(&pending.issuer)
            .map_err(|_| ClientError::Corrupt)?;
        let sigs = self.services.keyring().withdraw(
            &self.auth(),
            &[pending.blinding.message().to_vec()],
            pending.claim.size_class,
        )?;
        if sigs.len() != 1 {
            return Err(ClientError::Corrupt);
        }
        let token = pk
            .finalize(
                pending.blinding.restore(),
                &sigs[0],
                &pending.claim.encode(),
            )
            .map_err(|_| ClientError::Corrupt)?;
        let receipt = self.services.content().put(
            Self::traffic_class(pending.class),
            &pending.name.0,
            &pending.chunk,
            pending.claim,
            &token,
        )?;
        self.keyring.apply(&Delta::AddUpload(Upload {
            name: pending.name,
            receipt: Receipt(receipt),
            size: 1u64 << pending.claim.size_class,
            class: pending.class,
            room: pending.room,
        }));
        self.keyring.pending_upload = None;
        self.save_keyring(rng)
    }
}

impl<S: Services> Client<S> {
    /// Create a room. This account is its first and only owner.
    pub fn create_room<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        name: &str,
    ) -> Result<RoomId, ClientError> {
        let mls = MlsRoom::create(&self.provider, &self.identity.public().sign, &self.signer)
            .map_err(|_| ClientError::Mls)?;

        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let id = RoomId(id);

        self.keyring.apply(&Delta::UpsertRoom(KeyRoom {
            id,
            generations: vec![],
            mls_group_id: Vec::new(),
            display_name: name.to_string(),
            my_lane: LaneId::message(&self.identity.public().sign).into(),
        }));
        self.open_generation(id, &mls)?;
        let gid = mls.group_id();
        self.rooms.insert(id, mls);
        if let Some(r) = self.keyring.rooms.iter_mut().find(|r| r.id == id) {
            r.mls_group_id = gid;
        }
        self.save_mls()?;
        self.save_keyring(rng)?;
        Ok(id)
    }

    /// Record the current generation's archive secret.
    ///
    /// Called on creation and after every membership change, because that is when
    /// the MLS exporter secret rotates. Missing one loses that stretch of history
    /// permanently — it cannot be re-derived afterwards.
    fn open_generation(&mut self, id: RoomId, mls: &MlsRoom) -> Result<(), ClientError> {
        let root = mls.root(&self.provider).map_err(|_| ClientError::Mls)?;
        self.keyring.apply(&Delta::OpenGeneration {
            room: id,
            generation: Generation {
                epoch: mls.generation(),
                root,
                my_next: 0,
                members: mls.members().iter().map(|k| *k.as_bytes()).collect(),
            },
        });
        Ok(())
    }

    /// Publish a key package so an owner can add this account to a room.
    pub fn key_package(&self) -> Result<Vec<u8>, ClientError> {
        publish_key_package(&self.provider, &self.identity.public().sign, &self.signer)
            .map_err(|_| ClientError::Mls)
    }

    /// Publish a key package and save its private join state before returning.
    /// This lets a separate process accept the resulting invitation later.
    pub fn saved_key_package<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<u8>, ClientError> {
        let package = self.key_package()?;
        self.save_mls()?;
        self.save_keyring(rng)?;
        Ok(package)
    }

    /// Add someone to a room, given their key package. Owners only.
    ///
    /// Returns the welcome to hand them, and the past generation roots they will
    /// need. Those roots are the out-of-band re-share `Spark-spec.md` F4 flags as
    /// sitting outside MLS's guarantees — a joiner derives the *current*
    /// generation for themselves, and can derive no earlier one.
    pub fn invite<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        id: RoomId,
        key_package_bytes: &[u8],
    ) -> Result<Invitation, ClientError> {
        let mls = self.rooms.get_mut(&id).ok_or(ClientError::NoSuchRoom)?;
        let commit = mls
            .add_member_bytes(&self.provider, &self.signer, key_package_bytes)
            .map_err(|_| ClientError::Mls)?;
        let welcome = commit.welcome.clone().ok_or(ClientError::Mls)?;

        let m = self.rooms.get(&id).expect("present");
        let root = m.root(&self.provider).map_err(|_| ClientError::Mls)?;
        let epoch = m.generation();
        self.keyring.apply(&Delta::OpenGeneration {
            room: id,
            generation: Generation {
                epoch,
                root,
                my_next: 0,
                members: m.members().iter().map(|k| *k.as_bytes()).collect(),
            },
        });

        let past = self
            .keyring
            .room(id)
            .ok_or(ClientError::NoSuchRoom)?
            .generations
            .iter()
            .map(|g| (g.epoch, *g.root.expose(), g.members.clone()))
            .collect();

        self.save_mls()?;
        self.save_keyring(rng)?;
        Ok(Invitation {
            welcome,
            generations: past,
            room: id,
        })
    }

    /// Accept an invitation.
    pub fn accept<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        inv: &Invitation,
        name: &str,
    ) -> Result<RoomId, ClientError> {
        let mls = MlsRoom::join(&self.provider, &inv.welcome).map_err(|_| ClientError::Mls)?;
        self.keyring.apply(&Delta::UpsertRoom(KeyRoom {
            id: inv.room,
            generations: vec![],
            mls_group_id: Vec::new(),
            display_name: name.to_string(),
            my_lane: LaneId::message(&self.identity.public().sign).into(),
        }));
        // The re-shared past, then the current generation this account can derive
        // for itself.
        for (epoch, root, members) in &inv.generations {
            if *epoch >= mls.generation() {
                continue;
            }
            self.keyring.apply(&Delta::OpenGeneration {
                room: inv.room,
                generation: Generation {
                    epoch: *epoch,
                    root: Secret::new(*root),
                    my_next: 0,
                    members: members.clone(),
                },
            });
        }
        self.open_generation(inv.room, &mls)?;
        let gid = mls.group_id();
        self.rooms.insert(inv.room, mls);
        if let Some(r) = self.keyring.rooms.iter_mut().find(|r| r.id == inv.room) {
            r.mls_group_id = gid;
        }
        self.save_mls()?;
        self.save_keyring(rng)?;
        Ok(inv.room)
    }

    /// Say something.
    ///
    /// The message is sealed under the room's current archive secret and uploaded
    /// as a chunk. Delivery is the recipients reading it (decision D-A), so there
    /// is no send-to-N step here and no fan-out for a server to correlate.
    pub fn send<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        id: RoomId,
        body: &[u8],
    ) -> Result<(), ClientError> {
        if self.keyring.pending_upload.is_some() {
            return Err(ClientError::PendingUpload);
        }
        let mls = self.rooms.get(&id).ok_or(ClientError::NoSuchRoom)?;
        let epoch = mls.generation();
        let lane = LaneId::message(&self.identity.public().sign);

        // The write cursor, not the read cursor. Resuming from what has been
        // *read* would make this client overwrite its own last message.
        let mut outbox = Outbox::new(id, epoch, lane, self.keyring.my_next(id, epoch));

        if outbox.next_seq() == u64::MAX {
            return Err(ClientError::Corrupt);
        }
        // Reserve before sealing so ordinary crash recovery skips consumed slots.
        // Random nonces keep stale/concurrent cursors from reusing the keystream.
        let (reservation, delta) = outbox.reserve();
        self.keyring.apply(&delta);

        let slot = reservation.consume();
        // What this client had seen when it wrote. That is what makes a reply
        // causally later than the message it replies to.
        let mut clock = spark_sync::Clock::new();
        for e in self.history.get(&id).into_iter().flatten() {
            if e.epoch == epoch {
                clock.observe(e.lane(), e.seq);
            }
        }
        let root = self.generation_root(id, epoch)?;
        let signed = Signed::new(
            &room::signature_context(
                &self
                    .keyring
                    .room(id)
                    .ok_or(ClientError::NoSuchRoom)?
                    .mls_group_id,
                &root,
            ),
            &clock,
            slot,
            epoch,
            body.to_vec(),
            &self.identity.public().sign,
            |m| self.identity.sign(m),
        );
        let entry = Entry::new(slot, epoch, clock, Payload::Application(signed));

        let mut nonce = [0; 24];
        rng.fill_bytes(&mut nonce);
        let (name, chunk) = room::seal(&root, slot, &nonce, &entry.encode());
        self.upload(rng, name, &chunk, ChunkClass::RoomLog, Some(id))?;
        self.save_keyring(rng)?;
        Ok(())
    }

    fn generation_root(&self, id: RoomId, epoch: u64) -> Result<room::RoomRoot, ClientError> {
        self.keyring
            .room(id)
            .ok_or(ClientError::NoSuchRoom)?
            .generations
            .iter()
            .find(|g| g.epoch == epoch)
            .map(|g| g.root.clone())
            .ok_or(ClientError::Corrupt)
    }

    fn fetch_entry(
        &self,
        id: RoomId,
        epoch: u64,
        root: &room::RoomRoot,
        slot: Slot,
    ) -> Result<Option<Entry>, ClientError> {
        let name = room::name(root, slot);
        let Some(bytes) = self.services.content().get(Class::Text, name.as_bytes())? else {
            return Ok(None);
        };
        let chunk = Chunk::from_bytes(bytes).map_err(|_| ClientError::Corrupt)?;
        let plain = room::open(root, slot, &chunk).map_err(|_| ClientError::Corrupt)?;
        let e = Entry::decode(&plain, slot).map_err(|_| ClientError::Corrupt)?;
        if e.epoch != epoch {
            return Err(ClientError::Corrupt);
        }
        let Payload::Application(ref signed) = e.payload else {
            return Err(ClientError::Corrupt);
        };
        let r = self.keyring.room(id).ok_or(ClientError::NoSuchRoom)?;
        let generation = r
            .generations
            .iter()
            .find(|g| g.epoch == epoch)
            .ok_or(ClientError::Corrupt)?;
        // Clocks are attacker-controlled claims. Unknown lanes cannot create
        // ordering work or masquerade as membership observations.
        if e.clock.len() > generation.members.len() {
            return Err(ClientError::Corrupt);
        }
        let lanes: std::collections::BTreeSet<_> = generation
            .members
            .iter()
            .map(|key| spark_crypto::VerifyingKey::from_bytes(key).map(|k| LaneId::message(&k)))
            .collect::<Result<_, _>>()
            .map_err(|_| ClientError::Corrupt)?;
        if e.clock.lanes().any(|lane| !lanes.contains(&lane)) {
            return Err(ClientError::Corrupt);
        }
        let from = signed
            .verify(
                &room::signature_context(&r.mls_group_id, root),
                &e.clock,
                slot,
                epoch,
            )
            .map_err(|_| ClientError::Corrupt)?;
        if !r
            .generations
            .iter()
            .find(|g| g.epoch == epoch)
            .ok_or(ClientError::Corrupt)?
            .members
            .contains(from.as_bytes())
        {
            return Err(ClientError::Corrupt);
        }
        Ok(Some(e))
    }

    /// Fetch whatever is new and return the room's history in order.
    ///
    /// Returns the *whole* conversation, not only what this call retrieved.
    ///
    /// Requests go out one chunk name at a time. Batching them would tell the
    /// store that those names belong together, which is the correlation decision
    /// D-A exists to avoid, reintroduced one layer down.
    /// Takes no entropy: syncing writes nothing to the keyring. The read cursor
    /// lives in memory precisely so that reading does not have to persist.
    pub fn sync(&mut self, id: RoomId, probe_ahead: u64) -> Result<Vec<Message>, ClientError> {
        let room_gens: Vec<(u64, room::RoomRoot, Vec<LaneId>)> = {
            let r = self.keyring.room(id).ok_or(ClientError::NoSuchRoom)?;
            r.generations
                .iter()
                .map(|g| {
                    (
                        g.epoch,
                        g.root.clone(),
                        g.members
                            .iter()
                            .filter_map(|b| spark_crypto::VerifyingKey::from_bytes(b).ok())
                            .map(|k| LaneId::message(&k))
                            .collect(),
                    )
                })
                .collect()
        };

        // Scan cursors are disposable, like plaintext history. Continue through long
        // gaps on later calls, and revisit holes so temporary withholding is not final.
        let known: std::collections::BTreeSet<(u64, [u8; 16], u64)> = self
            .history
            .get(&id)
            .into_iter()
            .flatten()
            .map(|e| (e.epoch, e.lane, e.seq))
            .collect();
        let mut fetched = Vec::new();
        for (epoch, root, lanes) in room_gens {
            for lane in lanes {
                let scan_key = (id, epoch, *lane.as_bytes());
                let (start, mut backfill, mut sweep_end) =
                    self.scans.get(&scan_key).copied().unwrap_or((0, 0, 0));
                let mut next = start;
                let mut misses = 0;
                for _ in 0..256 {
                    let slot = Slot::new(lane, next);
                    let Some(after) = next.checked_add(1) else {
                        break;
                    };
                    next = after;
                    match self.fetch_entry(id, epoch, &root, slot) {
                        Ok(Some(e)) => {
                            misses = 0;
                            if !known.contains(&(epoch, e.lane, e.seq)) {
                                fetched.push(e);
                            }
                        }
                        Ok(None) | Err(ClientError::Corrupt) => misses += 1,
                        Err(e) => return Err(e),
                    }
                    if misses >= probe_ahead.clamp(1, 256) {
                        break;
                    }
                }
                // A separate rotating budget repairs earlier temporary holes.
                for _ in 0..256 {
                    if backfill >= sweep_end {
                        backfill = 0;
                        sweep_end = next;
                        break;
                    }
                    let slot = Slot::new(lane, backfill);
                    backfill += 1;
                    if known.contains(&(epoch, *lane.as_bytes(), slot.seq)) {
                        continue;
                    }
                    match self.fetch_entry(id, epoch, &root, slot) {
                        Ok(Some(e)) => fetched.push(e),
                        Ok(None) | Err(ClientError::Corrupt) => {}
                        Err(e) => return Err(e),
                    }
                }
                self.scans.insert(scan_key, (next, backfill, sweep_end));
            }
        }

        self.history.entry(id).or_default().extend(fetched);

        // The whole conversation, not just what this call fetched. A caller asking
        // for a room's messages wants the room's messages.
        let all = self.history.get(&id).cloned().unwrap_or_default();
        Ok(total_order(all)
            .into_iter()
            .filter_map(|e| match &e.payload {
                // Authorship is verified here, not assumed. An entry whose
                // signature does not check is dropped rather than shown: it is
                // not a message from anyone.
                Payload::Application(s) => Some(Message {
                    from: spark_crypto::VerifyingKey::from_bytes(&s.sender)
                        .expect("verified on ingress"),
                    body: s.body.clone(),
                    generation: e.epoch,
                }),
                _ => None,
            })
            .collect())
    }

    /// Contacts approved by this account, restored with the encrypted keyring.
    pub fn contacts(&self) -> &[spark_keyring::model::Contact] {
        &self.keyring.contacts
    }

    /// Add/update an approved contact and return our confidential reply card.
    /// A card is 64 public identity bytes followed by a 32-byte inbox permit.
    pub fn add_contact<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        name: &str,
        identity: &[u8; 64],
        permit: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, ClientError> {
        if name.trim().is_empty() || name.len() > 256 {
            return Err(ClientError::Corrupt);
        }
        let sign: [u8; 32] = identity[..32].try_into().unwrap();
        spark_crypto::VerifyingKey::from_bytes(&sign).map_err(|_| ClientError::Corrupt)?;
        let kem = identity[32..].try_into().unwrap();
        let mut next = self.keyring.contacts.clone();
        let receive_permit = if let Some(c) = next.iter_mut().find(|c| c.sign == sign) {
            if c.kem != kem {
                return Err(ClientError::Corrupt);
            }
            c.name = name.to_owned();
            if permit.is_some() {
                c.send_permit = permit;
            }
            c.receive_permit
        } else {
            if next.len() >= 64 {
                return Err(ClientError::Corrupt);
            }
            let mut receive_permit = [0; 32];
            rng.fill_bytes(&mut receive_permit);
            next.push(spark_keyring::model::Contact {
                name: name.into(),
                sign,
                kem,
                receive_permit,
                send_permit: permit,
            });
            receive_permit
        };
        self.keyring.contacts = next;
        self.save_keyring(rng)?;
        let me = self.identity.public();
        Ok([
            me.sign.as_bytes().as_slice(),
            me.kem.as_bytes(),
            &receive_permit,
        ]
        .concat())
    }

    /// Revoke a contact's inbox access.
    pub fn remove_contact<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        sign: &[u8; 32],
    ) -> Result<(), ClientError> {
        self.keyring.contacts.retain(|c| &c.sign != sign);
        self.save_keyring(rng)
    }

    /// Send a signed, sealed note using a contact's explicit inbox permission.
    pub fn contact_note<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        sign: &[u8; 32],
        note: &str,
    ) -> Result<(), ClientError> {
        let contact = self
            .keyring
            .contacts
            .iter()
            .find(|c| &c.sign == sign)
            .ok_or(ClientError::Corrupt)?;
        let permit = contact.send_permit.ok_or(ClientError::Corrupt)?;
        if note.len() > 8 * 1024 {
            return Err(ClientError::Corrupt);
        }
        let mut ephemeral = [0; 32];
        rng.fill_bytes(&mut ephemeral);
        let recipient = spark_identity::PublicIdentity {
            sign: spark_crypto::VerifyingKey::from_bytes(sign).map_err(|_| ClientError::Corrupt)?,
            kem: spark_crypto::KemPublic::from_bytes(contact.kem),
        };
        let sealed = spark_identity::reach::seal_request(
            &recipient.kem,
            &self.identity,
            note,
            None,
            Secret::new(ephemeral),
        );
        self.services.keyring().put_request(
            recipient.addr().as_bytes(),
            sealed.as_bytes(),
            &permit,
        )?;
        Ok(())
    }

    /// Open only authenticated notes from user-approved contacts.
    pub fn contact_inbox(&self) -> Result<Vec<spark_identity::reach::OpenRequest>, ClientError> {
        let auth = self.auth();
        let mut out = Vec::new();
        for (index, bytes) in self.services.keyring().requests(&auth)? {
            if let Ok(note) = spark_identity::reach::open_request(
                &self.identity,
                &spark_identity::reach::SealedRequest::from_bytes(bytes),
                None,
            ) && self.keyring.contacts.get(index as usize).is_some_and(|c| {
                c.sign == *note.from.sign.as_bytes() && c.kem == *note.from.kem.as_bytes()
            }) {
                out.push(note);
            }
            self.services.keyring().drop_request(&auth, index)?;
        }
        Ok(out)
    }

    /// Share a file. Its metadata is stripped first, and it is refused outright if
    /// that cannot be done.
    pub fn share_file<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        id: RoomId,
        bytes: &[u8],
    ) -> Result<(ChunkName, Secret<32>), ClientError> {
        let clean = scrub::scrub(bytes).map_err(|_| ClientError::Unscrubbable)?;
        let (name, key, chunk) = spark_chunk::media::seal(&clean);
        self.upload(rng, name, &chunk, ChunkClass::Media, Some(id))?;
        self.save_keyring(rng)?;
        Ok((name, key))
    }

    /// Release an upload and redeem its blind refund without linking the receipt to this account.
    pub fn release_upload<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        name: ChunkName,
    ) -> Result<(), ClientError> {
        let upload = self
            .keyring
            .uploads
            .iter()
            .find(|u| u.name.0 == *name.as_bytes())
            .cloned()
            .ok_or(ClientError::Corrupt)?;
        let size_class = spark_tokens::class_for(upload.size);
        let class = Self::traffic_class(upload.class);
        let pending = match self
            .keyring
            .refunds
            .iter()
            .find(|r| r.receipt == upload.receipt)
        {
            Some(pending) => pending.clone(),
            None => {
                let issuer = self.services.content().refund_key(class, size_class)?;
                let pk = spark_crypto::IssuerPublic::from_der(&issuer)
                    .map_err(|_| ClientError::Corrupt)?;
                let mut serial = [0; 32];
                rng.fill_bytes(&mut serial);
                let claim = spark_crypto::TokenClaim { serial, size_class };
                let (_, blinding) = pk
                    .blind(rng, &claim.refund_message())
                    .map_err(|_| ClientError::Corrupt)?;
                let pending = spark_keyring::model::PendingRefund {
                    receipt: upload.receipt,
                    claim,
                    issuer,
                    blinding: blinding.save(),
                };
                self.keyring.refunds.push(pending.clone());
                pending
            }
        };
        // Every attempt persists first, including retry after an ambiguous save.
        self.save_keyring(rng)?;
        let pk = spark_crypto::IssuerPublic::from_der(&pending.issuer)
            .map_err(|_| ClientError::Corrupt)?;
        let claim = pending.claim;
        let message = claim.refund_message();
        let blinded = pending.blinding.message();
        let sig = self.services.content().release(
            class,
            name.as_bytes(),
            &upload.receipt.0,
            size_class,
            &blinded,
        )?;
        let token = pk
            .finalize(pending.blinding.restore(), &sig, &message)
            .map_err(|_| ClientError::Corrupt)?;
        self.services
            .keyring()
            .credit_refund(&self.auth(), claim, &token)?;
        self.keyring.apply(&Delta::ReleaseUpload(upload.receipt));
        self.save_keyring(rng)
    }

    /// Fetch a shared file by its capability.
    pub fn fetch_file(&self, name: ChunkName, key: &Secret<32>) -> Result<Vec<u8>, ClientError> {
        let bytes = self
            .services
            .content()
            .get(Class::Media, name.as_bytes())?
            .ok_or(ClientError::Service(ServiceError::NotFound))?;
        let chunk = Chunk::from_bytes(bytes).map_err(|_| ClientError::Corrupt)?;
        if chunk.kind().map_err(|_| ClientError::Corrupt)? != spark_chunk::Kind::Media
            || spark_chunk::media::name_of(&chunk) != name
        {
            return Err(ClientError::Corrupt);
        }
        Ok(spark_chunk::media::open(&chunk, key)
            .map_err(|_| ClientError::Corrupt)?
            .to_vec())
    }
}

impl<S: Services> core::fmt::Debug for Client<S> {
    /// Shape only. A client holds an identity, every room root this account has,
    /// and the decrypted conversation; a derived `Debug` would print all of it
    /// into whatever log called it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("addr", &self.identity.addr().to_hex())
            .field("rooms", &self.keyring.rooms.len())
            .field("bytes_held", &self.keyring.bytes_held())
            .finish_non_exhaustive()
    }
}

/// What an owner hands a joiner.
///
/// The past generation roots are the out-of-band re-share `Spark-spec.md` F4
/// flags as sitting outside MLS's guarantees. They are here, in one field, rather
/// than spread through the protocol.
///
/// # On serializing it
///
/// The derives exist because an invitation has to reach a joiner who is not in
/// this process — over the FFI to a mobile app, and from there by whatever channel
/// two people already trust. The encoded bytes are **not** public: they carry
/// every past generation root, which is the archive key for the room's whole
/// history. `Debug` redacts them for exactly that reason and continues to; a
/// serializer cannot, because the joiner needs them. Anything that moves this blob
/// is responsible for confidentiality, and `Spark-spec.md` F4 is where that being
/// out-of-band is accounted for.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Invitation {
    /// The MLS welcome.
    pub welcome: Vec<u8>,
    /// Every generation the joiner cannot derive for itself: `(epoch, root)`.
    pub generations: Vec<(u64, [u8; 32], Vec<[u8; 32]>)>,
    /// Which room.
    pub room: RoomId,
}

impl core::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The generation roots are archive secrets for the room's whole history.
        write!(
            f,
            "Invitation({} bytes, {} generations redacted)",
            self.welcome.len(),
            self.generations.len()
        )
    }
}
