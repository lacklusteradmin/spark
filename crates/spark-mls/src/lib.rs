//! OpenMLS wrapper: group state, commits, flat owner set.
//!
//! layer 2, zone `pure` — see `docs/layering.toml`.
//!
//! Below the I/O line: no network, no filesystem, no clock. Everything here is
//! testable with no server in existence — gate 4 runs two clients in one process.
//!
//! Build-notes §3: **do not implement MLS**. This crate implements the *policy*
//! that sits on top of it — who may add, remove, appoint, dismiss, leave, and
//! dissolve — and nothing cryptographic. `Spark-spec.md` F4 is the whole
//! specification for that policy, and it is short:
//!
//! * Owners are a flat set. No hierarchy, no second role.
//! * Owners add and remove members, and appoint and dismiss owners.
//! * An owner may leave only once another exists.
//! * The last owner may dissolve the room instead.
//! * **A 1:1 is a room of two owners**, on the same code path. Build-notes §4:
//!   "Do not implement a separate 1:1 code path."
//!
//! The MLS provider — entropy, crypto backend, storage — arrives as a parameter.
//! That is what keeps this crate `pure`, and it is the same discipline as
//! `Mnemonic::from_entropy`: the entropy source for something unrecoverable is
//! named at the call site.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod owners;

pub use owners::{OWNERS_EXT, OwnerSet, OwnerSetError};

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
/// One generation of a room's archive secret.
///
/// Structurally identical to `spark_chunk::RoomRoot`; not shared as a type
/// because spark-chunk sits at the same layer.
pub type RoomRoot = spark_crypto::Secret<32>;

/// MLS exporter label for the archive secret.
pub const ROOT_LABEL: &str = "spark/v1/room-root";
use spark_crypto::VerifyingKey;
use spark_identity::Identity;

/// The cipher suite, fixed by `Spark-build-notes.md` §3.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Re-export so callers do not need a direct openmls dependency for the signer.
pub type Signer = SignatureKeyPair;

/// Build the MLS signer from a Spark identity.
///
/// The MLS signature key **is** the identity key. A leaf is therefore provably
/// the Spark identity it claims, and `LaneId::message(sign_pub)` names the same
/// key that signed the commit — one identity, not two that have to be kept in
/// step.
pub fn signer_for(id: &Identity, secret: &spark_crypto::Secret<32>) -> Signer {
    SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        secret.expose().to_vec(),
        id.public().sign.as_bytes().to_vec(),
    )
}

fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(OWNERS_EXT)]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

fn credential(k: &VerifyingKey, signer: &Signer) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(k.as_bytes().to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

/// Publish a key package, serialized, so an owner can add this identity to a room.
///
/// Bytes rather than an OpenMLS type, so callers above this crate never need
/// openmls in their own dependency list. Build-notes §3 says not to implement
/// MLS; keeping its types out of the API is how that stays true of the callers
/// too.
pub fn publish_key_package<P: OpenMlsProvider>(
    provider: &P,
    me: &VerifyingKey,
    signer: &Signer,
) -> Result<Vec<u8>, RoomError> {
    // Wrapped in MlsMessageOut, not serialized bare: the reader deserializes an
    // MlsMessageIn, and the two framings must match or the package will not parse.
    ser(&MlsMessageOut::from(
        key_package(provider, me, signer)?.key_package().clone(),
    ))
}

/// Publish a key package so an owner can add this identity to a room.
pub fn key_package<P: OpenMlsProvider>(
    provider: &P,
    me: &VerifyingKey,
    signer: &Signer,
) -> Result<KeyPackageBundle, RoomError> {
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .build(CIPHERSUITE, provider, signer, credential(me, signer))
        .map_err(|_| RoomError::Mls)
}

/// A room: one MLS group, one owner set, one room root.
pub struct Room {
    group: MlsGroup,
}

/// What an operation produced, ready for the commit lane.
///
/// `Debug` reports sizes only. A welcome carries the joiner's path secrets, and a
/// commit carries group state; neither belongs in a log.
pub struct Commit {
    /// The serialized MLS commit, for the commit lane.
    pub commit: Vec<u8>,
    /// A serialized welcome, when the operation added someone.
    pub welcome: Option<Vec<u8>>,
}

/// What processing an inbound message yielded.
#[derive(Debug)]
pub enum Event {
    /// An application message, already decrypted.
    Message(Vec<u8>),
    /// A commit was applied. The owner set after it is attached, because a commit
    /// may have changed it and every caller wants to know.
    Applied(OwnerSet),
    /// A proposal was queued. Nothing has changed yet; an owner must commit it.
    Proposed,
}

impl Room {
    /// Create a room. The creator is its first and only owner.
    pub fn create<P: OpenMlsProvider>(
        provider: &P,
        me: &VerifyingKey,
        signer: &Signer,
    ) -> Result<Self, RoomError> {
        let group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .with_capabilities(capabilities())
            .with_group_context_extensions(OwnerSet::founder(me).extensions())
            .build(provider, signer, credential(me, signer))
            .map_err(|_| RoomError::Mls)?;
        Ok(Self { group })
    }

    /// Join from a welcome.
    ///
    /// The joiner can derive the *current* generation's root immediately, because
    /// it comes from the MLS exporter and they are now in the group. Earlier
    /// generations they cannot derive at all — that is MLS forward secrecy — so an
    /// existing member re-shares the past roots out of band. That re-share is the
    /// mechanism `Spark-spec.md` F4 flags as sitting outside MLS's guarantees, and
    /// it is now exactly one list of 32-byte values.
    pub fn join<P: OpenMlsProvider>(provider: &P, welcome: &[u8]) -> Result<Self, RoomError> {
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(welcome).map_err(|_| RoomError::Mls)?;
        let w = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(RoomError::NotAWelcome),
        };
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = StagedWelcome::new_from_welcome(provider, &cfg, w, None)
            .map_err(|_| RoomError::Mls)?
            .into_group(provider)
            .map_err(|_| RoomError::Mls)?;
        OwnerSet::from_group(&group)?;
        Ok(Self { group })
    }

    /// The archive secret for the room's **current** generation.
    ///
    /// Derived from the MLS exporter, so it changes at every epoch — and every
    /// membership change is a commit, which is an epoch. That is what makes
    /// removal actually remove read access: a member who never reaches epoch n+1
    /// cannot derive generation n+1's root, so the names of chunks written after
    /// they left are not merely unreadable to them but uncomputable.
    ///
    /// It also removes a distribution problem. A randomly generated root would
    /// have to be sent to every member and re-sent on every rotation; an exporter
    /// secret is derived independently by everyone who is in the group.
    pub fn root<P: OpenMlsProvider>(&self, provider: &P) -> Result<RoomRoot, RoomError> {
        let b = self
            .group
            .export_secret(provider.crypto(), ROOT_LABEL, &[], 32)
            .map_err(|_| RoomError::Mls)?;
        let a: [u8; 32] = b.as_slice().try_into().map_err(|_| RoomError::Mls)?;
        Ok(spark_crypto::Secret::new(a))
    }

    /// Which MLS group this room is, for reloading it from storage.
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Reload a room from a provider whose storage has been restored.
    ///
    /// The counterpart to persisting the provider's storage. Without it a
    /// recovered account holds every archive secret but does not know who is in
    /// the room — and therefore which lanes to read.
    pub fn load<P: OpenMlsProvider>(
        provider: &P,
        group_id: &[u8],
    ) -> Result<Option<Self>, RoomError> {
        MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
            .map_err(|_| RoomError::Mls)
            .map(|o| o.map(|group| Self { group }))
    }

    /// The generation number, which is the MLS epoch.
    pub fn generation(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The current owner set, read from the group context.
    pub fn owners(&self) -> Result<OwnerSet, RoomError> {
        Ok(OwnerSet::from_group(&self.group)?)
    }

    /// Every member's identity key.
    pub fn members(&self) -> Vec<VerifyingKey> {
        self.group
            .members()
            .filter_map(|m| {
                let b: [u8; 32] = m.credential.serialized_content().try_into().ok()?;
                VerifyingKey::from_bytes(&b).ok()
            })
            .collect()
    }

    /// This client's own identity key.
    pub fn me(&self) -> Result<VerifyingKey, RoomError> {
        let b: [u8; 32] = self
            .group
            .own_leaf_node()
            .ok_or(RoomError::Mls)?
            .credential()
            .serialized_content()
            .try_into()
            .map_err(|_| RoomError::Mls)?;
        VerifyingKey::from_bytes(&b).map_err(|_| RoomError::Mls)
    }

    /// The MLS epoch, which orders commits.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    fn require_owner(&self) -> Result<(), RoomError> {
        let me = self.me()?;
        if self.owners()?.contains(&me) {
            Ok(())
        } else {
            Err(RoomError::NotAnOwner)
        }
    }

    fn leaf_of(&self, who: &VerifyingKey) -> Result<LeafNodeIndex, RoomError> {
        self.group
            .members()
            .find(|m| m.credential.serialized_content() == who.as_bytes())
            .map(|m| m.index)
            .ok_or(RoomError::NotAMember)
    }

    /// Add a member from a serialized key package. Owners only.
    pub fn add_member_bytes<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        key_package: &[u8],
    ) -> Result<Commit, RoomError> {
        let kp = match MlsMessageIn::tls_deserialize_exact_bytes(key_package)
            .map_err(|_| RoomError::Mls)?
            .extract()
        {
            MlsMessageBodyIn::KeyPackage(kp) => kp,
            _ => return Err(RoomError::Mls),
        };
        // Validated, not merely parsed: this checks the package's own signature
        // and lifetime before it ever reaches the group. Deserializing without
        // validating would let a malformed package through to the add path.
        let kp = kp
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| RoomError::Mls)?;
        self.add_member(provider, signer, &kp)
    }

    /// Add a member. Owners only.
    pub fn add_member<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        kp: &KeyPackage,
    ) -> Result<Commit, RoomError> {
        self.require_owner()?;
        let (commit, welcome, _) = self
            .group
            .add_members(provider, signer, core::slice::from_ref(kp))
            .map_err(|_| RoomError::Mls)?;
        self.group
            .merge_pending_commit(provider)
            .map_err(|_| RoomError::Mls)?;
        Ok(Commit {
            commit: ser(&commit)?,
            welcome: Some(ser(&welcome)?),
        })
    }

    /// Remove a member. Owners only.
    ///
    /// Removing an owner also drops them from the owner set, in the same commit.
    /// Two commits would leave a window in which a removed member is still listed
    /// as an owner, and MLS gives no way to make two commits atomic.
    pub fn remove_member<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        who: &VerifyingKey,
    ) -> Result<Commit, RoomError> {
        self.require_owner()?;
        let owners = self.owners()?;
        if owners.contains(who) && owners.len() == 1 {
            return Err(RoomError::LastOwner);
        }
        let leaf = self.leaf_of(who)?;
        let (commit, _, _) = self
            .group
            .remove_members(provider, signer, &[leaf])
            .map_err(|_| RoomError::Mls)?;
        self.group
            .merge_pending_commit(provider)
            .map_err(|_| RoomError::Mls)?;
        if owners.contains(who) {
            let c = self.set_owners(provider, signer, &owners.without(who))?;
            return Ok(Commit {
                commit: c.commit,
                welcome: None,
            });
        }
        Ok(Commit {
            commit: ser(&commit)?,
            welcome: None,
        })
    }

    fn set_owners<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        next: &OwnerSet,
    ) -> Result<Commit, RoomError> {
        let (commit, _, _) = self
            .group
            .update_group_context_extensions(provider, next.extensions(), signer)
            .map_err(|_| RoomError::Mls)?;
        self.group
            .merge_pending_commit(provider)
            .map_err(|_| RoomError::Mls)?;
        Ok(Commit {
            commit: ser(&commit)?,
            welcome: None,
        })
    }

    /// Appoint another member as an owner. Owners only.
    pub fn appoint_owner<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        who: &VerifyingKey,
    ) -> Result<Commit, RoomError> {
        self.require_owner()?;
        self.leaf_of(who)?;
        let next = self.owners()?.with(who);
        self.set_owners(provider, signer, &next)
    }

    /// Dismiss an owner, who stays a member. Owners only.
    ///
    /// The last owner cannot be dismissed, including by themselves: F4 gives no
    /// takeover mechanism for a room whose owners have all gone.
    pub fn dismiss_owner<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        who: &VerifyingKey,
    ) -> Result<Commit, RoomError> {
        self.require_owner()?;
        let owners = self.owners()?;
        if !owners.contains(who) {
            return Err(RoomError::NotAnOwner);
        }
        if owners.len() == 1 {
            return Err(RoomError::LastOwner);
        }
        let next = owners.without(who);
        self.set_owners(provider, signer, &next)
    }

    /// Propose to leave the room.
    ///
    /// F4: "An owner may leave only once another exists." A non-owner may always
    /// propose to go; the last owner gets [`RoomError::LastOwner`] and must
    /// dissolve instead.
    ///
    /// **This returns a proposal, not a commit.** MLS does not let a member
    /// commit their own removal — someone else has to. So leaving is two steps,
    /// and a departure is not final until an owner calls
    /// [`Room::commit_pending`]. The consequence is worth stating plainly because
    /// it is not obvious: a member cannot unilaterally leave a room whose owners
    /// have stopped responding. F4 provides no takeover mechanism for that, and
    /// this crate does not invent one.
    pub fn leave<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
    ) -> Result<Vec<u8>, RoomError> {
        let me = self.me()?;
        let owners = self.owners()?;
        if owners.contains(&me) && owners.len() == 1 {
            return Err(RoomError::LastOwner);
        }
        ser(&self
            .group
            .leave_group(provider, signer)
            .map_err(|_| RoomError::Mls)?)
    }

    /// Commit whatever proposals have accumulated, such as a member's departure.
    /// Owners only.
    pub fn commit_pending<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
    ) -> Result<Commit, RoomError> {
        self.require_owner()?;
        let (commit, welcome, _) = self
            .group
            .commit_to_pending_proposals(provider, signer)
            .map_err(|_| RoomError::Mls)?;
        self.group
            .merge_pending_commit(provider)
            .map_err(|_| RoomError::Mls)?;
        Ok(Commit {
            commit: ser(&commit)?,
            welcome: welcome.as_ref().map(ser).transpose()?,
        })
    }

    /// Dissolve the room. The last owner only.
    ///
    /// The caller derives every chunk name from the generation roots it holds in
    /// its keyring and has the store delete them (`Spark-spec.md` F7: room chunks
    /// are freed by deletion, media by receipt count). **Shared media is not
    /// freed** — each uploader reclaims their own space from their upload list,
    /// and the client must say so, because users will assume dissolving cleans up.
    pub fn dissolve(self) -> Result<Dissolution, RoomError> {
        let owners = OwnerSet::from_group(&self.group)?;
        let b: [u8; 32] = self
            .group
            .own_leaf_node()
            .ok_or(RoomError::Mls)?
            .credential()
            .serialized_content()
            .try_into()
            .map_err(|_| RoomError::Mls)?;
        let me = VerifyingKey::from_bytes(&b).map_err(|_| RoomError::Mls)?;
        if !owners.contains(&me) {
            return Err(RoomError::NotAnOwner);
        }
        if owners.len() != 1 {
            return Err(RoomError::OtherOwnersRemain);
        }
        Ok(Dissolution {
            generations: self.group.epoch().as_u64() + 1,
        })
    }

    /// Send an application message.
    pub fn send<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &Signer,
        body: &[u8],
    ) -> Result<Vec<u8>, RoomError> {
        ser(&self
            .group
            .create_message(provider, signer, body)
            .map_err(|_| RoomError::Mls)?)
    }

    /// Process an inbound message: an application message, or a commit to apply.
    pub fn process<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        bytes: &[u8],
    ) -> Result<Event, RoomError> {
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(bytes).map_err(|_| RoomError::Mls)?;
        let pm = msg
            .try_into_protocol_message()
            .map_err(|_| RoomError::Mls)?;
        let processed = self
            .group
            .process_message(provider, pm)
            .map_err(|_| RoomError::Mls)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Event::Message(m.into_bytes())),
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                self.group
                    .merge_staged_commit(provider, *sc)
                    .map_err(|_| RoomError::Mls)?;
                Ok(Event::Applied(self.owners()?))
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                self.group
                    .store_pending_proposal(provider.storage(), *p)
                    .map_err(|_| RoomError::Mls)?;
                Ok(Event::Proposed)
            }
            _ => Err(RoomError::Unsupported),
        }
    }
}

impl core::fmt::Debug for Commit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Commit({} bytes, welcome: {})",
            self.commit.len(),
            self.welcome
                .as_ref()
                .map_or("none".into(), |w| format!("{} bytes", w.len()))
        )
    }
}

/// What a dissolve yields.
pub struct Dissolution {
    /// How many generations the room had. The caller holds their roots and
    /// derives the names to delete.
    pub generations: u64,
}

/// Serialize an MLS message for the commit lane.
///
/// Uses the `tls_codec` that `openmls` re-exports rather than a direct
/// dependency: a second version of it in the graph makes `MlsMessageOut` fail to
/// satisfy a bound that looks identical.
impl core::fmt::Debug for Dissolution {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Dissolution({} generations)", self.generations)
    }
}

fn ser<T: TlsSerialize>(m: &T) -> Result<Vec<u8>, RoomError> {
    m.tls_serialize_detached().map_err(|_| RoomError::Mls)
}

/// Why a room operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoomError {
    /// The caller is not an owner of this room.
    NotAnOwner,
    /// The subject is not a member of this room.
    NotAMember,
    /// The operation would leave the room with no owner. Dissolve instead.
    LastOwner,
    /// Dissolving requires being the only owner left.
    OtherOwnersRemain,
    /// The bytes were not a welcome message.
    NotAWelcome,
    /// A message kind Spark does not use.
    Unsupported,
    /// The owner set would not load from the group context.
    Owners(OwnerSetError),
    /// MLS refused the operation. Deliberately opaque: distinguishing the causes
    /// would mostly report which of OpenMLS's forty error variants fired, and no
    /// caller can act differently on that.
    Mls,
}

impl From<OwnerSetError> for RoomError {
    fn from(e: OwnerSetError) -> Self {
        Self::Owners(e)
    }
}

impl core::fmt::Display for RoomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAnOwner => f.write_str("not an owner of this room"),
            Self::NotAMember => f.write_str("not a member of this room"),
            Self::LastOwner => {
                f.write_str("the last owner cannot leave; dissolve the room instead")
            }
            Self::OtherOwnersRemain => f.write_str("other owners remain; appoint or dismiss first"),
            Self::NotAWelcome => f.write_str("not a welcome message"),
            Self::Unsupported => f.write_str("unsupported message kind"),
            Self::Owners(e) => write!(f, "{e}"),
            Self::Mls => f.write_str("MLS refused the operation"),
        }
    }
}
impl core::error::Error for RoomError {}
