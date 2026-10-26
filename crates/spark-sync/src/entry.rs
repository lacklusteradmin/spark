//! What a room-log chunk decrypts to. `docs/protocol.md` §5.

use crate::clock::Clock;
use serde::{Deserialize, Serialize};
use spark_chunk::{LaneId, Slot};
use spark_crypto::{Signature, VerifyingKey};

/// The wire format version of a room log entry.
pub const ENTRY_VERSION: u8 = 1;

/// What an entry carries.
///
/// # Why an application message is not an MLS ciphertext
///
/// An earlier draft of `docs/protocol.md` §5 had `Application(MlsMessageOut)`.
/// Gate 6 showed that cannot work: MLS deletes each sender-ratchet key as it is
/// used, and drops past-epoch secrets, because that is what forward secrecy *is*.
/// An archive of MLS ciphertexts is therefore unreadable after a restore — by
/// anyone, including its owner. The whole point of F2 is that it is readable from
/// the seed.
///
/// So the archive layer is the room chunk's own AEAD, keyed from `room_root`,
/// which is what `Spark-spec.md` F4 already implies when it says an existing
/// member "re-shares the historical keys". Under decision D-A there is no
/// separate MLS delivery path to lose: members read chunks. MLS carries
/// membership and the owner set; its exporter derives each generation root.
///
/// Confidentiality at rest comes from the chunk AEAD. Authorship comes from the
/// signature below, made with the identity key that is also the MLS credential —
/// so a message is provably from a member, and `Spark-spec.md` D8's deniability
/// analysis is unchanged: it proves the holder of key X wrote it, not who holds X.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Payload {
    /// An MLS handshake message. Commit lane only, and still an MLS ciphertext:
    /// commits are consumed live and are not replayed from the archive.
    Commit(Vec<u8>),
    /// A message, signed by its sender.
    Application(Signed),
    /// A heartbeat carrying only the clock, so a quiet member still advertises
    /// what it has seen.
    LaneAdvert,
}

/// Domain separator for the authorship signature.
pub const MSG_CONTEXT: &[u8] = b"spark/v1/msg";

/// A message and the proof of who wrote it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Signed {
    /// The message.
    pub body: Vec<u8>,
    /// The sender's identity key, which is also their MLS credential.
    pub sender: [u8; 32],
    /// A signature over the slot as well as the body, so a message cannot be
    /// lifted out of one slot and replayed into another.
    ///
    /// A `Vec` rather than `[u8; 64]` only because serde stops deriving at 32
    /// elements. The length is checked on verify, so a short signature is a
    /// verification failure rather than a panic.
    pub sig: Vec<u8>,
}

/// The bytes an authorship signature covers.
fn signed_over(
    context: &[u8; 32],
    clock: &Clock,
    lane: &[u8; 16],
    seq: u64,
    epoch: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut v = MSG_CONTEXT.to_vec();
    v.extend_from_slice(context);
    let clock = postcard::to_allocvec(clock).expect("canonical clock");
    v.extend_from_slice(&(clock.len() as u64).to_be_bytes());
    v.extend_from_slice(&clock);
    v.extend_from_slice(lane);
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(body);
    v
}

impl Signed {
    /// Sign a message for a slot.
    pub fn new(
        context: &[u8; 32],
        clock: &Clock,
        slot: Slot,
        epoch: u64,
        body: Vec<u8>,
        sender: &VerifyingKey,
        sign: impl FnOnce(&[u8]) -> Signature,
    ) -> Self {
        let msg = signed_over(context, clock, slot.lane.as_bytes(), slot.seq, epoch, &body);
        Self {
            body,
            sender: *sender.as_bytes(),
            sig: sign(&msg).as_bytes().to_vec(),
        }
    }

    /// Verify authorship against the slot it was found in.
    pub fn verify(
        &self,
        context: &[u8; 32],
        clock: &Clock,
        slot: Slot,
        epoch: u64,
    ) -> Result<VerifyingKey, EntryError> {
        let sig: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| EntryError::BadSignature)?;
        let key = VerifyingKey::from_bytes(&self.sender).map_err(|_| EntryError::BadSignature)?;
        if spark_chunk::LaneId::message(&key) != slot.lane {
            return Err(EntryError::BadSignature);
        }
        let msg = signed_over(
            context,
            clock,
            slot.lane.as_bytes(),
            slot.seq,
            epoch,
            &self.body,
        );
        key.verify(&msg, &Signature::from_bytes(sig))
            .map_err(|_| EntryError::BadSignature)?;
        Ok(key)
    }
}

/// One entry of a room's log.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Format version.
    pub version: u8,
    /// Which lane. Redundant with the chunk name, and deliberately so: it binds
    /// the plaintext to the slot it was sealed for, so a chunk replayed into
    /// another slot fails to make sense even if it somehow decrypted.
    pub lane: [u8; 16],
    /// Position within the lane.
    pub seq: u64,
    /// MLS epoch at the time of writing.
    pub epoch: u64,
    /// The heads this writer had seen.
    pub clock: Clock,
    /// The contents.
    pub payload: Payload,
}

impl Entry {
    /// Build an entry for a slot.
    pub fn new(slot: Slot, epoch: u64, clock: Clock, payload: Payload) -> Self {
        Self {
            version: ENTRY_VERSION,
            lane: *slot.lane.as_bytes(),
            seq: slot.seq,
            epoch,
            clock,
            payload,
        }
    }

    /// The slot this entry belongs in.
    pub fn slot(&self) -> Slot {
        Slot::new(LaneId::from_bytes(self.lane), self.seq)
    }

    /// The lane.
    pub fn lane(&self) -> LaneId {
        LaneId::from_bytes(self.lane)
    }

    /// Encode for sealing.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("entry is a plain serializable struct")
    }

    /// Decode a sealed entry's plaintext.
    ///
    /// Rejects an entry whose declared slot does not match the one it was fetched
    /// from. The chunk key is derived from `(lane, seq)`, so a mismatch means
    /// something is wrong that authentication alone would not have caught.
    pub fn decode(bytes: &[u8], expected: Slot) -> Result<Self, EntryError> {
        let e: Entry = postcard::from_bytes(bytes).map_err(|_| EntryError::Malformed)?;
        if e.version != ENTRY_VERSION {
            return Err(EntryError::UnknownVersion(e.version));
        }
        if e.slot() != expected {
            return Err(EntryError::SlotMismatch);
        }
        Ok(e)
    }
}

/// Why an entry would not decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryError {
    /// The bytes are not an entry.
    Malformed,
    /// An entry format this build does not know.
    UnknownVersion(u8),
    /// The entry claims a different slot than the one it was fetched from.
    SlotMismatch,
    /// The authorship signature does not verify.
    BadSignature,
}

impl core::fmt::Display for EntryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("not a room log entry"),
            Self::UnknownVersion(v) => write!(f, "unknown entry version {v}"),
            Self::SlotMismatch => {
                f.write_str("entry claims a different slot than it was stored at")
            }
            Self::BadSignature => f.write_str("message authorship did not verify"),
        }
    }
}
impl core::error::Error for EntryError {}
