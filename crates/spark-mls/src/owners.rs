//! The owner set: a flat set, carried inside the MLS group context.
//!
//! `Spark-spec.md` F4: "Owners are a flat set. The creator starts as one and may
//! appoint others. [...] There is no hierarchy and no second role, so a 1:1 is a
//! room where both people are owners."
//!
//! It lives in a group context extension rather than in application state for one
//! reason: F4 also says "simultaneous dismissals resolve by MLS commit order,
//! which means the server picks". Putting the set in the group context makes that
//! true for free — changing it *is* a commit, and MLS already totally orders
//! commits. An application-level owner list would need its own ordering rule, and
//! two clients could disagree about who was dismissed first.

use openmls::prelude::*;
use spark_crypto::VerifyingKey;

/// The extension type carrying the owner set. Private-use range.
pub const OWNERS_EXT: u16 = 0xff5b;

/// The owners of a room, as a canonical sorted set.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct OwnerSet(Vec<[u8; 32]>);

impl OwnerSet {
    /// A set holding one owner: the room's creator.
    pub fn founder(k: &VerifyingKey) -> Self {
        Self(vec![*k.as_bytes()])
    }

    /// Whether a key is an owner.
    pub fn contains(&self, k: &VerifyingKey) -> bool {
        self.0.contains(k.as_bytes())
    }

    /// How many owners there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty. A room in this state cannot be managed at all;
    /// F4 provides no takeover mechanism and this is not treated as recoverable.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every owner, in canonical order.
    pub fn keys(&self) -> impl Iterator<Item = VerifyingKey> + '_ {
        self.0
            .iter()
            .filter_map(|b| VerifyingKey::from_bytes(b).ok())
    }

    /// Add an owner. Idempotent.
    pub fn with(&self, k: &VerifyingKey) -> Self {
        let mut v = self.0.clone();
        if !v.contains(k.as_bytes()) {
            v.push(*k.as_bytes());
        }
        v.sort_unstable();
        Self(v)
    }

    /// Remove an owner. Idempotent.
    pub fn without(&self, k: &VerifyingKey) -> Self {
        let mut v = self.0.clone();
        v.retain(|x| x != k.as_bytes());
        v.sort_unstable();
        Self(v)
    }

    /// Encode for the group context.
    ///
    /// Sorted and fixed-width, so two clients that agree on the set produce
    /// identical bytes. A non-canonical encoding would make the group context
    /// hash differ between members who agree.
    pub fn encode(&self) -> Vec<u8> {
        let mut sorted = self.0.clone();
        sorted.sort_unstable();
        sorted.concat()
    }

    /// Decode from the group context.
    pub fn decode(b: &[u8]) -> Result<Self, OwnerSetError> {
        if !b.len().is_multiple_of(32) {
            return Err(OwnerSetError::Malformed);
        }
        let mut v: Vec<[u8; 32]> = b
            .chunks_exact(32)
            .map(|c| c.try_into().expect("chunk is 32 bytes"))
            .collect();
        if v.iter().any(|b| VerifyingKey::from_bytes(b).is_err())
            || v.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(OwnerSetError::Malformed);
        }
        let before = v.len();
        v.sort_unstable();
        v.dedup();
        if v.len() != before {
            return Err(OwnerSetError::Malformed);
        }
        Ok(Self(v))
    }

    /// The group context extensions carrying this set.
    ///
    /// `RequiredCapabilities` travels with it because MLS refuses to set a group
    /// context extension that is not declared there.
    pub fn extensions(&self) -> Extensions<GroupContext> {
        Extensions::from_vec(vec![
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(OWNERS_EXT)],
                &[],
                &[CredentialType::Basic],
            )),
            Extension::Unknown(OWNERS_EXT, UnknownExtension(self.encode())),
        ])
        .expect("two distinct extension types")
    }

    /// Read the set out of a group's context.
    pub fn from_group(g: &MlsGroup) -> Result<Self, OwnerSetError> {
        let ext = g
            .extensions()
            .unknown(OWNERS_EXT)
            .ok_or(OwnerSetError::Missing)?;
        Self::decode(&ext.0)
    }
}

/// Why an owner set would not load.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerSetError {
    /// The group context carries no owner set. Not a Spark room.
    Missing,
    /// Present but not a sorted, duplicate-free list of 32-byte keys.
    Malformed,
}

impl core::fmt::Display for OwnerSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("group context has no owner set"),
            Self::Malformed => f.write_str("owner set is malformed"),
        }
    }
}
impl core::error::Error for OwnerSetError {}
