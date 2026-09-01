//! Reachability: invites, contact requests, and key migration.
//!
//! `Spark-spec.md` F5. Two ways to reach someone, and both end in a request that
//! sits in a tray until it is accepted:
//!
//! * an **invite**, exchanged out of band as a link or QR code;
//! * an **exact name**, resolved through the issuer.
//!
//! Neither creates a room. That is the whole spam defence: "A regenerated
//! throwaway key can send requests but reaches nobody who declines."
//!
//! # What a decline leaves behind
//!
//! Nothing, for the sender. There is deliberately no operation anywhere in this
//! module, or on any service, by which a sender learns the fate of a request. A
//! declined request is indistinguishable from one not yet looked at, which is
//! what makes declining safe: refusing someone must not tell them they were
//! refused, or refusing becomes an act with consequences.

use crate::{Addr, PublicIdentity};
use spark_crypto::{
    KemPublic, KemSecret, Nonce, Secret, VerifyingKey, aead, expand, extract, sha256_parts,
};
use zeroize::Zeroizing;

/// Invite format version, first byte of the encoded form.
pub const INVITE_VERSION: u8 = 1;
/// Domain separator for the request key schedule.
pub const REQUEST_SALT: &[u8] = b"spark/v1/request";
/// Length of the secret that proves an invite was actually handed out.
pub const INVITE_SECRET_LEN: usize = 16;

/// A capability to ask one account for a room.
///
/// Carries the `invite_secret` so that holding someone's address is *not* enough
/// to reach them. Without it, every account with a name would be reachable by
/// anyone who resolved that name once — the invite path and the name path would
/// collapse into one, and revoking an invite would be impossible. Forgetting the
/// secret revokes every invite issued under it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Invite {
    /// Where the request is delivered.
    pub addr: Addr,
    /// The key the request is sealed to.
    pub kem: KemPublic,
    /// Proof of having been invited.
    pub secret: [u8; INVITE_SECRET_LEN],
}

impl Invite {
    /// Mint an invite for this identity.
    ///
    /// `secret` is caller-supplied entropy, as everywhere below the I/O line.
    pub fn new(me: &PublicIdentity, secret: [u8; INVITE_SECRET_LEN]) -> Self {
        Self {
            addr: me.addr(),
            kem: me.kem,
            secret,
        }
    }

    /// Encode for a link or a QR code.
    ///
    /// Hex, with a four-byte checksum. Not the most compact encoding available;
    /// chosen because a mistyped invite must fail cleanly rather than resolve to
    /// somebody else's address, and because a bespoke alphabet is one more thing
    /// to get wrong for a saving that does not change whether a QR code scans.
    pub fn encode(&self) -> String {
        let mut b = vec![INVITE_VERSION];
        b.extend_from_slice(self.addr.as_bytes());
        b.extend_from_slice(self.kem.as_bytes());
        b.extend_from_slice(&self.secret);
        let sum = sha256_parts(&[b"spark/v1/invite", &b]);
        b.extend_from_slice(&sum[..4]);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Parse a link or QR payload.
    pub fn parse(s: &str) -> Result<Self, InviteError> {
        let s = s.trim().trim_start_matches("spark:");
        if !s.len().is_multiple_of(2) {
            return Err(InviteError::Malformed);
        }
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(|_| InviteError::Malformed)?;

        let want = 1 + 32 + 32 + INVITE_SECRET_LEN + 4;
        if b.len() != want {
            return Err(InviteError::Malformed);
        }
        if b[0] != INVITE_VERSION {
            return Err(InviteError::UnknownVersion(b[0]));
        }
        let body = &b[..want - 4];
        if sha256_parts(&[b"spark/v1/invite", body])[..4] != b[want - 4..] {
            return Err(InviteError::BadChecksum);
        }
        let addr: [u8; 32] = b[1..33].try_into().expect("33-1 is 32");
        let kem: [u8; 32] = b[33..65].try_into().expect("65-33 is 32");
        let secret: [u8; INVITE_SECRET_LEN] = b[65..want - 4].try_into().expect("checked length");
        Ok(Self {
            addr: Addr::from_bytes(addr),
            kem: KemPublic::from_bytes(kem),
            secret,
        })
    }
}

/// Why an invite would not parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InviteError {
    /// Not the right shape.
    Malformed,
    /// An invite format this build does not know.
    UnknownVersion(u8),
    /// Mistyped: the checksum does not match.
    BadChecksum,
}

impl core::fmt::Display for InviteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("not an invite"),
            Self::UnknownVersion(v) => write!(f, "unknown invite version {v}"),
            Self::BadChecksum => f.write_str("invite is mistyped"),
        }
    }
}
impl core::error::Error for InviteError {}

/// A contact request, sealed to its recipient.
///
/// The bytes are what the keyring service stores. It can see the recipient — that
/// is unavoidable, since the request has to be delivered somewhere, and it is
/// listed as open question §9.5 in the protocol. It cannot see the sender: the
/// write is authorised by a blind token, and the sender's identity is inside the
/// AEAD.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedRequest(Vec<u8>);

impl SealedRequest {
    /// The bytes to hand to the keyring service.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Wrap bytes fetched from the service.
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self(b)
    }
}

/// What the recipient sees once a request is opened.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenRequest {
    /// Who is asking. Verified: the request carries their public identity, and
    /// the AEAD only opens if it was sealed to the recipient's key.
    pub from: PublicIdentity,
    /// A short note, so a request is not an anonymous knock.
    pub note: String,
    /// Whether the sender proved they held an invite, rather than merely knowing
    /// a name. The client should show this: the two are different levels of
    /// "how did you find me".
    pub invited: bool,
}

fn schedule(shared: &Secret<32>) -> (Secret<32>, Nonce) {
    let prk = extract(REQUEST_SALT, shared.expose());
    (
        expand::<32>(&prk, b"key"),
        *expand::<24>(&prk, b"nonce").expose(),
    )
}

/// Seal a contact request to a recipient.
///
/// `ephemeral` is caller-supplied entropy: a fresh X25519 secret used once. It
/// must never be reused, because the nonce is derived from the shared secret.
pub fn seal_request(
    to: &KemPublic,
    from: &PublicIdentity,
    note: &str,
    invite_secret: Option<[u8; INVITE_SECRET_LEN]>,
    ephemeral: Secret<32>,
) -> SealedRequest {
    let eph = KemSecret::from_secret(&ephemeral);
    let (key, nonce) = schedule(&eph.diffie_hellman(to));

    let mut plain = Vec::new();
    plain.extend_from_slice(from.sign.as_bytes());
    plain.extend_from_slice(from.kem.as_bytes());
    match invite_secret {
        Some(s) => {
            plain.push(1);
            plain.extend_from_slice(&s);
        }
        None => plain.push(0),
    }
    plain.extend_from_slice(note.as_bytes());

    let eph_pub = *eph.public().as_bytes();
    let mut out = eph_pub.to_vec();
    out.extend_from_slice(&aead::seal(&key, &nonce, &eph_pub, &plain));
    SealedRequest(out)
}

/// Open a contact request addressed to this identity.
///
/// `expect_invite` is the secret behind the invites this account has issued. A
/// request that presents it is marked `invited`; one that does not is still
/// delivered, because the name path is a legitimate way to reach someone.
pub fn open_request(
    me: &crate::Identity,
    sealed: &SealedRequest,
    expect_invite: Option<[u8; INVITE_SECRET_LEN]>,
) -> Result<OpenRequest, RequestError> {
    let b = &sealed.0;
    if b.len() < 32 {
        return Err(RequestError::Malformed);
    }
    let eph_pub: [u8; 32] = b[..32].try_into().expect("checked length");
    let (key, nonce) = schedule(&me.diffie_hellman(&KemPublic::from_bytes(eph_pub)));
    let plain: Zeroizing<Vec<u8>> =
        aead::open(&key, &nonce, &eph_pub, &b[32..]).map_err(|_| RequestError::NotForMe)?;

    if plain.len() < 65 {
        return Err(RequestError::Malformed);
    }
    let sign: [u8; 32] = plain[..32].try_into().expect("checked length");
    let kem: [u8; 32] = plain[32..64].try_into().expect("checked length");
    let sign = VerifyingKey::from_bytes(&sign).map_err(|_| RequestError::Malformed)?;

    let (invited, note_at) = match plain[64] {
        0 => (false, 65),
        1 => {
            if plain.len() < 65 + INVITE_SECRET_LEN {
                return Err(RequestError::Malformed);
            }
            let s: [u8; INVITE_SECRET_LEN] = plain[65..65 + INVITE_SECRET_LEN]
                .try_into()
                .expect("checked length");
            // A wrong secret is not an error: it is simply not an invited request.
            // Treating it as an error would tell a prober whether they guessed.
            (expect_invite == Some(s), 65 + INVITE_SECRET_LEN)
        }
        _ => return Err(RequestError::Malformed),
    };

    Ok(OpenRequest {
        from: PublicIdentity {
            sign,
            kem: KemPublic::from_bytes(kem),
        },
        note: String::from_utf8_lossy(&plain[note_at..]).into_owned(),
        invited,
    })
}

/// Why a request would not open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestError {
    /// Not sealed to this identity, or modified.
    NotForMe,
    /// Opened, but not a request.
    Malformed,
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotForMe => f.write_str("request is not addressed to this identity"),
            Self::Malformed => f.write_str("request did not decode"),
        }
    }
}
impl core::error::Error for RequestError {}

// ------------------------------------------------------------- key migration

/// Context bytes a migration attestation covers.
pub const MIGRATION_CONTEXT: &[u8] = b"spark/v1/migrate";

/// A statement, signed by an old key, that a new key is its successor.
///
/// `Spark-spec.md` F3 says migration "needs no new mechanism — it is F4's room
/// membership used deliberately". That is true of the *mechanism*: an owner adds
/// the new key and removes the old one. But an owner still has to know the
/// request is genuine rather than an impostor asking to be let in, and F3 gives
/// them nothing to check. This is that check, and it is the smallest possible
/// one: a signature, verified locally, that adds no server state.
///
/// It does not undo the past. F3 is explicit: "the old key still decrypts
/// anything it held before leaving."
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Migration {
    /// The key being retired.
    pub old: VerifyingKey,
    /// Its successor.
    pub new: VerifyingKey,
    /// The old key's signature.
    pub sig: [u8; 64],
}

impl Migration {
    /// Sign a migration with the old identity.
    pub fn sign(old: &crate::Identity, new: &PublicIdentity) -> Self {
        let msg = Self::message(&old.public().sign, &new.sign);
        Self {
            old: old.public().sign,
            new: new.sign,
            sig: *old.sign(&msg).as_bytes(),
        }
    }

    /// Verify the attestation.
    pub fn verify(&self) -> Result<(), MigrationError> {
        let msg = Self::message(&self.old, &self.new);
        self.old
            .verify(&msg, &spark_crypto::Signature::from_bytes(self.sig))
            .map_err(|_| MigrationError::BadSignature)
    }

    fn message(old: &VerifyingKey, new: &VerifyingKey) -> Vec<u8> {
        let mut v = MIGRATION_CONTEXT.to_vec();
        v.extend_from_slice(old.as_bytes());
        v.extend_from_slice(new.as_bytes());
        v
    }
}

/// Why a migration attestation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MigrationError {
    /// Not signed by the key it claims to retire.
    BadSignature,
}

impl core::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("migration was not signed by the key it retires")
    }
}
impl core::error::Error for MigrationError {}
