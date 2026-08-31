//! trust domain 3: name mapping, blind signing, payment nodes.
//!
//! layer 10, zone `io` — see `docs/layering.toml`.
//!
//! The only service that sees money. It is a separate trust domain for that
//! reason: blind vouchers cut the payment-to-key link cryptographically, but if
//! this ran in the same process as the keyring service, request timing and
//! operational logs would rejoin it.
//!
//! Two rules carry most of the weight:
//!
//! * **Names resolve but are not browsable** (`Spark-spec.md` F5). An exact name
//!   returns a key; nothing else does. There is no prefix search, no listing, and
//!   no count — so the namespace cannot be enumerated.
//! * **A transfer overwrites the mapping** (build-notes §4). Appending a history
//!   would link an old key to a new one, which is precisely what transfer exists
//!   to avoid: a seller cannot hand over a seed without keeping read access, so
//!   they transfer to a key they have never seen.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use spark_crypto::{Signature, VerifyingKey};
use spark_store::{Cell, Db};

/// Table of name to key mappings, keyed by name.
pub const T_NAME: &str = "name_mapping";
/// Table of issuance counters, keyed by a fixed row id.
pub const T_ISSUANCE: &str = "issuance";
/// Table of spent payment vouchers, keyed by serial.
pub const T_VOUCHER: &str = "voucher_spent";

/// What a signed transfer covers.
pub const TRANSFER_CONTEXT: &[u8] = b"spark/v1/name/transfer";

/// A request to the issuer.
#[derive(Clone, Debug)]
pub enum Request {
    /// Resolve one exact name.
    Resolve(String),
    /// Register a name against a key, paying with a voucher.
    Register {
        /// The exact name.
        name: String,
        /// The key that will hold it.
        key: [u8; 32],
        /// A blind payment voucher.
        voucher: Vec<u8>,
        /// Days since the epoch through which the name is paid.
        paid_until_day: u32,
    },
    /// Move a name to a key the current holder signs for.
    Transfer {
        /// The name.
        name: String,
        /// The new holder.
        new_key: [u8; 32],
        /// The current holder's signature over the transfer.
        sig: [u8; 64],
    },
    /// Issue a blind signature against a payment.
    BlindSign {
        /// The blinded request.
        blinded: Vec<u8>,
        /// A payment voucher serial.
        voucher: Vec<u8>,
    },
}

/// A response from the issuer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// The key holding a name, or nothing.
    ///
    /// A miss and a hit are the same shape and the same cost: anything that made
    /// them distinguishable in timing would be a probe oracle.
    Resolved(Option<[u8; 32]>),
    /// Registered.
    Registered,
    /// Transferred. The old key appears nowhere afterwards.
    Transferred,
    /// A blind signature.
    Signed(Vec<u8>),
    /// Refused.
    Refused(Refusal),
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The name is held by someone else.
    Taken,
    /// No such name.
    Unknown,
    /// The signature does not verify under the current holder's key.
    BadSignature,
    /// That voucher has already been spent.
    VoucherSpent,
    /// The name is not in the sellable format.
    BadName,
}

/// The issuer.
#[derive(Clone)]
pub struct Issuer {
    db: Db,
}

impl Issuer {
    /// A service over `db`.
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// The store, for the permitted-knowledge audit.
    pub fn db(&self) -> &Db {
        &self.db
    }

    fn key_of(&self, name: &str) -> Option<[u8; 32]> {
        let c = self.db.field(T_NAME, name, "name_pubkey")?;
        c.bytes()?.try_into().ok()
    }

    /// Handle one request.
    pub fn handle(&self, req: Request) -> Response {
        match req {
            // Exact match only. No prefix, no listing, no autocomplete: the
            // namespace must not be enumerable (F5).
            Request::Resolve(name) => Response::Resolved(self.key_of(&name)),

            Request::Register {
                name,
                key,
                voucher,
                paid_until_day,
            } => {
                if name.is_empty()
                    || name.len() > 64
                    || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    return Response::Refused(Refusal::BadName);
                }
                if self.key_of(&name).is_some() {
                    return Response::Refused(Refusal::Taken);
                }
                if !self.spend(&voucher) {
                    return Response::Refused(Refusal::VoucherSpent);
                }
                self.write(&name, key, paid_until_day);
                Response::Registered
            }

            Request::Transfer { name, new_key, sig } => {
                let Some(holder) = self.key_of(&name) else {
                    return Response::Refused(Refusal::Unknown);
                };
                let Ok(vk) = VerifyingKey::from_bytes(&holder) else {
                    return Response::Refused(Refusal::BadSignature);
                };
                let mut msg = TRANSFER_CONTEXT.to_vec();
                msg.extend_from_slice(name.as_bytes());
                msg.extend_from_slice(&new_key);
                if vk.verify(&msg, &Signature::from_bytes(sig)).is_err() {
                    return Response::Refused(Refusal::BadSignature);
                }
                let paid = self
                    .db
                    .field(T_NAME, &name, "paid_until_day")
                    .and_then(|c| c.num())
                    .unwrap_or(0) as u32;
                // Overwrite. There is no history table here and there must not be
                // one: it would join the old key to the new.
                self.write(&name, new_key, paid);
                Response::Transferred
            }

            Request::BlindSign { blinded, voucher } => {
                if !self.spend(&voucher) {
                    return Response::Refused(Refusal::VoucherSpent);
                }
                self.db.bump(
                    T_ISSUANCE,
                    "total",
                    "blind_sig_count",
                    1,
                    vec![("blind_sig_count", Cell::Num(0))],
                );
                // Stage 10 replaces this with RFC 9474. The shape is already the
                // point: nothing recorded here can be joined to a redemption.
                let mut sig = b"blindsig:".to_vec();
                sig.extend_from_slice(&blinded);
                Response::Signed(sig)
            }
        }
    }

    fn write(&self, name: &str, key: [u8; 32], paid_until_day: u32) {
        self.db.put(
            T_NAME,
            name,
            vec![
                ("name", Cell::Text(name.to_string())),
                ("name_pubkey", Cell::Bytes(key.to_vec())),
                ("paid_until_day", Cell::Num(paid_until_day as u64)),
            ],
        );
    }

    fn spend(&self, voucher: &[u8]) -> bool {
        let key: String = voucher.iter().map(|b| format!("{b:02x}")).collect();
        self.db.put_if_absent(
            T_VOUCHER,
            &key,
            vec![("spent_voucher_serial", Cell::Bytes(voucher.to_vec()))],
        )
    }
}
