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

pub mod wire;

use spark_crypto::{
    Clock, Grant, IssuerKey, IssuerPublic, KeySet, Pacing, Signature, Token, VerifyingKey,
    VoucherClaim, verify_any,
};
use spark_store::{Cell, Db};

/// Table of name to key mappings, keyed by name.
pub const T_NAME: &str = "name_mapping";
/// Table of issuance counters, keyed by a fixed row id.
pub const T_ISSUANCE: &str = "issuance";
/// Table of spent payment vouchers, keyed by serial.
pub const T_VOUCHER: &str = "voucher_spent";
/// Table of payments already exchanged for a voucher, keyed by reference.
pub const T_PAYMENT: &str = "payment_spent";

/// Days a lapsed name is held before it returns to sale (`Spark-spec.md` F9).
pub const GRACE_DAYS: u32 = 10;

/// What a signed transfer covers.
pub const TRANSFER_CONTEXT: &[u8] = b"spark/v1/name/transfer";

/// A request to the issuer.
#[derive(Clone, Debug)]
pub enum Request {
    /// Resolve one exact name.
    ///
    /// `today` because a lapsed name must stop resolving, and this service holds
    /// no clock — the same discipline as everywhere else.
    Resolve(String, u32),
    /// Register a name against a key, paying with a voucher.
    Register {
        /// The exact name.
        name: String,
        /// The holder's **public identity**: signing key followed by KEM key.
        ///
        /// Both halves, because resolving a name has to yield enough to seal a
        /// contact request to that person. The signing key alone would mean a
        /// second lookup somewhere, and there is nowhere else to look.
        key: [u8; 64],
        /// The unblinded voucher claim: a serial the buyer chose and what it buys.
        claim: VoucherClaim,
        /// The issuer's signature over that claim.
        voucher: Token,
        /// Today, so expiry is the caller's clock rather than the server's.
        today: u32,
    },
    /// Move a name to a key the current holder signs for.
    Transfer {
        /// The name.
        name: String,
        /// The new holder's public identity.
        new_key: [u8; 64],
        /// The current holder's signature over the transfer.
        sig: [u8; 64],
    },
    /// Buy a voucher.
    ///
    /// The buyer sends a *blinded* claim. The issuer confirms the payment, marks
    /// it spent, and signs bytes it cannot read. It therefore has nothing to
    /// record that would join the payment to the voucher, and later nothing to
    /// join the voucher to the name it buys — which is the entire construction,
    /// not a policy about what to log.
    Purchase {
        /// The blinded voucher claim.
        blinded: Vec<u8>,
        /// A reference to a settled payment on whatever chain the buyer used.
        ///
        /// Payments settle through self-hosted nodes rather than a processor,
        /// which would see every transaction and reintroduce the record vouchers
        /// exist to avoid (F9).
        payment: Vec<u8>,
        /// What the buyer says they paid, checked against the price table.
        amount: u64,
    },
    /// Renew a name for further months, paying with another voucher.
    Renew {
        /// The name.
        name: String,
        /// The unblinded voucher claim.
        claim: VoucherClaim,
        /// Its signature.
        voucher: Token,
        /// Today, so expiry is the caller's clock rather than the server's.
        today: u32,
    },
    /// The issuer's voucher-signing public key.
    IssuerKey,
}

/// A response from the issuer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// The public identity holding a name, or nothing.
    ///
    /// A miss and a hit are the same shape and the same cost: anything that made
    /// them distinguishable in timing would be a probe oracle.
    Resolved(Option<[u8; 64]>),
    /// Registered.
    Registered,
    /// Transferred. The old key appears nowhere afterwards.
    Transferred,
    /// A blind signature over a voucher claim. Still blinded.
    Signed(Vec<u8>),
    /// The voucher-signing public key.
    IssuerKey(Vec<u8>),
    /// A name was renewed, through the given day.
    Renewed(u32),
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
    /// The voucher does not verify under the issuer's key.
    BadVoucher,
    /// The voucher does not buy what is being asked for.
    WrongGrant,
    /// That payment has already been exchanged for a voucher.
    PaymentSpent,
    /// The amount does not match the price table.
    Underpaid,
    /// The name is not in the sellable format.
    BadName,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Which names are sellable at all.
fn is_sellable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Premium pricing scales with scarcity (`Spark-spec.md` D9): single characters
/// highest, then two-character names, then longer. A price table rather than a
/// design question — this is the shape of the table, not its final numbers.
pub fn is_premium(name: &str) -> bool {
    name.len() <= 2
}

/// The issuer.
#[derive(Clone)]
pub struct Issuer {
    db: Db,
    signing: std::sync::Arc<std::sync::Mutex<KeySet>>,
    pacing: Pacing,
    overruns: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Issuer {
    /// A service over `db`, with its own voucher-signing key.
    ///
    /// **Its own**, not the keyring service's. They are separate trust domains
    /// (`Spark-spec.md` D2's reasoning applied to services rather than traffic):
    /// one key shared between the service that sees money and the service that
    /// sees `hash(pubkey)` would let whoever holds it mint both, and would make
    /// the two domains one in every way that matters.
    pub fn new(db: Db, signing: IssuerKey) -> Self {
        Self {
            db,
            signing: std::sync::Arc::new(std::sync::Mutex::new(KeySet::new(signing))),
            pacing: Pacing::DEFAULT,
            overruns: Default::default(),
        }
    }

    /// The voucher-signing public key.
    pub fn signing_public(&self) -> IssuerPublic {
        self.signing.lock().expect("keyset lock").signing().public()
    }

    /// Every key a voucher may have been signed with, newest first.
    pub fn accepted_keys(&self) -> Vec<IssuerPublic> {
        self.signing.lock().expect("keyset lock").accepted()
    }

    /// Retire the voucher-signing key in favour of `next`.
    ///
    /// Bounds the blast radius of RUSTSEC-2023-0071. The retired key still
    /// verifies, so a voucher someone bought before the rotation is still good.
    pub fn rotate_signing_key(&self, next: IssuerKey) {
        self.signing.lock().expect("keyset lock").rotate(next);
    }

    /// How many requests took longer than one pacing tick. Non-zero means the
    /// tick is set too low for this machine.
    pub fn pacing_overruns(&self) -> u64 {
        self.overruns.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Handle a request on a fixed cadence. **The production entry point.**
    ///
    /// Wraps the whole request path, not the signing call alone: pacing the
    /// signature while the surrounding parse and database write vary would leave
    /// the variance intact.
    pub fn handle_paced<C: Clock>(&self, clock: &C, req: Request) -> Response {
        let start = clock.now_nanos();
        let out = self.handle(req);
        let paced = self.pacing.after(clock.now_nanos().saturating_sub(start));
        if paced.overran {
            self.overruns
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        clock.sleep_nanos(paced.wait_nanos);
        out
    }

    /// Whether a name is still resolvable on `today`.
    ///
    /// A name resolves through its paid-until day and for [`GRACE_DAYS`] after.
    /// Past that it is reclaimed and returns to sale (F9), and a recycled name
    /// means its new holder may receive requests meant for someone else — which
    /// F5's approval step reduces to a request they can decline.
    fn live(&self, name: &str, today: u32) -> bool {
        self.db
            .field(T_NAME, name, "paid_until_day")
            .and_then(|c| c.num())
            .is_some_and(|p| today <= p as u32 + GRACE_DAYS)
    }

    /// The store, for the permitted-knowledge audit.
    pub fn db(&self) -> &Db {
        &self.db
    }

    fn key_of(&self, name: &str) -> Option<[u8; 64]> {
        let c = self.db.field(T_NAME, name, "name_pubkey")?;
        c.bytes()?.try_into().ok()
    }

    /// Handle one request.
    pub fn handle(&self, req: Request) -> Response {
        match req {
            Request::IssuerKey => match self.signing_public().to_der() {
                Ok(d) => Response::IssuerKey(d),
                Err(_) => Response::Refused(Refusal::BadVoucher),
            },

            // Exact match only, and only while the name is live. No prefix, no
            // listing, no autocomplete: the namespace must not be enumerable (F5).
            Request::Resolve(name, today) => Response::Resolved(
                self.live(&name, today)
                    .then(|| self.key_of(&name))
                    .flatten(),
            ),

            Request::Purchase {
                blinded,
                payment,
                amount,
            } => {
                // Spend the payment before signing. A payment that could be
                // replayed would mint unlimited vouchers, which is the same hole
                // as a reusable token one service down.
                let key = hex(&payment);
                if !self.db.put_if_absent(
                    T_PAYMENT,
                    &key,
                    vec![("spent_payment_ref", Cell::Bytes(payment))],
                ) {
                    return Response::Refused(Refusal::PaymentSpent);
                }
                // The amount is checked against the price table, but the *claim*
                // is blinded — so this cannot verify that the buyer paid for what
                // they are about to receive. That is unavoidable and is why the
                // caller declares the amount: a buyer who underpays for a premium
                // name gets a signature over a claim the price did not cover, and
                // redemption is where that is caught, below.
                if amount == 0 {
                    return Response::Refused(Refusal::Underpaid);
                }
                self.db.bump(
                    T_ISSUANCE,
                    "total",
                    "blind_sig_count",
                    1,
                    vec![("blind_sig_count", Cell::Num(0))],
                );
                match self
                    .signing
                    .lock()
                    .expect("keyset lock")
                    .signing()
                    .blind_sign(&blinded)
                {
                    Ok(sig) => Response::Signed(sig),
                    Err(_) => Response::Refused(Refusal::BadVoucher),
                }
            }

            Request::Register {
                name,
                key,
                claim,
                voucher,
                today,
            } => {
                if !is_sellable(&name) {
                    return Response::Refused(Refusal::BadName);
                }
                // A live name is taken; a lapsed one has returned to sale.
                if self.live(&name, today) {
                    return Response::Refused(Refusal::Taken);
                }
                let Grant::NameMonths { months, premium } = claim.grant else {
                    return Response::Refused(Refusal::WrongGrant);
                };
                // The tier the voucher paid for must match the tier the name is.
                if premium != is_premium(&name) {
                    return Response::Refused(Refusal::WrongGrant);
                }
                if let Err(r) = self.spend_voucher(&claim, &voucher) {
                    return Response::Refused(r);
                }
                self.write(&name, key, today + months as u32 * 30, premium);
                Response::Registered
            }

            Request::Renew {
                name,
                claim,
                voucher,
                today,
            } => {
                let Some(paid) = self
                    .db
                    .field(T_NAME, &name, "paid_until_day")
                    .and_then(|c| c.num())
                else {
                    return Response::Refused(Refusal::Unknown);
                };
                if !self.live(&name, today) {
                    // Past grace it is not a renewal, it is a purchase, and the
                    // name may already belong to someone else.
                    return Response::Refused(Refusal::Unknown);
                }
                let Grant::NameMonths { months, premium } = claim.grant else {
                    return Response::Refused(Refusal::WrongGrant);
                };
                if premium != is_premium(&name) {
                    return Response::Refused(Refusal::WrongGrant);
                }
                if let Err(r) = self.spend_voucher(&claim, &voucher) {
                    return Response::Refused(r);
                }
                // Extend from whichever is later: renewing early must not shorten
                // the term, and renewing during grace must not credit the lapse.
                let base = (paid as u32).max(today);
                let until = base + months as u32 * 30;
                let key = self.key_of(&name).expect("a live name has a holder");
                self.write(&name, key, until, premium);
                Response::Renewed(until)
            }

            Request::Transfer { name, new_key, sig } => {
                let Some(holder) = self.key_of(&name) else {
                    return Response::Refused(Refusal::Unknown);
                };
                // The signing half is the first 32 bytes; that is what signs a
                // transfer.
                let sign: [u8; 32] = holder[..32].try_into().expect("64 begins with 32");
                let Ok(vk) = VerifyingKey::from_bytes(&sign) else {
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
                let premium = self
                    .db
                    .field(T_NAME, &name, "name_tier")
                    .and_then(|c| c.num())
                    .is_some_and(|t| t == 1);
                // Overwrite. There is no history table here and there must not be
                // one: it would join the old key to the new, which is precisely
                // what transfer exists to avoid. A seller cannot hand over a seed
                // without keeping read access, so they transfer to a key they have
                // never seen.
                self.write(&name, new_key, paid, premium);
                Response::Transferred
            }
        }
    }

    /// Verify a voucher and mark its serial spent.
    fn spend_voucher(&self, claim: &VoucherClaim, voucher: &Token) -> Result<(), Refusal> {
        // Every accepted key, so a voucher bought before a rotation still works.
        if verify_any(&self.accepted_keys(), voucher, &claim.encode()).is_err() {
            return Err(Refusal::BadVoucher);
        }
        // Verify before spending: an unsigned serial must not be able to burn a
        // slot, or anyone could lock out a voucher they guessed.
        let key = hex(&claim.serial);
        if !self.db.put_if_absent(
            T_VOUCHER,
            &key,
            vec![("spent_voucher_serial", Cell::Bytes(claim.serial.to_vec()))],
        ) {
            return Err(Refusal::VoucherSpent);
        }
        Ok(())
    }

    fn write(&self, name: &str, key: [u8; 64], paid_until_day: u32, premium: bool) {
        self.db.put(
            T_NAME,
            name,
            vec![
                ("name", Cell::Text(name.to_string())),
                ("name_pubkey", Cell::Bytes(key.to_vec())),
                ("paid_until_day", Cell::Num(paid_until_day as u64)),
                ("name_tier", Cell::Num(premium as u64)),
            ],
        );
    }
}
