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
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Trusted payment adapter. Verify settlement, recipient, value, and a payment
/// commitment to this exact blinded request. Never trust a request-supplied amount.
pub trait PaymentVerifier: Send + Sync {
    /// True only for an irrevocably settled payment bound to these bytes.
    fn verify(&self, payment: &[u8], amount: u64, blinded: &[u8]) -> bool;
}
struct DenyPayments;
impl PaymentVerifier for DenyPayments {
    fn verify(&self, _: &[u8], _: u64, _: &[u8]) -> bool {
        false
    }
}

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
    /// a trusted server clock; the hint is ignored.
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
        /// Untrusted client date hint; ignored for authorization and expiry.
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
    /// Read the current transfer challenge.
    TransferChallenge(String),
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
        /// Untrusted client date hint; ignored for authorization and expiry.
        today: u32,
    },
    /// The issuer's voucher-signing public key.
    IssuerKey(u64),
}

/// A response from the issuer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// The public identity holding a name, or nothing.
    ///
    /// A miss and a hit are the same shape and the same cost: anything that made
    /// them distinguishable in timing would be a probe oracle.
    Resolved(Option<[u8; 64]>),
    /// Current transfer challenge, if the name exists.
    TransferChallenge(Option<[u8; 32]>),
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
    signing: Arc<Mutex<BTreeMap<u64, KeySet>>>,
    payment_verifier: Arc<dyn PaymentVerifier>,
    operation: Arc<Mutex<()>>,
    day_clock: Arc<dyn Fn() -> u32 + Send + Sync>,
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
        let key = KeySet::from_secret_bytes(
            &db.secret("price/1", || KeySet::new(signing).secret_bytes().unwrap()),
        )
        .expect("issuer key vault");
        let mut signing = BTreeMap::from([(1, key)]);
        for name in db.secret_names("price/") {
            let price = name[6..].parse().expect("vault price");
            signing.insert(
                price,
                KeySet::from_secret_bytes(&db.secret(&name, || unreachable!()))
                    .expect("issuer vault"),
            );
        }
        Self {
            db,
            signing: Arc::new(Mutex::new(signing)),
            payment_verifier: Arc::new(DenyPayments),
            operation: Default::default(),
            day_clock: Arc::new(|| {
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock before epoch")
                    .as_secs()
                    / 86400)
                    .try_into()
                    .expect("day overflow")
            }),
            pacing: Pacing::DEFAULT,
            overruns: Default::default(),
        }
    }

    /// Configure a trusted payment adapter. The default rejects all payments.
    pub fn with_payment_verifier(mut self, verifier: Arc<dyn PaymentVerifier>) -> Self {
        self.payment_verifier = verifier;
        self
    }

    /// Inject a server-owned clock, for deterministic tests or deployment time.
    pub fn with_day_clock(mut self, clock: Arc<dyn Fn() -> u32 + Send + Sync>) -> Self {
        self.day_clock = clock;
        self
    }

    /// Provision a separate key for a price, outside the network request path.
    pub fn provision_price(&self, price: u64, key: IssuerKey) {
        assert!(price > 0);
        let transaction = self
            .db
            .transaction()
            .expect("price provisioning transaction");
        let key = KeySet::from_secret_bytes(&self.db.secret(&format!("price/{price}"), || {
            KeySet::new(key).secret_bytes().unwrap()
        }))
        .expect("issuer vault");
        self.signing.lock().unwrap().entry(price).or_insert(key);
        transaction.commit().expect("price provisioning commit");
    }

    /// The verification key for one price. Unknown prices fail closed.
    pub fn signing_public_for(&self, price: u64) -> Option<IssuerPublic> {
        self.signing
            .lock()
            .unwrap()
            .get(&price)
            .map(|k| k.signing().public())
    }

    /// The default one-unit voucher verification key.
    pub fn signing_public(&self) -> IssuerPublic {
        self.signing_public_for(1).unwrap()
    }

    /// Rotate one provisioned price key.
    pub fn rotate_price_key(&self, price: u64, key: IssuerKey) {
        let transaction = self.db.transaction().expect("rotation transaction");
        let mut keys = self.signing.lock().unwrap();
        let set = keys.get_mut(&price).expect("provisioned price");
        set.rotate(key);
        self.db
            .replace_secret(&format!("price/{price}"), &set.secret_bytes().unwrap());
        transaction.commit().expect("rotation commit");
    }

    /// Accepted verification keys for the default price only.
    pub fn accepted_keys(&self) -> Vec<IssuerPublic> {
        self.signing.lock().unwrap().get(&1).unwrap().accepted()
    }

    /// Rotate the default price key, retaining accepted verification keys.
    pub fn rotate_signing_key(&self, next: IssuerKey) {
        self.rotate_price_key(1, next);
    }

    /// Current transfer challenge; replaced on registration and every transfer.
    pub fn transfer_challenge(&self, name: &str) -> Option<[u8; 32]> {
        self.db
            .field(T_NAME, name, "transfer_nonce")?
            .bytes()?
            .try_into()
            .ok()
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
            .is_some_and(|p| u64::from(today) <= p.saturating_add(u64::from(GRACE_DAYS)))
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
        let transaction = self
            .db
            .transaction()
            .expect("service transaction unavailable");
        let response = self.handle_inner(req);
        transaction.commit().expect("service commit failed");
        response
    }

    fn handle_inner(&self, req: Request) -> Response {
        let _operation = self.operation.lock().unwrap();
        let server_today = (self.day_clock)();
        match req {
            Request::TransferChallenge(name) => {
                Response::TransferChallenge(self.transfer_challenge(&name))
            }
            Request::IssuerKey(price) => {
                match self.signing_public_for(price).and_then(|k| k.to_der().ok()) {
                    Some(d) => Response::IssuerKey(d),
                    None => Response::Refused(Refusal::BadVoucher),
                }
            }

            // Exact match only, and only while the name is live. No prefix, no
            // listing, no autocomplete: the namespace must not be enumerable (F5).
            Request::Resolve(name, _today) => Response::Resolved(
                self.live(&name, server_today)
                    .then(|| self.key_of(&name))
                    .flatten(),
            ),

            Request::Purchase {
                blinded,
                payment,
                amount,
            } => {
                if payment.is_empty()
                    || payment.len() > 256
                    || blinded.len() != 256
                    || amount == 0
                    || !self.payment_verifier.verify(&payment, amount, &blinded)
                {
                    return Response::Refused(Refusal::Underpaid);
                }
                let signing = self.signing.lock().unwrap();
                let Some(keyset) = signing.get(&amount) else {
                    return Response::Refused(Refusal::Underpaid);
                };
                let key = hex(&payment);
                let request_hash = spark_crypto::sha256_parts(&[&amount.to_be_bytes(), &blinded]);
                if self.db.has(T_PAYMENT, &key) {
                    if self
                        .db
                        .field(T_PAYMENT, &key, "payment_request_hash")
                        .and_then(|c| c.bytes().map(|b| b == request_hash))
                        .unwrap_or(false)
                    {
                        return Response::Signed(
                            self.db
                                .field(T_PAYMENT, &key, "payment_response")
                                .unwrap()
                                .bytes()
                                .unwrap()
                                .to_vec(),
                        );
                    }
                    return Response::Refused(Refusal::PaymentSpent);
                }
                let Ok(sig) = keyset.signing().blind_sign(&blinded) else {
                    return Response::Refused(Refusal::BadVoucher);
                };
                self.db.put(
                    T_PAYMENT,
                    &key,
                    vec![
                        ("spent_payment_ref", Cell::Bytes(payment)),
                        ("payment_request_hash", Cell::Bytes(request_hash.to_vec())),
                        ("payment_response", Cell::Bytes(sig.clone())),
                    ],
                );
                self.db.bump(
                    T_ISSUANCE,
                    "total",
                    "blind_sig_count",
                    1,
                    vec![("blind_sig_count", Cell::Num(0))],
                );
                Response::Signed(sig)
            }

            Request::Register {
                name,
                key,
                claim,
                voucher,
                today: _,
            } => {
                let today = server_today;
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
                if months == 0 || premium != is_premium(&name) {
                    return Response::Refused(Refusal::WrongGrant);
                }
                let Some(until) = today.checked_add(u32::from(months) * 30) else {
                    return Response::Refused(Refusal::WrongGrant);
                };
                if let Err(r) = self.spend_voucher(&claim, &voucher) {
                    return Response::Refused(r);
                }
                self.write(&name, key, until, premium);
                Response::Registered
            }

            Request::Renew {
                name,
                claim,
                voucher,
                today: _,
            } => {
                let today = server_today;
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
                if months == 0 || premium != is_premium(&name) {
                    return Response::Refused(Refusal::WrongGrant);
                }
                // Extend from whichever is later: renewing early must not shorten
                // the term, and renewing during grace must not credit the lapse.
                let base = (paid as u32).max(today);
                let Some(until) = base.checked_add(u32::from(months) * 30) else {
                    return Response::Refused(Refusal::WrongGrant);
                };
                if let Err(r) = self.spend_voucher(&claim, &voucher) {
                    return Response::Refused(r);
                }
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
                if !self.live(&name, server_today) {
                    return Response::Refused(Refusal::Unknown);
                }
                let mut msg = TRANSFER_CONTEXT.to_vec();
                msg.extend_from_slice(&self.transfer_challenge(&name).expect("registered nonce"));
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
        let keys = self
            .signing
            .lock()
            .unwrap()
            .get(&claim.price())
            .map(KeySet::accepted)
            .unwrap_or_default();
        if verify_any(&keys, voucher, &claim.encode()).is_err() {
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
        use spark_crypto::blind::TryRng;
        let mut nonce = [0; 32];
        spark_store::mint::OsRandom
            .try_fill_bytes(&mut nonce)
            .unwrap();
        self.db.put(
            T_NAME,
            name,
            vec![
                ("name", Cell::Text(name.to_string())),
                ("name_pubkey", Cell::Bytes(key.to_vec())),
                ("paid_until_day", Cell::Num(paid_until_day as u64)),
                ("name_tier", Cell::Num(premium as u64)),
                ("transfer_nonce", Cell::Bytes(nonce.to_vec())),
            ],
        );
    }
}
