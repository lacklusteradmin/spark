//! trust domain 1: addr blobs, quota counters, token withdrawal.
//!
//! layer 10, zone `io` — see `docs/layering.toml`.
//!
//! The only service that knows an account-shaped identifier exists. It sees
//! `hash(pubkey)` and never a public key, never a room, never a peer.
//!
//! **Authentication is stateless.** The challenge is an HMAC of the address under
//! a server secret and the current minute, so the server verifies by recomputing
//! rather than by remembering. Build-notes §3 asks for a stateless server, and a
//! stored challenge table would be one more thing holding a per-account row.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use spark_chunk::Chunk;
use spark_crypto::{IssuerKey, IssuerPublic, Secret, Signature, VerifyingKey, hmac_sha256_parts};
use spark_store::{Cell, Db};

/// Table of keyring snapshots, keyed by address.
pub const T_KEYRING: &str = "keyring";
/// Table of keyring deltas, keyed by `addr:index`.
pub const T_DELTA: &str = "keyring_delta";
/// Table of quota counters, keyed by address.
pub const T_QUOTA: &str = "quota";
/// Table of rate-limit windows, keyed by address.
pub const T_RATE: &str = "rate";
/// Table of spent refund vouchers, keyed by voucher.
pub const T_REFUND: &str = "refund_spent";
/// Table of pending contact requests, keyed by `addr:index`.
pub const T_REQUEST: &str = "request";
/// Requests one address will hold before further ones are dropped.
pub const MAX_PENDING: usize = 64;

/// Deltas allowed before the client is expected to write a snapshot.
pub const COMPACT_AFTER: u32 = 64;
/// The earned-quota minimum an unpaid key holds (`Spark-spec.md` D1).
pub const FREE_QUOTA: u64 = 1 << 20;

/// A request to the keyring service. Every variant is authenticated.
#[derive(Clone, Debug)]
pub enum Request {
    /// Ask for the current challenge for an address.
    Challenge {
        /// The keyring address.
        addr: [u8; 32],
    },
    /// Fetch the snapshot.
    GetSnapshot(Auth),
    /// Fetch deltas written after the snapshot.
    GetDeltas(Auth),
    /// Append a delta.
    PutDelta(Auth, Vec<u8>),
    /// Replace the snapshot and drop the deltas it subsumes.
    PutSnapshot(Auth, Vec<u8>),
    /// Read quota.
    GetQuota(Auth),
    /// Fetch the token issuer's public key. Unauthenticated: it is public.
    GetIssuerKey,
    /// Exchange quota for blind tokens.
    ///
    /// The client sends *blinded* messages. This service debits quota for the
    /// size class it is told and signs bytes it cannot read; the content service
    /// later sees the token spent and cannot connect the two. That is the whole
    /// construction, and the reason a placeholder token that embedded the address
    /// was a leak rather than a stand-in.
    WithdrawTokens {
        /// Who is paying.
        auth: Auth,
        /// One blinded message per token.
        blinded: Vec<Vec<u8>>,
        /// The size class each token will authorise.
        size_class: u8,
    },
    /// Credit a refund voucher returned by the content service.
    CreditRefund(Auth, Vec<u8>, u64),

    /// Leave a contact request for an address.
    ///
    /// **Deliberately unauthenticated.** The sender is by definition not the
    /// holder of the recipient's key, so there is nothing they could sign that
    /// this service should accept. Spam is priced instead of identified: the
    /// write costs a blind token, exactly as an upload does, which is the same
    /// answer F7 gives to the same question.
    PutRequest {
        /// Where to leave it.
        addr: [u8; 32],
        /// The sealed request. Opaque here.
        blob: Vec<u8>,
        /// A blind token, spendable once.
        token: Vec<u8>,
    },
    /// Read the tray. Recipient only.
    GetRequests(Auth),
    /// Discard one request, accepted or declined alike.
    DropRequest(Auth, u32),
}

/// Proof that the caller holds the key behind an address.
#[derive(Clone, Debug)]
pub struct Auth {
    /// The keyring address.
    pub addr: [u8; 32],
    /// The public key it was derived from.
    pub key: [u8; 32],
    /// A signature over the current challenge.
    pub sig: [u8; 64],
}

/// A response from the keyring service.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// The challenge to sign.
    Challenge([u8; 32]),
    /// A sealed keyring snapshot, or nothing for a new account.
    Snapshot(Option<Vec<u8>>),
    /// Sealed deltas, in write order.
    Deltas(Vec<Vec<u8>>),
    /// A delta was appended. Carries whether compaction is now due.
    Appended {
        /// The delta's index.
        index: u32,
        /// Whether the client should write a fresh snapshot.
        compact: bool,
    },
    /// A snapshot was written.
    SnapshotWritten,
    /// Current quota.
    Quota {
        /// Bytes held.
        used: u64,
        /// Bytes allowed.
        limit: u64,
    },
    /// Blind signatures, one per blinded message. Still blinded: only the client
    /// can unblind them, which is what makes them unlinkable when spent.
    Tokens(Vec<Vec<u8>>),
    /// The issuer's public key, for clients and for the content service.
    IssuerKey(Vec<u8>),
    /// A refund was credited.
    Credited,
    /// A request was accepted for delivery.
    ///
    /// Returned whether or not the tray was full and whether or not the address
    /// exists. A sender who could tell those apart would have an oracle for
    /// which addresses are real and which people are ignoring them.
    RequestTaken,
    /// The tray, oldest first, as `(index, bytes)`.
    Requests(Vec<(u32, Vec<u8>)>),
    /// A request was discarded.
    RequestDropped,
    /// Refused.
    Refused(Refusal),
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The signature did not verify against the current challenge.
    BadAuth,
    /// The address is not the hash of the presented key.
    AddrMismatch,
    /// The bytes are not a well-formed chunk.
    Malformed,
    /// The withdrawal would exceed this key's quota.
    OverQuota,
    /// That refund voucher has already been credited.
    VoucherSpent,
}

/// The keyring service.
#[derive(Clone)]
pub struct Keyring {
    db: Db,
    issuer: std::sync::Arc<IssuerKey>,
    server_secret: Secret<32>,
    /// The current minute, supplied rather than read from a clock. A `now()` here
    /// would make every test time-dependent and the challenge unverifiable in a
    /// replay of a recorded session.
    minute: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Keyring {
    /// A service over `db`, with a server secret used only for challenges and an
    /// issuer key for storage tokens.
    pub fn new(db: Db, server_secret: Secret<32>, issuer: IssuerKey) -> Self {
        Self {
            db,
            issuer: std::sync::Arc::new(issuer),
            server_secret,
            minute: Default::default(),
        }
    }

    /// The token issuer's public key, which the content service needs to verify
    /// spends and clients need to blind against.
    pub fn issuer_public(&self) -> IssuerPublic {
        self.issuer.public()
    }

    /// The store, for the permitted-knowledge audit.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Advance the clock. Callers drive this; the service never reads one.
    pub fn set_minute(&self, m: u64) {
        self.minute.store(m, std::sync::atomic::Ordering::SeqCst);
    }

    /// The challenge an address must sign right now.
    pub fn challenge(&self, addr: &[u8; 32]) -> [u8; 32] {
        let m = self.minute.load(std::sync::atomic::Ordering::SeqCst);
        hmac_sha256_parts(
            &self.server_secret,
            &[b"spark/v1/challenge", addr, &m.to_be_bytes()],
        )
    }

    fn verify(&self, a: &Auth) -> Result<String, Refusal> {
        // The address must be the hash of the presented key, or an attacker could
        // authenticate against one account with another account's key.
        let expect = spark_crypto::sha256_parts(&[spark_identity_addr_prefix(), &a.key]);
        if expect != a.addr {
            return Err(Refusal::AddrMismatch);
        }
        let key = VerifyingKey::from_bytes(&a.key).map_err(|_| Refusal::BadAuth)?;
        key.verify(&self.challenge(&a.addr), &Signature::from_bytes(a.sig))
            .map_err(|_| Refusal::BadAuth)?;
        Ok(hex(&a.addr))
    }

    /// Handle one request.
    pub fn handle(&self, req: Request) -> Response {
        let auth = match &req {
            Request::Challenge { addr } => return Response::Challenge(self.challenge(addr)),
            Request::PutRequest { addr, blob, token } => {
                return self.put_request(*addr, blob.clone(), token.clone());
            }
            Request::GetIssuerKey => {
                return match self.issuer.public().to_der() {
                    Ok(d) => Response::IssuerKey(d),
                    Err(_) => Response::Refused(Refusal::Malformed),
                };
            }
            Request::GetSnapshot(a)
            | Request::GetDeltas(a)
            | Request::PutDelta(a, _)
            | Request::PutSnapshot(a, _)
            | Request::GetQuota(a)
            | Request::WithdrawTokens { auth: a, .. }
            | Request::CreditRefund(a, _, _)
            | Request::GetRequests(a)
            | Request::DropRequest(a, _) => a,
        };
        let addr = match self.verify(auth) {
            Ok(a) => a,
            Err(r) => return Response::Refused(r),
        };
        self.count_request(&addr);

        match req {
            Request::Challenge { .. } | Request::GetIssuerKey => unreachable!("handled above"),
            Request::GetSnapshot(_) => Response::Snapshot(
                self.db
                    .field(T_KEYRING, &addr, "snapshot_bytes")
                    .and_then(|c| c.bytes().map(<[u8]>::to_vec)),
            ),
            Request::GetDeltas(_) => Response::Deltas(
                self.delta_keys(&addr)
                    .into_iter()
                    .filter_map(|k| self.db.field(T_DELTA, &k, "delta_bytes"))
                    .filter_map(|c| c.bytes().map(<[u8]>::to_vec))
                    .collect(),
            ),
            Request::PutDelta(_, bytes) => self.put_delta(&addr, bytes),
            Request::PutSnapshot(_, bytes) => self.put_snapshot(&addr, bytes),
            Request::GetQuota(_) => Response::Quota {
                used: self.used(&addr),
                limit: self.limit(&addr),
            },
            Request::WithdrawTokens {
                blinded,
                size_class,
                ..
            } => self.withdraw(&addr, &blinded, size_class),
            Request::CreditRefund(_, v, amount) => self.credit(&addr, v, amount),
            Request::PutRequest { .. } => unreachable!("handled above"),
            Request::GetRequests(_) => Response::Requests(
                self.request_keys(&addr)
                    .into_iter()
                    .filter_map(|k| {
                        let i = k.rsplit(':').next()?.parse().ok()?;
                        let b = self.db.field(T_REQUEST, &k, "request_bytes")?;
                        Some((i, b.bytes()?.to_vec()))
                    })
                    .collect(),
            ),
            Request::DropRequest(_, i) => {
                // No notification goes anywhere. A declined request and one not
                // yet looked at are the same thing from outside, which is what
                // makes declining safe to do (F5).
                self.db.delete(T_REQUEST, &format!("{addr}:{i}"));
                Response::RequestDropped
            }
        }
    }

    fn request_keys(&self, addr: &str) -> Vec<String> {
        let mut ks: Vec<String> = self
            .db
            .keys(T_REQUEST)
            .into_iter()
            .filter(|k| k.starts_with(&format!("{addr}:")))
            .collect();
        ks.sort_by_key(|k| {
            k.rsplit(':')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        });
        ks
    }

    fn put_request(&self, addr: [u8; 32], blob: Vec<u8>, token: Vec<u8>) -> Response {
        let serial = hex(&token);
        if !self.db.put_if_absent(
            T_REQUEST,
            &format!("token:{serial}"),
            vec![("request_bytes", Cell::Bytes(token))],
        ) {
            // Even this is not distinguishable to a sender who reuses a token by
            // accident versus one probing: both get the same answer below.
            return Response::RequestTaken;
        }
        let a = hex(&addr);
        let existing = self.request_keys(&a);
        if existing.len() < MAX_PENDING {
            let index = existing
                .last()
                .and_then(|k| k.rsplit(':').next())
                .and_then(|n| n.parse::<u32>().ok())
                .map_or(0, |n| n + 1);
            self.db.put(
                T_REQUEST,
                &format!("{a}:{index}"),
                vec![
                    ("addr", Cell::Text(a)),
                    ("request_index", Cell::Num(index as u64)),
                    ("request_bytes", Cell::Bytes(blob)),
                    (
                        "mtime",
                        Cell::Num(self.minute.load(std::sync::atomic::Ordering::SeqCst)),
                    ),
                ],
            );
        }
        // Same answer whether it was stored, dropped for a full tray, or sent to
        // an address that does not exist.
        Response::RequestTaken
    }

    fn delta_keys(&self, addr: &str) -> Vec<String> {
        let mut ks: Vec<String> = self
            .db
            .keys(T_DELTA)
            .into_iter()
            .filter(|k| k.starts_with(&format!("{addr}:")))
            .collect();
        ks.sort_by_key(|k| {
            k.rsplit(':')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        });
        ks
    }

    fn put_delta(&self, addr: &str, bytes: Vec<u8>) -> Response {
        if Chunk::from_bytes(bytes.clone()).is_err() {
            return Response::Refused(Refusal::Malformed);
        }
        let index = self.delta_keys(addr).len() as u32;
        self.db.put(
            T_DELTA,
            &format!("{addr}:{index}"),
            vec![
                ("addr", Cell::Text(addr.to_string())),
                ("delta_index", Cell::Num(index as u64)),
                ("delta_bytes", Cell::Bytes(bytes)),
                (
                    "mtime",
                    Cell::Num(self.minute.load(std::sync::atomic::Ordering::SeqCst)),
                ),
            ],
        );
        Response::Appended {
            index,
            compact: index + 1 >= COMPACT_AFTER,
        }
    }

    fn put_snapshot(&self, addr: &str, bytes: Vec<u8>) -> Response {
        if Chunk::from_bytes(bytes.clone()).is_err() {
            return Response::Refused(Refusal::Malformed);
        }
        self.db.put(
            T_KEYRING,
            addr,
            vec![
                ("addr", Cell::Text(addr.to_string())),
                ("snapshot_len", Cell::Num(bytes.len() as u64)),
                ("snapshot_bytes", Cell::Bytes(bytes)),
                (
                    "mtime",
                    Cell::Num(self.minute.load(std::sync::atomic::Ordering::SeqCst)),
                ),
            ],
        );
        for k in self.delta_keys(addr) {
            self.db.delete(T_DELTA, &k);
        }
        Response::SnapshotWritten
    }

    fn used(&self, addr: &str) -> u64 {
        self.db
            .field(T_QUOTA, addr, "quota_media_used")
            .and_then(|c| c.num())
            .unwrap_or(0)
    }
    fn limit(&self, addr: &str) -> u64 {
        self.db
            .field(T_QUOTA, addr, "quota_limit")
            .and_then(|c| c.num())
            .unwrap_or(FREE_QUOTA)
    }

    fn quota_row(&self, addr: &str) -> spark_store::Row {
        vec![
            ("addr", Cell::Text(addr.to_string())),
            ("quota_media_used", Cell::Num(0)),
            ("quota_text_used", Cell::Num(0)),
            ("quota_limit", Cell::Num(FREE_QUOTA)),
        ]
    }

    fn withdraw(&self, addr: &str, blinded: &[Vec<u8>], size_class: u8) -> Response {
        if !(10..=40).contains(&size_class) {
            return Response::Refused(Refusal::Malformed);
        }
        let cost = (1u64 << size_class) * blinded.len() as u64;
        if self.used(addr) + cost > self.limit(addr) {
            return Response::Refused(Refusal::OverQuota);
        }
        self.db.bump(
            T_QUOTA,
            addr,
            "quota_media_used",
            cost as i64,
            self.quota_row(addr),
        );

        // Signing blinded bytes. Nothing about `addr` reaches the signature, and
        // nothing about the signature is recorded here.
        let mut out = Vec::with_capacity(blinded.len());
        for b in blinded {
            match self.issuer.blind_sign(b) {
                Ok(sig) => out.push(sig),
                Err(_) => return Response::Refused(Refusal::Malformed),
            }
        }
        Response::Tokens(out)
    }

    fn credit(&self, addr: &str, voucher: Vec<u8>, amount: u64) -> Response {
        let key = hex(&voucher);
        if !self.db.put_if_absent(
            T_REFUND,
            &key,
            vec![("spent_refund_voucher", Cell::Bytes(voucher))],
        ) {
            return Response::Refused(Refusal::VoucherSpent);
        }
        self.db.bump(
            T_QUOTA,
            addr,
            "quota_media_used",
            -(amount as i64),
            self.quota_row(addr),
        );
        Response::Credited
    }

    fn count_request(&self, addr: &str) {
        let m = self.minute.load(std::sync::atomic::Ordering::SeqCst);
        let start = self
            .db
            .field(T_RATE, addr, "rate_window_start")
            .and_then(|c| c.num());
        if start != Some(m) {
            self.db.put(
                T_RATE,
                addr,
                vec![
                    ("addr", Cell::Text(addr.to_string())),
                    ("rate_window_start", Cell::Num(m)),
                    ("rate_count", Cell::Num(0)),
                ],
            );
        }
        self.db.bump(T_RATE, addr, "rate_count", 1, vec![]);
    }
}

/// The domain separator `spark-identity` hashes ahead of a public key.
///
/// Duplicated rather than imported: this crate must not depend on
/// `spark-identity`, which sits in the client's graph. A test asserts the two
/// agree, so the duplication cannot drift.
fn spark_identity_addr_prefix() -> &'static [u8] {
    b"spark/v1/keyring/addr"
}
