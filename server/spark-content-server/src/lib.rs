//! trust domain 2: account-free chunk store, write-once, receipts.
//!
//! layer 10, zone `io` — see `docs/layering.toml`.
//!
//! This service has **no accounts**. There is no login, no session, and no column
//! anywhere below that could name a writer. `docs/protocol.md` §6.2: writes carry
//! a blind token, reads carry nothing at all.
//!
//! Three rules here are each load-bearing for something in the spec, and each is
//! easy to "improve" into a leak:
//!
//! * **Write-once per name.** The commit lane's arbitration point (§4) and the
//!   backstop that makes derived room-chunk nonces safe (§3.2). A store that
//!   allowed overwrite would silently break the AEAD, not merely the ordering.
//! * **No discount for a chunk that already exists.** A cheaper duplicate upload
//!   would let anyone probe what Spark holds (build-notes §4). The token is spent
//!   either way, and the caller is told nothing about which case occurred.
//! * **Receipts are opaque and counted, not owned.** The store learns how many
//!   unknown parties hold a chunk, never who. Media is freed at zero; room chunks
//!   are freed by outright deletion at dissolve. They are not the same mechanism.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use spark_chunk::{Chunk, Kind, media};
use spark_crypto::{IssuerPublic, Token, TokenClaim};
use spark_store::{Cell, Db};

/// Table of stored chunks, keyed by chunk name.
pub const T_CHUNK: &str = "chunk";
/// Table of outstanding receipts, keyed by `chunk_name:receipt_hash`.
pub const T_RECEIPT: &str = "receipt";
/// Table of spent token serials, keyed by serial.
pub const T_TOKEN: &str = "token_spent";

/// A request to the content service.
#[derive(Clone, Debug)]
pub enum Request {
    /// Store a chunk, authorised by a blind token and nothing else.
    Put {
        /// The claimed name.
        name: [u8; 32],
        /// The sealed chunk.
        chunk: Vec<u8>,
        /// What the token authorises: a serial the client chose and a size class.
        claim: TokenClaim,
        /// The issuer's signature over that claim. This service verifies it and
        /// learns nothing else — not who drew the token, not when, not for what.
        token: Token,
    },
    /// Fetch a chunk. Unauthenticated by design.
    Get {
        /// The name, which with the key is the whole capability.
        name: [u8; 32],
    },
    /// Ask whether a name exists. Unauthenticated.
    Head {
        /// The name.
        name: [u8; 32],
    },
    /// Return a receipt, decrementing the holder count.
    Release {
        /// The chunk.
        name: [u8; 32],
        /// The receipt issued at upload.
        receipt: [u8; 32],
    },
    /// Delete a room chunk outright, at dissolve.
    Delete {
        /// The chunk.
        name: [u8; 32],
    },
}

/// A response from the content service.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// Stored. The receipt releases it later and refunds quota.
    Stored {
        /// Opaque, random, and the only thing tying an uploader to a chunk —
        /// held by the uploader, never by the store.
        receipt: [u8; 32],
    },
    /// The chunk bytes.
    Chunk(Vec<u8>),
    /// Whether a name exists.
    Exists(bool),
    /// Released. The refund voucher crosses the anonymity seam (§7).
    Released {
        /// Whether the bytes were freed, meaning the count reached zero.
        freed: bool,
        /// A blinded refund voucher, which the store cannot link to the release.
        voucher: Vec<u8>,
    },
    /// Deleted.
    Deleted,
    /// Refused, with a reason that tells the caller nothing it did not know.
    Refused(Refusal),
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// A chunk already exists under that name. Write-once.
    NameTaken,
    /// The claimed name does not match `SHA-256(chunk)` for a media chunk.
    NameMismatch,
    /// The bytes are not a well-formed chunk.
    Malformed,
    /// That token serial has already been spent.
    TokenSpent,
    /// The token does not verify under the issuer's key.
    BadToken,
    /// The chunk is larger than the token's size class allows.
    TooLarge,
    /// No such name.
    NotFound,
    /// The receipt does not match any outstanding holder of that chunk.
    BadReceipt,
    /// `Delete` is for room chunks only; media is freed by receipt count.
    NotDeletable,
}

/// The content service.
#[derive(Clone)]
pub struct Content {
    db: Db,
    issuer: IssuerPublic,
    /// Supplies receipts and voucher blinding. A parameter, not a syscall — the
    /// same discipline as everywhere below the I/O line, and it keeps this
    /// service's tests deterministic.
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Content {
    /// A service over `db`.
    /// A service over `db`, verifying tokens against the issuer's public key.
    ///
    /// Only the public half. This service cannot mint a token, and therefore
    /// cannot forge the evidence that someone paid for an upload.
    pub fn new(db: Db, issuer: IssuerPublic) -> Self {
        Self {
            db,
            issuer,
            counter: Default::default(),
        }
    }

    /// The store, for the permitted-knowledge audit.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Deterministic stand-in for the random receipts and blinded vouchers the
    /// real service issues. Stage 8 replaces this with RFC 9474.
    fn opaque(&self) -> [u8; 32] {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out[8..16].copy_from_slice(b"receipt-");
        out
    }

    /// Handle one request.
    pub fn handle(&self, req: Request) -> Response {
        match req {
            Request::Put {
                name,
                chunk,
                claim,
                token,
            } => self.put(name, chunk, claim, token),
            Request::Get { name } => match self.db.field(T_CHUNK, &hex(&name), "chunk_bytes") {
                Some(Cell::Bytes(b)) => Response::Chunk(b),
                _ => Response::Refused(Refusal::NotFound),
            },
            Request::Head { name } => Response::Exists(self.db.has(T_CHUNK, &hex(&name))),
            Request::Release { name, receipt } => self.release(name, receipt),
            Request::Delete { name } => self.delete(name),
        }
    }

    fn put(&self, name: [u8; 32], bytes: Vec<u8>, claim: TokenClaim, token: Token) -> Response {
        // Verify before spending: an unsigned serial must not be able to burn a
        // slot in the spent list, or anyone could lock out a token they guessed.
        if self.issuer.verify(&token, &claim.encode()).is_err() {
            return Response::Refused(Refusal::BadToken);
        }
        if bytes.len() as u64 > claim.max_bytes() {
            return Response::Refused(Refusal::TooLarge);
        }

        // The serial is the only thing recorded, and the client chose it. It says
        // nothing about who drew the token, which is the entire point of signing
        // it blind.
        let serial = hex(&claim.serial);
        // Spend it whatever happens next. Refunding on a duplicate would be
        // exactly the discount that lets a caller probe what the store holds.
        if !self.db.put_if_absent(
            T_TOKEN,
            &serial,
            vec![("spent_token_serial", Cell::Bytes(claim.serial.to_vec()))],
        ) {
            return Response::Refused(Refusal::TokenSpent);
        }

        let Ok(chunk) = Chunk::from_bytes(bytes.clone()) else {
            return Response::Refused(Refusal::Malformed);
        };
        let Ok(kind) = chunk.kind() else {
            return Response::Refused(Refusal::Malformed);
        };

        // A media name is the hash of the finished chunk, so the store can verify
        // it holding no key at all — which is what closes name squatting. A room
        // chunk name is an HMAC under a secret the store does not have, so it is
        // accepted as claimed. The asymmetry is deliberate (§6.2).
        if kind == Kind::Media && media::name_of(&chunk).as_bytes() != &name {
            return Response::Refused(Refusal::NameMismatch);
        }

        let key = hex(&name);
        let receipt = self.opaque();
        let stored = self.db.put_if_absent(
            T_CHUNK,
            &key,
            vec![
                ("chunk_name", Cell::Text(key.clone())),
                ("chunk_bytes", Cell::Bytes(bytes.clone())),
                ("chunk_len", Cell::Num(bytes.len() as u64)),
                ("chunk_kind", Cell::Num(kind as u8 as u64)),
                ("receipt_count", Cell::Num(0)),
            ],
        );
        if !stored {
            // Already held. The caller still pays, still gets a receipt, and is
            // told nothing that distinguishes this from a fresh upload.
            if kind == Kind::RoomLog {
                // Except here: a taken room-chunk name is the commit lane losing
                // its CAS, and the loser must know to retry at the next seq.
                return Response::Refused(Refusal::NameTaken);
            }
        }
        self.db.bump(T_CHUNK, &key, "receipt_count", 1, vec![]);
        self.db.put(
            T_RECEIPT,
            &format!("{key}:{}", hex(&receipt)),
            vec![
                ("chunk_name", Cell::Text(key)),
                ("receipt_hash", Cell::Bytes(receipt.to_vec())),
            ],
        );
        Response::Stored { receipt }
    }

    fn release(&self, name: [u8; 32], receipt: [u8; 32]) -> Response {
        let key = hex(&name);
        let rkey = format!("{key}:{}", hex(&receipt));
        if !self.db.has(T_RECEIPT, &rkey) {
            return Response::Refused(Refusal::BadReceipt);
        }
        self.db.delete(T_RECEIPT, &rkey);
        self.db.bump(T_CHUNK, &key, "receipt_count", -1, vec![]);

        let count = self
            .db
            .field(T_CHUNK, &key, "receipt_count")
            .and_then(|c| c.num())
            .unwrap_or(0);
        let freed = count == 0;
        if freed {
            self.db.delete(T_CHUNK, &key);
        }
        // The voucher is blinded: the store does not know whose release it just
        // signed, which is what stops the refund rejoining upload to identity.
        Response::Released {
            freed,
            voucher: self.opaque().to_vec(),
        }
    }

    fn delete(&self, name: [u8; 32]) -> Response {
        let key = hex(&name);
        match self
            .db
            .field(T_CHUNK, &key, "chunk_kind")
            .and_then(|c| c.num())
        {
            None => Response::Refused(Refusal::NotFound),
            Some(k) if k == Kind::RoomLog as u8 as u64 => {
                for r in self.db.keys(T_RECEIPT) {
                    if r.starts_with(&format!("{key}:")) {
                        self.db.delete(T_RECEIPT, &r);
                    }
                }
                self.db.delete(T_CHUNK, &key);
                Response::Deleted
            }
            // Media is shared, so it is freed by receipt count and never by one
            // holder's say-so (build-notes §4).
            Some(_) => Response::Refused(Refusal::NotDeletable),
        }
    }
}
