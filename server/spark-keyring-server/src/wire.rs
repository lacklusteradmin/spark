//! Conversion between the protocol and this service's own types.

use crate::{Auth, Keyring, Refusal, Request, Response};
use spark_wire::keyring as w;

impl Keyring {
    /// Handle one protocol request.
    ///
    /// A malformed signature length is refused here rather than deeper in: the
    /// protocol carries it as a `Vec` because serde stops deriving arrays at 32,
    /// so this is where that becomes a fixed-size array again.
    pub fn handle_wire(&self, req: w::Req) -> w::Resp {
        let transaction = self.db.transaction().expect("auth transaction");
        let mut inspect = req.clone();
        let verified = if let Some(proof) = inspect.auth_mut() {
            let expected =
                spark_crypto::sha256_parts(&[super::spark_identity_addr_prefix(), &proof.key]);
            let valid = expected == proof.addr
                && proof.challenge == self.challenge(&proof.addr)
                && proof.nonce != [0; 32]
                && spark_crypto::VerifyingKey::from_bytes(&proof.key)
                    .ok()
                    .is_some_and(|key| {
                        proof.sig.as_slice().try_into().ok().is_some_and(|bytes| {
                            key.verify(
                                &req.signing_bytes(),
                                &spark_crypto::Signature::from_bytes(bytes),
                            )
                            .is_ok()
                        })
                    });
            if !valid {
                return w::Resp::Refused(w::Refusal::BadAuth);
            }
            let minute = self.now_minute();
            // Persist a high-water mark: a backward clock jump must not revive
            // challenges whose spent nonces have already been pruned.
            let last = self
                .db
                .field("auth_window", "current", "minute")
                .and_then(|c| c.num())
                .unwrap_or(0);
            if minute < last {
                return w::Resp::Refused(w::Refusal::BadAuth);
            }
            let count = if minute == last {
                self.db
                    .field("auth_window", "current", "count")
                    .and_then(|c| c.num())
                    .unwrap_or(0)
            } else {
                0
            };
            if count >= 65_536 {
                return w::Resp::Refused(w::Refusal::OverQuota);
            }
            let prefix = format!("{minute:020}:");
            let replay = format!(
                "{prefix}{}:{}",
                super::hex(&proof.addr),
                super::hex(&proof.nonce)
            );
            // This is an indexed range delete, not a scan/decoding of all records.
            self.db.delete_before("auth_spent", &prefix);
            if !self.db.put_if_absent(
                "auth_spent",
                &replay,
                vec![("auth_nonce", spark_store::Cell::Bytes(proof.nonce.to_vec()))],
            ) {
                return w::Resp::Refused(w::Refusal::BadAuth);
            }
            self.db.put(
                "auth_window",
                "current",
                vec![
                    ("minute", spark_store::Cell::Num(minute)),
                    ("count", spark_store::Cell::Num(count + 1)),
                ],
            );
            true
        } else {
            false
        };
        let response = match from_wire(req) {
            Some(r) => self.handle_inner(r, verified).into(),
            None => w::Resp::Refused(w::Refusal::BadAuth),
        };
        transaction.commit().expect("auth commit");
        response
    }
}

fn auth(a: spark_wire::Auth) -> Option<Auth> {
    Some(Auth {
        addr: a.addr,
        key: a.key,
        sig: a.sig.try_into().ok()?,
    })
}

fn from_wire(r: w::Req) -> Option<Request> {
    Some(match r {
        w::Req::Challenge { addr } => Request::Challenge { addr },
        w::Req::GetSnapshot(a) => Request::GetSnapshot(auth(a)?),
        w::Req::GetDeltas(a) => Request::GetDeltas(auth(a)?),
        w::Req::PutDelta(a, b) => Request::PutDelta(auth(a)?, b),
        w::Req::PutSnapshot(a, b, expected, permits) => {
            Request::PutSnapshot(auth(a)?, b, expected, permits)
        }
        w::Req::GetQuota(a) => Request::GetQuota(auth(a)?),
        w::Req::WithdrawTokens {
            auth: a,
            blinded,
            size_class,
        } => Request::WithdrawTokens {
            auth: auth(a)?,
            blinded,
            size_class,
        },
        w::Req::CreditRefund(a, v, n) => Request::CreditRefund(auth(a)?, v, n),
        w::Req::SetContacts(a, permits) => Request::SetContacts(auth(a)?, permits),
        w::Req::PutRequest { addr, blob, permit } => Request::PutRequest { addr, blob, permit },
        w::Req::GetRequests(a) => Request::GetRequests(auth(a)?),
        w::Req::DropRequest(a, i) => Request::DropRequest(auth(a)?, i),
        w::Req::GetIssuerKey(c) => Request::GetIssuerKey(c),
    })
}

impl From<Response> for w::Resp {
    fn from(r: Response) -> Self {
        match r {
            Response::Challenge(c) => w::Resp::Challenge(c),
            Response::Snapshot(s) => w::Resp::Snapshot(s),
            Response::Deltas(d) => w::Resp::Deltas(d),
            Response::Appended { index, compact } => w::Resp::Appended { index, compact },
            Response::SnapshotWritten => w::Resp::SnapshotWritten,
            Response::Quota { used, limit } => w::Resp::Quota { used, limit },
            Response::Tokens(t) => w::Resp::Tokens(t),
            Response::IssuerKey(k) => w::Resp::IssuerKey(k),
            Response::Credited => w::Resp::Credited,
            Response::RequestTaken => w::Resp::RequestTaken,
            Response::Requests(r) => w::Resp::Requests(r),
            Response::RequestDropped => w::Resp::RequestDropped,
            Response::Refused(x) => w::Resp::Refused(match x {
                Refusal::BadAuth => w::Refusal::BadAuth,
                Refusal::AddrMismatch => w::Refusal::AddrMismatch,
                Refusal::Malformed => w::Refusal::Malformed,
                Refusal::OverQuota => w::Refusal::OverQuota,
                Refusal::VoucherSpent => w::Refusal::VoucherSpent,
            }),
        }
    }
}
