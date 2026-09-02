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
        match from_wire(req) {
            Some(r) => self.handle(r).into(),
            None => w::Resp::Refused(w::Refusal::BadAuth),
        }
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
        w::Req::PutSnapshot(a, b) => Request::PutSnapshot(auth(a)?, b),
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
        w::Req::PutRequest { addr, blob, token } => Request::PutRequest { addr, blob, token },
        w::Req::GetRequests(a) => Request::GetRequests(auth(a)?),
        w::Req::DropRequest(a, i) => Request::DropRequest(auth(a)?, i),
        w::Req::GetIssuerKey => Request::GetIssuerKey,
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
