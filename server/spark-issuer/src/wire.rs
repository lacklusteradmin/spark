//! Conversion between the protocol and this service's own types.

use crate::{Issuer, Refusal, Request, Response};
use spark_wire::issuer as w;

impl Issuer {
    /// Handle one protocol request.
    pub fn handle_wire(&self, req: w::Req) -> w::Resp {
        match from_wire(req) {
            Some(r) => self.handle(r).into(),
            None => w::Resp::Refused(w::Refusal::BadName),
        }
    }
}

fn key64(v: Vec<u8>) -> Option<[u8; 64]> {
    v.try_into().ok()
}

fn from_wire(r: w::Req) -> Option<Request> {
    Some(match r {
        w::Req::Resolve { name, today } => Request::Resolve(name, today),
        w::Req::Purchase {
            blinded,
            payment,
            amount,
        } => Request::Purchase {
            blinded,
            payment,
            amount,
        },
        w::Req::Register {
            name,
            key,
            claim,
            voucher,
            today,
        } => Request::Register {
            name,
            key: key64(key)?,
            claim,
            voucher,
            today,
        },
        w::Req::Renew {
            name,
            claim,
            voucher,
            today,
        } => Request::Renew {
            name,
            claim,
            voucher,
            today,
        },
        w::Req::Transfer { name, new_key, sig } => Request::Transfer {
            name,
            new_key: key64(new_key)?,
            sig: sig.try_into().ok()?,
        },
        w::Req::GetIssuerKey => Request::IssuerKey,
    })
}

impl From<Response> for w::Resp {
    fn from(r: Response) -> Self {
        match r {
            Response::Resolved(k) => w::Resp::Resolved(k.map(|x| x.to_vec())),
            Response::Signed(s) => w::Resp::Signed(s),
            Response::Registered => w::Resp::Registered,
            Response::Renewed(d) => w::Resp::Renewed(d),
            Response::Transferred => w::Resp::Transferred,
            Response::IssuerKey(k) => w::Resp::IssuerKey(k),
            Response::Refused(x) => w::Resp::Refused(match x {
                Refusal::Taken => w::Refusal::Taken,
                Refusal::Unknown => w::Refusal::Unknown,
                Refusal::BadSignature => w::Refusal::BadSignature,
                Refusal::VoucherSpent => w::Refusal::VoucherSpent,
                Refusal::BadVoucher => w::Refusal::BadVoucher,
                Refusal::WrongGrant => w::Refusal::WrongGrant,
                Refusal::PaymentSpent => w::Refusal::PaymentSpent,
                Refusal::Underpaid => w::Refusal::Underpaid,
                Refusal::BadName => w::Refusal::BadName,
            }),
        }
    }
}
