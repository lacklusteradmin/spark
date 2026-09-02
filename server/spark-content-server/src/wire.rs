//! Conversion between the protocol and this service's own types.
//!
//! `spark-wire` is the protocol; the types in this crate are the implementation.
//! Keeping them apart means a change to either shows up here, as a change to the
//! mapping, rather than one silently becoming the other.

use crate::{Content, Refusal, Request, Response};
use spark_wire::content as w;

impl Content {
    /// Handle one protocol request.
    pub fn handle_wire(&self, req: w::Req) -> w::Resp {
        self.handle(from_wire(req)).into()
    }
}

fn from_wire(r: w::Req) -> Request {
    match r {
        w::Req::Put {
            name,
            chunk,
            claim,
            token,
        } => Request::Put {
            name,
            chunk,
            claim,
            token,
        },
        w::Req::Get { name } => Request::Get { name },
        w::Req::Head { name } => Request::Head { name },
        w::Req::Release { name, receipt } => Request::Release { name, receipt },
        w::Req::Delete { name } => Request::Delete { name },
    }
}

impl From<Response> for w::Resp {
    fn from(r: Response) -> Self {
        match r {
            Response::Stored { receipt } => w::Resp::Stored { receipt },
            Response::Chunk(b) => w::Resp::Chunk(b),
            Response::Exists(e) => w::Resp::Exists(e),
            Response::Released { freed, voucher } => w::Resp::Released { freed, voucher },
            Response::Deleted => w::Resp::Deleted,
            Response::Refused(x) => w::Resp::Refused(match x {
                Refusal::NameTaken => w::Refusal::NameTaken,
                Refusal::NameMismatch => w::Refusal::NameMismatch,
                Refusal::Malformed => w::Refusal::Malformed,
                Refusal::TokenSpent => w::Refusal::TokenSpent,
                Refusal::BadToken => w::Refusal::BadToken,
                Refusal::TooLarge => w::Refusal::TooLarge,
                Refusal::NotFound => w::Refusal::NotFound,
                Refusal::BadReceipt => w::Refusal::BadReceipt,
                Refusal::NotDeletable => w::Refusal::NotDeletable,
            }),
        }
    }
}
