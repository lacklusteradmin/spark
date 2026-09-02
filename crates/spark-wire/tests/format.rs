//! The wire format's claims, checked without a socket.

use spark_crypto::{Grant, Token, TokenClaim, VoucherClaim};
use spark_wire::*;

fn auth() -> Auth {
    Auth {
        addr: [1; 32],
        key: [2; 32],
        sig: vec![3; 64],
    }
}

fn token() -> Token {
    Token {
        sig: vec![9; 256],
        randomizer: [4; 32],
    }
}

#[test]
fn every_request_round_trips() {
    let reqs: Vec<keyring::Req> = vec![
        keyring::Req::Challenge { addr: [7; 32] },
        keyring::Req::GetSnapshot(auth()),
        keyring::Req::GetDeltas(auth()),
        keyring::Req::PutDelta(auth(), vec![1, 2, 3]),
        keyring::Req::PutSnapshot(auth(), vec![4, 5]),
        keyring::Req::GetQuota(auth()),
        keyring::Req::WithdrawTokens {
            auth: auth(),
            blinded: vec![vec![1; 8]],
            size_class: 12,
        },
        keyring::Req::CreditRefund(auth(), vec![6], 512),
        keyring::Req::PutRequest {
            addr: [8; 32],
            blob: vec![9],
            token: vec![10],
        },
        keyring::Req::GetRequests(auth()),
        keyring::Req::DropRequest(auth(), 3),
        keyring::Req::GetIssuerKey,
    ];
    for r in reqs {
        let f = Frame::encode(17, &r).expect("encode");
        let back = Frame::from_bytes(&f.to_bytes()).expect("parse");
        assert_eq!(back.req_id, 17);
        assert_eq!(back.body::<keyring::Req>().expect("decode"), r);
    }
}

#[test]
fn the_content_protocol_round_trips() {
    let claim = TokenClaim {
        serial: [5; 32],
        size_class: 20,
    };
    let reqs = vec![
        content::Req::Put {
            name: [1; 32],
            chunk: vec![2; 100],
            claim,
            token: token(),
        },
        content::Req::Get { name: [3; 32] },
        content::Req::Head { name: [4; 32] },
        content::Req::Release {
            name: [5; 32],
            receipt: [6; 32],
        },
        content::Req::Delete { name: [7; 32] },
    ];
    for r in reqs {
        let f = Frame::encode(1, &r).unwrap();
        assert_eq!(
            Frame::from_bytes(&f.to_bytes())
                .unwrap()
                .body::<content::Req>()
                .unwrap(),
            r
        );
    }
}

#[test]
fn the_issuer_protocol_round_trips() {
    let claim = VoucherClaim {
        serial: [1; 32],
        grant: Grant::NameMonths {
            months: 12,
            premium: false,
        },
    };
    let reqs = vec![
        issuer::Req::Resolve {
            name: "riverbank".into(),
            today: 20_000,
        },
        issuer::Req::Purchase {
            blinded: vec![1; 32],
            payment: vec![2; 8],
            amount: 60,
        },
        issuer::Req::Register {
            name: "riverbank".into(),
            key: vec![3; 64],
            claim,
            voucher: token(),
            today: 20_000,
        },
        issuer::Req::Renew {
            name: "r".into(),
            claim,
            voucher: token(),
            today: 20_000,
        },
        issuer::Req::Transfer {
            name: "r".into(),
            new_key: vec![4; 64],
            sig: vec![5; 64],
        },
        issuer::Req::GetIssuerKey,
    ];
    for r in reqs {
        let f = Frame::encode(1, &r).unwrap();
        assert_eq!(
            Frame::from_bytes(&f.to_bytes())
                .unwrap()
                .body::<issuer::Req>()
                .unwrap(),
            r
        );
    }
}

#[test]
fn the_opcode_and_the_payload_never_disagree() {
    // The opcode duplicates postcard's variant tag. That is deliberate — a server
    // dispatches on the header before decoding anything an attacker chose — but a
    // duplication nobody checks is a duplication that drifts.
    let cases: Vec<(u8, Vec<u8>)> = vec![
        (
            0,
            Frame::encode(0, &keyring::Req::Challenge { addr: [0; 32] })
                .unwrap()
                .payload,
        ),
        (
            11,
            Frame::encode(0, &keyring::Req::GetIssuerKey)
                .unwrap()
                .payload,
        ),
        (
            1,
            Frame::encode(0, &content::Req::Get { name: [0; 32] })
                .unwrap()
                .payload,
        ),
        (
            5,
            Frame::encode(0, &issuer::Req::GetIssuerKey)
                .unwrap()
                .payload,
        ),
    ];
    for (op, payload) in cases {
        assert_eq!(
            payload[0], op,
            "postcard's variant tag drifted from the declared opcode"
        );
    }
}

#[test]
fn a_frame_whose_header_lies_about_its_body_is_rejected() {
    // The header is what a server dispatched on. If it says one thing and the
    // body is another, trusting the body would mean the dispatch was a lie.
    let mut f = Frame::encode(1, &keyring::Req::GetIssuerKey).unwrap();
    f.op = 0; // claim it is a Challenge
    assert_eq!(
        f.body::<keyring::Req>().unwrap_err(),
        WireError::OpcodeMismatch
    );
}

#[test]
fn a_truncated_or_oversized_frame_is_refused() {
    assert_eq!(
        Frame::from_bytes(&[1, 2, 3]).unwrap_err(),
        WireError::Truncated
    );
    assert_eq!(Frame::from_bytes(&[]).unwrap_err(), WireError::Truncated);

    let huge = vec![0u8; MAX_FRAME + 1];
    assert_eq!(Frame::from_bytes(&huge).unwrap_err(), WireError::TooLarge);

    // And a body too large to frame is refused at encode time, not sent and then
    // rejected by the peer.
    let big = content::Req::Put {
        name: [0; 32],
        chunk: vec![0; MAX_FRAME],
        claim: TokenClaim {
            serial: [0; 32],
            size_class: 30,
        },
        token: token(),
    };
    assert_eq!(Frame::encode(0, &big).unwrap_err(), WireError::TooLarge);
}

#[test]
fn garbage_does_not_decode_into_a_request() {
    let f = Frame {
        req_id: 1,
        op: 0,
        payload: vec![0xff; 64],
    };
    assert!(matches!(
        f.body::<keyring::Req>(),
        Err(WireError::Malformed) | Err(WireError::OpcodeMismatch)
    ));
}

#[test]
fn the_header_is_exactly_what_the_protocol_says() {
    // docs/protocol.md §6: `frame := req_id: u32le || opcode: u8 || payload`.
    let f = Frame {
        req_id: 0x0403_0201,
        op: 0x2a,
        payload: vec![0xaa, 0xbb],
    };
    assert_eq!(f.to_bytes(), vec![0x01, 0x02, 0x03, 0x04, 0x2a, 0xaa, 0xbb]);
    assert_eq!(HEADER, 5);
}

#[test]
fn the_issuer_protocol_has_no_way_to_enumerate() {
    // F5: names resolve but are not browsable. Enforced by the shape of the enum,
    // not by a filter on an endpoint someone could later relax.
    let src = include_str!("../src/issuer.rs");
    let start = src.find("pub enum Req").expect("Req enum");
    let end = src[start..].find("\n}").expect("enum ends") + start;
    let fields: String = src[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("///") && !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["List", "Search", "Prefix", "Scan", "All", "Count"] {
        assert!(
            !fields.contains(banned),
            "the issuer protocol gained `{banned}`"
        );
    }
}

#[test]
fn no_content_operation_carries_an_identity() {
    // The strongest claim the content service makes, checked against the protocol
    // rather than the implementation: writes carry a blind token, reads nothing.
    let src = include_str!("../src/content.rs");
    let start = src.find("pub enum Req").expect("Req enum");
    let end = src[start..].find("\n}").expect("enum ends") + start;
    // Fields, not prose. The doc comments legitimately say "signature" — of the
    // *issuer*, over a blind token — and a check that reads them is checking the
    // wrong thing.
    let fields: String = src[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("///") && !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["Auth", "addr", "pubkey", "signature", "account", "sig:"] {
        assert!(
            !fields.contains(banned),
            "the content protocol gained `{banned}`: writes are authorised by token, never identity"
        );
    }
}
