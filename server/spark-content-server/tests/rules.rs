//! The content service's load-bearing rules, each easy to "improve" into a leak.
//! Tested here rather than in the gate so a regression names itself.

use spark_chunk::{Chunk, Kind, LaneId, Slot, media, room};
use spark_content_server::*;
use spark_crypto::blind::{TryCryptoRng, TryRng};
use spark_crypto::{IssuerKey, IssuerPublic, Secret, Token, TokenClaim};
use spark_store::Db;
use std::sync::OnceLock;

/// A deterministic RNG. Entropy is a parameter below the I/O line, and this is
/// what that buys: tests that give the same answer on every machine.
struct Fixed(u64);
impl TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for c in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        Ok(())
    }
}
impl TryCryptoRng for Fixed {}

/// One issuer key for the whole test binary: RSA keygen is slow, and every test
/// here is about the store's rules rather than about the issuer.
fn issuer() -> &'static IssuerKey {
    static K: OnceLock<IssuerKey> = OnceLock::new();
    K.get_or_init(|| IssuerKey::generate(&mut Fixed(42)).expect("keygen"))
}

fn svc() -> Content {
    Content::new(Db::new(), issuer().public())
}

/// A token authorising up to 1 MiB, with `n` as its serial.
fn tok(n: u8) -> (TokenClaim, Token) {
    let claim = TokenClaim {
        serial: [n; 32],
        size_class: 20,
    };
    let pk: IssuerPublic = issuer().public();
    let (bm, b) = pk
        .blind(&mut Fixed(n as u64 + 1), &claim.encode())
        .expect("blind");
    let sig = issuer().blind_sign(&bm).expect("sign");
    (
        claim,
        pk.finalize(b, &sig, &claim.encode()).expect("finalize"),
    )
}
fn hexed(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn a_name_is_write_once() {
    // The commit lane's arbitration point, and the backstop that makes derived
    // room-chunk nonces safe. A store that allowed overwrite would break the
    // AEAD, not merely the ordering.
    let c = svc();
    let root: room::RoomRoot = Secret::new([1; 32]);
    let (name, chunk) = room::seal(&root, Slot::new(LaneId::COMMIT, 0), &[7; 24], b"first");

    assert!(matches!(
        c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            claim: tok(1).0,
            token: tok(1).1
        }),
        Response::Stored { .. }
    ));
    // A second commit racing for the same slot loses and must retry at seq+1.
    assert_eq!(
        c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            claim: tok(2).0,
            token: tok(2).1
        }),
        Response::Refused(Refusal::NameTaken)
    );
}

#[test]
fn two_accounts_uploading_one_file_produce_one_chunk_and_two_charges() {
    let c = svc();
    let (name, _, chunk) = media::seal_raw(b"the same photograph");
    let mut receipts = Vec::new();
    for t in [tok(1), tok(2)] {
        match c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            claim: t.0,
            token: t.1,
        }) {
            Response::Stored { receipt } => receipts.push(receipt),
            r => panic!("refused: {r:?}"),
        }
    }
    assert_ne!(receipts[0], receipts[1], "two holders got one receipt");
    assert_eq!(c.db().keys(T_CHUNK).len(), 1, "one file became two chunks");
    assert_eq!(
        c.db().keys(T_TOKEN).len(),
        2,
        "the second upload was not charged"
    );
}

#[test]
fn a_duplicate_upload_is_indistinguishable_from_a_fresh_one() {
    // A discount, or a distinguishable response, would let anyone probe what
    // Spark holds (build-notes §4).
    let c = svc();
    let (name, _, chunk) = media::seal_raw(b"probe target");
    let first = c.handle(Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim: tok(1).0,
        token: tok(1).1,
    });
    let second = c.handle(Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim: tok(2).0,
        token: tok(2).1,
    });
    assert!(matches!(first, Response::Stored { .. }));
    assert!(
        matches!(second, Response::Stored { .. }),
        "a duplicate upload was answered differently: {second:?}"
    );
}

#[test]
fn a_token_cannot_be_spent_twice() {
    let c = svc();
    let (n1, _, c1) = media::seal_raw(b"one");
    let (n2, _, c2) = media::seal_raw(b"two");
    assert!(matches!(
        c.handle(Request::Put {
            name: *n1.as_bytes(),
            chunk: c1.as_bytes().to_vec(),
            claim: tok(9).0,
            token: tok(9).1
        }),
        Response::Stored { .. }
    ));
    assert_eq!(
        c.handle(Request::Put {
            name: *n2.as_bytes(),
            chunk: c2.as_bytes().to_vec(),
            claim: tok(9).0,
            token: tok(9).1
        }),
        Response::Refused(Refusal::TokenSpent)
    );
}

#[test]
fn a_forged_media_name_is_rejected_without_any_key() {
    // Hashing the finished chunk is what lets the store verify a name while
    // holding nothing. Without it, anyone could squat a name they cannot produce.
    let c = svc();
    let (name, _, _) = media::seal_raw(b"the real file");
    let impostor = Chunk::seal(
        Kind::Media,
        &Secret::new([3; 32]),
        &[3; 24],
        b"not the real file",
    );
    assert_eq!(
        c.handle(Request::Put {
            name: *name.as_bytes(),
            chunk: impostor.as_bytes().to_vec(),
            claim: tok(1).0,
            token: tok(1).1
        }),
        Response::Refused(Refusal::NameMismatch)
    );
}

#[test]
fn media_is_freed_at_zero_holders_and_room_chunks_by_deletion() {
    // "Room chunks are freed by deletion at dissolve; media chunks by receipt
    // count. They are not the same mechanism." (build-notes §4)
    let c = svc();
    let (mname, _, mchunk) = media::seal_raw(b"shared");
    let mut rs = Vec::new();
    for t in [tok(1), tok(2)] {
        match c.handle(Request::Put {
            name: *mname.as_bytes(),
            chunk: mchunk.as_bytes().to_vec(),
            claim: t.0,
            token: t.1,
        }) {
            Response::Stored { receipt } => rs.push(receipt),
            r => panic!("{r:?}"),
        }
    }
    match release(&c, *mname.as_bytes(), rs[0]) {
        Response::Released { freed, .. } => assert!(!freed, "freed while a holder remains"),
        r => panic!("{r:?}"),
    }
    assert!(c.db().has(T_CHUNK, &hexed(mname.as_bytes())));
    match release(&c, *mname.as_bytes(), rs[1]) {
        Response::Released { freed, .. } => assert!(freed, "bytes not freed at zero holders"),
        r => panic!("{r:?}"),
    }
    assert!(!c.db().has(T_CHUNK, &hexed(mname.as_bytes())));

    // Media cannot be deleted outright by one holder's say-so.
    let (m2, _, ch2) = media::seal_raw(b"still shared");
    c.handle(Request::Put {
        name: *m2.as_bytes(),
        chunk: ch2.as_bytes().to_vec(),
        claim: tok(5).0,
        token: tok(5).1,
    });
    assert_eq!(
        c.handle(Request::Delete {
            name: *m2.as_bytes(),
            receipt: [0; 32]
        }),
        Response::Refused(Refusal::BadReceipt)
    );

    // A room chunk is deleted outright at dissolve.
    let root: room::RoomRoot = Secret::new([1; 32]);
    let (rname, rchunk) = room::seal(&root, Slot::new(LaneId::COMMIT, 0), &[7; 24], b"history");
    let result = c.handle(Request::Put {
        name: *rname.as_bytes(),
        chunk: rchunk.as_bytes().to_vec(),
        claim: tok(6).0,
        token: tok(6).1,
    });
    let Response::Stored { receipt } = result else {
        panic!("upload")
    };
    assert_eq!(
        c.handle(Request::Delete {
            receipt,
            name: *rname.as_bytes()
        }),
        Response::Deleted
    );
    assert_eq!(
        c.handle(Request::Get {
            name: *rname.as_bytes()
        }),
        Response::Refused(Refusal::NotFound)
    );
    assert!(matches!(
        release(&c, *rname.as_bytes(), receipt),
        Response::Released { freed: true, .. }
    ));
    assert!(!c.db().has(T_CHUNK, &hexed(rname.as_bytes())));
}

#[test]
fn reads_carry_nothing_and_are_answered_to_anyone() {
    // The name plus the key is the whole capability. There is no session here to
    // authenticate against, which is the point.
    let c = svc();
    let (name, key, chunk) = media::seal_raw(b"readable by anyone who knows the name");
    c.handle(Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim: tok(1).0,
        token: tok(1).1,
    });
    match c.handle(Request::Get {
        name: *name.as_bytes(),
    }) {
        Response::Chunk(b) => {
            let got = Chunk::from_bytes(b).unwrap();
            assert_eq!(
                &media::open(&got, &key).unwrap()[..],
                b"readable by anyone who knows the name"
            );
        }
        r => panic!("{r:?}"),
    }
    assert_eq!(
        c.handle(Request::Head {
            name: *name.as_bytes()
        }),
        Response::Exists(true)
    );
    assert_eq!(
        c.handle(Request::Head { name: [9; 32] }),
        Response::Exists(false)
    );
}

fn release(c: &Content, name: [u8; 32], receipt: [u8; 32]) -> Response {
    let Response::RefundKey(der) = c.handle(Request::GetRefundKey(20)) else {
        panic!()
    };
    let pk = IssuerPublic::from_der(&der).unwrap();
    let claim = TokenClaim {
        serial: spark_crypto::sha256(&receipt),
        size_class: 20,
    };
    let (blinded, _) = pk.blind(&mut Fixed(21), &claim.refund_message()).unwrap();
    c.handle(Request::Release {
        name,
        receipt,
        size_class: 20,
        blinded,
    })
}
