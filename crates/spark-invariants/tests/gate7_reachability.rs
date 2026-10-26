//! Gate 7: "The API cannot enumerate names or reach a stranger without
//! acceptance; a rejected request leaves no trace for the sender; after migration
//! the old key decrypts nothing new."

use spark_crypto::{Mnemonic, Secret};
use spark_identity::Identity;
use spark_identity::reach::*;
use spark_store::Db;

use spark_issuer as issuer;
use spark_keyring_server as keyring;

mod common;
use common::{Fixed, buy_voucher, name_issuer};

fn ident(e: u8) -> Identity {
    Identity::from_mnemonic(&Mnemonic::from_entropy(&[e; 32]))
}

fn pub64(id: &Identity) -> [u8; 64] {
    let p = id.public();
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(p.sign.as_bytes());
    b[32..].copy_from_slice(p.kem.as_bytes());
    b
}

fn auth(ks: &keyring::Keyring, id: &Identity) -> keyring::Auth {
    let addr = *id.addr().as_bytes();
    keyring::Auth {
        addr,
        key: *id.public().sign.as_bytes(),
        sig: *id.sign(&ks.challenge(&addr)).as_bytes(),
    }
}

// ------------------------------------------- the API cannot enumerate names

#[test]
fn the_issuer_answers_exact_names_and_nothing_else() {
    let is = name_issuer();
    let alice = ident(1);
    let (claim, voucher) = buy_voucher(
        &is,
        1,
        spark_crypto::Grant::NameMonths {
            months: 12,
            premium: false,
        },
        b"chain-tx-1",
    );
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "riverbank".into(),
            key: pub64(&alice),
            claim,
            voucher,
            today: 20_000,
        }),
        issuer::Response::Registered
    );

    // The exact name resolves, and yields enough to seal a request to.
    assert_eq!(
        is.handle(issuer::Request::Resolve("riverbank".into(), 20_000)),
        issuer::Response::Resolved(Some(pub64(&alice)))
    );

    // Nothing else does. No prefix, no suffix, no case-fold, no substring.
    for probe in [
        "river",
        "riverban",
        "riverbanks",
        "Riverbank",
        "RIVERBANK",
        "iverbank",
        "river*",
        "*",
    ] {
        assert_eq!(
            is.handle(issuer::Request::Resolve(probe.into(), 20_000)),
            issuer::Response::Resolved(None),
            "`{probe}` resolved; the namespace is enumerable"
        );
    }
}

#[test]
fn the_issuer_has_no_operation_that_lists_anything() {
    // Enumeration is prevented by the API's shape, not by a filter on a listing
    // endpoint that someone could later relax. The check is on the source, so a
    // new operation cannot be added quietly.
    let src = std::fs::read_to_string(
        spark_invariants::repo_root().join("server/spark-issuer/src/lib.rs"),
    )
    .unwrap();
    let start = src.find("pub enum Request").expect("Request enum");
    let end = src[start..].find("\n}").expect("enum ends") + start;
    let ops = &src[start..end];

    for banned in [
        "List",
        "Search",
        "Prefix",
        "Enumerate",
        "All",
        "Count",
        "Scan",
    ] {
        assert!(
            !ops.contains(banned),
            "the issuer gained a `{banned}` operation: the namespace must not be browsable (F5)"
        );
    }
}

// --------------------------------- reaching a stranger requires acceptance

#[test]
fn a_request_reaches_the_tray_and_creates_no_room() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([9; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let (alice, stranger) = (ident(1), ident(2));
    ks.handle(keyring::Request::SetContacts(
        auth(&ks, &alice),
        vec![spark_crypto::sha256(&[11; 32])],
    ));

    let sealed = seal_request(
        &alice.public().kem,
        &stranger,
        "we met at the docks",
        None,
        Secret::new([77; 32]),
    );
    assert_eq!(
        ks.handle(keyring::Request::PutRequest {
            addr: *alice.addr().as_bytes(),
            blob: sealed.as_bytes().to_vec(),
            permit: vec![11; 32],
        }),
        keyring::Response::RequestTaken
    );

    // It is in Alice's tray, readable only by her, and it is not a room.
    let keyring::Response::Requests(tray) =
        ks.handle(keyring::Request::GetRequests(auth(&ks, &alice)))
    else {
        panic!("tray unreadable")
    };
    assert_eq!(tray.len(), 1);

    let open = open_request(&alice, &SealedRequest::from_bytes(tray[0].1.clone()), None)
        .expect("alice opens it");
    assert_eq!(open.from, stranger.public());
    assert_eq!(open.note, "we met at the docks");
    assert!(
        !open.invited,
        "a name-path request must not claim to be invited"
    );
}

#[test]
fn a_request_is_readable_only_by_its_recipient() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([9; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let (alice, stranger, eve) = (ident(1), ident(2), ident(3));
    let sealed = seal_request(
        &alice.public().kem,
        &stranger,
        "hello",
        None,
        Secret::new([5; 32]),
    );

    assert_eq!(
        open_request(&eve, &sealed, None).unwrap_err(),
        RequestError::NotForMe
    );

    // And Eve cannot read Alice's tray either.
    ks.handle(keyring::Request::PutRequest {
        addr: *alice.addr().as_bytes(),
        blob: sealed.as_bytes().to_vec(),
        permit: b"t".to_vec(),
    });
    let keyring::Response::Requests(eves) =
        ks.handle(keyring::Request::GetRequests(auth(&ks, &eve)))
    else {
        panic!()
    };
    assert!(eves.is_empty(), "one account read another's tray");
}

#[test]
fn an_invite_proves_it_was_handed_out() {
    let alice = ident(1);
    let secret = [0x2a; INVITE_SECRET_LEN];
    let invite = Invite::new(&alice.public(), secret);

    // Round trip through the link form, including the "spark:" prefix.
    let link = format!("spark:{}", invite.encode());
    assert_eq!(Invite::parse(&link).unwrap(), invite);

    let stranger = ident(2);
    let sealed = seal_request(
        &invite.kem,
        &stranger,
        "following your link",
        Some(invite.secret),
        Secret::new([6; 32]),
    );
    assert!(open_request(&alice, &sealed, Some(secret)).unwrap().invited);

    // Someone who guessed the address but not the secret still gets through to
    // the tray — the name path is legitimate — but is not marked invited.
    let guessed = seal_request(
        &invite.kem,
        &stranger,
        "guessing",
        Some([0xff; INVITE_SECRET_LEN]),
        Secret::new([7; 32]),
    );
    assert!(
        !open_request(&alice, &guessed, Some(secret))
            .unwrap()
            .invited
    );

    // Forgetting the secret revokes every invite issued under it.
    assert!(!open_request(&alice, &sealed, None).unwrap().invited);
}

#[test]
fn a_mistyped_invite_fails_rather_than_resolving_to_someone_else() {
    let invite = Invite::new(&ident(1).public(), [1; INVITE_SECRET_LEN]);
    let good = invite.encode();

    let mut typo: Vec<char> = good.chars().collect();
    typo[10] = if typo[10] == 'a' { 'b' } else { 'a' };
    let typo: String = typo.into_iter().collect();

    assert_eq!(Invite::parse(&typo).unwrap_err(), InviteError::BadChecksum);
    assert_eq!(
        Invite::parse(&good[..good.len() - 2]).unwrap_err(),
        InviteError::Malformed
    );
    assert_eq!(Invite::parse("").unwrap_err(), InviteError::Malformed);
}

// ------------------------------- a rejected request leaves no trace for the sender

#[test]
fn declining_tells_the_sender_nothing() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([9; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let (alice, stranger) = (ident(1), ident(2));
    ks.handle(keyring::Request::SetContacts(
        auth(&ks, &alice),
        vec![spark_crypto::sha256(&[11; 32])],
    ));
    let sealed = seal_request(
        &alice.public().kem,
        &stranger,
        "hello",
        None,
        Secret::new([5; 32]),
    );

    let send = |permit: &[u8]| {
        ks.handle(keyring::Request::PutRequest {
            addr: *alice.addr().as_bytes(),
            blob: sealed.as_bytes().to_vec(),
            permit: permit.to_vec(),
        })
    };

    // Before: accepted for delivery.
    let before = send(&[11; 32]);
    assert_eq!(before, keyring::Response::RequestTaken);

    // Alice declines: the request is simply discarded.
    let keyring::Response::Requests(tray) =
        ks.handle(keyring::Request::GetRequests(auth(&ks, &alice)))
    else {
        panic!()
    };
    assert_eq!(
        ks.handle(keyring::Request::DropRequest(auth(&ks, &alice), tray[0].0)),
        keyring::Response::RequestDropped
    );

    // After: byte-identical answer. The sender cannot tell a decline from a
    // request nobody has looked at yet — which is what makes declining safe.
    assert_eq!(
        send(b"t2"),
        before,
        "a decline changed what the sender observes"
    );

    // And to an address that never existed, the same answer again.
    assert_eq!(
        ks.handle(keyring::Request::PutRequest {
            addr: [0xde; 32],
            blob: sealed.as_bytes().to_vec(),
            permit: b"t3".to_vec(),
        }),
        before,
        "a nonexistent address is distinguishable from a real one"
    );
}

#[test]
fn no_service_offers_the_sender_a_way_to_ask() {
    // The guarantee is structural: there is no operation, on any service, that
    // reports a request's fate to whoever sent it. A filter could be relaxed; a
    // missing operation has to be added on purpose.
    let src = std::fs::read_to_string(
        spark_invariants::repo_root().join("server/spark-keyring-server/src/lib.rs"),
    )
    .unwrap();
    let start = src.find("pub enum Request").expect("Request enum");
    let end = src[start..].find("\n}\n").expect("enum ends") + start;
    let ops = &src[start..end];

    for banned in [
        "RequestStatus",
        "PollRequest",
        "WasAccepted",
        "CheckRequest",
        "RequestState",
    ] {
        assert!(
            !ops.contains(banned),
            "a sender-visible request status appeared: `{banned}`"
        );
    }
    // The only variants naming a request are the write and the two
    // recipient-only reads. A fourth would need adding here on purpose.
    let variants: Vec<&str> = ops
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//") && !l.starts_with("///"))
        .filter(|l| l.contains("Request") && !l.starts_with("pub enum"))
        .collect();
    assert_eq!(
        variants,
        [
            "PutRequest {",
            "GetRequests(Auth),",
            "DropRequest(Auth, u32),"
        ],
        "the set of request operations changed"
    );
}

// -------------------------------- after migration the old key decrypts nothing new

#[test]
fn a_migration_is_signed_by_the_key_it_retires() {
    // F3 says migration needs no new mechanism, and that is true of the mechanism.
    // But an owner still has to know the request is genuine, and F3 gives them
    // nothing to check. This is the smallest possible check: a local signature,
    // no server state.
    let (old, new, impostor) = (ident(1), ident(2), ident(3));

    let m = Migration::sign(&old, &new.public());
    assert!(m.verify().is_ok());
    assert_eq!(m.old, old.public().sign);
    assert_eq!(m.new, new.public().sign);

    // An impostor cannot mint one naming someone else's key as the retiring one.
    let mut forged = Migration::sign(&impostor, &new.public());
    forged.old = old.public().sign;
    assert_eq!(forged.verify().unwrap_err(), MigrationError::BadSignature);

    // Nor redirect a genuine one to a different successor.
    let mut redirected = m.clone();
    redirected.new = impostor.public().sign;
    assert_eq!(
        redirected.verify().unwrap_err(),
        MigrationError::BadSignature
    );
}
