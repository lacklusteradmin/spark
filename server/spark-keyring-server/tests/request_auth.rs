use spark_crypto::{IssuerKey, Secret, SigningKey};
use spark_keyring_server::Keyring;
use spark_store::{Db, mint::OsRandom};
use spark_wire::keyring::{Refusal, Req, Resp};
fn service(db: Db) -> Keyring {
    let s = Keyring::new(
        db,
        Secret::new([7; 32]),
        IssuerKey::generate(&mut OsRandom).unwrap(),
    );
    s.set_minute(10);
    s
}
fn request(s: &Keyring, seed: u8, nonce: u8) -> Req {
    let key = SigningKey::from_secret(&Secret::new([seed; 32]));
    let public = *key.verifying_key().as_bytes();
    let addr = spark_crypto::sha256_parts(&[b"spark/v1/keyring/addr", &public]);
    let mut r = Req::GetQuota(spark_wire::Auth {
        addr,
        key: public,
        sig: vec![],
        challenge: s.challenge(&addr),
        nonce: [nonce; 32],
    });
    let signature = key.sign(&r.signing_bytes());
    r.auth_mut().unwrap().sig = signature.as_bytes().to_vec();
    r
}
#[test]
fn complete_request_is_bound_and_nonce_is_single_use() {
    let s = service(Db::new());
    let r = request(&s, 1, 1);
    let proof = r.clone().auth_mut().unwrap().clone();
    for forged in [
        Req::GetSnapshot(proof.clone()),
        Req::PutDelta(proof.clone(), vec![7]),
        Req::SetContacts(proof, vec![[9; 32]]),
    ] {
        assert!(matches!(
            s.handle_wire(forged),
            Resp::Refused(Refusal::BadAuth)
        ));
    }
    assert!(matches!(s.handle_wire(r.clone()), Resp::Quota { .. }));
    assert!(matches!(s.handle_wire(r), Resp::Refused(Refusal::BadAuth)));
    assert!(matches!(
        s.handle_wire(request(&s, 1, 2)),
        Resp::Quota { .. }
    ));
}
#[test]
fn concurrent_replays_have_exactly_one_winner() {
    let s = std::sync::Arc::new(service(Db::new()));
    let r = request(&s, 2, 3);
    let jobs: Vec<_> = (0..8)
        .map(|_| {
            let s = s.clone();
            let r = r.clone();
            std::thread::spawn(move || matches!(s.handle_wire(r), Resp::Quota { .. }))
        })
        .collect();
    assert_eq!(
        jobs.into_iter()
            .filter_map(|h| h.join().unwrap().then_some(()))
            .count(),
        1
    );
}
#[test]
fn clock_rollback_does_not_revive_pruned_proofs() {
    let s = service(Db::new());
    let old = request(&s, 3, 1);
    assert!(matches!(s.handle_wire(old.clone()), Resp::Quota { .. }));
    s.set_minute(11);
    assert!(matches!(
        s.handle_wire(request(&s, 3, 2)),
        Resp::Quota { .. }
    ));
    assert_eq!(s.db().keys("auth_spent").len(), 1);
    s.set_minute(10);
    assert!(matches!(
        s.handle_wire(old),
        Resp::Refused(Refusal::BadAuth)
    ));
}
#[test]
fn reopening_service_preserves_signing_keys_and_replay_state() {
    let dir = std::env::temp_dir().join(format!("spark-auth-restart-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = dir.join("auth.sqlite");
    let (req, public, small) = {
        let s = service(Db::open(&path).unwrap());
        let r = request(&s, 4, 4);
        assert!(matches!(s.handle_wire(r.clone()), Resp::Quota { .. }));
        (
            r,
            s.issuer_public().to_der().unwrap(),
            s.issuer_public_for(10).unwrap().to_der().unwrap(),
        )
    };
    {
        let s = Keyring::new(
            Db::open(&path).unwrap(),
            Secret::new([99; 32]),
            IssuerKey::generate(&mut OsRandom).unwrap(),
        );
        s.set_minute(10);
        let mut inspect = req.clone();
        let proof = inspect.auth_mut().unwrap();
        assert_eq!(s.challenge(&proof.addr), proof.challenge);
        assert_eq!(s.issuer_public().to_der().unwrap(), public);
        assert_eq!(s.issuer_public_for(10).unwrap().to_der().unwrap(), small);
        assert!(matches!(
            s.handle_wire(req),
            Resp::Refused(Refusal::BadAuth)
        ));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn changing_contacts_or_nonce_invalidates_the_signature() {
    let s = service(Db::new());
    let key = SigningKey::from_secret(&Secret::new([8; 32]));
    let mut template = request(&s, 8, 8);
    let mut r = Req::SetContacts(template.auth_mut().unwrap().clone(), vec![[1; 32]]);
    r.auth_mut().unwrap().sig = key.sign(&r.signing_bytes()).as_bytes().to_vec();
    let Req::SetContacts(auth, _) = r.clone() else {
        unreachable!()
    };
    assert!(matches!(
        s.handle_wire(Req::SetContacts(auth, vec![[2; 32]])),
        Resp::Refused(Refusal::BadAuth)
    ));
    let mut changed_nonce = r.clone();
    changed_nonce.auth_mut().unwrap().nonce = [9; 32];
    assert!(matches!(
        s.handle_wire(changed_nonce),
        Resp::Refused(Refusal::BadAuth)
    ));
    assert!(matches!(s.handle_wire(r), Resp::RequestDropped));
}
