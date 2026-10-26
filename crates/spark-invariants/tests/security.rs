//! Regression tests for hostile protocol inputs, not just honest round trips.
mod common;
use common::Fixed;
use spark_content_server as content;
use spark_crypto::{IssuerKey, Mnemonic, Secret, TokenClaim};
use spark_identity::Identity;
use spark_keyring_server as keyring;
use spark_store::Db;

fn identity(n: u8) -> Identity {
    Identity::from_mnemonic(&Mnemonic::from_entropy(&[n; 32]))
}
fn auth(k: &keyring::Keyring, id: &Identity) -> keyring::Auth {
    let addr = *id.addr().as_bytes();
    keyring::Auth {
        addr,
        key: *id.public().sign.as_bytes(),
        sig: *id.sign(&k.challenge(&addr)).as_bytes(),
    }
}
fn services() -> (keyring::Keyring, content::Content) {
    let k = keyring::Keyring::new(
        Db::new(),
        Secret::new([19; 32]),
        IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let c = content::Content::with_keys(Db::new(), k.accepted_keys());
    k.set_refund_keys(c.refund_keys());
    (k, c)
}
fn mint(
    k: &keyring::Keyring,
    id: &Identity,
    serial: u8,
    paid: u8,
    claimed: u8,
) -> (TokenClaim, spark_crypto::Token) {
    let pk = k.issuer_public_for(paid).unwrap();
    let claim = TokenClaim {
        serial: [serial; 32],
        size_class: claimed,
    };
    let (bm, b) = pk
        .blind(&mut Fixed(17 + serial as u64), &claim.encode())
        .unwrap();
    let keyring::Response::Tokens(sigs) = k.handle(keyring::Request::WithdrawTokens {
        auth: auth(k, id),
        blinded: vec![bm],
        size_class: paid,
    }) else {
        panic!("withdraw")
    };
    (claim, pk.finalize(b, &sigs[0], &claim.encode()).unwrap())
}
#[test]
fn storage_denomination_cannot_be_upgraded_inside_the_blind_message() {
    let (k, c) = services();
    let a = identity(1);
    let (claim, token) = mint(&k, &a, 1, 10, 20);
    let (name, _, chunk) = spark_chunk::media::seal_raw(b"small upload, oversized claim");
    assert_eq!(
        c.handle(content::Request::Put {
            name: *name.as_bytes(),
            chunk: chunk.as_bytes().to_vec(),
            claim,
            token
        }),
        content::Response::Refused(content::Refusal::BadToken)
    );
    assert!(c.db().keys(content::T_TOKEN).is_empty());
}
#[test]
fn refund_requires_real_signature_exact_denomination_and_single_redemption() {
    let (k, c) = services();
    let a = identity(2);
    let fake = spark_crypto::Token {
        sig: vec![0; 256],
        randomizer: [0; 32],
    };
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(
            auth(&k, &a),
            TokenClaim {
                serial: [9; 32],
                size_class: 20
            },
            fake
        )),
        keyring::Response::Refused(keyring::Refusal::Malformed)
    );
    let (claim, token) = mint(&k, &a, 2, 10, 10);
    // A legitimate storage signature cannot be used as a refund signature.
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(
            auth(&k, &a),
            claim,
            token.clone()
        )),
        keyring::Response::Refused(keyring::Refusal::Malformed)
    );
    let (name, _, chunk) = spark_chunk::media::seal_raw(b"refundable");
    let content::Response::Stored { receipt } = c.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim,
        token,
    }) else {
        panic!()
    };
    let (wrong, _, _) = common::release(&c, *name.as_bytes(), receipt, 20);
    assert_eq!(
        wrong,
        content::Response::Refused(content::Refusal::BadReceipt)
    );
    let (ok, refund, token) = common::release(&c, *name.as_bytes(), receipt, 10);
    assert!(matches!(
        ok,
        content::Response::Released { freed: true, .. }
    ));
    let token = token.unwrap();
    let mut inflated = refund;
    inflated.size_class = 20;
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(
            auth(&k, &a),
            inflated,
            token.clone()
        )),
        keyring::Response::Refused(keyring::Refusal::Malformed)
    );
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(
            auth(&k, &a),
            refund,
            token.clone()
        )),
        keyring::Response::Credited
    );
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(auth(&k, &a), refund, token)),
        keyring::Response::Credited
    );
    assert!(matches!(
        k.handle(keyring::Request::GetQuota(auth(&k, &a))),
        keyring::Response::Quota { used: 0, .. }
    ));
}
#[test]
fn room_read_key_does_not_authorize_delete_and_old_predictable_receipts_fail() {
    let (k, c) = services();
    let a = identity(3);
    let root = Secret::new([8; 32]);
    let slot = spark_chunk::Slot::new(spark_chunk::LaneId::COMMIT, 0);
    let (name, chunk) = spark_chunk::room::seal(&root, slot, &[1; 24], b"history");
    let (claim, token) = mint(&k, &a, 3, 10, 10);
    let content::Response::Stored { receipt } = c.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim,
        token,
    }) else {
        panic!()
    };
    for n in 0..8u64 {
        let mut guessed = [0; 32];
        guessed[..8].copy_from_slice(&n.to_be_bytes());
        guessed[8..16].copy_from_slice(b"receipt-");
        assert_ne!(receipt, guessed);
        assert_eq!(
            c.handle(content::Request::Delete {
                name: *name.as_bytes(),
                receipt: guessed
            }),
            content::Response::Refused(content::Refusal::BadReceipt)
        );
    }
    assert!(matches!(
        c.handle(content::Request::Get {
            name: *name.as_bytes()
        }),
        content::Response::Chunk(_)
    ));
    assert_eq!(
        c.handle(content::Request::Delete {
            name: *name.as_bytes(),
            receipt
        }),
        content::Response::Deleted
    );
}
#[test]
fn unknown_contact_requests_allocate_nothing_and_revocation_closes_the_gate() {
    let (k, _) = services();
    let a = identity(4);
    let addr = *a.addr().as_bytes();
    let before = k.db().all_bytes().len();
    for n in 0..100u8 {
        k.handle(keyring::Request::PutRequest {
            addr,
            blob: vec![1; 1024],
            permit: vec![n; 32],
        });
    }
    assert_eq!(k.db().all_bytes().len(), before);
    let permit = [55; 32];
    k.handle(keyring::Request::SetContacts(
        auth(&k, &a),
        vec![spark_crypto::sha256(&permit)],
    ));
    for n in 0..100u8 {
        k.handle(keyring::Request::PutRequest {
            addr,
            blob: vec![n; 1024],
            permit: permit.to_vec(),
        });
    }
    assert_eq!(k.db().keys(keyring::T_REQUEST).len(), 1);
    k.handle(keyring::Request::SetContacts(auth(&k, &a), vec![]));
    k.handle(keyring::Request::PutRequest {
        addr,
        blob: vec![2],
        permit: permit.to_vec(),
    });
    assert!(k.db().keys(keyring::T_REQUEST).is_empty());
}
#[test]
fn archive_signatures_bind_generation_clock_and_sender_lane() {
    use spark_sync::{Clock, entry::Signed};
    let a = identity(5);
    let slot = spark_chunk::Slot::new(spark_chunk::LaneId::message(&a.public().sign), 0);
    let clock = Clock::new();
    let context = [1; 32];
    let signed = Signed::new(
        &context,
        &clock,
        slot,
        0,
        b"hello".to_vec(),
        &a.public().sign,
        |b| a.sign(b),
    );
    assert!(signed.verify(&context, &clock, slot, 0).is_ok());
    assert!(signed.verify(&[2; 32], &clock, slot, 0).is_err());
    let mut edited = clock.clone();
    edited.observe(slot.lane, 12);
    assert!(signed.verify(&context, &edited, slot, 0).is_err());
    let fake_lane =
        spark_chunk::Slot::new(spark_chunk::LaneId::message(&identity(6).public().sign), 0);
    let signed = Signed::new(
        &context,
        &clock,
        fake_lane,
        0,
        b"hello".to_vec(),
        &a.public().sign,
        |b| a.sign(b),
    );
    assert!(signed.verify(&context, &clock, fake_lane, 0).is_err());
}
#[test]
fn reused_slot_with_new_nonce_does_not_reuse_the_keystream() {
    let root = Secret::new([7; 32]);
    let slot = spark_chunk::Slot::new(spark_chunk::LaneId::COMMIT, 0);
    let (name, a) = spark_chunk::room::seal(&root, slot, &[1; 24], b"AAAAAAAA");
    let (same, b) = spark_chunk::room::seal(&root, slot, &[2; 24], b"BBBBBBBB");
    assert_eq!(name, same);
    let xor: Vec<_> = a.as_bytes()[32..40]
        .iter()
        .zip(&b.as_bytes()[32..40])
        .map(|(a, b)| a ^ b)
        .collect();
    assert_ne!(xor, vec![b'A' ^ b'B'; 8]);
    assert_eq!(
        &*spark_chunk::room::open(&root, slot, &a).unwrap(),
        b"AAAAAAAA"
    );
    assert_eq!(
        &*spark_chunk::room::open(&root, slot, &b).unwrap(),
        b"BBBBBBBB"
    );
}

#[test]
fn encrypting_a_note_to_someone_does_not_authenticate_a_forged_sender() {
    use spark_crypto::{KemSecret, aead, expand, extract};
    use spark_identity::reach::{REQUEST_SALT, SealedRequest, open_request, seal_request};
    let recipient = identity(81);
    let attacker = identity(82);
    let victim = identity(83);
    let ephemeral = Secret::new([61; 32]);
    let eph = KemSecret::from_secret(&ephemeral);
    let shared = eph.diffie_hellman(&recipient.public().kem);
    let prk = extract(REQUEST_SALT, shared.expose());
    let key = expand::<32>(&prk, b"key");
    let nonce = *expand::<24>(&prk, b"nonce").expose();
    let sealed = seal_request(&recipient.public().kem, &attacker, "spoof", None, ephemeral);
    let bytes = sealed.as_bytes();
    let mut plain = aead::open(&key, &nonce, &bytes[..32], &bytes[32..]).unwrap();
    plain[..32].copy_from_slice(victim.public().sign.as_bytes());
    // Attacker can build a valid AEAD, but cannot sign as the approved victim.
    let forged = [
        bytes[..32].to_vec(),
        aead::seal(&key, &nonce, &bytes[..32], &plain),
    ]
    .concat();
    assert!(open_request(&recipient, &SealedRequest::from_bytes(forged), None).is_err());
}

#[test]
fn one_receipt_cannot_be_refunded_twice_by_concurrent_requests() {
    let (k, c) = services();
    let a = identity(84);
    let (claim, token) = mint(&k, &a, 7, 10, 10);
    let (name, _, chunk) = spark_chunk::media::seal_raw(b"concurrent refund");
    let content::Response::Stored { receipt } = c.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim,
        token,
    }) else {
        panic!()
    };
    let content::Response::RefundKey(der) = c.handle(content::Request::GetRefundKey(10)) else {
        panic!()
    };
    let pk = spark_crypto::IssuerPublic::from_der(&der).unwrap();
    let (blinded, _) = pk
        .blind(
            &mut Fixed(61),
            &TokenClaim {
                serial: [41; 32],
                size_class: 10,
            }
            .refund_message(),
        )
        .unwrap();
    let request = content::Request::Release {
        name: *name.as_bytes(),
        receipt,
        size_class: 10,
        blinded,
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let c = c.clone();
            let r = request.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                c.handle(r)
            })
        })
        .collect();
    let replies: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        replies
            .iter()
            .filter(|r| matches!(r, content::Response::Released { .. }))
            .count(),
        4
    );
    assert!(
        replies.windows(2).all(|w| w[0] == w[1]),
        "exact retries return the same signature"
    );
    assert_eq!(
        c.handle(content::Request::Head {
            name: *name.as_bytes()
        }),
        content::Response::Exists(false)
    );
}

#[test]
fn copying_an_archive_root_to_another_group_cannot_replay_its_signatures() {
    let root = Secret::new([21; 32]);
    let a = identity(91);
    let original = spark_chunk::room::signature_context(b"original MLS group", &root);
    let transplanted = spark_chunk::room::signature_context(b"different MLS group", &root);
    let clock = spark_sync::Clock::new();
    let slot = spark_chunk::Slot::new(spark_chunk::LaneId::message(&a.public().sign), 0);
    let signed = spark_sync::entry::Signed::new(
        &original,
        &clock,
        slot,
        0,
        b"belongs to the original group".to_vec(),
        &a.public().sign,
        |m| a.sign(m),
    );
    assert!(signed.verify(&original, &clock, slot, 0).is_ok());
    assert!(signed.verify(&transplanted, &clock, slot, 0).is_err());
}

#[test]
fn room_ciphertext_cannot_squat_a_media_address() {
    let (k, c) = services();
    let a = identity(70);
    let (name, _, media) = spark_chunk::media::seal_raw(b"a predictable public file");
    let (_, room) = spark_chunk::room::seal(
        &Secret::new([19; 32]),
        spark_chunk::Slot::new(spark_chunk::LaneId::message(&a.public().sign), 0),
        &[8; 24],
        b"poison",
    );
    let (claim, token) = mint(&k, &a, 71, 10, 10);
    assert!(matches!(
        c.handle(content::Request::Put {
            name: *name.as_bytes(),
            chunk: room.as_bytes().to_vec(),
            claim,
            token
        }),
        content::Response::Refused(_)
    ));
    let (claim, token) = mint(&k, &a, 72, 10, 10);
    assert!(matches!(
        c.handle(content::Request::Put {
            name: *name.as_bytes(),
            chunk: media.as_bytes().to_vec(),
            claim,
            token
        }),
        content::Response::Stored { .. }
    ));
    assert_eq!(
        c.handle(content::Request::Get {
            name: *name.as_bytes()
        }),
        content::Response::Chunk(media.as_bytes().to_vec())
    );
}

#[test]
fn withdrawal_retry_debits_once_and_malformed_batch_debits_nothing() {
    let (k, _) = services();
    let a = identity(73);
    let pk = k.issuer_public_for(10).unwrap();
    let claim = TokenClaim {
        serial: [73; 32],
        size_class: 10,
    };
    let (blinded, _) = pk.blind(&mut Fixed(73), &claim.encode()).unwrap();
    let bad = keyring::Request::WithdrawTokens {
        auth: auth(&k, &a),
        blinded: vec![blinded.clone(), vec![0; 256]],
        size_class: 10,
    };
    // Zero is not a valid RSA-PSS blind request, but raw RSA zero can sign.
    // Out-of-range modulus-sized input must fail the whole batch before charging.
    let bad = match bad {
        keyring::Request::WithdrawTokens {
            auth,
            mut blinded,
            size_class,
        } => {
            blinded[1] = vec![255; 256];
            keyring::Request::WithdrawTokens {
                auth,
                blinded,
                size_class,
            }
        }
        _ => unreachable!(),
    };
    assert!(matches!(k.handle(bad), keyring::Response::Refused(_)));
    assert!(matches!(
        k.handle(keyring::Request::GetQuota(auth(&k, &a))),
        keyring::Response::Quota { used: 0, .. }
    ));
    let request = keyring::Request::WithdrawTokens {
        auth: auth(&k, &a),
        blinded: vec![blinded],
        size_class: 10,
    };
    let first = k.handle(request.clone());
    assert!(matches!(first, keyring::Response::Tokens(_)));
    assert_eq!(first, k.handle(request));
    assert!(matches!(
        k.handle(keyring::Request::GetQuota(auth(&k, &a))),
        keyring::Response::Quota { used: 1024, .. }
    ));
}

#[test]
fn a_redeemed_refund_cannot_be_replayed_into_another_account() {
    let (k, c) = services();
    let a = identity(74);
    let b = identity(75);
    let (name, _, chunk) = spark_chunk::media::seal_raw(b"refund target");
    let (claim, token) = mint(&k, &a, 74, 10, 10);
    let content::Response::Stored { receipt } = c.handle(content::Request::Put {
        name: *name.as_bytes(),
        chunk: chunk.as_bytes().to_vec(),
        claim,
        token,
    }) else {
        panic!()
    };
    let (_, claim, token) = common::release(&c, *name.as_bytes(), receipt, 10);
    let token = token.unwrap();
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(
            auth(&k, &a),
            claim,
            token.clone()
        )),
        keyring::Response::Credited
    );
    assert_eq!(
        k.handle(keyring::Request::CreditRefund(auth(&k, &b), claim, token)),
        keyring::Response::Refused(keyring::Refusal::VoucherSpent)
    );
}
