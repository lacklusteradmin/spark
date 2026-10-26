//! Gate 10: "Redemption cannot be linked to payment, or a name to the payment
//! that bought it; a transfer leaves no record joining old key to new; an expired
//! name does not reduce quota."

use spark_crypto::{Grant, Mnemonic, Secret, Token, VoucherClaim};
use spark_identity::Identity;
use spark_store::{Cell, Db};

use spark_issuer as issuer;
use spark_keyring_server as keyring;

mod common;
use common::{Fixed, issuer as token_issuer};

/// Day 20 000 since the epoch, give or take. Time is a parameter; no service here
/// reads a clock.
const TODAY: u32 = 20_000;

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

/// An issuer with its own signing key. `seed` distinguishes issuers: two calls
/// with the same seed are the *same* issuer, which is worth knowing before
/// writing a test about forged vouchers.
fn service_seeded(seed: u64) -> issuer::Issuer {
    issuer::Issuer::new(
        Db::new(),
        spark_crypto::IssuerKey::generate(&mut Fixed(seed)).expect("keygen"),
    )
    .with_payment_verifier(std::sync::Arc::new(common::TestPayments))
    .with_day_clock(std::sync::Arc::new(|| TODAY))
}

fn service() -> issuer::Issuer {
    service_seeded(77)
}

/// Buy a voucher: blind a claim, pay, unblind. `payment` is a chain reference.
fn buy(
    is: &issuer::Issuer,
    serial: u8,
    grant: Grant,
    payment: &[u8],
) -> Result<(VoucherClaim, Token), issuer::Refusal> {
    let claim = VoucherClaim {
        serial: [serial; 32],
        grant,
    };
    if is.signing_public_for(claim.price()).is_none() {
        is.provision_price(
            claim.price(),
            spark_crypto::IssuerKey::generate(&mut Fixed(
                u64::from_le_bytes(
                    spark_crypto::sha256(&is.signing_public().to_der().unwrap())[..8]
                        .try_into()
                        .unwrap(),
                )
                .wrapping_add(claim.price()),
            ))
            .unwrap(),
        );
    }
    let pk = is.signing_public_for(claim.price()).unwrap();
    let (blinded, b) = pk
        .blind(&mut Fixed(serial as u64 + 1), &claim.encode())
        .expect("blind");
    match is.handle(issuer::Request::Purchase {
        blinded,
        payment: payment.to_vec(),
        amount: claim.price(),
    }) {
        issuer::Response::Signed(sig) => Ok((
            claim,
            pk.finalize(b, &sig, &claim.encode()).expect("finalize"),
        )),
        issuer::Response::Refused(r) => Err(r),
        r => panic!("unexpected: {r:?}"),
    }
}

/// Every byte the issuer holds.
fn issuer_bytes(is: &issuer::Issuer) -> Vec<u8> {
    is.db().all_bytes()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// --------------------------- redemption cannot be linked to payment

#[test]
fn the_issuer_never_sees_the_serial_it_signs() {
    // The cryptographic half. The issuer could not record the link even if it
    // wanted to, because at signing time the serial is not in front of it.
    let is = service();
    let claim = VoucherClaim {
        serial: [0xab; 32],
        grant: Grant::Storage { size_class: 26 },
    };
    if is.signing_public_for(claim.price()).is_none() {
        is.provision_price(
            claim.price(),
            spark_crypto::IssuerKey::generate(&mut Fixed(
                u64::from_le_bytes(
                    spark_crypto::sha256(&is.signing_public().to_der().unwrap())[..8]
                        .try_into()
                        .unwrap(),
                )
                .wrapping_add(claim.price()),
            ))
            .unwrap(),
        );
    }
    let pk = is.signing_public_for(claim.price()).unwrap();
    let (blinded, _) = pk.blind(&mut Fixed(3), &claim.encode()).unwrap();

    assert!(
        !contains(&blinded, &claim.serial),
        "the serial was visible to the issuer"
    );
    assert!(
        !contains(&blinded, &claim.encode()),
        "the claim was visible to the issuer"
    );
}

#[test]
fn no_stored_row_joins_a_payment_to_a_voucher() {
    // The bookkeeping half. Even the tables the issuer does keep must not put a
    // payment and a voucher serial in the same place.
    let is = service();
    let payment = b"chain-tx-0xdeadbeef";
    let (claim, voucher) = buy(&is, 1, Grant::Storage { size_class: 26 }, payment).unwrap();

    // Redeem it somewhere. Storage grants are redeemed at the keyring service, so
    // the issuer never learns the serial was used at all.
    assert!(
        contains(&issuer_bytes(&is), payment),
        "the payment was not recorded as spent"
    );

    // Only settled reference and exact-retry metadata are retained. Neither the
    // hidden serial nor the redeemed name is available at issuance.
    for row in is.db().rows(issuer::T_PAYMENT) {
        let fields: Vec<&str> = row.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            fields,
            [
                "spent_payment_ref",
                "payment_request_hash",
                "payment_response"
            ],
            "payment retry metadata changed"
        );
        assert!(
            !contains(&issuer_bytes(&is), &claim.serial),
            "the voucher serial reached the issuer at all"
        );
    }
    let _ = voucher;
}

#[test]
fn a_name_cannot_be_linked_to_the_payment_that_bought_it() {
    let is = service();
    let payment = b"chain-tx-0xfeedface";
    let (claim, voucher) = buy(
        &is,
        2,
        Grant::NameMonths {
            months: 12,
            premium: false,
        },
        payment,
    )
    .unwrap();
    let alice = ident(1);

    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "riverbank".into(),
            key: pub64(&alice),
            claim,
            voucher,
            today: TODAY,
        }),
        issuer::Response::Registered
    );

    // No row holds both the name and the payment.
    for table in [
        issuer::T_NAME,
        issuer::T_PAYMENT,
        issuer::T_VOUCHER,
        issuer::T_ISSUANCE,
    ] {
        for row in is.db().rows(table) {
            let mut bytes = Vec::new();
            for (n, c) in &row {
                bytes.extend_from_slice(n.as_bytes());
                match c {
                    Cell::Bytes(v) => bytes.extend_from_slice(v),
                    Cell::Text(t) => bytes.extend_from_slice(t.as_bytes()),
                    Cell::Num(v) => bytes.extend_from_slice(&v.to_be_bytes()),
                }
            }
            let has_name = contains(&bytes, b"riverbank");
            let has_payment = contains(&bytes, payment);
            assert!(
                !(has_name && has_payment),
                "a row in `{table}` joins the name to the payment that bought it"
            );
        }
    }
}

#[test]
fn a_payment_cannot_mint_two_vouchers() {
    let is = service();
    let payment = b"chain-tx-once";
    assert!(buy(&is, 1, Grant::Storage { size_class: 26 }, payment).is_ok());
    assert_eq!(
        buy(&is, 2, Grant::Storage { size_class: 26 }, payment).unwrap_err(),
        issuer::Refusal::PaymentSpent
    );
}

#[test]
fn a_voucher_cannot_be_spent_twice() {
    let is = service();
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-a",
    )
    .unwrap();
    let alice = ident(1);

    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "first".into(),
            key: pub64(&alice),
            claim,
            voucher: voucher.clone(),
            today: TODAY,
        }),
        issuer::Response::Registered
    );
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "second".into(),
            key: pub64(&alice),
            claim,
            voucher,
            today: TODAY,
        }),
        issuer::Response::Refused(issuer::Refusal::VoucherSpent)
    );
}

#[test]
fn a_forged_voucher_buys_nothing() {
    let is = service();
    let other = service_seeded(1234); // a genuinely different issuer key
    let (claim, voucher) = buy(
        &other,
        1,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-x",
    )
    .unwrap();

    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "stolen".into(),
            key: pub64(&ident(1)),
            claim,
            voucher,
            today: TODAY,
        }),
        issuer::Response::Refused(issuer::Refusal::BadVoucher)
    );
}

#[test]
fn a_basic_voucher_does_not_buy_a_premium_name() {
    // D1: both tiers unlock full quota, so the paywall gates desirability rather
    // than entry. That only holds if the tiers cannot be swapped at redemption.
    let is = service();
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-y",
    )
    .unwrap();
    assert!(
        issuer::is_premium("ab"),
        "a two-character name should be premium"
    );

    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "ab".into(),
            key: pub64(&ident(1)),
            claim,
            voucher,
            today: TODAY,
        }),
        issuer::Response::Refused(issuer::Refusal::WrongGrant)
    );
}

// ------------------- a transfer leaves no record joining old key to new

#[test]
fn a_transfer_leaves_no_record_joining_old_key_to_new() {
    let is = service();
    let (seller, buyer) = (ident(1), ident(2));
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 12,
            premium: false,
        },
        b"tx-1",
    )
    .unwrap();
    is.handle(issuer::Request::Register {
        name: "harbour".into(),
        key: pub64(&seller),
        claim,
        voucher,
        today: TODAY,
    });
    assert!(contains(
        &issuer_bytes(&is),
        seller.public().sign.as_bytes()
    ));

    let mut msg = issuer::TRANSFER_CONTEXT.to_vec();
    msg.extend_from_slice(&is.transfer_challenge("harbour").unwrap());
    msg.extend_from_slice(b"harbour");
    msg.extend_from_slice(&pub64(&buyer));
    assert_eq!(
        is.handle(issuer::Request::Transfer {
            name: "harbour".into(),
            new_key: pub64(&buyer),
            sig: *seller.sign(&msg).as_bytes(),
        }),
        issuer::Response::Transferred
    );

    // The old key appears nowhere afterwards. This exists because a seed cannot
    // be handed over, only copied: a seller who sold their seed would keep
    // permanent read access to everything the buyer does next.
    let after = issuer_bytes(&is);
    assert!(
        !contains(&after, seller.public().sign.as_bytes()),
        "the old key survived the transfer: that is a record joining it to the new one"
    );
    assert!(contains(&after, buyer.public().sign.as_bytes()));

    assert_eq!(
        is.handle(issuer::Request::Resolve("harbour".into(), TODAY)),
        issuer::Response::Resolved(Some(pub64(&buyer)))
    );
}

#[test]
fn only_the_holder_can_transfer() {
    let is = service();
    let (holder, impostor, target) = (ident(1), ident(2), ident(3));
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 12,
            premium: false,
        },
        b"tx-2",
    )
    .unwrap();
    is.handle(issuer::Request::Register {
        name: "quay".into(),
        key: pub64(&holder),
        claim,
        voucher,
        today: TODAY,
    });

    let mut msg = issuer::TRANSFER_CONTEXT.to_vec();
    msg.extend_from_slice(&is.transfer_challenge("quay").unwrap());
    msg.extend_from_slice(b"quay");
    msg.extend_from_slice(&pub64(&target));
    assert_eq!(
        is.handle(issuer::Request::Transfer {
            name: "quay".into(),
            new_key: pub64(&target),
            sig: *impostor.sign(&msg).as_bytes(),
        }),
        issuer::Response::Refused(issuer::Refusal::BadSignature)
    );
}

// ------------------------------- an expired name does not reduce quota

#[test]
fn an_expired_name_does_not_reduce_quota() {
    // F9: "Quota belongs to the key, never to the name. [...] a lapsed name costs
    // that key its name and nothing else." It holds structurally: quota lives on
    // the keyring service and names on the issuer, so the issuer has no reach
    // into quota even in principle.
    let is = service();
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        spark_crypto::IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let alice = ident(1);
    let auth = || {
        let addr = *alice.addr().as_bytes();
        keyring::Auth {
            addr,
            key: *alice.public().sign.as_bytes(),
            sig: *alice.sign(&ks.challenge(&addr)).as_bytes(),
        }
    };

    // Draw a token, which is what quota is for.
    let pk = ks.issuer_public_for(12).unwrap();
    let (blinded, _) = spark_tokens::begin(&pk, &mut Fixed(5), &[[1; 32]], 12).unwrap();
    assert!(matches!(
        ks.handle(keyring::Request::WithdrawTokens {
            auth: auth(),
            blinded,
            size_class: 12
        }),
        keyring::Response::Tokens(_)
    ));
    let keyring::Response::Quota { used, limit } = ks.handle(keyring::Request::GetQuota(auth()))
    else {
        panic!()
    };

    // Buy a name, let it lapse past grace.
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-3",
    )
    .unwrap();
    is.handle(issuer::Request::Register {
        name: "lapsing".into(),
        key: pub64(&alice),
        claim,
        voucher,
        today: TODAY,
    });
    let expired = TODAY + 30 + issuer::GRACE_DAYS + 1;
    assert_eq!(
        is.clone()
            .with_day_clock(std::sync::Arc::new(move || expired))
            .handle(issuer::Request::Resolve("lapsing".into(), 0)),
        issuer::Response::Resolved(None),
        "a lapsed name still resolves"
    );

    let keyring::Response::Quota {
        used: after,
        limit: limit_after,
    } = ks.handle(keyring::Request::GetQuota(auth()))
    else {
        panic!()
    };
    assert_eq!(
        (after, limit_after),
        (used, limit),
        "losing a name changed quota"
    );
}

#[test]
fn a_name_resolves_through_its_grace_period_then_returns_to_sale() {
    let is = service();
    let (first, second) = (ident(1), ident(2));
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-4",
    )
    .unwrap();
    is.handle(issuer::Request::Register {
        name: "seasonal".into(),
        key: pub64(&first),
        claim,
        voucher,
        today: TODAY,
    });
    let paid_until = TODAY + 30;

    // Live through the paid term and the ten-day grace.
    for day in [TODAY, paid_until, paid_until + issuer::GRACE_DAYS] {
        assert!(
            matches!(
                is.clone()
                    .with_day_clock(std::sync::Arc::new(move || day))
                    .handle(issuer::Request::Resolve("seasonal".into(), 0)),
                issuer::Response::Resolved(Some(_))
            ),
            "the name stopped resolving on day {day}, inside its grace period"
        );
    }

    // One day past grace it is gone, and someone else may buy it.
    let gone = paid_until + issuer::GRACE_DAYS + 1;
    assert_eq!(
        is.clone()
            .with_day_clock(std::sync::Arc::new(move || gone))
            .handle(issuer::Request::Resolve("seasonal".into(), 0)),
        issuer::Response::Resolved(None)
    );

    let (c2, v2) = buy(
        &is,
        2,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-5",
    )
    .unwrap();
    assert_eq!(
        is.clone()
            .with_day_clock(std::sync::Arc::new(move || gone))
            .handle(issuer::Request::Register {
                name: "seasonal".into(),
                key: pub64(&second),
                claim: c2,
                voucher: v2,
                today: gone,
            }),
        issuer::Response::Registered,
        "a reclaimed name did not return to sale"
    );
    assert_eq!(
        is.clone()
            .with_day_clock(std::sync::Arc::new(move || gone))
            .handle(issuer::Request::Resolve("seasonal".into(), 0)),
        issuer::Response::Resolved(Some(pub64(&second)))
    );
}

#[test]
fn renewing_early_extends_rather_than_shortens() {
    let is = service();
    let alice = ident(1);
    let (claim, voucher) = buy(
        &is,
        1,
        Grant::NameMonths {
            months: 12,
            premium: false,
        },
        b"tx-6",
    )
    .unwrap();
    is.handle(issuer::Request::Register {
        name: "steady".into(),
        key: pub64(&alice),
        claim,
        voucher,
        today: TODAY,
    });

    let (c2, v2) = buy(
        &is,
        2,
        Grant::NameMonths {
            months: 12,
            premium: false,
        },
        b"tx-7",
    )
    .unwrap();
    let issuer::Response::Renewed(until) = is.handle(issuer::Request::Renew {
        name: "steady".into(),
        claim: c2,
        voucher: v2,
        today: TODAY + 1,
    }) else {
        panic!("renewal refused")
    };
    assert_eq!(
        until,
        TODAY + 30 * 24,
        "renewing early lost the remaining term"
    );

    // A name past grace cannot be renewed: it is a purchase, and may already
    // belong to someone else.
    let (c3, v3) = buy(
        &is,
        3,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"tx-8",
    )
    .unwrap();
    assert_eq!(
        is.clone()
            .with_day_clock(std::sync::Arc::new(move || until + issuer::GRACE_DAYS + 1))
            .handle(issuer::Request::Renew {
                name: "steady".into(),
                claim: c3,
                voucher: v3,
                today: until + issuer::GRACE_DAYS + 1,
            }),
        issuer::Response::Refused(issuer::Refusal::Unknown)
    );
}

#[test]
fn the_price_table_charges_premium_names_more() {
    let basic = VoucherClaim {
        serial: [0; 32],
        grant: Grant::NameMonths {
            months: 1,
            premium: false,
        },
    };
    let premium = VoucherClaim {
        serial: [0; 32],
        grant: Grant::NameMonths {
            months: 1,
            premium: true,
        },
    };
    assert!(
        premium.price() > basic.price() * 10,
        "premium names are not priced to fund anything"
    );
    assert!(
        basic.price() > 0,
        "a free name is unlimited free accounts (D1)"
    );

    // Twelve months costs twelve times one.
    let year = VoucherClaim {
        serial: [0; 32],
        grant: Grant::NameMonths {
            months: 12,
            premium: false,
        },
    };
    assert_eq!(year.price(), basic.price() * 12);

    let _ = token_issuer();
}

#[test]
fn unverified_payment_fails_closed_without_consuming_reference() {
    let is = issuer::Issuer::new(
        Db::new(),
        spark_crypto::IssuerKey::generate(&mut Fixed(77)).unwrap(),
    );
    assert_eq!(
        is.handle(issuer::Request::Purchase {
            blinded: vec![1; 256],
            payment: b"made-up-tx".to_vec(),
            amount: 1
        }),
        issuer::Response::Refused(issuer::Refusal::Underpaid)
    );
    assert!(is.db().rows(issuer::T_PAYMENT).is_empty());
}

#[test]
fn cheap_blind_signing_key_cannot_authorize_expensive_hidden_grant() {
    let is = service();
    // Payment is settled for one unit, but the blinded message claims 255 premium months.
    let claim = VoucherClaim {
        serial: [192; 32],
        grant: Grant::NameMonths {
            months: 255,
            premium: true,
        },
    };
    let pk = is.signing_public_for(1).unwrap();
    let (blinded, b) = pk.blind(&mut Fixed(999), &claim.encode()).unwrap();
    let issuer::Response::Signed(sig) = is.handle(issuer::Request::Purchase {
        blinded,
        payment: b"paid-one-unit".to_vec(),
        amount: 1,
    }) else {
        panic!()
    };
    let voucher = pk.finalize(b, &sig, &claim.encode()).unwrap();
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "ab".into(),
            key: pub64(&ident(1)),
            claim,
            voucher,
            today: TODAY
        }),
        issuer::Response::Refused(issuer::Refusal::BadVoucher)
    );
}

#[test]
fn caller_future_date_cannot_steal_live_name() {
    let is = service();
    let grant = Grant::NameMonths {
        months: 1,
        premium: false,
    };
    let (claim, voucher) = buy(&is, 180, grant, b"owner-payment").unwrap();
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "protected".into(),
            key: pub64(&ident(1)),
            claim,
            voucher,
            today: TODAY
        }),
        issuer::Response::Registered
    );
    let (claim, voucher) = buy(&is, 181, grant, b"attacker-payment").unwrap();
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "protected".into(),
            key: pub64(&ident(2)),
            claim,
            voucher,
            today: u32::MAX
        }),
        issuer::Response::Refused(issuer::Refusal::Taken)
    );
    assert_eq!(
        is.handle(issuer::Request::Resolve("protected".into(), u32::MAX)),
        issuer::Response::Resolved(Some(pub64(&ident(1))))
    );
}

#[test]
fn old_transfer_cannot_replay_after_ownership_returns() {
    let is = service();
    let a = ident(1);
    let b = ident(2);
    let (claim, voucher) = buy(
        &is,
        182,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"transfer-payment",
    )
    .unwrap();
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "replay-proof".into(),
            key: pub64(&a),
            claim,
            voucher,
            today: TODAY
        }),
        issuer::Response::Registered
    );
    let transfer = |from: &Identity, to: &Identity| {
        let mut msg = issuer::TRANSFER_CONTEXT.to_vec();
        msg.extend_from_slice(&is.transfer_challenge("replay-proof").unwrap());
        msg.extend_from_slice(b"replay-proof");
        msg.extend_from_slice(&pub64(to));
        issuer::Request::Transfer {
            name: "replay-proof".into(),
            new_key: pub64(to),
            sig: *from.sign(&msg).as_bytes(),
        }
    };
    let old = transfer(&a, &b);
    assert_eq!(is.handle(old.clone()), issuer::Response::Transferred);
    assert_eq!(is.handle(transfer(&b, &a)), issuer::Response::Transferred);
    assert_eq!(
        is.handle(old),
        issuer::Response::Refused(issuer::Refusal::BadSignature)
    );
}

#[test]
fn invalid_storage_price_classes_do_not_overflow() {
    for size_class in 0..=u8::MAX {
        let price = VoucherClaim {
            serial: [0; 32],
            grant: Grant::Storage { size_class },
        }
        .price();
        assert_eq!(price > 0, (20..=40).contains(&size_class));
    }
}

#[test]
fn exact_purchase_retry_returns_the_original_blind_signature() {
    let is = service();
    let grant = Grant::NameMonths {
        months: 1,
        premium: false,
    };
    let (_, first) = buy(&is, 190, grant, b"lost-purchase-response").unwrap();
    let (_, retry) = buy(&is, 190, grant, b"lost-purchase-response").unwrap();
    assert_eq!(first, retry);
    assert_eq!(
        is.db()
            .field(issuer::T_ISSUANCE, "total", "blind_sig_count")
            .and_then(|c| c.num()),
        Some(1)
    );
}

#[test]
fn concurrent_registrations_have_exactly_one_winner() {
    let is = service();
    let grant = Grant::NameMonths {
        months: 1,
        premium: false,
    };
    let (c1, v1) = buy(&is, 193, grant, b"race-one").unwrap();
    let (c2, v2) = buy(&is, 194, grant, b"race-two").unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [(c1, v1, pub64(&ident(1))), (c2, v2, pub64(&ident(2)))]
        .into_iter()
        .map(|(claim, voucher, key)| {
            let is = is.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                is.handle(issuer::Request::Register {
                    name: "race".into(),
                    key,
                    claim,
                    voucher,
                    today: TODAY,
                })
            })
        })
        .collect();
    let responses: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        responses
            .iter()
            .filter(|r| **r == issuer::Response::Registered)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|r| **r == issuer::Response::Refused(issuer::Refusal::Taken))
            .count(),
        1
    );
    assert_eq!(is.db().rows(issuer::T_VOUCHER).len(), 1);
}

#[test]
fn date_overflow_does_not_spend_a_valid_voucher() {
    let is = service().with_day_clock(std::sync::Arc::new(|| u32::MAX));
    let (claim, voucher) = buy(
        &is,
        195,
        Grant::NameMonths {
            months: 1,
            premium: false,
        },
        b"overflow",
    )
    .unwrap();
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "overflow".into(),
            key: pub64(&ident(1)),
            claim,
            voucher,
            today: 0
        }),
        issuer::Response::Refused(issuer::Refusal::WrongGrant)
    );
    assert!(is.db().rows(issuer::T_VOUCHER).is_empty());
}
