//! RUSTSEC-2023-0071 mitigations, at the service boundary.
//!
//! Base blinding is applied on every signature by the library, which is why the
//! advisory's attack complexity is high. It is a mitigation, not a proof, and the
//! advisory has no patched version — so the channel is closed where Spark
//! controls it: responses go out on a fixed cadence, and the signing keys rotate
//! so a recovered one mints for a bounded time.
//!
//! The clock is injected. A test that measured real elapsed time would be flaky
//! on a loaded CI machine, and a timing countermeasure whose tests are flaky is
//! one nobody will trust the day it fails for real.

use spark_crypto::{Clock, Grant, IssuerKey, Secret, VoucherClaim};
use spark_identity::Identity;
use spark_store::Db;
use std::cell::RefCell;

use spark_issuer as issuer;
use spark_keyring_server as keyring;

mod common;
use common::Fixed;

/// A clock the test drives. `work` scripts what each request is pretended to cost.
///
/// `handle_paced` reads the clock exactly twice per request: once at the start and
/// once after the work. So the cost is applied on the *second* read of each pair —
/// applying it on both would make every request consume the next one's script,
/// which is what the first version of this did.
struct FakeClock {
    now: RefCell<u64>,
    work: RefCell<Vec<u64>>,
    reads: RefCell<u64>,
    slept: RefCell<Vec<u64>>,
}

impl FakeClock {
    fn with_work(work: &[u64]) -> Self {
        Self {
            now: RefCell::new(0),
            work: RefCell::new(work.iter().rev().copied().collect()),
            reads: RefCell::new(0),
            slept: RefCell::new(Vec::new()),
        }
    }
    /// How long the service waited after each request.
    fn waits(&self) -> Vec<u64> {
        self.slept.borrow().clone()
    }
}

impl Clock for FakeClock {
    fn now_nanos(&self) -> u64 {
        let mut reads = self.reads.borrow_mut();
        *reads += 1;
        if (*reads).is_multiple_of(2)
            && let Some(w) = self.work.borrow_mut().pop()
        {
            *self.now.borrow_mut() += w;
        }
        *self.now.borrow()
    }
    fn sleep_nanos(&self, nanos: u64) {
        self.slept.borrow_mut().push(nanos);
        *self.now.borrow_mut() += nanos;
    }
}

fn ident(e: u8) -> Identity {
    Identity::from_mnemonic(&spark_crypto::Mnemonic::from_entropy(&[e; 32]))
}

#[test]
fn a_paced_service_answers_in_the_same_time_whatever_the_work_cost() {
    // The property the mitigation rests on. Four requests whose internal cost
    // differs by two orders of magnitude must be indistinguishable from outside.
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let costs = [1_000u64, 900_000, 12_345_678, 40_000_000];
    let clock = FakeClock::with_work(&costs);

    let alice = ident(1);
    for _ in costs.iter() {
        let addr = *alice.addr().as_bytes();
        let auth = keyring::Auth {
            addr,
            key: *alice.public().sign.as_bytes(),
            sig: *alice.sign(&ks.challenge(&addr)).as_bytes(),
        };
        ks.handle_paced(&clock, keyring::Request::GetQuota(auth));
    }

    // work + wait, per request.
    let totals: Vec<u64> = costs
        .iter()
        .zip(clock.waits())
        .map(|(w, wait)| w + wait)
        .collect();
    assert!(
        totals.windows(2).all(|w| w[0] == w[1]),
        "response time varied with the work: {totals:?}"
    );
    assert_eq!(
        ks.pacing_overruns(),
        0,
        "the default tick was too small for this work"
    );
}

#[test]
fn work_beyond_the_tick_is_counted_rather_than_hidden() {
    // Past one tick the number of ticks varies with the input and the channel is
    // back, coarsened. The service must be able to alert on that.
    let is = issuer::Issuer::new(Db::new(), IssuerKey::generate(&mut Fixed(77)).unwrap());
    let clock = FakeClock::with_work(&[10_000, 60_000_000]); // second exceeds 50 ms
    for _ in 0..2 {
        is.handle_paced(&clock, issuer::Request::Resolve("nobody".into(), 20_000));
    }
    assert_eq!(is.pacing_overruns(), 1, "an overrun went unreported");
}

#[test]
fn pacing_does_not_change_the_answers() {
    // `handle` stays public and unpaced so behaviour can be tested without a
    // clock. The two must agree, or the tested path is not the shipped one.
    let is = issuer::Issuer::new(Db::new(), IssuerKey::generate(&mut Fixed(77)).unwrap());
    let clock = FakeClock::with_work(&[1_000, 1_000]);
    let a = is.handle(issuer::Request::Resolve("nobody".into(), 20_000));
    let b = is.handle_paced(&clock, issuer::Request::Resolve("nobody".into(), 20_000));
    assert_eq!(a, b);
}

#[test]
fn a_voucher_survives_a_rotation_of_the_key_that_signed_it() {
    // Rotation bounds how long a recovered key can mint. It must not invalidate
    // vouchers people already bought, or nobody will ever rotate.
    let is = issuer::Issuer::new(Db::new(), IssuerKey::generate(&mut Fixed(77)).unwrap());
    let claim = VoucherClaim {
        serial: [3; 32],
        grant: Grant::NameMonths {
            months: 12,
            premium: false,
        },
    };
    let pk = is.signing_public();
    let (blinded, b) = pk.blind(&mut Fixed(5), &claim.encode()).unwrap();
    let issuer::Response::Signed(sig) = is.handle(issuer::Request::Purchase {
        blinded,
        payment: b"tx-1".to_vec(),
        amount: claim.price(),
    }) else {
        panic!("purchase refused")
    };
    let voucher = pk.finalize(b, &sig, &claim.encode()).unwrap();

    is.rotate_signing_key(IssuerKey::generate(&mut Fixed(78)).unwrap());
    assert_eq!(
        is.accepted_keys().len(),
        2,
        "the retired key stopped being accepted at once"
    );

    let mut key64 = [0u8; 64];
    key64[..32].copy_from_slice(ident(1).public().sign.as_bytes());
    key64[32..].copy_from_slice(ident(1).public().kem.as_bytes());
    assert_eq!(
        is.handle(issuer::Request::Register {
            name: "afterrotation".into(),
            key: key64,
            claim,
            voucher,
            today: 20_000,
        }),
        issuer::Response::Registered,
        "a voucher bought before the rotation stopped working"
    );
}

#[test]
fn rotating_changes_the_key_tokens_are_signed_with() {
    let ks = keyring::Keyring::new(
        Db::new(),
        Secret::new([1; 32]),
        IssuerKey::generate(&mut Fixed(42)).unwrap(),
    );
    let before = ks.issuer_public().to_der().unwrap();
    ks.rotate_issuer_key(IssuerKey::generate(&mut Fixed(43)).unwrap());
    let after = ks.issuer_public().to_der().unwrap();

    assert_ne!(before, after, "rotation did not change the signing key");
    assert_eq!(
        ks.accepted_keys().len(),
        2,
        "the retired key must still verify"
    );
    assert_eq!(
        ks.accepted_keys()[0].to_der().unwrap(),
        after,
        "newest key is not first"
    );
}
