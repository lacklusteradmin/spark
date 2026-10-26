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
    let is = issuer::Issuer::new(Db::new(), IssuerKey::generate(&mut Fixed(77)).unwrap())
        .with_payment_verifier(std::sync::Arc::new(common::TestPayments))
        .with_day_clock(std::sync::Arc::new(|| 20_000));
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
    let is = issuer::Issuer::new(Db::new(), IssuerKey::generate(&mut Fixed(77)).unwrap())
        .with_payment_verifier(std::sync::Arc::new(common::TestPayments))
        .with_day_clock(std::sync::Arc::new(|| 20_000));
    let clock = FakeClock::with_work(&[1_000, 1_000]);
    let a = is.handle(issuer::Request::Resolve("nobody".into(), 20_000));
    let b = is.handle_paced(&clock, issuer::Request::Resolve("nobody".into(), 20_000));
    assert_eq!(a, b);
}

#[test]
fn a_voucher_survives_a_rotation_of_the_key_that_signed_it() {
    // Rotation bounds how long a recovered key can mint. It must not invalidate
    // vouchers people already bought, or nobody will ever rotate.
    let is = issuer::Issuer::new(Db::new(), IssuerKey::generate(&mut Fixed(77)).unwrap())
        .with_payment_verifier(std::sync::Arc::new(common::TestPayments))
        .with_day_clock(std::sync::Arc::new(|| 20_000));
    let claim = VoucherClaim {
        serial: [3; 32],
        grant: Grant::NameMonths {
            months: 12,
            premium: false,
        },
    };
    is.provision_price(claim.price(), IssuerKey::generate(&mut Fixed(177)).unwrap());
    let pk = is.signing_public_for(claim.price()).unwrap();
    let (blinded, b) = pk.blind(&mut Fixed(5), &claim.encode()).unwrap();
    let issuer::Response::Signed(sig) = is.handle(issuer::Request::Purchase {
        blinded,
        payment: b"tx-1".to_vec(),
        amount: claim.price(),
    }) else {
        panic!("purchase refused")
    };
    let voucher = pk.finalize(b, &sig, &claim.encode()).unwrap();

    is.rotate_price_key(claim.price(), IssuerKey::generate(&mut Fixed(78)).unwrap());
    is.rotate_signing_key(IssuerKey::generate(&mut Fixed(79)).unwrap());
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
        ks.accepted_keys().keys(20).len(),
        2,
        "the retired key must still verify"
    );
    assert_eq!(
        ks.accepted_keys().keys(20)[0].to_der().unwrap(),
        after,
        "newest key is not first"
    );
}

/// The private key must not reach the `rsa` crate.
///
/// This is the actual fix for RUSTSEC-2023-0071, and the pacing above is now
/// defence in depth rather than the whole answer. `blind-rsa-signatures` is still
/// used — for blinding, unblinding and verification, none of which touch a secret
/// — so the vulnerable crate is still in the dependency graph and `cargo-deny`
/// still has to be told about it. What makes that ignore honest is this test: the
/// allowed secret-key methods only expose components, serialize PKCS#8, or derive
/// the public key. Online private exponentiation uses the constant-time path.
///
/// Written against the source rather than the dependency graph because that is
/// where the mistake would be made. Reintroducing the vulnerable path is one line
/// — `self.0.sk.blind_sign(..)` is shorter than what replaced it, and it would
/// pass every other test in the workspace, because it produces the same bytes.
/// That is exactly the kind of regression a graph-level check cannot see.
#[test]
fn no_secret_key_operation_goes_through_the_unpatched_rsa_crate() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../spark-crypto/src/blind.rs"
    ))
    .expect("blind.rs");

    // Comments explain the ban and would otherwise trip it.
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut uses: Vec<&str> = Vec::new();
    let mut rest = code.as_str();
    while let Some(i) = rest.find(".sk") {
        rest = &rest[i + 3..];
        let call: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace() || *c == '.')
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !call.is_empty() {
            uses.push(Box::leak(call.into_boxed_str()));
        }
    }

    assert!(
        !uses.is_empty(),
        "no use of the secret key found at all — this test has stopped checking anything"
    );

    // The hazard the fix itself introduced. `ct::public_modexp` bounds its ladder
    // by the exponent's real bit length instead of the modulus precision, which is
    // right for `e` and would leak the private exponent's length if it were ever
    // handed `d`. Both signatures take `(base, exp, modulus)`, so the mistake is a
    // one-word edit that changes no test result — only the timing.
    let public_calls: Vec<&str> = code
        .match_indices("ct::public_modexp(")
        .map(|(i, _)| {
            let rest = &code[i + "ct::public_modexp(".len()..];
            let end = rest.find(')').unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    assert_eq!(
        public_calls.len(),
        1,
        "expected exactly one variable-time exponentiation, found {}: {public_calls:?}",
        public_calls.len()
    );
    // And the other direction: the constant-time path must stay unbounded. Bounding
    // it by the exponent's own bit length is a one-word edit that produces identical
    // signatures and leaks how many bits `d` has — a timing test could not tell the
    // difference without being flaky, so the source is where it gets checked.
    assert_eq!(
        code.matches("pow_bounded_exp(").count(),
        1,
        "expected exactly one bounded ladder in blind.rs — the public one"
    );
    assert!(
        code.contains("None => m.pow(&e),"),
        "the full-precision arm of `ct::pow` is no longer a plain `pow`. That arm is \
         the private-key exponentiation: its cost must depend on the modulus \
         precision, which is public, and never on the exponent, which is the key."
    );

    let args: Vec<&str> = public_calls[0].split(',').map(str::trim).collect();
    assert_eq!(
        args.get(1).copied(),
        Some("&e"),
        "the variable-time path was given `{}` as its exponent. It is only safe for \
         the public exponent; anything else leaks that exponent's bit length in the \
         time pattern, which is the whole of RUSTSEC-2023-0071.",
        args.get(1).copied().unwrap_or("nothing")
    );
    for call in &uses {
        // `to_der` is PKCS#8 serialization only (upstream SecretKey::to_der);
        // it performs no signing/exponentiation. Persisted deployment keys need
        // this operation. Keep every computational private-key method forbidden.
        assert!(
            matches!(*call, "components" | "to_der" | "public_key"),
            "unexpected secret-key operation `{call}`; private exponentiation must use blind::ct::modexp"
        );
    }
}
