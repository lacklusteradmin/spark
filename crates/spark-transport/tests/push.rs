//! D3's push semantics, and the two that are structural: off never registers,
//! and on cannot be reached without the warning.

use spark_transport::push::*;
use std::cell::Cell;

/// Push turned on the only way it can be: by handing back the warning.
fn on() -> Setting {
    Setting::On(Consent::acknowledge(ENABLE_WARNING).expect("the real warning"))
}

#[test]
fn off_means_the_platform_is_never_asked_for_a_token() {
    // D3: "Off must mean never registering. Disabling notifications in the OS only
    // stops them being displayed while the token persists, and a control that
    // appears to close the leak while leaving it open is worse than none."
    //
    // So the check is not "no token was returned" — it is that the minting call
    // never happened. A token that was never minted cannot persist, cannot leak
    // through a later bug, and cannot be found on the device afterwards.
    let minted = Cell::new(false);
    let r = register(Setting::Off, || {
        minted.set(true);
        Token::new("apns-token".into())
    });

    assert_eq!(r.unwrap_err(), PushDisabled);
    assert!(
        !minted.get(),
        "the platform was asked for a token while push was off"
    );
}

#[test]
fn on_registers_and_yields_the_token() {
    let minted = Cell::new(false);
    let r = register(on(), || {
        minted.set(true);
        Token::new("fcm-token".into())
    })
    .expect("registration");
    assert!(minted.get());
    assert_eq!(r.token().expose(), "fcm-token");
}

#[test]
fn a_token_does_not_appear_in_debug_output() {
    // It is a real-world identifier, bound to an Apple or Google account. It does
    // not belong in a log.
    let r = register(on(), || Token::new("secret-token-value".into())).unwrap();
    let shown = format!("{r:?} {:?}", r.token());
    assert!(
        !shown.contains("secret-token-value"),
        "a push token leaked through Debug"
    );
}

#[test]
fn the_wake_up_signal_carries_nothing() {
    // D3: "content-free and identity-free wake-up signals". The push provider sees
    // the payload, so anything in it is something Apple and Google learn.
    assert!(Wake::payload().is_empty());
    // And there is no field to add one to later.
    assert_eq!(core::mem::size_of::<Wake>(), 0);
}

#[test]
fn both_settings_state_their_cost() {
    // On leaks; off costs functionality. Saying only half is its own dishonesty.
    assert_eq!(on().warning(), ENABLE_WARNING);

    let off = Setting::Off.warning();
    assert!(
        off.len() > 40,
        "turning push off has costs and they are not stated"
    );
    assert!(
        off.contains("open Spark"),
        "the functional cost is not stated"
    );
}

#[test]
fn turning_push_on_requires_the_exact_warning() {
    // The product decision: if push is turned on at all, the user is told the risk
    // first. A boolean "user agreed" would let an interface enable push without
    // ever having displayed anything, so the interface has to hand back the text.
    //
    // Each rejection here is a way a careless or stale interface could otherwise
    // get through: nothing shown, a button label, the first sentence only, a
    // restyled copy, and a previous wording that has since been made stronger.
    let truncated = &ENABLE_WARNING[..ENABLE_WARNING.find('.').unwrap() + 1];
    let older = "Apple and Google will know when messages arrive for you, and the token \
                 that makes this work is tied to your Apple or Google account. Spark's \
                 encryption does not cover that.";
    for (what, shown) in [
        ("nothing", ""),
        ("a button label", "OK"),
        ("the first sentence only", truncated),
        ("a restyled copy", &ENABLE_WARNING.to_uppercase()),
        ("trailing whitespace", &format!("{ENABLE_WARNING} ")),
        ("an older, weaker wording", older),
    ] {
        assert_eq!(
            Consent::acknowledge(shown),
            Err(WarningNotShown),
            "push could be turned on after showing {what}"
        );
    }
    assert!(Consent::acknowledge(ENABLE_WARNING).is_ok());
}

#[test]
fn the_warning_names_every_part_of_the_risk() {
    // "Loud" means complete, not long. Each clause is a different thing the user
    // is giving up, and a warning missing any one of them understates the cost.
    for (clause, why) in [
        ("Apple or Google", "who learns something"),
        ("when messages arrive", "what they learn"),
        (
            "tied to your Apple or Google account",
            "what makes it about a person",
        ),
        (
            "a server has to keep",
            "that Spark's side holds it too, not only Apple's",
        ),
        (
            "links this Spark account to you",
            "the consequence, said plainly",
        ),
        ("encryption does not cover", "that E2EE is no defence here"),
        (
            "does not undo what was already seen",
            "that off later is not a reset",
        ),
    ] {
        assert!(
            ENABLE_WARNING.contains(clause),
            "the push warning no longer says {why} (missing {clause:?})"
        );
    }
}

#[test]
fn push_is_off_by_default_and_is_its_own_switch() {
    // The product decision recorded in D3: off unless the user turns it on.
    // `Spark-build-notes.md` §2 says servers may never store real-world
    // identifiers and a push token is one; off by default is how that holds for
    // everyone who has not chosen otherwise.
    //
    // And still its own switch: D3 says it "stays its own switch rather than
    // folding into a combined profile. The three protections cover different
    // things, and bundling them invites the assumption that one setting covers
    // everything."
    assert_eq!(Setting::default(), Setting::Off);

    // Nothing in this module's API mentions Tor or cover traffic. If push were
    // ever folded into a combined profile, this would be where it showed up.
    let src = include_str!("../src/push.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for coupled in ["Mode::", "Hysteria", "route::"] {
        assert!(
            !code.contains(coupled),
            "push became coupled to `{coupled}`"
        );
    }
}
