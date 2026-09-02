//! D3's push semantics, and the one that is structural.

use spark_transport::push::*;
use std::cell::Cell;

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
    let r = register(Setting::On, || {
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
    let r = register(Setting::On, || Token::new("secret-token-value".into())).unwrap();
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
    let on = Setting::On.warning();
    assert!(
        on.contains("Apple") && on.contains("Google"),
        "the leak is not named"
    );

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
fn push_is_on_by_default_and_is_its_own_switch() {
    // D3: on by default, and "stays its own switch rather than folding into a
    // combined profile. The three protections cover different things, and bundling
    // them invites the assumption that one setting covers everything."
    assert_eq!(Setting::default(), Setting::On);

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
