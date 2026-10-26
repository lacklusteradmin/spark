//! Push notifications. `Spark-spec.md` D3, and threat W2.
//!
//! # Off by default, and loud to turn on
//!
//! A product decision, recorded in D3: push is **off** unless the user turns it
//! on, and turning it on means being told the risk first. Delivering a push
//! requires a server to hold a token tied to a real Apple or Google account,
//! which `Spark-build-notes.md` §2 says Spark's servers may never store. Off by
//! default is how both can hold: nobody's account is bridged to their identity
//! unless they chose it after reading what it costs.
//!
//! "Told first" is structural rather than a convention. [`Setting::On`] carries a
//! [`Consent`], and [`Consent::acknowledge`] is its only constructor — it takes
//! back the warning text the interface displayed and refuses anything that is not
//! exactly [`ENABLE_WARNING`]. So there is no path to "on" through an API that
//! never mentioned the risk, and an interface still showing a previous wording
//! fails closed when the wording changes, rather than enabling push under a
//! warning that no longer says what is true.
//!
//! # The one thing that has to be structural
//!
//! D3: "Off must mean never registering. Disabling notifications in the OS only
//! stops them being displayed while the token persists, and a control that
//! appears to close the leak while leaving it open is worse than none."
//!
//! So the platform call that mints a token is not made at all when the setting is
//! off. [`register`] takes the minting operation as a closure and never invokes
//! it in that case, and [`Registration`] has no other constructor. "Registered but
//! suppressed" is not a state this module can represent.
//!
//! # Why push is its own switch
//!
//! D3 again: "Push stays its own switch rather than folding into a combined
//! profile. The three protections cover different things, and bundling them
//! invites the assumption that one setting covers everything." Nothing here
//! consults the Tor mode or whether cover traffic is on.

/// What the user must be shown before push can be turned on.
///
/// Every clause is load-bearing, and `the_warning_names_every_part_of_the_risk`
/// holds each one in place: who learns something (Apple or Google), what they
/// learn (when messages arrive), what links it to the person (a token tied to
/// their account, held by a server), that Spark's encryption is no defence, and
/// that turning it off later does not take back what was already seen. The last
/// one is the clause a softer warning would leave out.
///
/// # Translations
///
/// When the app is localized, each translation belongs in this module and
/// [`Consent::acknowledge`] should accept exactly those. Loosening the check to a
/// boolean or a version number would make "the user saw the warning" something
/// the interface asserts rather than something it has to demonstrate.
pub const ENABLE_WARNING: &str = "Turning on push notifications tells Apple or Google when \
    messages arrive for you. To deliver them, a server has to keep a push token that \
    is tied to your Apple or Google account, and that links this Spark account to \
    you. Spark's encryption does not cover any of this. Turning push off later stops \
    it from then on, but does not undo what was already seen.";

/// What staying off costs, stated alongside the risk of turning it on.
///
/// D3: saying only half of a tradeoff is its own kind of dishonesty. Off is the
/// default, so this is the cost every user pays unless they choose otherwise.
pub const OFF_COST: &str = "Messages will arrive when you open Spark, and not before. \
    Nothing is registered with Apple or Google.";

/// Proof that the user was shown [`ENABLE_WARNING`] and accepted it.
///
/// The field is private, so this module is the only place one can be made, and
/// [`Consent::acknowledge`] is the only function here that makes one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Consent(());

impl Consent {
    /// Accept the warning the interface displayed.
    ///
    /// `shown` must be exactly [`ENABLE_WARNING`] — not a prefix, not a paraphrase,
    /// not differently cased. The interface has to have had the real text in hand
    /// to get past this, and an interface still carrying an older wording is
    /// refused rather than allowed to enable push under it.
    pub fn acknowledge(shown: &str) -> Result<Self, WarningNotShown> {
        if shown == ENABLE_WARNING {
            Ok(Self(()))
        } else {
            Err(WarningNotShown)
        }
    }
}

/// The text handed to [`Consent::acknowledge`] was not the current warning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WarningNotShown;

impl core::fmt::Display for WarningNotShown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("push was not turned on: the current warning was not shown")
    }
}
impl core::error::Error for WarningNotShown {}

/// Whether the user wants push.
///
/// **Off by default** — see the module documentation for why, and D3.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Setting {
    /// Never registered. Messages arrive on app open, or through background
    /// polling the platform throttles by design.
    #[default]
    Off,
    /// Registered with the platform, and therefore leaking per W2. Cannot be
    /// reached without a [`Consent`].
    On(Consent),
}

impl Setting {
    /// What this setting costs, in the user's words.
    pub const fn warning(self) -> &'static str {
        match self {
            Setting::On(_) => ENABLE_WARNING,
            Setting::Off => OFF_COST,
        }
    }
}

/// A token minted by the platform's push service.
///
/// Opaque here. What matters is that it exists only inside a [`Registration`].
pub struct Token(String);

impl Token {
    /// Wrap a token the platform handed back.
    pub fn new(t: String) -> Self {
        Self(t)
    }
    /// The token, for the one call that sends it onward.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A push token is a real-world identifier. It does not belong in a log.
        f.write_str("Token(redacted)")
    }
}

/// Proof that push was registered while the setting was on.
#[derive(Debug)]
pub struct Registration {
    token: Token,
}

impl Registration {
    /// The token to hand to the delivery service.
    pub fn token(&self) -> &Token {
        &self.token
    }
}

/// Register for push, if and only if the setting allows it.
///
/// `mint` is the platform call — `UNUserNotificationCenter`, `FirebaseMessaging`,
/// whatever the client is wrapping. **It is not invoked when the setting is off.**
/// That is the whole point: a token that was never minted cannot persist, cannot
/// be leaked by a later bug, and cannot be found on the device afterwards.
pub fn register(
    setting: Setting,
    mint: impl FnOnce() -> Token,
) -> Result<Registration, PushDisabled> {
    match setting {
        Setting::On(_) => Ok(Registration { token: mint() }),
        Setting::Off => Err(PushDisabled),
    }
}

/// Push is off, so nothing was registered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PushDisabled;

impl core::fmt::Display for PushDisabled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("push is off, so nothing was registered")
    }
}
impl core::error::Error for PushDisabled {}

/// What a wake-up may carry.
///
/// D3: "content-free and identity-free wake-up signals". The push provider sees
/// the payload, so anything in it is something Apple and Google learn. There is
/// therefore nothing to put in it — the client wakes and fetches for itself.
///
/// A unit struct rather than an empty byte string, so there is no field for
/// someone to add "just a room name" to later.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Wake;

impl Wake {
    /// The payload, which is empty and stays empty.
    pub const fn payload() -> &'static [u8] {
        &[]
    }
}
