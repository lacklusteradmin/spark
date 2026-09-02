//! Push notifications. `Spark-spec.md` D3, and threat W2.
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

/// Whether the user wants push.
///
/// On by default, per D3 — with the leak stated rather than hidden, which is what
/// [`Setting::warning`] is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Setting {
    /// Registered with the platform, and therefore leaking per W2.
    #[default]
    On,
    /// Never registered. Messages arrive on app open, or through background
    /// polling the platform throttles by design.
    Off,
}

impl Setting {
    /// What to tell the user, in their words.
    ///
    /// D3 requires "a warning that states the leak plainly". Turning push off also
    /// costs real functionality, and saying only half of that is its own kind of
    /// dishonesty.
    pub const fn warning(self) -> &'static str {
        match self {
            Setting::On => {
                "Apple and Google will know when messages arrive for you, and the token \
                 that makes this work is tied to your Apple or Google account. Spark's \
                 encryption does not cover that."
            }
            Setting::Off => {
                "Messages will arrive when you open Spark, and not before. Nothing is \
                 registered with Apple or Google — turning this back on registers again."
            }
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
        Setting::On => Ok(Registration { token: mint() }),
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
