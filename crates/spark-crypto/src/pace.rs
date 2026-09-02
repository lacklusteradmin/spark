//! Removing the timing channel from a private-key operation.
//!
//! # Why this lives in a crypto crate
//!
//! It is not cryptography. It is here because it exists for exactly one purpose —
//! protecting the blind-signing operation in [`crate::blind`] — and because the
//! alternative is two servers each implementing it slightly differently.
//!
//! # What it is for
//!
//! RUSTSEC-2023-0071, the Marvin Attack: the `rsa` crate's modular exponentiation
//! is not constant-time, so an attacker who can time private-key operations over
//! the network may recover the key. Spark performs that operation on two servers.
//!
//! Base blinding *is* applied on every signature (`blind_sign_with_rng` passes an
//! RNG, and `rsa` randomises the base when given one), which is the classical
//! defence and is why the advisory's CVSS says the attack complexity is high. It
//! is a mitigation, not a proof, and the advisory has no patched version.
//!
//! So the channel is closed where Spark controls it: the *response* is emitted on
//! a fixed tick boundary rather than as soon as the work finishes. An attacker
//! measuring response time sees a quantised value that does not vary with the
//! input, whatever the library underneath does.
//!
//! # What this does not fix
//!
//! * The tick must exceed the worst-case work, or the *number* of ticks varies
//!   and the channel is back, coarsened. [`Pacing::after`] reports that as
//!   [`Paced::overran`] so a service can count it rather than discover it later.
//! * It must wrap the whole request path, not the signing call alone. Pacing the
//!   signature while the surrounding parse and database write vary would leave
//!   the variance intact.
//! * It is a mitigation. When `rsa` lands a constant-time implementation this
//!   becomes defence in depth rather than the control.

/// How long to wait, and whether the tick was big enough.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Paced {
    /// Nanoseconds to wait before responding.
    pub wait_nanos: u64,
    /// The work took longer than one tick, so the number of ticks now varies with
    /// the input and the timing channel is partly open again.
    ///
    /// Not an error: refusing to answer would be worse. It is a signal that the
    /// tick is set too low for this machine, and a service should count it.
    pub overran: bool,
}

/// Emits results on a fixed cadence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pacing {
    tick_nanos: u64,
}

impl Pacing {
    /// A cadence of `tick_nanos`.
    ///
    /// Choose it comfortably above the worst-case signing time on the slowest
    /// machine the service will run on. Token withdrawal and voucher purchase are
    /// not latency-sensitive — nobody is waiting on the result — so the tick can
    /// be generous. 50 ms is the suggested starting point, and
    /// [`Pacing::DEFAULT`] is that.
    pub const fn new(tick_nanos: u64) -> Self {
        Self {
            tick_nanos: if tick_nanos == 0 { 1 } else { tick_nanos },
        }
    }

    /// 50 milliseconds.
    pub const DEFAULT: Pacing = Pacing::new(50_000_000);

    /// The cadence in nanoseconds.
    pub const fn tick_nanos(&self) -> u64 {
        self.tick_nanos
    }

    /// How long to wait, given how long the work took.
    ///
    /// Work of zero duration still waits a full tick. Returning immediately would
    /// make "nothing to do" distinguishable from "signed something", which is a
    /// smaller channel than the one being closed but the same channel.
    pub const fn after(&self, elapsed_nanos: u64) -> Paced {
        let t = self.tick_nanos;
        // Round up to the next whole tick, with zero rounding up to one.
        let ticks = elapsed_nanos / t + 1;
        let target = ticks * t;
        Paced {
            wait_nanos: target - elapsed_nanos,
            overran: elapsed_nanos >= t,
        }
    }
}

/// A clock a paced service reads and sleeps against.
///
/// A trait rather than a call to the standard library, for the same reason
/// entropy is a parameter everywhere below the I/O line: a test that depends on
/// real elapsed time is a test that fails on a loaded CI machine, and a timing
/// countermeasure whose tests are flaky is one nobody will trust when it fails
/// for real.
pub trait Clock {
    /// Nanoseconds since some fixed point. Only differences are meaningful.
    fn now_nanos(&self) -> u64;
    /// Wait.
    fn sleep_nanos(&self, nanos: u64);
}
