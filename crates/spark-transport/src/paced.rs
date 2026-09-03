//! A channel that transmits on a schedule instead of when it has something to say.
//!
//! `Spark-spec.md` F12 and D12. [`crate::hysteria`] is the scheduler; this is what
//! connects it to a real connection, and without it the scheduler was a module
//! nothing called.
//!
//! # Both directions have to be uniform, but only one has to be paced
//!
//! The client transmits on a fixed cadence whether or not it has anything, so an
//! observer cannot tell a busy user from a sleeping one. The server does not need
//! its own cadence — it only ever answers, so its transmissions already land on the
//! client's schedule. What it *does* need is uniform size: a 4 KB request answered
//! by an 8 KB reply tells an observer that a real request went out, and the cadence
//! bought nothing.
//!
//! So responses are padded into the same frames, and a reply too large for one
//! slot arrives across several. That is the cost, and it is why media stays out of
//! the stream entirely (D12) — a photo at one frame per minute is not a slow photo.
//!
//! # The clock is a parameter
//!
//! A test that waited sixty seconds per slot would not be run. More importantly, a
//! test that measured real elapsed time would be flaky, and a timing countermeasure
//! whose tests are flaky is one nobody trusts the day it fails for real — the same
//! reasoning as `spark_crypto::pace`.

use crate::channel::ChannelError;
use crate::hysteria::{Frame as CoverFrame, Hysteria, Reassembler};
use crate::route::Class;
use spark_wire::{Frame, Operation};
use std::io::{Read, Write};

/// Advances the transmit schedule.
///
/// Production waits for the next slot; a test steps it directly. Nothing here
/// reads a clock of its own, so nothing here can be slow by accident.
pub trait Ticker {
    /// Block until the next slot.
    fn wait_for_slot(&mut self);
}

/// A ticker that sleeps for the real interval.
pub struct RealTicker {
    interval: std::time::Duration,
}

impl RealTicker {
    /// A ticker on `interval`.
    ///
    /// The interval is a parameter for the same reason the ticker itself is: a
    /// test that waited out `Default`'s minute per request would take an hour, so
    /// it would not be written, and the paced path would go unexercised. It is not
    /// a knob to turn down in production — shortening it narrows the window an
    /// observer has to average over.
    pub fn every(interval: std::time::Duration) -> Self {
        Self { interval }
    }
}

impl Default for RealTicker {
    /// `Spark-spec.md` F12's interval.
    fn default() -> Self {
        Self::every(std::time::Duration::from_secs(
            crate::hysteria::INTERVAL_SECS,
        ))
    }
}

impl Ticker for RealTicker {
    fn wait_for_slot(&mut self) {
        std::thread::sleep(self.interval);
    }
}

/// A ticker that returns at once. For tests, and for nothing else.
#[derive(Default)]
pub struct Immediate;

impl Ticker for Immediate {
    fn wait_for_slot(&mut self) {}
}

/// A connection whose transmissions go out on a schedule.
pub struct Paced<S: Read + Write, T: Ticker> {
    inner: crate::channel::Channel<S>,
    out: Hysteria,
    inbound: Reassembler,
    ticker: T,
    next_id: u32,
    /// Cover frames sent while nothing was queued. Not diagnostics: it is how
    /// "idle and busy are indistinguishable" is checkable of a live connection.
    slots: u64,
}

impl<S: Read + Write, T: Ticker> Paced<S, T> {
    /// Wrap a channel in the transmit schedule.
    pub fn new(inner: crate::channel::Channel<S>, ticker: T) -> Self {
        Self {
            inner,
            out: Hysteria::new(),
            inbound: Reassembler::new(),
            ticker,
            next_id: 1,
            slots: 0,
        }
    }

    /// How many slots have been transmitted, carrying anything or nothing.
    pub fn slots(&self) -> u64 {
        self.slots
    }

    /// Turn one slot with nothing queued, sending cover traffic.
    ///
    /// What an idle client does, and the reason the mode works at all: a client
    /// that only transmitted when it had something would be announcing exactly
    /// that.
    pub fn turn_slot(&mut self) -> Result<(), ChannelError> {
        self.ticker.wait_for_slot();
        let cover = self.out.tick();
        self.slots += 1;
        self.inner.send_raw(cover.as_bytes())?;
        let reply = self.inner.recv_raw()?;
        let cover = CoverFrame::from_bytes(&reply)
            .ok_or(ChannelError::Wire(spark_wire::WireError::Malformed))?;
        self.inbound
            .accept(&cover)
            .map(|_| ())
            .map_err(|_| ChannelError::Wire(spark_wire::WireError::Malformed))
    }

    /// Send a request and wait for its response, both on the schedule.
    ///
    /// `class` is checked rather than assumed: media does not travel here, and
    /// enqueueing it would make the delay unusable and the frame size a lie.
    pub fn call<Q, R>(&mut self, class: Class, req: &Q) -> Result<R, ChannelError>
    where
        Q: serde::Serialize + Operation,
        R: serde::de::DeserializeOwned + Operation,
    {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let framed = Frame::encode(id, req)?.to_bytes();
        self.out
            .enqueue(class, &framed)
            .map_err(|_| ChannelError::Wire(spark_wire::WireError::Encode))?;

        loop {
            // A slot goes out whether or not anything is queued. There is no
            // "nothing to send" path, because a skipped transmission is the signal
            // the whole mode exists to suppress.
            self.ticker.wait_for_slot();
            let cover = self.out.tick();
            self.slots += 1;
            self.inner.send_raw(cover.as_bytes())?;

            let reply = self.inner.recv_raw()?;
            let cover = CoverFrame::from_bytes(&reply)
                .ok_or(ChannelError::Wire(spark_wire::WireError::Malformed))?;
            for msg in self
                .inbound
                .accept(&cover)
                .map_err(|_| ChannelError::Wire(spark_wire::WireError::Malformed))?
            {
                let f = Frame::from_bytes(&msg)?;
                if f.req_id == id {
                    return Ok(f.body::<R>()?);
                }
            }
        }
    }
}
