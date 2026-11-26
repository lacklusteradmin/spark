//! A channel that transmits on a schedule instead of when it has something to say.
//!
//! `docs/SPARK-SPEC.md` F12 and D12. [`crate::hysteria`] is the scheduler; this is what
//! connects it to a real connection, and without it the scheduler was a module
//! nothing called.
//!
//! # Keeping the schedule
//!
//! F12 has the client transmit on a fixed cadence whether or not it has anything,
//! so an observer cannot tell a busy user from a sleeping one. [`Scheduled`] does
//! that: a thread of its own turns one slot at every boundary of a fixed clock,
//! carrying whatever is queued or nothing, and callers hand it their requests.
//! [`Paced`] is the connection underneath. It can be used on its own with a
//! [`Ticker`] the caller steps, which is how the tests check its shape, but on its
//! own it transmits only while a request waits for its reply — which tells an
//! observer exactly when there was something to say.
//!
//! # Both directions have to be uniform, but only one has to be paced
//!
//! The server does not need its own cadence — it only ever answers, so its
//! transmissions already land on the client's schedule. What it *does* need is
//! uniform size: a 4 KB request answered by an 8 KB reply tells an observer that a
//! real request went out, and the cadence bought nothing.
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

use crate::channel::{Channel, ChannelError};
use crate::hysteria::{Frame as CoverFrame, Hysteria, Reassembler};
use crate::route::Class;
use spark_wire::{Frame, Operation};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// Advances the transmit schedule.
///
/// Production waits for the next slot; a test steps it directly. Nothing here
/// reads a clock of its own, so nothing here can be slow by accident.
pub trait Ticker {
    /// Block until the next slot.
    fn wait_for_slot(&mut self);
}

/// A ticker that sleeps for the real interval.
///
/// A whole interval from each call, not to a fixed clock boundary, so a request's
/// first slot goes out one interval after the request. [`Scheduled`] keeps a fixed
/// clock instead.
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
    /// `docs/SPARK-SPEC.md` F12's interval.
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
    /// Slots transmitted, carrying a request or not. Not diagnostics: it is how
    /// whether pacing happened at all is checkable of a live connection.
    slots: u64,
}

impl<S: Read + Write, T: Ticker> Paced<S, T> {
    /// Wrap a channel in the transmit schedule.
    pub fn new(inner: Channel<S>, ticker: T) -> Self {
        Self::with_schedule(inner, ticker, Hysteria::new())
    }

    fn with_schedule(inner: Channel<S>, ticker: T, out: Hysteria) -> Self {
        Self {
            inner,
            out,
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
    /// What an idle client has to do for the mode to work at all: a client that
    /// only transmitted when it had something would be announcing exactly that.
    /// [`Scheduled`] does it at every boundary of its clock.
    pub fn turn_slot(&mut self) -> Result<(), ChannelError> {
        self.ticker.wait_for_slot();
        self.turn().map(|_| ())
    }

    /// Queue a protocol frame for the next slots.
    ///
    /// Media is refused: it does not travel here, and enqueueing it would make the
    /// delay unusable and the frame size a lie.
    fn queue(&mut self, class: Class, framed: &[u8]) -> Result<(), ChannelError> {
        self.out
            .enqueue(class, framed)
            .map_err(|_| ChannelError::Wire(spark_wire::WireError::Encode))
    }

    /// Transmit one slot now and read the peer's answer to it.
    ///
    /// Returns the messages the answer completed. A slot goes out whether or not
    /// anything is queued: there is no "nothing to send" path, because a skipped
    /// transmission is the signal the whole mode exists to suppress.
    fn turn(&mut self) -> Result<Vec<Vec<u8>>, ChannelError> {
        let cover = self.out.tick();
        self.slots += 1;
        self.inner.send_raw(cover.as_bytes())?;
        let reply = self.inner.recv_raw()?;
        let cover = CoverFrame::from_bytes(&reply)
            .ok_or(ChannelError::Wire(spark_wire::WireError::Malformed))?;
        self.inbound
            .accept(&cover)
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
        self.queue(class, &framed)?;

        loop {
            self.ticker.wait_for_slot();
            for msg in self.turn()? {
                let f = Frame::from_bytes(&msg)?;
                if f.req_id == id {
                    return Ok(f.body::<R>()?);
                }
            }
        }
    }
}

/// A paced connection that keeps `docs/SPARK-SPEC.md` F12's schedule by itself.
///
/// The connection belongs to a thread that turns one slot at every boundary of a
/// clock started when the connection opened — a frame carrying whatever is queued,
/// or a dummy — whether or not anything is waiting. [`Scheduled::call`] queues a
/// request and waits for its reply, so a request waits for the next boundary (one
/// interval at worst) and travels in a frame that would have gone out anyway. The
/// server answers a frame before handling what it carried, so the reply comes back
/// in the answer to the frame after. An idle client and a busy one send the same
/// frames at the same times.
///
/// A boundary missed because the previous slot's answer was slow is skipped, not
/// sent late: the schedule keeps its phase rather than bursting to catch up.
///
/// Dropping this stops the thread, and the connection closes with it.
pub struct Scheduled {
    jobs: mpsc::Sender<Job>,
    next_id: AtomicU32,
    slots: Arc<AtomicU64>,
}

/// Where a request's answer goes.
type Answer = mpsc::SyncSender<Result<Frame, ChannelError>>;

/// A request waiting for a slot.
struct Job {
    id: u32,
    class: Class,
    framed: Vec<u8>,
    answer: Answer,
}

impl Scheduled {
    /// Start keeping the schedule on `inner`, one slot per `interval`.
    ///
    /// `schedule` comes from [`crate::hysteria::enable`], so the platform has been
    /// asked whether it can hold the stream before anything is sent. An interval
    /// under a millisecond is taken as one.
    pub fn start<S>(
        inner: Channel<S>,
        schedule: Hysteria,
        interval: Duration,
    ) -> std::io::Result<Self>
    where
        S: Read + Write + Send + 'static,
    {
        let (jobs, waiting) = mpsc::channel();
        let slots = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&slots);
        let paced = Paced::with_schedule(inner, Immediate, schedule);
        std::thread::Builder::new()
            .name("spark-cover".into())
            .spawn(move || drive(paced, SlotClock::new(interval), &waiting, &counted))?;
        Ok(Self {
            jobs,
            next_id: AtomicU32::new(1),
            slots,
        })
    }

    /// Send a request in the next slot and wait for its reply.
    ///
    /// Media is refused, as by [`Paced::call`].
    pub fn call<Q, R>(&self, class: Class, req: &Q) -> Result<R, ChannelError>
    where
        Q: serde::Serialize + Operation,
        R: serde::de::DeserializeOwned + Operation,
    {
        let id = self.id();
        let framed = Frame::encode(id, req)?.to_bytes();
        let (answer, reply) = mpsc::sync_channel(1);
        self.jobs
            .send(Job {
                id,
                class,
                framed,
                answer,
            })
            .map_err(|_| ChannelError::Closed)?;
        let f = reply.recv().map_err(|_| ChannelError::Closed)??;
        Ok(f.body::<R>()?)
    }

    /// How many slots have been transmitted, carrying anything or nothing.
    pub fn slots(&self) -> u64 {
        self.slots.load(Ordering::Relaxed)
    }

    /// A request id: never zero, and distinct from the others in flight.
    fn id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

/// The thread behind [`Scheduled`]: one slot per boundary, until the owner is gone
/// or the connection fails.
fn drive<S: Read + Write>(
    mut paced: Paced<S, Immediate>,
    mut clock: SlotClock,
    jobs: &mpsc::Receiver<Job>,
    slots: &AtomicU64,
) {
    let mut waiting: BTreeMap<u32, Answer> = BTreeMap::new();
    loop {
        let due = clock.next_boundary();
        // Take requests until the slot is due. Arriving early changes nothing on
        // the wire: the frame goes out at the boundary either way.
        loop {
            let now = Instant::now();
            if now >= due {
                break;
            }
            match jobs.recv_timeout(due - now) {
                Ok(job) => match paced.queue(job.class, &job.framed) {
                    Ok(()) => {
                        waiting.insert(job.id, job.answer);
                    }
                    Err(e) => {
                        let _ = job.answer.send(Err(e));
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                // The `Scheduled` is gone, and with it every caller: a caller holds
                // it for as long as it waits.
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }

        let done = match paced.turn() {
            Ok(done) => done,
            Err(e) => return fail(waiting, e),
        };
        slots.store(paced.slots(), Ordering::Relaxed);
        for msg in done {
            let f = match Frame::from_bytes(&msg) {
                Ok(f) => f,
                Err(e) => return fail(waiting, e.into()),
            };
            // An answer to nothing in flight is dropped rather than handed to the
            // wrong caller.
            if let Some(answer) = waiting.remove(&f.req_id) {
                let _ = answer.send(Ok(f));
            }
        }
    }
}

/// Tell everyone waiting that the connection is gone.
///
/// The thread returns after this, which drops the job queue, so later calls fail
/// at once rather than wait for a slot that will never come.
fn fail(waiting: BTreeMap<u32, Answer>, e: ChannelError) {
    for answer in waiting.into_values() {
        let _ = answer.send(Err(e));
    }
}

/// Slot boundaries at whole intervals from when the clock started.
struct SlotClock {
    next: Instant,
    interval: Duration,
}

impl SlotClock {
    fn new(interval: Duration) -> Self {
        let interval = interval.max(Duration::from_millis(1));
        Self {
            next: Instant::now() + interval,
            interval,
        }
    }

    /// The next boundary that has not passed.
    ///
    /// Boundaries missed while a slot waited on its answer are skipped, so the
    /// schedule keeps its phase instead of sending a late burst.
    fn next_boundary(&mut self) -> Instant {
        let now = Instant::now();
        if self.next < now {
            let step = self.interval.as_nanos();
            let late = (now - self.next).as_nanos();
            // At most the time the clock has been running, so it fits.
            let skip = u64::try_from(late.div_ceil(step) * step).unwrap_or(u64::MAX);
            self.next += Duration::from_nanos(skip);
        }
        let due = self.next;
        self.next += self.interval;
        due
    }
}
