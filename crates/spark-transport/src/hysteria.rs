//! Cover traffic. `Spark-spec.md` F12 and D12.
//!
//! The client transmits on a fixed schedule whether or not the user is doing
//! anything. Real messages occupy slots in place of dummies, so traffic looks the
//! same whether the user is chatting constantly or asleep.
//!
//! This is the only mechanism that meaningfully attacks traffic-analysis
//! correlation (W4), and it pairs with Tor: Tor hides *where* you are, this hides
//! *when* you speak.
//!
//! # What has to be uniform, and why all three
//!
//! F12: "Every transmission is padded to a uniform size and sent to the same
//! endpoint, since an observer who can spot a dummy by length or destination gets
//! the timing back for free." Timing alone is not enough — a schedule whose frames
//! vary in size is a schedule with the answer written on it.
//!
//! # Parameters, and why they are not maximal
//!
//! D12 sets them for adoption rather than for strength: "a setting only a few
//! hundred people enable makes those people a recognisable group." Cover traffic
//! hides you inside a crowd transmitting on the same schedule, so its strength
//! scales with how many people leave it on.

use crate::route::Class;

/// Seconds between transmissions.
///
/// D12: shorter defends better but keeps the radio awake and visibly costs
/// battery, so nobody leaves it on. A real message takes the next slot — 30
/// seconds of delay on average, 60 at worst.
pub const INTERVAL_SECS: u64 = 60;

/// Bytes in every frame, before sealing.
///
/// D12: covers most text messages; larger ones split across slots. Roughly
/// 5.6 MB a day.
pub const FRAME_BYTES: usize = 4096;

/// Bytes of framing before the first record.
const FRAME_HEADER: usize = 1;
/// Bytes of framing per record: message id, fragment index, fragment count, length.
const RECORD_HEADER: usize = 8;

/// The most payload one frame can carry.
pub const MAX_PAYLOAD_PER_FRAME: usize = FRAME_BYTES - FRAME_HEADER - RECORD_HEADER;

/// One transmission. Always exactly [`FRAME_BYTES`] long, dummy or not.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame(Vec<u8>);

impl Frame {
    /// The bytes to seal and send.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Whether this frame carries nothing. **Visible only after decryption** — an
    /// observer sees the same length either way, which is the point.
    pub fn is_dummy(&self) -> bool {
        self.0[0] == 0
    }

    /// Wrap bytes received from a peer.
    ///
    /// Returns `None` for anything that is not exactly [`FRAME_BYTES`] long. A
    /// frame of another size is not a frame: uniform size is the property, so
    /// accepting a short one would be accepting the thing being defended against.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == FRAME_BYTES).then(|| Self(b.to_vec()))
    }
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the contents: a frame is either cover or a message.
        write!(
            f,
            "Frame({} bytes, {})",
            self.0.len(),
            if self.is_dummy() { "cover" } else { "carrying" }
        )
    }
}

/// One fragment waiting for a slot.
struct Fragment {
    msg: u16,
    index: u16,
    total: u16,
    bytes: Vec<u8>,
}

/// The transmit schedule.
pub struct Hysteria {
    queue: std::collections::VecDeque<Fragment>,
    next_msg: u16,
    sent: u64,
}

impl Default for Hysteria {
    fn default() -> Self {
        Self::new()
    }
}

impl Hysteria {
    /// A schedule with nothing queued.
    pub fn new() -> Self {
        Self {
            queue: Default::default(),
            next_msg: 0,
            sent: 0,
        }
    }

    /// How many fragments are waiting.
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// How many frames have been produced. Equal for an idle client and a busy
    /// one after the same number of ticks, which is the property gate 11 checks.
    pub fn frames_sent(&self) -> u64 {
        self.sent
    }

    /// Queue a message for the next available slots.
    ///
    /// Media is refused. D12: "Media stays out of the stream, since large
    /// attachments make delay unusable." A one-minute cadence over a photo is not
    /// a slower photo, it is a broken product — and its timing is observable
    /// anyway, matching the mixed-mode tradeoff in D2.
    pub fn enqueue(&mut self, class: Class, payload: &[u8]) -> Result<(), HysteriaError> {
        if class == Class::Media {
            return Err(HysteriaError::MediaNotCarried);
        }
        if payload.is_empty() {
            return Err(HysteriaError::Empty);
        }
        let chunks: Vec<&[u8]> = payload.chunks(MAX_PAYLOAD_PER_FRAME).collect();
        let total = u16::try_from(chunks.len()).map_err(|_| HysteriaError::TooLarge)?;
        let msg = self.next_msg;
        self.next_msg = self.next_msg.wrapping_add(1);
        for (i, c) in chunks.into_iter().enumerate() {
            self.queue.push_back(Fragment {
                msg,
                index: i as u16,
                total,
                bytes: c.to_vec(),
            });
        }
        Ok(())
    }

    /// Produce the frame for this slot.
    ///
    /// **Always returns a frame.** There is no "nothing to send" path, because a
    /// skipped transmission is the signal the whole mode exists to suppress.
    pub fn tick(&mut self) -> Frame {
        let mut body = Vec::with_capacity(FRAME_BYTES);
        body.push(0u8); // record count, filled in below
        let mut count = 0u8;

        while count < u8::MAX {
            let Some(next) = self.queue.front() else {
                break;
            };
            if body.len() + RECORD_HEADER + next.bytes.len() > FRAME_BYTES {
                break;
            }
            let f = self.queue.pop_front().expect("just checked");
            body.extend_from_slice(&f.msg.to_be_bytes());
            body.extend_from_slice(&f.index.to_be_bytes());
            body.extend_from_slice(&f.total.to_be_bytes());
            body.extend_from_slice(&(f.bytes.len() as u16).to_be_bytes());
            body.extend_from_slice(&f.bytes);
            count += 1;
        }
        body[0] = count;
        // Pad to a uniform size. Zeroes are fine: the frame is sealed before it
        // leaves, so an observer sees ciphertext of a fixed length either way.
        body.resize(FRAME_BYTES, 0);

        self.sent += 1;
        Frame(body)
    }
}

/// Reassembles messages from received frames.
#[derive(Default)]
pub struct Reassembler {
    partial: std::collections::BTreeMap<u16, Vec<Option<Vec<u8>>>>,
}

impl Reassembler {
    /// A fresh reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a decrypted frame; returns any messages it completed.
    pub fn accept(&mut self, frame: &Frame) -> Result<Vec<Vec<u8>>, HysteriaError> {
        let b = frame.as_bytes();
        if b.len() != FRAME_BYTES {
            return Err(HysteriaError::Malformed);
        }
        let count = b[0] as usize;
        let mut at = FRAME_HEADER;
        let mut done = Vec::new();

        for _ in 0..count {
            if at + RECORD_HEADER > FRAME_BYTES {
                return Err(HysteriaError::Malformed);
            }
            let msg = u16::from_be_bytes([b[at], b[at + 1]]);
            let index = u16::from_be_bytes([b[at + 2], b[at + 3]]) as usize;
            let total = u16::from_be_bytes([b[at + 4], b[at + 5]]) as usize;
            let len = u16::from_be_bytes([b[at + 6], b[at + 7]]) as usize;
            at += RECORD_HEADER;
            if total == 0 || index >= total || at + len > FRAME_BYTES {
                return Err(HysteriaError::Malformed);
            }
            let slots = self.partial.entry(msg).or_insert_with(|| vec![None; total]);
            if slots.len() != total {
                return Err(HysteriaError::Malformed);
            }
            slots[index] = Some(b[at..at + len].to_vec());
            at += len;

            if slots.iter().all(Option::is_some) {
                let whole: Vec<u8> = slots
                    .iter()
                    .flat_map(|s| s.clone().expect("all present"))
                    .collect();
                self.partial.remove(&msg);
                done.push(whole);
            }
        }
        Ok(done)
    }
}

/// Why a payload could not be queued, or a frame read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HysteriaError {
    /// Media does not travel in the stream.
    MediaNotCarried,
    /// Nothing to send.
    Empty,
    /// More fragments than the framing can number.
    TooLarge,
    /// The frame does not parse.
    Malformed,
}

impl core::fmt::Display for HysteriaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MediaNotCarried => {
                f.write_str("photos and files do not go through cover traffic")
            }
            Self::Empty => f.write_str("nothing to send"),
            Self::TooLarge => f.write_str("message is too large to send at all"),
            Self::Malformed => f.write_str("frame did not parse"),
        }
    }
}
impl core::error::Error for HysteriaError {}

// ------------------------------------------------------- platform capability

/// Where the client is running.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    /// macOS, Windows, Linux.
    Desktop,
    /// Android, where a foreground service can hold a connection open.
    Android,
    /// iOS, which throttles persistent background execution by design.
    Ios,
}

/// Whether cover traffic can be offered on a platform, and what to say about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Availability {
    /// The stream runs continuously, including while the app is backgrounded.
    Full,
    /// The platform cannot sustain the stream, so the mode is not offered.
    ///
    /// D12: "If it cannot be done, the mode is desktop and Android only, stated in
    /// the UI rather than shipped as a setting that silently does less than it
    /// claims." A mode that stops when the app closes reveals precisely what it
    /// exists to hide — worse than not having it, because the user believes they
    /// are covered.
    Unavailable {
        /// What to tell the user. Not an error string; the actual sentence.
        reason: &'static str,
    },
}

impl Platform {
    /// Whether this platform can hold the stream open while backgrounded.
    ///
    /// # This is a claim, and it has not been verified here
    ///
    /// `Spark-build-notes.md` §5 stage 12 lists "privacy-preserving push and
    /// background cover traffic" as the assumptions most likely to fail, and D12
    /// says of iOS: "Verify during the mobile spike."
    ///
    /// **That spike has not been run.** The answer below is the conservative one:
    /// iOS is treated as unable until someone demonstrates otherwise, because the
    /// failure mode of guessing the other way is a user who believes their timing
    /// is covered when it is not. If the spike succeeds, this function changes and
    /// the tests below change with it.
    pub const fn sustains_background(self) -> bool {
        match self {
            Platform::Desktop | Platform::Android => true,
            Platform::Ios => false,
        }
    }

    /// Whether the mode may be offered here.
    pub const fn availability(self) -> Availability {
        if self.sustains_background() {
            Availability::Full
        } else {
            Availability::Unavailable {
                reason: "Cover traffic is not available on iOS. It only works if it keeps \
                         running when the app is closed, and iOS stops it — a version that \
                         paused would tell an observer exactly when you put your phone down.",
            }
        }
    }

    /// Whether a client on this platform may turn the mode on.
    pub const fn may_enable(self) -> bool {
        matches!(self.availability(), Availability::Full)
    }
}

/// Turn cover traffic on for a platform, or find out why not.
///
/// The only constructor for a running schedule. A `Hysteria` obtained any other
/// way does not exist, so "shipped as a setting that silently does less than it
/// claims" is not a thing the API can express.
pub fn enable(platform: Platform) -> Result<Hysteria, Availability> {
    match platform.availability() {
        Availability::Full => Ok(Hysteria::new()),
        other => Err(other),
    }
}
