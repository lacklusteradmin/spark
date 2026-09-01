//! Which traffic goes over Tor. `Spark-spec.md` D2.
//!
//! The whole policy is one function over two enums, and it is deliberately that
//! small: this is the decision an auditor most wants to be able to read in full.

/// What a connection is carrying.
///
/// Classification is a required argument to [`crate::Transport::open`], not an
/// inferred property. A request whose class nobody decided is a request routed by
/// accident, and the accident is always the same one — a media fetch escaping to
/// the network in a mode the user believed covered it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    /// Authentication, keyring reads and writes, token withdrawal, name
    /// resolution. Small, latency-sensitive, and the traffic that carries
    /// `hash(pubkey)`.
    Control,
    /// Room log chunks: messages and commits. Small enough that Tor's latency is
    /// tolerable, and the traffic whose timing correlates members.
    Text,
    /// Media chunk uploads and fetches. Bulk, and slow enough over Tor that many
    /// users would turn the whole thing off rather than wait.
    Media,
}

/// How much traffic is routed over Tor. `Spark-spec.md` D2.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mode {
    /// Everything over Tor.
    AlwaysOn,
    /// Nothing over Tor.
    AlwaysOff,
    /// Control and text over Tor, media direct. The default.
    ///
    /// D2's reasoning: routing delivery and control traffic costs little, while
    /// bulk attachments over Tor are slow enough that many users would otherwise
    /// disable it entirely. The cost is stated in the spec and worth repeating
    /// wherever this is read — an observer can tie an IP to specific media chunks,
    /// and since media names are content-derived, that links a network address to
    /// identifiable content.
    #[default]
    TextOverTor,
}

impl Mode {
    /// Whether this class goes over Tor in this mode.
    pub const fn uses_tor(self, class: Class) -> bool {
        match self {
            Mode::AlwaysOn => true,
            Mode::AlwaysOff => false,
            Mode::TextOverTor => matches!(class, Class::Control | Class::Text),
        }
    }

    /// What to tell the user, in the client's own words rather than the protocol's.
    pub const fn describe(self) -> &'static str {
        match self {
            Mode::AlwaysOn => "Everything goes over Tor. Photos and files will be slow.",
            Mode::AlwaysOff => {
                "Nothing goes over Tor. The server sees the address you connect from."
            }
            Mode::TextOverTor => {
                "Messages go over Tor. Photos and files go direct, so their servers see your address."
            }
        }
    }
}
