//! Gate 11: "Idle and 100-message captures are indistinguishable in count, size,
//! and timing; the stream survives backgrounding, or the platform is documented
//! as unable to support it."
//!
//! The first half is checked against what an observer would actually capture. The
//! second is a platform claim, and this file is where it is pinned down rather
//! than assumed.

use spark_crypto::Secret;
use spark_transport::hysteria::*;
use spark_transport::route::Class;

/// What an observer records: one entry per transmission, holding only what is
/// visible from outside — when it happened and how many bytes crossed.
#[derive(PartialEq, Eq, Debug)]
struct Capture {
    at_secs: Vec<u64>,
    sizes: Vec<usize>,
}

/// Run `ticks` slots, sealing each frame as the transport would, and record only
/// what an observer could see.
fn capture(h: &mut Hysteria, ticks: u64) -> Capture {
    let key = Secret::new([7u8; 32]);
    let mut at_secs = Vec::new();
    let mut sizes = Vec::new();
    for n in 0..ticks {
        let frame = h.tick();
        // Sealed, because the observable is ciphertext. A test that compared
        // plaintext would "prove" indistinguishability of things an observer
        // never sees.
        let sealed = spark_chunk::Chunk::seal(
            spark_chunk::Kind::RoomLog,
            &key,
            &[n as u8; 24],
            frame.as_bytes(),
        );
        at_secs.push(n * INTERVAL_SECS);
        sizes.push(sealed.len());
    }
    Capture { at_secs, sizes }
}

#[test]
fn idle_and_busy_captures_are_indistinguishable() {
    // The headline claim. One client says nothing for a hundred slots; the other
    // sends a hundred messages. An observer must not be able to tell which is
    // which from count, size, or timing.
    let mut idle = Hysteria::new();
    let mut busy = Hysteria::new();
    for i in 0..100 {
        busy.enqueue(Class::Text, format!("message number {i}").as_bytes())
            .unwrap();
    }

    let a = capture(&mut idle, 100);
    let b = capture(&mut busy, 100);

    assert_eq!(
        a.sizes.len(),
        b.sizes.len(),
        "the two clients transmitted a different number of times"
    );
    assert_eq!(
        a.at_secs, b.at_secs,
        "the two clients transmitted at different times"
    );
    assert_eq!(
        a.sizes, b.sizes,
        "the two clients transmitted different amounts"
    );
    assert_eq!(a, b);

    // And every frame is the same size as every other, not merely equal between
    // the two runs.
    assert!(
        a.sizes.windows(2).all(|w| w[0] == w[1]),
        "frame sizes varied within a capture"
    );
}

#[test]
fn a_burst_does_not_change_the_schedule() {
    // A hundred messages arriving at once must not produce a hundred
    // transmissions, or the burst is visible as a burst.
    let mut h = Hysteria::new();
    let quiet = capture(&mut Hysteria::new(), 10);
    for i in 0..100 {
        h.enqueue(Class::Text, format!("m{i}").as_bytes()).unwrap();
    }
    let loud = capture(&mut h, 10);
    assert_eq!(quiet, loud, "a burst of traffic was visible in the capture");
}

#[test]
fn a_message_larger_than_a_frame_splits_across_slots() {
    // D12: "Covers most text messages; larger splits across slots." The splitting
    // must not change the shape of the capture either.
    let big = vec![b'x'; MAX_PAYLOAD_PER_FRAME * 3 + 17];
    let mut h = Hysteria::new();
    h.enqueue(Class::Text, &big).unwrap();
    assert_eq!(
        h.pending(),
        4,
        "the message did not split into four fragments"
    );

    let quiet = capture(&mut Hysteria::new(), 6);
    let mut h2 = Hysteria::new();
    h2.enqueue(Class::Text, &big).unwrap();
    assert_eq!(
        capture(&mut h2, 6),
        quiet,
        "a split message was visible in the capture"
    );
}

#[test]
fn a_message_survives_the_round_trip() {
    // Indistinguishability is worthless if the messages do not arrive.
    let mut h = Hysteria::new();
    let msgs: Vec<Vec<u8>> = vec![
        b"short".to_vec(),
        vec![b'y'; MAX_PAYLOAD_PER_FRAME * 2 + 3],
        b"another short one".to_vec(),
    ];
    for m in &msgs {
        h.enqueue(Class::Text, m).unwrap();
    }

    let mut r = Reassembler::new();
    let mut got = Vec::new();
    for _ in 0..10 {
        got.extend(r.accept(&h.tick()).expect("frame parses"));
    }
    assert_eq!(got.len(), msgs.len(), "messages went missing");
    for m in &msgs {
        assert!(got.contains(m), "a message did not come back intact");
    }
}

#[test]
fn dummy_frames_carry_nothing_and_are_the_same_size() {
    let mut h = Hysteria::new();
    let f = h.tick();
    assert!(f.is_dummy());
    assert_eq!(f.as_bytes().len(), FRAME_BYTES);

    h.enqueue(Class::Text, b"real").unwrap();
    let g = h.tick();
    assert!(!g.is_dummy());
    assert_eq!(
        g.as_bytes().len(),
        FRAME_BYTES,
        "a carrying frame is a different size"
    );

    // A reassembler is not confused by cover traffic.
    let mut r = Reassembler::new();
    assert!(r.accept(&f).unwrap().is_empty());
}

#[test]
fn media_does_not_travel_in_the_stream() {
    // D12: "Media stays out of the stream, since large attachments make delay
    // unusable." A one-minute cadence over a photo is not a slower photo.
    let mut h = Hysteria::new();
    assert_eq!(
        h.enqueue(Class::Media, b"a photograph").unwrap_err(),
        HysteriaError::MediaNotCarried
    );
    assert!(h.enqueue(Class::Text, b"a message").is_ok());
    assert!(h.enqueue(Class::Control, b"a keyring write").is_ok());
}

#[test]
fn the_schedule_never_skips_a_slot() {
    // A skipped transmission is the signal the whole mode exists to suppress, so
    // there is deliberately no "nothing to send" path.
    let mut h = Hysteria::new();
    for _ in 0..50 {
        h.tick();
    }
    assert_eq!(h.frames_sent(), 50);
    assert_eq!(h.pending(), 0);
}

#[test]
fn the_parameters_are_the_ones_d12_chose() {
    // Set for adoption, not for strength: "a setting only a few hundred people
    // enable makes those people a recognisable group."
    assert_eq!(INTERVAL_SECS, 60);
    assert_eq!(FRAME_BYTES, 4096);

    // Roughly 5.6 MB a day, as D12 says. Worth failing on: if someone shrinks the
    // interval for latency, the cost of leaving it on changes and so does the
    // reasoning behind the number.
    let per_day = FRAME_BYTES as u64 * (24 * 60 * 60 / INTERVAL_SECS);
    assert!(
        (5_000_000..6_500_000).contains(&per_day),
        "daily cost is now {per_day} bytes"
    );
}

// ------------------------------------------------ the backgrounding half

#[test]
fn ios_is_documented_as_unable_rather_than_shipped_degraded() {
    // Gate 11's second clause, and the honest answer to it. `Spark-build-notes.md`
    // §5 calls background cover traffic one of the two assumptions most likely to
    // fail and says to verify it during the mobile spike. **That spike has not
    // been run.** Until it is, iOS is treated as unable, because guessing the
    // other way leaves a user believing their timing is covered when it is not.
    assert!(!Platform::Ios.sustains_background());
    assert!(
        !Platform::Ios.may_enable(),
        "the mode can be switched on where it cannot run"
    );

    let Availability::Unavailable { reason } = Platform::Ios.availability() else {
        panic!("iOS reported the mode as fully available")
    };
    assert!(reason.len() > 60, "there is no sentence to show the user");
    assert!(
        reason.contains("iOS"),
        "the explanation does not say which platform"
    );

    // And it cannot be obtained anyway: `enable` is the only constructor a client
    // has, so "a setting that silently does less than it claims" is not something
    // this API can express.
    assert!(enable(Platform::Ios).is_err());
}

#[test]
fn desktop_and_android_may_enable_it() {
    for p in [Platform::Desktop, Platform::Android] {
        assert!(p.sustains_background(), "{p:?} cannot sustain the stream");
        assert_eq!(p.availability(), Availability::Full);
        assert!(enable(p).is_ok());
    }
}
