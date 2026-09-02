//! The pacing policy, exhaustively.
//!
//! RUSTSEC-2023-0071 is mitigated by emitting responses on a fixed cadence. That
//! only works if the cadence really is fixed, so this checks the arithmetic
//! rather than trusting it.

use spark_crypto::pace::*;

#[test]
fn total_time_is_a_whole_number_of_ticks_whatever_the_work_took() {
    // The property the whole countermeasure rests on.
    let p = Pacing::new(100);
    for elapsed in 0..1000u64 {
        let total = elapsed + p.after(elapsed).wait_nanos;
        assert_eq!(
            total % 100,
            0,
            "work of {elapsed}ns produced a total of {total}ns"
        );
        assert!(
            total > elapsed || elapsed == 0,
            "the response was not delayed at all"
        );
    }
}

#[test]
fn work_within_one_tick_is_indistinguishable() {
    // The case that matters: every signing operation that fits in a tick must
    // produce exactly the same observable duration.
    let p = Pacing::new(1_000);
    let totals: Vec<u64> = (0..1_000).map(|e| e + p.after(e).wait_nanos).collect();
    assert!(
        totals.iter().all(|&t| t == 1_000),
        "response time varied with the input"
    );
}

#[test]
fn zero_work_still_waits() {
    // Returning immediately would make "nothing to do" distinguishable from
    // "signed something" — a smaller channel than the one being closed, but the
    // same channel.
    let p = Pacing::new(50);
    assert_eq!(
        p.after(0),
        Paced {
            wait_nanos: 50,
            overran: false
        }
    );
}

#[test]
fn exceeding_a_tick_is_reported_rather_than_hidden() {
    // Past one tick the *number* of ticks varies with the input and the channel is
    // back, coarsened. A service must be able to count that rather than discover
    // it in an incident report.
    let p = Pacing::new(100);
    assert!(!p.after(99).overran);
    assert!(
        p.after(100).overran,
        "work of exactly one tick was not flagged"
    );
    assert!(p.after(250).overran);
    // It still paces, to the next boundary up.
    assert_eq!(p.after(250).wait_nanos, 50);
    assert_eq!(250 + p.after(250).wait_nanos, 300);
}

#[test]
fn a_zero_tick_is_clamped_rather_than_dividing_by_zero() {
    let p = Pacing::new(0);
    assert_eq!(p.tick_nanos(), 1);
    assert_eq!(p.after(0).wait_nanos, 1);
}

#[test]
fn the_default_tick_is_generous_enough_to_be_left_alone() {
    // Token withdrawal is not latency-sensitive. A tick too small to cover a
    // 2048-bit RSA signature on a slow machine would overrun constantly, and a
    // countermeasure that logs a warning on every request is one people turn off.
    assert!(
        Pacing::DEFAULT.tick_nanos() >= 20_000_000,
        "the default tick is too tight"
    );
}
