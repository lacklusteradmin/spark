//! The total order every client must agree on. `docs/protocol.md` §5.1.
//!
//! Gate 4's "every member sees identical history" is a test over this function,
//! and gate 6's "history matches after restore" is the same function applied to
//! chunks fetched from a server rather than held in memory.
//!
//! The order is:
//!
//! 1. `epoch` ascending — MLS already totally orders epochs.
//! 2. Within an epoch, causal order by vector clock.
//! 3. Concurrent writes: ascending lane bytes, then sequence.
//!
//! Rule 2 is a *partial* order, so it cannot be handed to a comparison sort: a
//! comparator built from "has seen" is not transitive, and Rust's sort is allowed
//! to panic on one that misbehaves. This does a deterministic topological sort
//! instead, breaking every tie by rule 3.

use crate::entry::Entry;
use std::collections::BTreeMap;

/// Sort entries into the order every client must compute identically.
///
/// A cycle in the causal relation — which honest clients cannot produce, but a
/// corrupt or hostile one can — is resolved by falling back to rule 3 for the
/// entries involved. Deterministic, and it terminates; the alternative is a
/// client that hangs on a malformed history.
pub fn total_order(mut entries: Vec<Entry>) -> Vec<Entry> {
    entries.sort_by(|a, b| {
        a.epoch
            .cmp(&b.epoch)
            .then_with(|| a.lane.cmp(&b.lane))
            .then_with(|| a.seq.cmp(&b.seq))
    });

    let mut out = Vec::with_capacity(entries.len());
    let mut i = 0;
    while i < entries.len() {
        let epoch = entries[i].epoch;
        let mut j = i;
        while j < entries.len() && entries[j].epoch == epoch {
            j += 1;
        }
        out.extend(order_within_epoch(&entries[i..j]));
        i = j;
    }
    out
}

/// Does `u` happen before `v`?
fn precedes(u: &Entry, v: &Entry) -> bool {
    // Same lane: sequence is the order, always.
    if u.lane == v.lane {
        return u.seq < v.seq;
    }
    // Different lanes: `v` saw `u` if its clock records `u`'s lane at or past
    // `u`'s sequence. If they saw each other, they are concurrent, and rule 3
    // decides.
    let v_saw_u = v.clock.has_seen(u.lane(), u.seq);
    let u_saw_v = u.clock.has_seen(v.lane(), v.seq);
    v_saw_u && !u_saw_v
}

fn order_within_epoch(group: &[Entry]) -> Vec<Entry> {
    let n = group.len();
    // `group` arrives pre-sorted by (lane, seq), so index order *is* rule 3.
    let mut indegree = vec![0usize; n];
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    for u in 0..n {
        for v in 0..n {
            if u != v && precedes(&group[u], &group[v]) {
                edges[u].push(v);
                indegree[v] += 1;
            }
        }
    }

    let mut out = Vec::with_capacity(n);
    let mut taken = vec![false; n];
    for _ in 0..n {
        // The lowest-index ready node: rule 3 as the tie-break, deterministically.
        let next = (0..n).find(|&k| !taken[k] && indegree[k] == 0).or_else(|| {
            // No ready node and entries remain: the causal relation has a cycle.
            // Fall back to rule 3 for the rest rather than looping forever.
            (0..n).find(|&k| !taken[k])
        });
        let Some(k) = next else { break };
        taken[k] = true;
        for &v in &edges[k] {
            indegree[v] = indegree[v].saturating_sub(1);
        }
        out.push(group[k].clone());
    }
    out
}

/// Group entries by lane, for inspection and tests.
pub fn by_lane(entries: &[Entry]) -> BTreeMap<[u8; 16], Vec<u64>> {
    let mut m: BTreeMap<[u8; 16], Vec<u64>> = BTreeMap::new();
    for e in entries {
        m.entry(e.lane).or_default().push(e.seq);
    }
    m
}
