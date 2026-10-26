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
use std::collections::{BTreeMap, BTreeSet};

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

// Same-lane chains imply all earlier entries; only the latest observed entry
// in each other lane needs an edge. Work scales with the supplied clocks, not
// the square of the entire recovered history.
fn order_within_epoch(group: &[Entry]) -> Vec<Entry> {
    let n = group.len();
    if n < 2 || group.first().unwrap().lane == group.last().unwrap().lane {
        return group.to_vec();
    }
    let mut lanes: BTreeMap<[u8; 16], Vec<usize>> = BTreeMap::new();
    for (i, entry) in group.iter().enumerate() {
        lanes.entry(entry.lane).or_default().push(i);
    }
    let mut outgoing = vec![Vec::new(); n];
    let mut indegree = vec![0usize; n];
    for indices in lanes.values() {
        for pair in indices.windows(2) {
            outgoing[pair[0]].push(pair[1]);
            indegree[pair[1]] += 1;
        }
    }
    for (v, entry) in group.iter().enumerate() {
        for lane in entry.clock.lanes() {
            if lane.as_bytes() == &entry.lane {
                continue;
            }
            let Some(indices) = lanes.get(lane.as_bytes()) else {
                continue;
            };
            let seen = entry.clock.get(lane).unwrap();
            let end = indices.partition_point(|&u| group[u].seq <= seen);
            if end == 0 {
                continue;
            }
            let u = indices[end - 1];
            outgoing[u].push(v);
            indegree[v] += 1;
        }
    }
    let mut remaining: BTreeSet<usize> = (0..n).collect();
    let mut ready: BTreeSet<usize> = (0..n).filter(|&i| indegree[i] == 0).collect();
    let mut out = Vec::with_capacity(n);
    while let Some(&fallback) = remaining.first() {
        // Malicious clocks can claim a cycle. Break it at a deterministic index.
        let k = ready.pop_first().unwrap_or(fallback);
        remaining.remove(&k);
        for &v in &outgoing[k] {
            indegree[v] -= 1;
            if indegree[v] == 0 && remaining.contains(&v) {
                ready.insert(v);
            }
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
