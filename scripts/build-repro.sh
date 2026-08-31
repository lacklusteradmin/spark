#!/usr/bin/env bash
# Deterministic release build. Every knob that would otherwise vary per machine
# or per invocation is pinned here, so two runs of this script on one commit
# produce byte-identical artifacts.
#
#   usage: scripts/build-repro.sh <output-dir>
set -euo pipefail

OUT="${1:?usage: build-repro.sh <output-dir>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

# Fixed epoch rather than "now": the timestamp must be a property of the commit,
# not of when the build ran.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export CARGO_INCREMENTAL=0
export LC_ALL=C
export TZ=UTC
export RUSTFLAGS="--remap-path-prefix=${ROOT}=/spark --remap-path-prefix=${CARGO_HOME_DIR}=/cargo"

cargo build --release --locked --target-dir "$OUT" --workspace
