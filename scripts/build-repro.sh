#!/usr/bin/env bash
# Deterministic release build. Every knob that would otherwise vary per machine
# or per invocation is pinned here, so two runs of this script on one commit
# produce byte-identical artifacts.
#
#   usage: scripts/build-repro.sh <output-dir>
#
# <output-dir> MUST live outside the repository. Build scripts that generate a
# file into $OUT_DIR and `include!` it — serde_core does exactly this — embed the
# target directory path in their metadata. Remapping it below fixes that, but
# only if it does not nest inside the repo path, which would make two overlapping
# --remap-path-prefix rules race.
set -euo pipefail

OUT="${1:?usage: build-repro.sh <output-dir>}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_HOME_DIR="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)"

case "$OUT" in
  "$ROOT"/*) echo "error: output dir must be outside $ROOT (see comment above)" >&2; exit 2 ;;
esac

# Fixed epoch rather than "now": the timestamp must be a property of the commit,
# not of when the build ran.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export CARGO_INCREMENTAL=0
export LC_ALL=C
export TZ=UTC
export RUSTFLAGS="--remap-path-prefix=${OUT}=/target \
--remap-path-prefix=${ROOT}=/spark \
--remap-path-prefix=${CARGO_HOME_DIR}=/cargo"

cargo build --release --locked --target-dir "$OUT" --workspace
