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

# The same job for the C compiler. `ring` builds C and assembly through the `cc`
# crate, and those objects embed absolute paths that --remap-path-prefix never
# sees, because it is a rustc flag. Defence in depth rather than a fix for
# anything observed: no such path was found in the linked output.
export CFLAGS="-ffile-prefix-map=${OUT}=/target -ffile-prefix-map=${ROOT}=/spark -ffile-prefix-map=${CARGO_HOME_DIR}=/cargo ${CFLAGS:-}"
export CXXFLAGS="$CFLAGS"
export ASMFLAGS="$CFLAGS"

# Drop the linker's build identifier.
#
# This is what gate 1 caught when TLS arrived. Apple's linker derives LC_UUID
# from its *inputs* — including their paths — rather than from the bytes it
# produces, so two builds of identical content in differently-named directories
# get different UUIDs, and the ad-hoc signature over them differs too. GNU ld's
# --build-id is the same idea with the same consequence.
#
# The identifier exists to match a binary to its debug symbols. A release build
# that ships no symbols has nothing to match, and a build nobody can reproduce is
# worth less than one nobody can symbolicate.
#
# Only on Linux. macOS cannot simply drop it: dyld refuses to *execute* a Mach-O
# with no LC_UUID, so a build script linked this way fails to run and the build
# never finishes. There the identifier is normalised out of the comparison instead
# (see verify-reproducible.sh), which is a weaker claim honestly stated rather than
# a stronger one quietly assumed. CI builds in a pinned Linux container, so the
# artifacts anyone would actually check are covered by the unqualified version.
if [ "$(uname -s)" != "Darwin" ]; then
  export RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--build-id=none"
fi

cargo build --release --locked --target-dir "$OUT" --workspace
