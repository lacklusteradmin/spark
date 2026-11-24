#!/usr/bin/env bash
# Gate 1, second half: two independent builds of one commit are byte-identical.
#
# The two target directories are separate AND differently named, so this also
# proves the output does not depend on where it was built — which is what a third
# party rebuilding a release actually needs. A pass here does not prove
# cross-machine reproducibility; the `compare-machines` CI job does that.
#
# What counts as an artifact, and how it is hashed, is scripts/repro-manifest.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/spark-repro.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
A="$WORK/build-alpha"
B="$WORK/build-beta-longer-name"

echo "==> build A  ($A)"
scripts/build-repro.sh "$A" >/dev/null
echo "==> build B  ($B)"
scripts/build-repro.sh "$B" >/dev/null

MA="$(scripts/repro-manifest.sh "$A")"
MB="$(scripts/repro-manifest.sh "$B")"

if [ -z "$MA" ]; then
  echo "FAIL: build A produced no artifacts to compare" >&2
  exit 1
fi

# Never narrow the check silently: name what was left out.
EX="$(scripts/repro-manifest.sh --excluded "$A")"
if [ -n "$EX" ]; then
  echo
  echo "excluded from comparison (host proc-macro dylibs, never shipped):"
  echo "$EX" | sed 's/^/  /'
  echo
fi

if [ "$MA" = "$MB" ]; then
  n=$(echo "$MA" | wc -l | tr -d ' ')
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "PASS: $n artifacts identical across two builds"
    echo "      (macOS: compared with LC_UUID and the ad-hoc signature zeroed —"
    echo "       Apple's linker derives the UUID from input paths, and dyld will not"
    echo "       run a Mach-O without one. Linux gets the unqualified comparison.)"
  else
    echo "PASS: $n artifacts byte-identical across two builds"
  fi
else
  echo "FAIL: builds diverged" >&2
  diff <(echo "$MA") <(echo "$MB") >&2 || true
  exit 1
fi
