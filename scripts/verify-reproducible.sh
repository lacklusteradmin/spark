#!/usr/bin/env bash
# Gate 1, second half: two independent builds of one commit are byte-identical.
#
# "Independent" means separate target directories, so nothing is reused between
# them. A pass here does not prove cross-machine reproducibility; CI does that
# by running this on a second runner and comparing the manifest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

A="$ROOT/repro-a"
B="$ROOT/repro-b"
rm -rf "$A" "$B"

echo "==> build A"
scripts/build-repro.sh "$A" >/dev/null
echo "==> build B"
scripts/build-repro.sh "$B" >/dev/null

manifest() {
  # Hash every produced binary and rlib, keyed by path relative to the target dir,
  # so the two manifests are comparable despite living in different directories.
  ( cd "$1/release" && find . -maxdepth 1 -type f \( -perm -u+x -o -name '*.rlib' \) \
      | LC_ALL=C sort | while read -r f; do
          printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "${f#./}"
        done )
}

MA="$(manifest "$A")"
MB="$(manifest "$B")"

if [ -z "$MA" ]; then
  echo "FAIL: build A produced no artifacts to compare" >&2
  exit 1
fi

if [ "$MA" = "$MB" ]; then
  echo "$MA"
  echo
  echo "PASS: $(echo "$MA" | wc -l | tr -d ' ') artifacts byte-identical across two builds"
else
  echo "FAIL: builds diverged" >&2
  diff <(echo "$MA") <(echo "$MB") >&2 || true
  exit 1
fi
