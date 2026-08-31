#!/usr/bin/env bash
# Gate 1, second half: two independent builds of one commit are byte-identical.
#
# The two target directories are separate AND differently named, so this also
# proves the output does not depend on where it was built — which is what a third
# party rebuilding a release actually needs. A pass here does not prove
# cross-machine reproducibility; the `compare-machines` CI job does that.
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

manifest() {
  # Hash every produced artifact, keyed by path relative to the target dir, so
  # the manifests are comparable despite living in different directories.
  #
  # deps/ is included deliberately: dependency artifacts are part of what a user
  # is asked to trust, and a nondeterministic dependency is still a
  # nondeterministic build.
  #
  # Proc-macro dylibs are excluded, and this is the only exclusion. A macOS
  # dylib carries its own absolute output path as the LC_ID_DYLIB install name,
  # written by the linker after --remap-path-prefix has done its work, so two
  # builds in differently-named directories differ in that string and in the
  # ad-hoc signature covering it. Measured: 53 bytes out of 2.8 MB, all of them
  # that path. These are host build tools that never ship, and their output is
  # fully captured in the rlibs below — which are compared and do match. If a
  # proc macro ever produced different code, that would show up there.
  ( cd "$1/release" && find . -maxdepth 2 -type f \
        \( -perm -u+x -o -name '*.rlib' \) \
        ! -name '*.dylib' ! -name '*.so' ! -name '*.dll' \
      | LC_ALL=C sort | while read -r f; do
          printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "${f#./}"
        done )
}

# Never narrow the check silently: name what was left out.
excluded() {
  ( cd "$1/release" && find . -maxdepth 2 -type f \
        \( -name '*.dylib' -o -name '*.so' -o -name '*.dll' \) \
      | LC_ALL=C sort | sed 's|^\./||' )
}

MA="$(manifest "$A")"
MB="$(manifest "$B")"

if [ -z "$MA" ]; then
  echo "FAIL: build A produced no artifacts to compare" >&2
  exit 1
fi

EX="$(excluded "$A")"
if [ -n "$EX" ]; then
  echo
  echo "excluded from comparison (host proc-macro dylibs, never shipped):"
  echo "$EX" | sed 's/^/  /'
  echo
fi

if [ "$MA" = "$MB" ]; then
  echo "PASS: $(echo "$MA" | wc -l | tr -d ' ') artifacts byte-identical across two builds"
else
  echo "FAIL: builds diverged" >&2
  diff <(echo "$MA") <(echo "$MB") >&2 || true
  exit 1
fi
