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

# macOS ships `shasum` (perl); slim Linux images ship `sha256sum` (coreutils) and
# often no perl at all. Pick whichever exists rather than assuming a platform.
if command -v sha256sum >/dev/null 2>&1; then
  raw_hash() { sha256sum "$1" | cut -d" " -f1; }
else
  raw_hash() { shasum -a 256 "$1" | cut -d" " -f1; }
fi

# On macOS, hash the artifact with its LC_UUID zeroed.
#
# Apple's linker derives LC_UUID from its *inputs*, including their paths, rather
# than from the bytes it produces — so two builds of byte-identical content in
# differently-named directories get different UUIDs, and the ad-hoc signature over
# them differs too. It cannot simply be dropped: dyld refuses to execute a Mach-O
# without one, so a build script linked that way never runs.
#
# This is therefore a weaker claim on macOS: identical *apart from the linker's
# build identifier*. Linux gets the unqualified claim, with --build-id=none, and
# that is where CI builds the artifacts a third party would check.
NORMALISE=""
if [ "$(uname -s)" = "Darwin" ]; then
  NORMALISE="yes"
fi

hash_of() {
  if [ -z "$NORMALISE" ]; then
    raw_hash "$1"
    return
  fi
  python3 - "$1" <<'PYEOF'
import hashlib, struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
magic = struct.unpack("<I", b[:4])[0] if len(b) >= 4 else 0
if magic in (0xFEEDFACF, 0xFEEDFACE):  # 64- and 32-bit Mach-O, little-endian
    ncmds = struct.unpack("<I", b[16:20])[0]
    off = 32 if magic == 0xFEEDFACF else 28
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", b[off:off + 8])
        if size == 0:
            break
        if cmd == 0x1B:            # LC_UUID
            b[off + 8:off + 24] = b"\x00" * 16
        elif cmd == 0x1D:          # LC_CODE_SIGNATURE: hashes everything above
            dataoff, datasize = struct.unpack("<II", b[off + 8:off + 16])
            b[dataoff:dataoff + datasize] = b"\x00" * datasize
        off += size
print(hashlib.sha256(bytes(b)).hexdigest())
PYEOF
}

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
          printf '%s  %s\n' "$(hash_of "$f")" "${f#./}"
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
  n=$(echo "$MA" | wc -l | tr -d ' ')
  if [ -n "$NORMALISE" ]; then
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
