#!/usr/bin/env bash
# The artifact manifest of one release build: what gate 1 compares.
#
#   usage: scripts/repro-manifest.sh <target-dir>              # "<sha256>  <path>" per artifact
#          scripts/repro-manifest.sh --excluded <target-dir>   # what was left out, by path
#
# verify-reproducible.sh compares two of these from one machine; the
# `cross-machine` CI job compares two from different machines. Both call this
# script, so the two checks cannot drift apart on what they count.
set -euo pipefail

EXCLUDED=""
if [ "${1:-}" = "--excluded" ]; then
  EXCLUDED="yes"
  shift
fi
TARGET="${1:?usage: repro-manifest.sh [--excluded] <target-dir>}"
cd "$TARGET/release"

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

# Every file the build produced as a compiled unit, relative to the release dir:
# what cargo hands over at the top level, and each dependency's output. Cargo
# keeps the latter in one flat `deps/` (older releases) or in a directory per unit,
# `build/<package>/<hash>/out/` (current ones); both are read, so the check does
# not shrink to the top level when the layout changes under it.
#
# Dependencies are included deliberately: dependency artifacts are part of what a
# user is asked to trust, and a nondeterministic dependency is still a
# nondeterministic build.
candidates() {
  find . -maxdepth 1 -type f
  if [ -d deps ]; then find ./deps -maxdepth 1 -type f; fi
  if [ -d build ]; then find ./build -mindepth 4 -maxdepth 4 -type f -path './build/*/*/out/*'; fi
  if [ -d examples ]; then find ./examples -maxdepth 1 -type f; fi
}

# Sort each candidate into compared (C), excluded (X) or not an artifact (-).
#
# Compared: executables, rlibs, and the libraries an app links. `spark-ffi` is
# built as a cdylib and a staticlib, and those two files are what a phone loads,
# so they are named here rather than caught by the dylib rule below.
#
# Excluded, and this is the only exclusion: proc-macro dylibs. A macOS dylib
# carries its own absolute output path as the LC_ID_DYLIB install name, written by
# the linker after --remap-path-prefix has done its work, so two builds in
# differently-named directories differ in that string and in the ad-hoc signature
# covering it. Measured: 53 bytes out of 2.8 MB, all of them that path. These are
# host build tools that never ship, and their output is fully captured in the
# rlibs, which are compared and do match. If a proc macro ever produced different
# code, that would show up there. (`spark-ffi` sets an `@rpath/` install name in
# its build.rs, so its dylib has no such path.)
#
# Not artifacts: build scripts and the files they generate, dep-info and rmeta.
# They are inputs to the compiled units above, which carry their effect.
classify() {
  case "${1##*/}" in
    libspark_ffi.a | libspark_ffi.dylib | libspark_ffi.so | spark_ffi.dll) kind=C ;;
    *.dylib | *.so | *.dll) kind=X ;;
    build_script_build* | build-script-build*) kind=- ;;
    *.rlib) kind=C ;;
    *) if [ -x "$1" ]; then kind=C; else kind=-; fi ;;
  esac
}

candidates | LC_ALL=C sort | while read -r f; do
  classify "$f"
  if [ -n "$EXCLUDED" ]; then
    if [ "$kind" = X ]; then echo "${f#./}"; fi
  elif [ "$kind" = C ]; then
    printf '%s  %s\n' "$(hash_of "$f")" "${f#./}"
  fi
done
