# Spark

A private, phone-number-free messenger that does one thing: chat.

- `Spark-spec.md` — the design specification. **Where anything conflicts, this wins.**
- `Spark-build-notes.md` — stack choices, traps, and the gates each stage must pass.
- `docs/protocol.md` — chunk format, naming, lanes, sync, and the server API.
  Fills the gap both specs name as unspecified.
- `docs/layering.toml` — the crate graph, enforced rather than described.
- `docs/permitted-knowledge.toml` — what each server may persist. Deny by default.

## Status

**Stage 2 of 12** (`Spark-build-notes.md` §5): identity, offline. `spark-crypto`
and `spark-identity` are implemented; every other crate is still a stub.

```bash
cargo test --workspace             # 30 tests
scripts/verify-reproducible.sh     # 65 artifacts byte-identical across two builds
```

**Gate 1** — invariant tests fail against a deliberately broken stub; two
independent builds of one commit are byte-identical. Both hold. The build
comparison uses two differently-named target directories outside the repo, so it
also proves the output does not depend on where it was built. One exclusion, and
it is printed on every run: host proc-macro dylibs carry their own absolute
output path in the Mach-O install name, written by the linker after
`--remap-path-prefix` has run. They never ship, and their output is captured in
the rlibs, which are compared.

**Gate 2** — the same seed yields identical keys on a clean machine; no code path
recovers an identity without it. Both hold. The first is
`crates/spark-identity/tests/vectors.txt`, frozen and committed: a diff there
means every existing account just lost its history. The second is structural and
lives in the harness, which reads `spark-identity`'s source and fails on any
constructor that is not seed-derived — a test inside the crate could only check
constructors it already imports.

The derivation chain in `docs/protocol.md` §2 was verified against an independent
Python implementation of PBKDF2-HMAC-SHA512 and HKDF-SHA256, and the mnemonic
against the official BIP-39 test vector.

## Setup

The toolchain is pinned to an exact version, because a different compiler can
change codegen and break byte-identical rebuilds. Install it once:

```bash
rustup toolchain install 1.94.1
```

## The invariant harness

Three nets, all running in CI from the first commit:

| Net | Catches | Where |
|---|---|---|
| Layering | I/O below the I/O line, cryptography above the FFI line, upward dependencies, undeclared crates | `docs/layering.toml` |
| Permitted knowledge | a server persisting a field it may not hold, including one renamed to look ordinary | `docs/permitted-knowledge.toml` |
| Banned dependencies | HTML parsers, embedded browsers, push SDKs, telemetry | `deny.toml` |

`crates/spark-invariants` has **no dependencies, deliberately**: the harness that
polices the dependency graph must not be part of it.

`crates/spark-invariants/fixtures/broken/` holds regressions that would each look
reasonable in a pull request — an upload-to-key link, a room membership index
renamed as bookkeeping, a name transfer history, three layering slips. The tests
assert the harness rejects each one *and names the specific reason*, so a check
cannot rot into one that passes everything. A harness nobody has watched fail
proves nothing.

## Build order

Stages 2 onward are in `Spark-build-notes.md` §5. Offline before online: stages
2 through 4 run entirely against `pure` crates, with no server in existence.
