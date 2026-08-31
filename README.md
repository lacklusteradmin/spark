# Spark

A private, phone-number-free messenger that does one thing: chat.

- `Spark-spec.md` — the design specification. **Where anything conflicts, this wins.**
- `Spark-build-notes.md` — stack choices, traps, and the gates each stage must pass.
- `docs/protocol.md` — chunk format, naming, lanes, sync, and the server API.
  Fills the gap both specs name as unspecified.
- `docs/layering.toml` — the crate graph, enforced rather than described.
- `docs/permitted-knowledge.toml` — what each server may persist. Deny by default.

## Status

**Stage 1 of 12** (`Spark-build-notes.md` §5): protocol doc, skeleton, invariant
harness. Every crate is a stub. No cryptography is implemented yet — stage 2 is
where identity begins.

Gate 1 requires two things, and both hold:

```bash
cargo test -p spark-invariants     # 14 tests, incl. 6 against deliberately broken stubs
scripts/verify-reproducible.sh     # 15 artifacts byte-identical across two builds
```

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
