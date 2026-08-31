# Spark

A private, phone-number-free messenger that does one thing: chat.

- `Spark-spec.md` — the design specification. **Where anything conflicts, this wins.**
- `Spark-build-notes.md` — stack choices, traps, and the gates each stage must pass.
- `docs/protocol.md` — chunk format, naming, lanes, sync, and the server API.
  Fills the gap both specs name as unspecified.
- `docs/layering.toml` — the crate graph, enforced rather than described.
- `docs/permitted-knowledge.toml` — what each server may persist. Deny by default.

## Status

**Stage 4 of 12** (`Spark-build-notes.md` §5): rooms, owners, MLS.
`spark-crypto`, `spark-identity`, `spark-chunk`, `spark-keyring` and `spark-mls`
are implemented; the rest are still stubs. Nothing has touched a network yet, by
construction — all five are `pure` crates, and gate 4 runs two clients in one
process.

```bash
cargo test --workspace             # 63 tests
scripts/verify-reproducible.sh     # 128 artifacts byte-identical across two builds
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

**Gate 3** — chunks decrypt from the seed alone via the keyring, and are inert
without it. Both hold. `crates/spark-keyring/tests/recovery.rs` is written as two
phases with a hard wall between them: the first builds an account and hands only
what a server would hold to the second, which starts from 24 words and nothing
else. The inert half asserts that the servers' entire contents contain no
plaintext, that a wrong seed opens neither the keyring nor any delta, and that a
correctly guessed message cannot be used to locate the chunk holding it.

**Gate 4** — every member sees identical history; a removed member cannot read
later messages; the last owner cannot leave without dissolving; a 1:1 uses the
same owner logic. All four hold, in `crates/spark-mls/tests/rooms.rs`.

## The envelope

```text
mnemonic ──HKDF──▶ keyring_key ──▶ [sealed keyring blob at addr]
                                         │
                                         ├─▶ room_root ──▶ room chunk keys ──▶ history
                                         └─▶ receipts, uploads, tokens, names
```

Two ciphertext layers, and the server holds both and can open neither. Nothing
else contributes — no device key, no escrow share — which is exactly why losing
the seed loses everything.

The two naming schemes are deliberately different:

| | Media | Room log |
|---|---|---|
| Name | `SHA-256(chunk)` | `HMAC(room_root, lane ‖ seq)` |
| Store can verify the name | yes | no |
| Outsider can compute it | given the file | never |
| Deduplicates | server-wide | not at all |

Files are hard to guess; sentences are not.

## Rooms

`spark-mls` implements the *policy* on top of MLS, and nothing cryptographic
(build-notes §3: do not implement MLS). The owner set lives in an MLS group
context extension rather than in application state, because F4 says simultaneous
dismissals resolve by MLS commit order — putting the set in the group context
makes that true for free, since changing it *is* a commit and MLS already totally
orders commits.

The MLS signature key **is** the Spark identity key, so a leaf is provably the
identity it claims and `LaneId::message(sign_pub)` names the same key that signed
the commit. One identity, not two that have to be kept in step.

Two things the API states plainly because they are easy to get wrong:

* **Joining takes the room root as a parameter.** MLS forward secrecy means a
  joiner cannot decrypt pre-join history on its own, so an existing member
  re-shares it out of band. That is the mechanism F4 flags as sitting outside
  MLS's guarantees, confined to one value and visible in one function signature.
* **Leaving returns a proposal, not a commit.** MLS does not let a member commit
  their own removal, so a departure is not final until an owner commits it. A
  member therefore cannot unilaterally leave a room whose owners have stopped
  responding; F4 provides no takeover mechanism and this crate does not invent
  one.

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
