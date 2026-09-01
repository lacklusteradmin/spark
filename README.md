# Spark

A private, phone-number-free messenger that does one thing: chat.

- `Spark-spec.md` — the design specification. **Where anything conflicts, this wins.**
- `Spark-build-notes.md` — stack choices, traps, and the gates each stage must pass.
- `docs/protocol.md` — chunk format, naming, lanes, sync, and the server API.
  Fills the gap both specs name as unspecified.
- `docs/layering.toml` — the crate graph, enforced rather than described.
- `docs/permitted-knowledge.toml` — what each server may persist. Deny by default.

## Status

**Stage 9 of 12** (`Spark-build-notes.md` §5): Tor. Nine of eleven client crates
and all three services are implemented. `spark-client` and `spark-ffi` are still
stubs.

```bash
cargo test --workspace             # 138 tests
scripts/verify-reproducible.sh     # 150 artifacts byte-identical across two builds
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

**Gate 5** — permitted-knowledge tests pass against the real server. They do, in
`crates/spark-invariants/tests/gate5_servers.rs`, and the check is stronger than
stage 1's: `spark-store` records the field names of every write, so
`Db::inventory` reports what a service *actually* stored rather than what someone
wrote down. Three assertions run against a live session — subset of the
whitelist, agreement with the hand-written `server/*-schema.toml`, and no
plaintext or graph edge anywhere. Each was confirmed by deliberately breaking it
first.

**Gate 6 — the go/no-go.** Wipe the device, restore from seed, history matches;
the server's entire database yields no plaintext and no graph edge. All of it
holds, in `crates/spark-invariants/tests/gate6_recovery.rs`, which runs the whole
stack: a real MLS room, real chunks, both real services, and then throws
everything away except twenty-four words.

**This gate changed the protocol.** See `docs/protocol.md` §5.0. The first version
of that test passed while the total order was reversed, because it only compared
two restores to each other rather than to what was actually said. Fixing the
assertion surfaced the real problem: `Payload::Application` held an MLS ciphertext,
and MLS deletes each sender-ratchet key as it is used. An archive of MLS
ciphertexts is unreadable after a restore, by anyone, including its owner — which
is the opposite of what F2 promises. The archive layer is now the room chunk's own
AEAD, keyed from `room_root`, with attribution from a signature by the identity
key that is also the MLS credential.

**Gate 7** — the API cannot enumerate names or reach a stranger without
acceptance; a rejected request leaves no trace for the sender; after migration the
old key decrypts nothing new. All three hold, in
`crates/spark-invariants/tests/gate7_reachability.rs`.

**This gate found a hole stage 6 had opened.** Since the archive became
`room_root`-sealed, a fixed root meant a removed member could still *compute the
names of* and decrypt everything written after they left — removal that removed
nothing. The root is now the MLS exporter secret for the epoch, so it rotates on
every membership change, and a keyring holds one **generation** per epoch.
Recovery walks all of them; a late joiner holds only the generations from after
they arrived.

**Gate 8** — two accounts uploading one file produce one chunk and two full
charges; a viewer is charged nothing; a ten-member room stores one history;
receipts restore from seed; dissolve deletes room chunks and spares shared media;
the content store logs nothing about who; GPS EXIF cannot survive a send. All of
it holds, in `crates/spark-invariants/tests/gate8_storage.rs`.

**"The content store logs nothing about who" failed first, and it was right to.**
The storage token had been a placeholder reading `token-{addr}-{n}` — it embedded
the address, and the content store records spent serials. Tokens are now real RFC
9474 blind RSA: the client blinds locally, the keyring service debits quota and
signs bytes it cannot read, and the content service verifies a signature that
tells it nothing about who drew it. The size class travels inside the signed
message so the store can check an upload fits what was paid for without learning
anything else.

**Gate 9** — always-on mode shows zero direct connections; mixed mode shows them
for media fetches only. Both hold, in `crates/spark-transport/tests/routing.rs`,
checked against a ledger of what the transport *did* rather than against the
routing table: a test that only asked `Mode::uses_tor` would pass while the code
ignored it.

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

## Generations

The archive secret is the MLS exporter secret for an epoch, not a value fixed at
room creation. Every membership change is a commit, and every commit is an epoch,
so the root rotates whenever the member set changes. A removed member never
reaches the next epoch, so later chunk names are not merely unreadable to them but
uncomputable.

It also removes a distribution problem: a random root would have to be sent to
every member and re-sent on every rotation, while an exporter secret is derived
independently by everyone in the group. What *cannot* be derived is a past
generation — that is forward secrecy — so those are the "historical keys" F4 says
an existing member re-shares, now reduced to one list of 32-byte values.

Every past generation must be kept. Losing one loses that stretch of history
permanently, for its owner as much as for anyone else.

## Tor

Traffic class is a required argument to `Transport::open`, never inferred. A
request whose class nobody decided is a request routed by accident, and the
accident is always the same one — media escaping in a mode the user believed
covered it.

Two details separate routing over Tor from appearing to:

* **The hostname goes to the proxy as a name**, using RFC 1928's `ATYP=0x03`.
  Resolving locally and sending an IP hands every lookup to the ISP's resolver,
  and the traffic that followed was over Tor for nothing. This is the most common
  way a Tor integration leaks, and it leaks silently.
* **Every request gets its own circuit**, via SOCKS5 username/password credentials
  that vary per request — Tor's `IsolateSOCKSAuth`. Sharing one circuit lets an
  exit-side observer link requests to each other even without an IP. A proxy that
  refuses username/password is refused in turn rather than falling back to
  no-auth, which would mean sharing a circuit while the user was told otherwise.

WebSocket framing and TLS are not here yet, and `docs/protocol.md` §6 specifies
both. Gate 9 is about *where* connections go, which is decided before a byte of
TLS is written.

## Metadata stripping

`scrub` returns an error for any format it cannot fully account for, and
`Scrubbed` — the only thing `media::seal` accepts — has no other constructor.
Sending an unscrubbable file is not something the API can express.

The obvious alternative, stripping what is recognised and passing the rest
through, ships GPS coordinates the first time someone sends a format it was not
taught about, with nothing anywhere reporting a problem. Build-notes §1: never
silently downgrade a privacy setting.

Re-encoding would be more thorough and is rejected on cost: it means an image
codec in the client, tens of thousands of lines of C-derived parsing on
attacker-supplied input, which is a larger risk than the one it closes. This walks
container structure only, never pixel data. PNG keeps an allow-list rather than
dropping a deny-list, because private chunks are legal and can hold anything.

A pleasant side effect: scrubbing before hashing means the same photograph from
two different phones deduplicates, where the raw files would not have.

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

## The three services

Separately deployed, separately operated. Blind vouchers cut the payment-to-key
link cryptographically, but an issuer sharing a process with the keyring service
would rejoin it through request timing and operational logs.

| | Knows | Authenticates by |
|---|---|---|
| Keyring | `hash(pubkey)`, blob size, mtime, quota and rate counters | Ed25519 challenge — stateless, an HMAC of the address under a server secret and the minute |
| Content | chunk name, bytes, receipt count, spent token serials. **No accounts** | writes: a blind token. reads: nothing at all |
| Issuer | name → key, paid-until, issuance count | blind (the voucher, not the caller) |

Rules that are easy to "improve" into a leak, so each has its own test in
`server/spark-content-server/tests/rules.rs`: a name is write-once (the commit
lane's arbitration point, and the backstop that makes derived room-chunk nonces
safe); a duplicate upload is charged in full and answered identically to a fresh
one; media is freed at zero holders while room chunks are deleted outright.

## Blocking before launch

**RUSTSEC-2023-0071 — the Marvin Attack.** The `rsa` crate is not constant-time,
so an attacker who can time private-key operations over the network may recover
the key. Spark does exactly that on a server: the keyring service blind-signs
storage tokens. Recovering the issuer key means minting unlimited tokens, which
removes the economic floor `Spark-spec.md` D1 depends on — the only defence Spark
has against mass account creation.

It arrives through `blind-rsa-signatures` -> `rsa`. No patch exists. It is ignored
in `deny.toml` to unblock development and is **not accepted for launch**. Closing
it needs one of:

* upstream landing a constant-time RSA implementation;
* moving the issuer to a different blind-signature construction;
* placing the signing operation where an attacker cannot time it.

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
