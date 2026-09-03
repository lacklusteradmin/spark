# Spark

A private, phone-number-free messenger that does one thing: chat.

- `Spark-spec.md` — the design specification. **Where anything conflicts, this wins.**
- `Spark-build-notes.md` — stack choices, traps, and the gates each stage must pass.
- `docs/protocol.md` — chunk format, naming, lanes, sync, and the server API.
  Fills the gap both specs name as unspecified.
- `docs/layering.toml` — the crate graph, enforced rather than described.
- `docs/permitted-knowledge.toml` — what each server may persist. Deny by default.

## Status

**All twelve stages done, and it runs.** Every crate is implemented; there are no
stubs left.

```bash
cargo test --workspace                    # 233 tests
scripts/verify-reproducible.sh            # 251 artifacts byte-identical across two builds
cargo run -p spark-cli -- demo            # two accounts in one process, and what the servers kept
cargo run -p spark-cli -- remote-demo     # the same, over real sockets
cargo run -p spark-cli -- serve           # the three services on TCP
```

`spark demo` stands up all three services in one process, runs two accounts
through a conversation with the real client, and then prints the servers' entire
contents and shows the plaintext is not in them. `spark new` generates a recovery
phrase and the address it derives.

**There is a network now.** `spark-wire` is the format of `docs/protocol.md` §6,
carried as WebSocket binary frames. `Services` has two implementations — one
in-process, one over TCP — and `crates/spark-cli/tests/network.rs` runs the same
client against both, because a client that works in-process and not over the wire
means every earlier gate was testing the wrong one.

**TLS is there, pinned to a key rather than delegated to the WebPKI.** Everything
Spark sends is already sealed, so what TLS adds is server authentication and
hiding the request pattern from a passive observer — neither of which the
encryption above it does.

**There is an FFI, and it is reachable.** Building it turned up two blockers that
were invisible while the only client was the CLI:

`Remote` — the sole networked `Services` — lived inside `spark-cli`, which is a
binary with **no lib target** and links all three servers. Nothing could depend on
it, so the only client that could reach a network was the one compiled into the
same binary as the servers it talked to. It is now `spark-net`.

`Client`'s API cannot cross the FFI line at all. `docs/layering.toml` bans
`spark-crypto`, `spark-identity`, `spark-chunk` and every cryptographic crate from
the `boundary` zone — and `Client` speaks in `Mnemonic`, `Addr`, `ChunkName`,
`Secret<32>` and an `R: CryptoRng`. So `spark_net::Session` converts, below the
line: what crosses is `String`, `Vec<u8>` and `u64`. That is not cosmetic — a
capability arriving as `Vec<u8>` is one the Swift side can carry but not
construct, because it has nothing to construct one with. The OS entropy source
stops there too, since a caller above the line has no safe way to supply one.

`libspark_ffi.a` and `libspark_ffi.dylib` are in the reproducible set, so the
binary a phone would load is byte-identical from source like everything else.

**Nothing here has been run on a phone.** `Spark-build-notes.md` §5 stage 12 calls
for a mobile spike, and the two assumptions it names as most likely to fail —
background cover traffic and privacy-preserving push — are exactly the two this
repository answers on paper. See `docs/threats.toml`, W2 and W4. What is verified
is that the bindings generate and compile: `uniffi-bindgen` produces Swift from
the built library, and that Swift compiles with `swiftc`. What is *not* verified is
anything about an app — no Xcode project, no device, no background execution.

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

**Gate 10** — redemption cannot be linked to payment, or a name to the payment
that bought it; a transfer leaves no record joining old key to new; an expired
name does not reduce quota. All four hold, in
`crates/spark-invariants/tests/gate10_namespace.rs`.

The last one holds *structurally*: quota lives on the keyring service and names on
the issuer, so the issuer has no reach into quota even in principle. F9's "quota
belongs to the key, never to the name" is a consequence of the service split
rather than a rule anything has to enforce.

The issuer signs vouchers with **its own key**, not the keyring service's. One key
shared between the service that sees money and the service that sees
`hash(pubkey)` would let whoever holds it mint both, and would make the two trust
domains one in every way that matters.

**Gate 11** — idle and 100-message captures are indistinguishable in count, size
and timing; the stream survives backgrounding, or the platform is documented as
unable to support it. Both hold, in
`crates/spark-transport/tests/hysteria.rs`. The capture is taken from *sealed*
frames, because the observable is ciphertext — a test comparing plaintext would
prove indistinguishability of something an observer never sees.

**The backgrounding half is answered "documented as unable", for iOS.**
`Spark-build-notes.md` §5 calls background cover traffic one of the two
assumptions most likely to fail and says to verify it during the mobile spike.
**That spike has not been run.** Until it is, iOS is treated as unable, because
guessing the other way leaves a user believing their timing is covered when it is
not. `enable()` is the only way to obtain a running schedule and it refuses on
iOS, so "a setting that silently does less than it claims" is not something the
API can express.

**Gate 12** — every W1–W7 threat has an implemented mitigation or a documented
accepted risk. `docs/threats.toml` is that reckoning and
`crates/spark-invariants/tests/gate12_threats.rs` is what stops it becoming a
document nobody checks: every mitigation must name a test that exists, every
threat must say what remains *after* the mitigation, and every one must point at
where the user is told. A threat with no answer fails the gate, because there is
deliberately no third status.

**Stage 12 produced one finding, and it blocks push.** `Spark-build-notes.md` §2
says the servers may never store real-world identifiers. `Spark-spec.md` D3 says
push is on by default. Delivering a push requires *something* to hold a mapping
from an account to an Apple or Google token, and a push token is a real-world
identifier. Both cannot hold as absolutes. No delivery service exists yet and none
should be built until this is resolved — the options are a fourth trust domain
holding that mapping and nothing else, push being opt-in rather than default, or
no push. It is recorded in W2 rather than left to be discovered mid-implementation.

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

## Push

D3's requirement that is easiest to get wrong: "Off must mean never registering.
Disabling notifications in the OS only stops them being displayed while the token
persists, and a control that appears to close the leak while leaving it open is
worse than none."

So `register` takes the platform's minting call as a closure and does not invoke
it when the setting is off. A token that was never minted cannot persist, cannot
leak through a later bug, and cannot be found on the device afterwards. The test
checks that the closure was never called, not that no token came back.

## Cover traffic

Three things have to be uniform, not one. F12: "Every transmission is padded to a
uniform size and sent to the same endpoint, since an observer who can spot a dummy
by length or destination gets the timing back for free." A schedule whose frames
vary in size is a schedule with the answer written on it.

There is deliberately no "nothing to send" path — `tick()` always returns a frame,
because a skipped transmission is the signal the mode exists to suppress. Media is
refused outright: a one-minute cadence over a photo is not a slower photo, and its
timing is observable anyway, matching D2's mixed-mode tradeoff.

The parameters are D12's, set for adoption rather than strength: cover traffic
hides you inside a crowd on the same schedule, so a setting only a few hundred
people enable makes those people a recognisable group. A test pins the daily cost
at roughly 5.6 MB, so shrinking the interval for latency has to be a decision
rather than a side effect.

The schedule is wired into the real client, not only into the scheduler: `Remote`
takes a `Cover` the same way it takes a `Mode`, and `spark remote-demo --cover`
runs the whole conversation on it. Two things follow from having done this on a
live connection rather than in a harness:

The **server** answers one uniform frame for every frame it receives, including
dummies. Silence in reply to a dummy would make dummies recognisable, which is the
client's whole cadence undone from the other end — a connection is paced or not,
decided by whether its first message is exactly one cover frame, so a peer cannot
switch mid-session.

Only the **first** transmission is special: the TLS handshake and the WebSocket
upgrade are not padded and do not need to be, because they happen once per
connection whether or not it goes on to say anything. `cover_traffic.rs` drops
that prefix deliberately and says so, rather than filtering by size — a size
filter would also hide a short frame, which is the failure the test is for.

It is **off by default**, and that is a real cost rather than a formality: at F12's
minute, every request waits up to a minute. `Remote::cover_slots()` exists so the
setting can be checked from outside — without it, a `Cover` that was accepted and
then dropped on the floor passes every test, since a paced session and an unpaced
one deliver the same messages.

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

## The wire

```text
frame := req_id: u32le || opcode: u8 || payload
```

`spark-wire` is pure, so every property of the encoding is checkable without a
socket. The opcode duplicates postcard's own variant tag on purpose — a server
dispatches on the header before decoding anything an attacker chose — and a test
asserts the two never disagree, so the duplication cannot rot. A frame whose
header advertises one operation and whose body decodes to another is rejected: the
header is what the dispatch trusted.

The wire types are deliberately **not** the servers' own request types. A server's
`Request` is its implementation; this is the protocol. Each server writes its own
conversion, so a change to either side shows up as a change to that conversion
rather than one silently becoming the other. Two tests read the protocol source
directly: the issuer has no operation that could enumerate, and no content
operation carries an identity.

Everything is synchronous and generic over `Read + Write`, which is what lets
TCP, SOCKS5 and WebSocket compose without any of them knowing about the others.
Making it async would have meant the SOCKS5 negotiation knowing about a runtime,
and the traffic-class routing decision leaking into every layer above it. The cost
is a thread per connection, which for a first server is the right trade.

## Routing, and where it is actually applied

Every connection the client makes goes through `Transport`, which decides direct
or Tor from the traffic class and, if Tor, negotiates SOCKS5 on a circuit of its
own. That sentence was not true until recently: the routing, the SOCKS5 and the
traffic classes all existed and passed gate 9 while the real client called
`TcpStream::connect`, so the Tor setting was a switch that did nothing. Gate 9 now
holds of the *client* — `always_on_shows_zero_direct_connections_from_the_real_client`
runs against a real SOCKS5 proxy.

**The content service gets two connections.** Its requests fall on both sides of
D2's default mode: room-log chunks are text and go over Tor, media is bulk and
goes direct. One connection would force a single routing decision for both, and
the mixed mode could not be offered at all.

There is deliberately no constructor that picks a Tor mode for you. There was one,
defaulting to the spec's default, and it is gone: how much goes over Tor is a
decision, and an API that makes it silently is how it stopped being one the first
time.

## TLS, and why not the WebPKI

A browser must reach any site in the world, so it trusts a large set of issuers.
Spark reaches a handful of endpoints it operates, and the WebPKI's guarantee is
"*some* CA vouched for this name" — there are on the order of a hundred and fifty
of them, any one of which can be compelled. For software whose whole claim is
that its operator cannot read your messages, that is a weaker statement than it
sounds.

So the client pins the server's **public key**, and the pin ships inside a
reproducibly built binary: a user can check that what they run contains the pin
they expect, which is not true of a trust store they inherited. The cost is
operational and real — rotating a server key means shipping a new pin. Pinning the
public key rather than the certificate is what keeps routine renewal free, and a
test asserts exactly that.

Over Tor this is partly redundant, since an onion address *is* a public key.
Pinning covers the direct path, which D2's default mode uses for media.

The verifier delegates handshake signature checking to rustls rather than
reimplementing it. Pinning replaces *which* key to trust; it does not replace
checking that the peer holds it, and that is the half where a mistake is silent.

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

## RUSTSEC-2023-0071, and what was done about it

**The Marvin Attack.** The `rsa` crate's modular exponentiation is not
constant-time, so an attacker who can time private-key operations over the network
may recover the key. Spark performs that operation on two servers: the keyring
service blind-signs storage tokens, and the issuer blind-signs name vouchers.
Recovering either key means minting them for free, which removes the economic
floor `Spark-spec.md` D1 depends on. The advisory still reads `patched = []`, and
names exactly one workaround: *avoid using the crate where attackers can observe
timing.* Two of our servers did precisely that, on input the attacker chose.

**The private-key operation no longer goes through it.** RFC 9474 §5 blind signing
is `s = m^d mod n` and nothing else — the message arrives already PSS-encoded by
the client, so there is no padding step on the signer's side and no branch that
could depend on the key. That one exponentiation is now done against
`crypto-bigint`'s constant-time modular exponentiation: a fixed 4-bit window,
unconditional squarings, and a branch-free sweep across all sixteen table entries
for every lookup. No secret-dependent branch and no secret-dependent memory index.
`crypto-bigint` is not an outside bet — it is already in the graph because `rsa`
depends on it, and migrating to it is how RustCrypto intends to fix this advisory.

**Why this is not the custom cryptography `Spark-build-notes.md` §1 forbids.** An
earlier version of this section rejected "build RFC 9474 on a constant-time RSA",
and that rejection stands: the scheme is subtle and reimplementing it would trade
one timing bug for a class of protocol bugs. This is a much smaller thing.
Everything protocol-shaped — PSS encoding, blinding, unblinding, verification, the
DER forms — is still `blind-rsa-signatures`, untouched, and none of it handles a
secret. What was replaced is a single arithmetic identity whose correctness is
fully decidable by comparison: `signing_matches_the_reference_implementation`
signs the same messages with the same key both ways and requires the bytes to be
equal. RSA signing is deterministic in `(m, d, n)`, so any difference at all is a
bug. Two edges that comparison alone would not have reached are tested directly: a
signature with a leading zero byte, which a naive big-endian encoding truncates
(about 1 in 256, so it is searched for rather than waited for), and a blinded
message at or above the modulus, which has no unique signature.

Every signature is also re-encrypted under the public exponent and compared to the
input, as the reference does: it turns a fault — injected, or mine — into a refused
request rather than a signature that leaks. That check runs through a *variable*-time
ladder bounded by `e`'s 17 bits, because `e` ships in the public key and hiding it
would double the cost of signing. Measured: 3.1ms per signature in release, against
6.1ms when the check was constant-time too, and a 50ms pacing tick to fit inside.
Deleting the check breaks no test, which is correct — a fault detector is inert on
correct input.

Having two exponentiation paths is itself a hazard, since they take the same
arguments and swapping them changes no test result, only the timing. So the
invariant below also pins both directions: exactly one variable-time call, with
`&e` as its exponent, and the private path left unbounded.

**What is enforced, not just claimed.** `blind-rsa-signatures` is still a
dependency and therefore `rsa` is still in the graph, so `cargo-deny` still has to
be told about the advisory. What makes that ignore honest is
`no_secret_key_operation_goes_through_the_unpatched_rsa_crate`, which reads
`blind.rs` and fails if anything but `components()` is ever called on the library's
secret key. Reintroducing the vulnerable path is one line, it is *shorter* than
what replaced it, and it produces identical bytes — so every other test in the
workspace would still pass. A dependency-graph check cannot see that; a source
check can.

**The pacing stays, with a different job.** `spark-crypto::pace` still emits
responses on a tick boundary and `KeySet` still rotates the signing keys. That was
the Marvin control; it is now defence in depth. It still earns its place, because
the private-key exponentiation was never the only thing whose duration varied —
quota checks, serial lookups and database writes vary with account state, and
pacing wraps the whole request path rather than the signature alone.

**What is left.** Key *generation* still runs inside `rsa` — prime search and
computing `d`. That is not a Marvin exposure: it happens once, at server setup,
offline, with no attacker-chosen input and no response to time. `IssuerKey` has no
`from_der`, so a private key never re-enters the library by any other route. The
remaining residual is that `crypto-bigint`'s constant-time claim is a design
property backed by code review, not a machine-checked proof.

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
