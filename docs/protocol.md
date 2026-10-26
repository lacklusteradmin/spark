# Spark Protocol — v0 (draft)

Status: **prelaunch implementation, security revision.** The Rust wire types define the exact encoding. The bundled `serve` uses durable SQLite WAL transactions, persistent service keys, and a persistent TLS identity. Replicated/distributed deployment and malicious-server freshness guarantees remain separate concerns.

Where this document conflicts with `Spark-spec.md`, the spec wins and this file is
the bug. Where it conflicts with `Spark-build-notes.md`, the build notes win on
stack choices and this file wins on wire detail.

Every constant here is deliberate. Nothing is "TBD in code": build-notes §1 says
*no unspecified crypto parameters*, so a parameter that is genuinely undecided is
listed in §9 Open, not left implicit.

---

## 1. Primitives

One primitive per job, chosen to keep the audit surface small.

| Job | Primitive | Notes |
|---|---|---|
| Group messaging | MLS, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | RFC 9420, via OpenMLS |
| Chunk encryption | XChaCha20-Poly1305 | 24-byte random nonce for room logs and keyrings |
| KDF | HKDF-SHA256 | extract + expand |
| Hash | SHA-256 | also the MLS suite hash; no second hash function |
| Keyed naming | HMAC-SHA256 | room chunk names |
| Signatures | Ed25519 | identity + MLS credential |
| Key agreement | X25519 | identity-key wrapping |
| Seed | BIP-39, 24 words | no passphrase in v0 (see §9.1) |
| Blind signatures | RFC 9474 blind RSA, 2048-bit | storage tokens **and** payment vouchers |

`SHA-256` is used for both content hashing and address derivation. There is no
BLAKE3, no SHA-3, no second AEAD. Adding one requires a decision record.

---

## 2. Identity and derivation

Derivation is HKDF with domain-separated `info` strings rather than a BIP-32 path.
Spark derives a fixed, small set of keys with no hierarchy, and SLIP-10 over
Ed25519 would add a spec dependency for no gain.

```
seed        = BIP39-Seed(mnemonic, passphrase = "")          # 64 bytes
root        = HKDF-Extract(salt = "spark/v1/root", ikm = seed)  # 32 bytes

ik_sign     = HKDF-Expand(root, "spark/v1/identity/ed25519", 32)  -> Ed25519 secret
ik_kem      = HKDF-Expand(root, "spark/v1/identity/x25519",  32)  -> X25519  secret
keyring_key = HKDF-Expand(root, "spark/v1/keyring/aead",     32)
```

The **keyring address** — the only account-shaped identifier any server sees — is

```
addr = SHA-256("spark/v1/keyring/addr" || ik_sign_pub)          # 32 bytes, hex-encoded
```

This is `hash(pubkey)` as the spec calls it. It is derived rather than raw so that
holding `addr` does not hand an observer a verification key.

**Invariant.** `root` and everything under it is reachable from the seed alone and
from nothing else. There is no device key, no escrow share, no server-side blob
that contributes entropy. A test asserts that clearing local state and re-deriving
from the mnemonic reproduces every key byte-for-byte (gate 2).

---

## 3. Chunk format

A chunk is the only object either store holds. One format, three kinds.

```
chunk := header || ciphertext

header (32 bytes, authenticated as AAD, never encrypted)
  offset  size  field
  0       4     magic     = b"SPK1"
  4       1     version   = 0x01
  5       1     kind      = 0x01 room-log | 0x02 media | 0x03 keyring
  6       2     flags     = 0x0000  (reserved; a non-zero flag is a parse error)
  8       24    nonce     XChaCha20-Poly1305 nonce

ciphertext := XChaCha20-Poly1305-Seal(key, nonce, aad = header, plaintext)
              (includes the 16-byte tag)
```

The header is in the AAD, so `kind` and `version` cannot be swapped under an
attacker. Nothing else is outside the AEAD: there is no plaintext length prefix,
no room id, no sender field. **A chunk carries no routing information.** Whoever
can name it and holds its key can read it; nobody else learns anything from it.

### 3.1 Kind 0x02 — media (convergent)

Dedup requires that one file always produces one byte-identical chunk, so both key
and nonce derive from the plaintext.

```
ck   = SHA-256(plaintext)
key   = HKDF-Expand(HKDF-Extract("spark/v1/media", ck), "key",   32)
nonce = HKDF-Expand(HKDF-Extract("spark/v1/media", ck), "nonce", 24)
name  = SHA-256(chunk); name[0] &= 0x7f       # media namespace
```

`name` is the hash of the finished chunk with its high bit cleared, so the content
store can verify that a write matches its claimed name without holding any key.
The server rejects room writes with that bit cleared. The disjoint namespaces prevent cross-kind squatting; the remaining 255 bits are derived from the hash.

The read capability is the pair `(name, key)`. The store never sees `key`. Readers verify the media kind and recompute the requested name before decryption; valid AEAD alone does not authorize different content at that address.

*Accepted cost, inherent to convergent encryption:* someone who already holds a
file can confirm Spark holds it too. `Spark-spec.md` F7 accepts this ("Deduplication
tells the operator that a chunk has several holders"). The confirmation-of-file
attack is the same fact from the other side; it is not a new leak.

### 3.2 Kind 0x01 — room log (keyed, not convergent)

Content-derived names would let an outsider compute the name of a guessed sentence
and test whether it exists (F7). Room chunk names are therefore derived from a
room secret.

```
name  = HMAC-SHA256(room_root, "spark/v1/room/name" || lane_id || be64(seq))
name[0] |= 0x80                            # room namespace
key   = HKDF-Expand(room_root, "spark/v1/room/key"   || lane_id || be64(seq), 32)
nonce = CSPRNG(24 bytes)  # fresh for every encryption, including failed writes
```

`room_root` is the 32-byte MLS exporter output with label `spark/v1/room-root`
and empty context for that epoch. Each generation's root and authenticated member
roster are saved in the encrypted keyring; joining members receive past generations
through the confidential invitation. A joiner derives the current root directly
from MLS. Removed members cannot derive future roots.

Write-once names arbitrate conflicting writes, **not nonce uniqueness**. A server
can see losing ciphertexts, and restored or concurrent clients can reuse a slot.
Random nonces keep those collisions from reusing the AEAD keystream. Persisting the
write cursor before upload remains necessary for orderly retries. A rolled-back
server snapshot is not proof of freshness; seed-only recovery cannot independently
prove that a malicious server returned the latest state.

### 3.3 Kind 0x03 — keyring

`key = keyring_key` (§2), random nonce per write. The keyring is mutable, so it
cannot use a derived nonce.

---

## 4. Lanes

A room's chunk namespace is split into lanes. This resolves the contradiction
between spec F7 ("append-only, so simultaneous senders never collide") and F4
("simultaneous dismissals resolve by MLS commit order, which means the server
picks"): the two statements are about different lanes.

```
lane_id (16 bytes)
  commit lane   0x00 || 0x00 * 15
  message lane  0x01 || SHA-256("spark/v1/lane" || member_ik_sign_pub)[0..15]
```

Message lanes are keyed by identity public key, not by MLS leaf index. Leaf indices
are recycled when members leave, so two different members could occupy leaf 3 in
different epochs and collide on one lane.

| | Commit lane | Message lanes |
|---|---|---|
| Count | exactly one per room | one per member |
| Carries | MLS handshake: add, remove, update, owner changes | MLS application messages |
| Ordering | total, arbitrated by the store | none; merged client-side |
| Contention | real — resolved by write-once CAS | stale devices and hostile members can collide |

A commit that loses the CAS re-derives against the new epoch and retries at
`seq+1`. It retries at a new slot and draws a fresh random nonce.

`lane_id` is never sent to a server. It only ever appears inside an HMAC keyed by
the secret `room_root`, so the resulting names are indistinguishable from random.

---

## 5. Room log plaintext and merge

Every room-log chunk decrypts to:

```
RoomChunk {
  lane:      [u8; 16],           // redundant with the name; binds plaintext to lane
  seq:       u64,
  epoch:     u64,                // MLS epoch at time of write
  clock:     Vec<(LaneId, u64)>, // vector clock: heads this writer had seen
  payload:   Payload,
}

Payload = Commit(MlsMessage)   // commit lane only; consumed live, never replayed
        | Application(Signed)  // message lanes only; see below
        | LaneAdvert           // heartbeat carrying only `clock`

Signed { body: bytes, sender: [u8;32], sig: [u8;64] }
  context = SHA256("spark/v1/archive-context" || canonical_MLS_group_id || generation_root)
  sig covers  "spark/v1/msg" || context
             || be64(encoded_clock_length) || canonical_postcard(clock)
             || lane || be64(seq) || be64(epoch) || body
```

Before admitting an application entry to history, verify the signature, the exact
requested epoch and slot, `lane == LaneId::message(sender)`, and membership in that
generation's saved roster. Invalid entries must not influence read cursors or
ordering. The signed group/root commitment binds the room and generation, including when a
historical root is copied into another invitation; the clock is
signed as well. A shared AEAD key alone does not authenticate one member to another.

MLS receives require application authorization before storing proposals or merging
commits. Committers must be current owners. Adds and owner-set changes require an
owner; a member may propose their own departure or identity-preserving update.
Validate BasicCredential identity bytes against the leaf signing key. Owner sets
must remain nonempty, canonical and a subset of the resulting members. Removing an
owner and changing the owner set occur in one commit. Unsupported external joins,
reinitialization and external senders are rejected.

### 5.0 Why an application message is not an MLS ciphertext

This section previously said `Application(MlsMessageOut)`. **That cannot work**,
and gate 6 is where it showed.

MLS deletes each sender-ratchet key as it is used and drops past-epoch secrets,
because that is what forward secrecy *is*. An archive of MLS ciphertexts is
therefore unreadable after a restore — by anyone, including its owner. F2 promises
the opposite: history comes back from the seed.

So the archive layer is the room chunk's own AEAD, keyed from `room_root`. This is
what `Spark-spec.md` F4 already implies when it says an existing member "re-shares
the historical keys", and under decision D-A there is no separate MLS delivery
path to lose, because members read chunks rather than receive messages. MLS
carries membership and the owner set; its exporter derives each generation root.

Confidentiality at rest comes from the chunk AEAD. Attribution comes from the
signature, made with the identity key that is also the MLS credential. D8's
deniability analysis is unchanged: a signature proves the holder of key X wrote a
message, not who holds key X.

**Cost, stated plainly.** Forward secrecy no longer protects the archive. Anyone
holding the seed can read all history, which `Spark-spec.md` F6 already accepts
("Anyone with the seed, including a court that seizes it, can restore and read the
history"). What changes is that this is now a property of the design rather than
an incidental one — there is no epoch after which old messages become unreadable
to their owner, by construction.

Vector clocks authenticate causal observations used in ordering. They are claims by the signer, not trusted discovery bounds or allocation sizes.

### 5.1 Total order

Clients must agree on history without a server ordering messages. The order is:

1. `epoch` ascending — MLS already totally orders epochs.
2. Within an epoch, causal order by vector clock.
3. Concurrent writes (neither clock dominates): ascending `lane_id` bytes, then `seq`.

The dependency graph uses the immediately preceding entry in the same lane and the last available entry at or below each other lane observation. A cycle claimed by a hostile signer is broken at the lowest remaining `(lane_id, seq)`; processing then resumes normally. The ready set uses the same tie-break. Gate 4 tests arrival-order independence and causal ordering.

### 5.2 Polling

Per sync tick and known lane, the client scans forward with a limit of 256 requests and a consecutive-miss threshold clamped to 1–256. Its disposable cursor advances even through a long gap. A separate sweep revisits at most 256 earlier slots against a fixed sweep endpoint, so temporary holes are eventually retried rather than forgotten. Cursors reset when plaintext history is wiped. Malformed or unauthenticated entries are excluded without aborting the other lanes. Large histories may require multiple ticks to load; a single result is not proof of completeness. Ordering builds same-lane predecessor chains and one dependency on the last observed entry in each other lane. With N entries and C clock observations, auxiliary storage is O(N+C), and time is O((N+C) log N), including deterministic cycle handling. Clients reject clock lanes outside the generation roster before adding an entry to history.

**Requests are issued independently, one name each.** Batching names into one
request would tell the store that those names belong together — which is exactly
the correlation D-A exists to avoid, reintroduced one layer down. The cost is
request amplification proportional to room size. See §9.2.

---

## 6. Server API

Three services, three trust domains, deployed separately. Transport is WebSocket
over TLS, binary frames, `postcard` encoding, optionally over a SOCKS5 proxy for
Tor. Every frame:

```
frame := req_id: u32le || opcode: u8 || payload
```

`req_id` correlates responses on one connection and is never persisted.

### 6.1 Keyring service — authenticated

Authenticated by an Ed25519 signature over `spark/v2/keyring-request || postcard(request with empty auth.sig)`. Auth is embedded in each protected operation, so the signature binds the operation, body, account, challenge, and nonce. This is the only service that knows
an `addr` exists.

| Op | Request | Response |
|---|---|---|
| `Challenge` | account address | 32-byte HMAC of address and current server minute |
| embedded `Auth` | `addr`, identity public key, challenge, random 32-byte nonce, complete-request signature | checked and nonce consumed atomically with the operation |
| `GetSnapshot` | — | chunk (kind 3) or empty |
| `GetDeltas` | `from: u32` | `[chunk]` |
| `PutDelta` | chunk | delta index |
| `PutSnapshot` | chunk, expected snapshot hash/delta count, contact permit hashes | atomic CAS; snapshot and inbox gate updated; deltas truncated |
| `GetQuota` | — | `{ media_bytes, text_bytes, limit }` |
| `GetIssuerKey` | `size_class` | denomination-specific public key |
| `WithdrawTokens` | `[blinded]`, `size_class` | `[blind_sig]`, quota debited |
| `CreditRefund` | refund claim and signature | quota credited |
| `SetContacts` | authenticated list of at most 64 opaque permit hashes | permissions replaced |
| `PutRequest` | recipient address, sealed signed note, 32-byte contact permit | uniform acknowledgement |
| `GetRequests` / `DropRequest` | authenticated recipient; optional slot index | read / discard |

The server supports snapshots plus append-only deltas. The current client journals whole encrypted snapshots. A stale writer is rejected by CAS and must reopen; it cannot overwrite newer rooms, receipts, or contact revocations. Lost snapshot responses are retried using exactly the same bytes. Malformed deltas and unavailable MLS state fail restoration explicitly.

Replay nonces are persisted until the minute expires. An indexed expiry sweep and a persistent minute high-water mark prevent pruning from reviving proofs after clock rollback. At most 65,536 authenticated requests are admitted per service minute; excess requests are refused before mutation. This is a resource bound, not a Sybil-resistance guarantee. Expired requests need a fresh proof; application retry identities remain unchanged. TLS still authenticates the server and protects the channel.

### 6.2 Content service — no identity, ever

| Op | Request | Response |
|---|---|---|
| `Put` | `name`, `chunk`, `token` | `receipt` (32 opaque random bytes) |
| `Get` | `name` | `chunk` or not-found |
| `Head` | `name` | exists / not |
| `GetRefundKey` | `size_class` | public key of separate refund mint |
| `Release` | `name`, `receipt`, `size_class`, blinded refund claim | blind refund signature |
| `Delete` | `name`, `receipt` | ok — room chunks only, explicit write capability required |

- `Put` is **write-once**: a name that exists is rejected, whatever the bytes. This
  is the CAS arbitration point for the commit lane (§4) and the ordering arbitration point for room chunks.
- `Put` verifies media names against SHA-256(chunk) with bit 255 cleared and requires room names to have that bit set. The remaining room-name bits are keyed and cannot be validated by the server. Keyring chunks are rejected.
- A new `Put` charges the token in full even when media already exists. An exact retry of the same token, name, and ciphertext returns the original receipt without charging or incrementing holders. A discount
  would let anyone probe what Spark holds (build-notes §4).
- `Get` and `Head` carry **no** authentication. The name plus key is the capability.

### 6.3 Issuer service — blind

| Op | Request | Response |
|---|---|---|
| `Resolve` | exact `name` | `pubkey` or not-found — **no prefix, no listing** |
| `GetIssuerKey` | provisioned price | price-specific public key |
| `Purchase` | `blinded`, payment reference, amount | blind signature after trusted settlement verification |
| `TransferChallenge` | exact name | current random nonce |
| `Register` | `name`, `pubkey`, voucher | ok |
| `Transfer` | `name`, `new_pubkey`, signature over context + current nonce + name + new key | ok; mapping overwritten and nonce replaced |

Expiry and grace use a server-owned clock; request date hints have no authority. Name writes and voucher spending are serialized; duration arithmetic is checked before spending. Transfers require a live name and a current nonce, preventing A→B→A replay. No transfer history is stored.

The default payment adapter **rejects all purchases**. Deployment must supply a trusted `PaymentVerifier` that verifies final settlement, destination, exact value, and a payment commitment to the blinded request. No such chain adapter is supplied yet. Price keys are provisioned out of band, never generated for an arbitrary network request. Redemption selects keys by the signed claim’s price; a cheap signing key cannot buy an expensive hidden grant. Exact purchase retries return the cached blind signature. Public prices partition the anonymity set; payment timing remains visible.

---

## 7. Storage authorization, deletion and blind refunds

Storage signing keys are separated by size class (10 through 40). The issuer charges
`2^size_class` and uses only that class's key. The content verifier chooses a key
from the **claimed** class's registry; changing a hidden claim's denomination
therefore cannot upgrade a cheap signature. A batch is bounded to 64 tokens.
Public keys must be provisioned through the deployment's trusted channel. A caller
cannot supply a verification key alongside a spend. Separate-process deployments
must propagate public denomination/rotation updates before accepting tokens; the
bundled deployment shares only public-key registries between services.

Receipts are 256-bit OS-random capabilities. The receipt ledger stores hashes and the original charged class; the spent-token retry record retains the issued receipt so a lost upload response can be recovered. Room roots, names and membership alone grant no delete
permission. `Delete` requires a receipt issued for that exact room chunk. An owner
performing dissolution needs explicitly delegated write capabilities; merely
knowing the room root is insufficient. Media cannot be deleted by this endpoint.
`Release` consumes the caller's receipt and frees bytes only at zero holders. `Delete` removes room ciphertext but retains its receipt accounting until refunds finish, so deleting a log does not strand the uploader’s quota.

The content service has a **separate**, denomination-separated refund mint. Its
public keys alone are provisioned to the keyring service. The client draws a fresh
serial, blinds `"spark/v1/refund" || serial || size_class`, and sends the blinded
request with its receipt. The store verifies the original receipt denomination,
signs, then consumes the receipt and decrements its count in a serialized operation.
Malformed blinding requests leave the receipt intact.

The client unblinds and redeems `(TokenClaim, Token)` at the keyring service.
Verification binds purpose, denomination and amount; the server derives the amount
from the authenticated class, never from a caller-supplied amount. Serial checking,
consumption and quota credit are serialized. A storage token cannot serve as a refund.

Before withdrawal or release, the client saves the claim, pinned public key, exact ciphertext (for upload), and secret unblinding state inside the encrypted keyring. `retry_pending_upload` resumes that exact operation after a crash; new sends are refused while it is pending. CLI: `retry-upload PROFILE`. Each upload receipt is retained separately, including duplicate uploads of the same file. Releasing a name releases one outstanding receipt.

Withdrawal retries are bound to account, denomination, and the complete blinded batch. A malformed batch debits nothing. Content release stores one blinded result per receipt and rejects a different retry request. Refund redemption returns success to the original account on retry without crediting twice; another account cannot replay it. Retry records never contain a link between an account and a content receipt.

Each service operation runs in a SQLite `BEGIN IMMEDIATE` transaction with WAL and `synchronous=FULL`; replies follow commit. Spend markers, accounting changes, and retry responses commit together. A private vault persists all provisioned denomination/price keys, rotation state, the challenge secret, and the TLS identity. `serve` holds an OS deployment-directory lock to prevent concurrent processes with divergent in-memory key registries. `Db::new()` is an ephemeral SQLite fixture; production uses `Db::open()`. This is local durability, not replicated consensus. Timing correlation across withdrawal/release/redemption remains an anonymity cost.

---

## 8. Keyring contents

```
Keyring {
  version: u16,
  rooms:    [ { room_id, generations: [(epoch, root, members, my_next)], display_name, my_lane } ],
  contacts: [ { name, sign, kem, receive_permit, send_permit } ],
  receipts: [ { chunk_name, receipt, kind, room_id: Option } ],
  uploads:  [ { chunk_name, size, room_id: Option, day: u32 } ],
  tokens:   [ unspent_token ],
  names:    [ { name, paid_until_day } ],
  pending:  [ contact_request ],
}
```

`receipts` MUST survive recovery: a lost receipt strands a chunk forever (F7).
`uploads` is listed to the user and **never** filtered by "looks unused" —
"no room references this" is indistinguishable from "a room references this but I
left it" (build-notes §4).

---

## 9. Open

Listed rather than implied. Each blocks its own stage, not the whole build.

1. **Passphrase on top of the seed.** Would need Argon2id and a documented KDF
   profile. v0 ships without one; adding it later changes derivation, so decide
   before gate 2 freezes the path.
2. **Poll amplification.** One request per lane per tick is `O(room size)`
   requests. Batching leaks the grouping; a shared per-room "head" object also
   leaks it. Possibly a PIR-flavoured or cover-padded batch. Needs its own decision
   before stage 6.
3. **Blind token anonymity set.** RFC 9474 hides the token contents, not the timing
   of a withdrawal. If withdrawals are identifying, the storage authorisation model
   does not deliver what it claims. Spike this early (risk item 04).
4. **Delta count leakage.** Keyring delta index tells the server roughly how many
   writes a key made. Close to what size and mtime already give, but it is an
   addition to §2 of the build notes and needs to be written into the permitted-
   knowledge list explicitly or designed out.
5. **Contacts-only delivery.** Users explicitly add contacts in the app. Contacts,
   public identities and random per-contact permits are stored in the encrypted
   keyring. Only permit hashes are provisioned to the keyring service. The sender
   receives a confidential 96-byte card (recipient public identity plus permit).
   Unknown, revoked and oversized requests allocate no storage. One outstanding
   request per permit prevents one contact filling the entire inbox. Requests are
   signed by their sender over the recipient encryption key, ephemeral key and
   complete plaintext, then encrypted; the app checks the signature and the exact
   approved contact corresponding to the permit slot before showing it. Changing
   the permit list clears the pending tray. The service learns permit count and
   repeat permit use, but no contact identity. This is an explicit metadata cost.
