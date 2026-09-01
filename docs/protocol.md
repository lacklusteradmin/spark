# Spark Protocol — v0 (draft)

Status: **draft, unimplemented.** This document fills the gap both specs name:
"Chunk format, sync protocol, and server API remain unspecified in both."

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
| Chunk encryption | XChaCha20-Poly1305 | 24-byte nonce makes derived nonces safe |
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
name  = SHA-256(chunk)                       # hash of header || ciphertext
```

`name` is the hash of the finished chunk, not of the plaintext, so the content
store can verify that a write matches its claimed name without holding any key.
That closes name-squatting: nobody can claim a name they cannot produce bytes for.

The read capability is the pair `(name, key)`. The store never sees `key`.

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
key   = HKDF-Expand(room_root, "spark/v1/room/key"   || lane_id || be64(seq), 32)
nonce = HKDF-Expand(room_root, "spark/v1/room/nonce" || lane_id || be64(seq), 24)
```

`room_root` is 32 bytes, generated at room creation. It is **not** an MLS exporter
secret: exporter secrets rotate per epoch, and history must stay addressable across
every epoch the room has ever had. `room_root` is distributed inside MLS and
re-shared to joiners — this is the mechanism F4 flags as sitting outside MLS's
guarantees, and it is deliberately confined to this one value.

A deterministic nonce is safe **only** because `(lane_id, seq)` is used exactly
once. Two rules enforce that:

- The content store is **write-once per name** (§6.2). A second write to a live
  name is rejected, so no stored chunk is ever overwritten under a reused nonce.
- The client MUST durably record "seq N consumed" **before** encrypting at seq N.
  Encrypt-then-record loses to a crash between the two, which would let a retry
  produce a second ciphertext under one nonce.

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
| Contention | real — resolved by write-once CAS | impossible by construction |

A commit that loses the CAS re-derives against the new epoch and retries at
`seq+1`. It does **not** retry at the same seq: that would reuse a nonce (§3.2).

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
  sig covers  "spark/v1/msg" || lane || be64(seq) || be64(epoch) || body
```

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
carries membership, the owner set, and the key agreement that distributes
`room_root`.

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

The **vector clock is the sync mechanism**, not a debugging aid. Reading any one
new chunk tells a client every lane's head as of that write, so discovery does not
require probing each lane blindly.

### 5.1 Total order

Clients must agree on history without a server ordering messages. The order is:

1. `epoch` ascending — MLS already totally orders epochs.
2. Within an epoch, causal order by vector clock.
3. Concurrent writes (neither clock dominates): ascending `lane_id` bytes, then `seq`.

Deterministic, and computed identically on every client. Gate 4's "every member
sees identical history" is a test over this function.

### 5.2 Polling

Per sync tick, for each known lane, the client requests the next unseen name. A
returned chunk updates the clock, which may reveal further heads to fetch.

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

Authenticated by Ed25519 challenge-response. This is the only service that knows
an `addr` exists.

| Op | Request | Response |
|---|---|---|
| `Challenge` | — | 32 random bytes |
| `Auth` | `addr`, `sig(challenge)` | ok |
| `GetSnapshot` | — | chunk (kind 3) or empty |
| `GetDeltas` | `from: u32` | `[chunk]` |
| `PutDelta` | chunk | delta index |
| `PutSnapshot` | chunk | ok, deltas truncated |
| `GetQuota` | — | `{ media_bytes, text_bytes, limit }` |
| `WithdrawTokens` | `[blinded]` | `[blind_sig]`, quota debited |
| `CreditRefund` | `refund_voucher` | quota credited |

The keyring is stored as a snapshot plus append-only deltas, compacted at 64
deltas, so an ordinary write is small rather than a full rewrite.

### 6.2 Content service — no identity, ever

| Op | Request | Response |
|---|---|---|
| `Put` | `name`, `chunk`, `token` | `receipt` (32 opaque random bytes) |
| `Get` | `name` | `chunk` or not-found |
| `Head` | `name` | exists / not |
| `Release` | `name`, `receipt` | `refund_voucher` |
| `Delete` | `name`, `proof` | ok — room chunks only, at dissolve |

- `Put` is **write-once**: a name that exists is rejected, whatever the bytes. This
  is the CAS arbitration point for the commit lane (§4) and the nonce-reuse
  backstop for room chunks (§3.2).
- `Put` verifies `kind == 0x02 ⇒ name == SHA-256(chunk)`. Room chunk names cannot
  be verified (they are keyed), so they are accepted as claimed.
- `Put` charges the token in full even when the chunk already exists. A discount
  would let anyone probe what Spark holds (build-notes §4).
- `Get` and `Head` carry **no** authentication. The name plus key is the capability.

### 6.3 Issuer service — blind

| Op | Request | Response |
|---|---|---|
| `Resolve` | exact `name` | `pubkey` or not-found — **no prefix, no listing** |
| `BlindSign` | `blinded`, payment proof | `blind_sig` |
| `Register` | `name`, `pubkey`, voucher | ok |
| `Transfer` | `name`, `new_pubkey`, `sig(old)` | ok — mapping **overwritten**, not appended |

---

## 7. Refunds across the anonymity seam

Quota lives on the keyring service, which knows the key. Tokens are spent at the
content service, which does not. Returning a receipt has to cross that seam without
rejoining the two.

```
1. client → content:  Release(name, receipt)
                      refcount--, and at zero the bytes are freed
2. content → client:  refund_voucher = BlindSign(blinded_refund_request)
                      the content service does not know whose request it signed
3. client            unblinds
4. client → keyring:  CreditRefund(refund_voucher)
                      quota credited; the voucher carries no link to step 1
```

If step 2 returned a cleartext credit, it would bind "this upload" to "this
identity" and undo the blind token that authorised the upload in the first place.
Refunds look like bookkeeping, which is why this is the easiest thing in the design
to get wrong.

---

## 8. Keyring contents

```
Keyring {
  version: u16,
  rooms:    [ { room_id, room_root, display_name, my_lane, heads: [(lane, seq)] } ],
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
5. **Contact-request delivery.** Requests reach a key with which the sender shares
   no room, so they cannot use a room lane. They land in the keyring service, which
   sees the recipient's `addr` at write time. Needs sealed-sender treatment.
