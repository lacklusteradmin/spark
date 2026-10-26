# Spark — Implementation Notes

Read `Spark-spec.md` first. This file holds only what the spec does not: concrete stack choices, traps, and testable checks. Where the two conflict, the spec wins.

---

## 1. Never bend

- No custom cryptography. Audited libraries only.
- No unspecified crypto parameters. Ask instead of inventing.
- The server never reads content or reconstructs the social graph.
- No account recovery without the seed. No reset, no support path, no escrow.
- No unencrypted mode, including debug builds.
- Never silently downgrade a privacy setting. Disable the feature or warn loudly.
- Strip EXIF client-side before encryption.
- Never store an upload-to-key link. Writes are authorised by blind token.
- Never store a payment-to-key link. Renewal is manual each cycle.
- No features outside chat.

**Escalate, don't improvise**, when an invariant blocks a feature, a crypto parameter is unspecified, or a shortcut would need the server to learn something below.

## 2. What the servers may know

**Keyring store:** that `hash(pubkey)` exists, its size and mtime, delivery routing at send time, per-key rate and quota counters.

**Content store:** a chunk's name, its bytes, outstanding receipt count, spent token serials. Writes carry a blind token; reads carry nothing.

Never: message content, sender-to-recipient links at rest, room membership, contact lists, who uploaded or fetched a chunk, real-world identifiers.

Write an automated check that fails if any other field is persisted. Run it in CI from the first commit.

## 3. Stack

- **MLS:** OpenMLS (Rust). Do not implement MLS.
- **Cipher suite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- **Core:** Rust, shared via UniFFI.
- **Chunk encryption:** XChaCha20-Poly1305 or AES-256-GCM. Random nonces, never reused.
- **Media naming:** convergent encryption. **Room chunk naming:** derived from the room key.
- **Seed:** BIP-39, 24 words, fixed documented derivation path.
- **KDF:** HKDF-SHA256; Argon2id if a passphrase is ever added.
- **Server:** Rust (axum) or Go. Stateless.
- **Storage:** two S3-compatible stores — keyrings by `hash(pubkey)`, and an account-free content store.
- **Transport:** WebSocket over TLS; Tor via SOCKS5, selectable per traffic class.
- **Blind signatures:** RFC 9474 blind RSA or an audited privacy-pass library. One primitive serves storage tokens and payment vouchers.
- **Reproducible builds from commit 1.** Pin compiler and dependency versions; remove timestamps, file ordering, embedded paths.

## 4. Traps

- **Do not index conversations server-side for sync efficiency.** This single shortcut turns Spark into Matrix.
- **Do not implement a separate 1:1 code path.** A two-person room is a room with two owners.
- **Do not infer that a chunk is unused.** "No room references this" is indistinguishable from "I left that room."
- **Do not bundle quota with the name.** Quota belongs to the key that paid, permanently.
- **Do not log name transfers.** Overwrite the mapping; a transfer history links an old key to a new one.
- **Do not give a discount when a chunk already exists.** It lets anyone probe what Spark holds.
- **Do not add an HTML fetcher or parser to the client**, in any form.
- **Do not let disabling push merely suppress display.** It must prevent APNs/FCM registration.
- **Do not put media in the Hysteria stream.** Delay becomes unusable.
- **Room chunks are freed by deletion at dissolve; media chunks by receipt count.** They are not the same mechanism.

## 5. Build order

Core and CLI together from commit 1. The CLI began as a scripted verification harness; it now also provides the first usable chat client, before mobile development. Offline before online.

1. **Protocol doc, skeleton, invariant harness.** Chunk format, sync and conflict resolution, wire format, derivation path.
2. **Identity, offline.** Seed to keypair, deterministic derivation, local key storage.
3. **Envelope encryption, offline.** Per-room data keys wrapped by the identity key; append-only sealed chunks; keyring.
4. **Rooms, owners, MLS.** Two clients in one process, no network.
5. **Server.** Keyring store, content store, sealed-sender relay. Nothing else.
6. **Sync and recovery — go/no-go.**
7. **Reachability.** Invite links and QR; exact-match name resolution; pending tray; key migration.
8. **Storage.** Dedup, blind tokens, receipts, upload list, quotas, EXIF stripping.
9. **Tor.** Per-traffic-class SOCKS5.
10. **Paid tiers and namespace.** Vouchers, name purchase, monthly renewal, transfer.
11. **Hysteria mode.** 60s, 4 KB uniform padding.
12. **Mobile spike and hardening.** Do this earlier if possible — privacy-preserving push and background cover traffic are the assumptions most likely to fail.

## 6. Gates

Do not advance past a failing gate.

| Stage | Must be true |
|---|---|
| 1 | Invariant tests fail against a deliberately broken stub; two independent builds of one commit are byte-identical. |
| 2 | The same seed yields identical keys on a clean machine; no code path recovers an identity without it. |
| 3 | Chunks decrypt from the seed alone via the keyring, and are inert without it. |
| 4 | Every member sees identical history; a removed member cannot read later messages; the last owner cannot leave without dissolving; a 1:1 uses the same owner logic. |
| 5 | Permitted-knowledge tests pass against the real server. |
| 6 | **Wipe the device, restore from seed, history matches. The server's entire database yields no plaintext and no graph edge.** |
| 7 | The API cannot enumerate names or reach a stranger without acceptance; a rejected request leaves no trace for the sender; after migration the old key decrypts nothing new. |
| 8 | Two accounts uploading one file produce one chunk and two full charges; a viewer is charged nothing; a ten-member room stores one history; receipts restore from seed; dissolve deletes room chunks and spares shared media; the content store logs nothing about who; GPS EXIF cannot survive a send. |
| 9 | Always-on mode shows zero direct connections; mixed mode shows them for media fetches only. |
| 10 | Redemption cannot be linked to payment, or a name to the payment that bought it; a transfer leaves no record joining old key to new; an expired name does not reduce quota. |
| 11 | Idle and 100-message captures are indistinguishable in count, size, and timing; the stream survives backgrounding, or the platform is documented as unable to support it. |
| 12 | Every W1–W7 threat has an implemented mitigation or a documented accepted risk. |
