# Spark — Design Specification

*A private, phone-number-free messenger that does one thing: chat.*

Every feature lists what it costs. Part II holds the decisions.

---

# Part I — Features

### F1. Always-on E2EE (MLS)
Every room is encrypted at all times using **MLS (RFC 9420)**. There is no unencrypted path. MLS is chosen over Signal's pairwise ratchet because Spark collapses what other apps split into DMs and group chats into a single room, so every conversation runs on group machinery.

Custom cryptography is forbidden. That is the flaw that sinks Telegram's MTProto.

### F2. Encrypted cloud history, recoverable by seed alone
History lives on the server as sealed chunks, with a small personal keyring under `hash(pubkey)` recording which chunks belong to which room. Envelope encryption does the work: per-room data keys encrypt the contents, and your identity key wraps those data keys. The server holds both ciphertext layers and can open neither. Recovery is: restore seed, unwrap keys, decrypt.

**Cost:** total self-custody. Losing the seed means losing everything permanently, because any recovery path available to you would also be available to an attacker.

### F3. Pseudonymous keypair identity
Identity is a keypair generated locally, in the style of a crypto wallet. Your seed phrase is your account.

**Key migration.** A user can generate a new key, be added to their rooms by a current member, and have the old key leave. History follows and the old key is locked out afterwards. This is the answer to a seed the user no longer trusts, and it needs no new mechanism — it is F4's room membership used deliberately.

**Cost:** attribution reaches the key rather than the person. Phone numbers were also doing anti-spam work, and without them identities are free and infinite, which is the problem D1 solves. Migration does not undo the past: the old key still decrypts anything it held before leaving.

### F4. One primitive: the room
Create a room and invite one or a few people. A 1:1 is a room of two, implemented by the same code path. No feeds, stories, channels, or broadcast surfaces. Everyone in a room sees the same history, so new members receive the full back-history. If someone shouldn't see prior messages, make a new room.

**Owners are a flat set.** The creator starts as one and may appoint others. Owners add and remove members, appoint and dismiss owners, and moderate per F6. There is no hierarchy and no second role, so a 1:1 is a room where both people are owners.

An owner may leave only once another exists; the last owner can dissolve the room instead, removing it from every keyring. Dissolving deletes the room's own chunks, since nothing else can reference them, but shared media stays and quota is not refunded automatically — each uploader reclaims their space from their upload list. The client must say so, since users will assume dissolving cleans up.

Simultaneous dismissals resolve by MLS commit order, which means the server picks; that is accepted, since the server orders all traffic anyway. If every owner disappears the room cannot be managed, active members leave, and no takeover mechanism is provided.

**Read-only spectators are deferred.** A view-only key would let someone read history without appearing in the member list, and once handed out it cannot be revoked or traced. Revocation and visibility need answering first.

**Cost:** MLS forward secrecy means a joiner cannot decrypt pre-join messages alone, so an existing member's client re-shares the historical keys. That sits outside MLS's guarantees and weakens post-compromise security, since any owner hands over the entire archive by adding a member.

Scope discipline is the actual anti-bloat rule: chat only, no third-party integrations, no voice or video. Structure alone guarantees nothing, since WeChat had rooms and became an economy anyway.

### F5. Reachability by approval
A room is joined via a link or QR code exchanged out-of-band, or by name. **Names resolve but are not browsable:** an exact name produces a contact request, with no listing, autocomplete, or partial matching, so the namespace cannot be enumerated. Requests land in a pending tray and create no room until accepted.

Approval carries the spam defense. A regenerated throwaway key can send requests but reaches nobody who declines, and blocking becomes "don't let this key back in."

**Cost:** this moves Spark from unreachable to reachable-but-ignorable, which is where Telegram sits — a real concession made for convenience. Rare names stay effectively private while common ones will be guessed, so the client should say so at purchase. A naive lookup also lets the server see who searches for whom, which is the contact graph forming server-side, so name resolution must be blind or the leak must be documented and accepted. Out-of-band invites still travel through a channel Spark cannot protect.

### F6. Delete-for-everyone, sender only
Two powers, deliberately split.

**Moderation removes from the room.** Owners can remove any message or attachment, so a room can be cleaned up without the uploader's cooperation.

**Releasing the bytes is storage, and only the sender can do it.** Releasing returns the upload receipt and refunds quota, so nobody spends or refunds another key's storage. Moderated content therefore keeps costing the uploader until they release it from their upload list.

**Cost:** deletion is cooperative, since a modified client can ignore it, and Spark assumes honest clients. Anyone with the seed, including a court that seizes it, can restore and read the history; MLS signs each message, so what survives is attributable to the sending key. Completeness cannot be shown — deletion leaves no tombstone, so a pruned history is indistinguishable from a complete one. Moderation removes content from view but not from the store.

### F7. Lean storage
Pasted URLs are inert text: no parsing, previews, OAuth, or integrations (D7). Attachments are capped at **128 MB media and 128 MB text** per account, plus a **~64 KB per-message limit** that prevents smuggling files as base64 text.

**Everything shared is stored once.** One content store holds sealed chunks and contains no accounts. Room history goes there alongside media, so a ten-person room costs one copy rather than ten, and each account keeps only a keyring: room keys and a chunk list.

**Media deduplicates server-wide** via convergent encryption, where the file key derives from the file's contents, so identical files land on the same name and a photo twenty people sent costs one copy. Room chunks are named from the room key instead, because content-derived names would let an outsider compute the name of a guessed sentence and test whether it exists — files are hard to guess, sentences are not. Room history is append-only, so simultaneous senders never collide.

**Writes are authorised by blind tokens, never identity.** Authenticated uploads would show the server two keys writing into one room, handing it the social graph. Instead an account exchanges quota for blindly signed tokens and spends one per upload. Reads carry no identity at all, since the chunk name plus key is the capability. This reuses F9's machinery rather than adding a subsystem.

**Quota measures what a key currently holds, and only what it uploaded.** Viewing and receiving are free, so nobody can drain your allowance by posting a large video. Uploads are charged in full even when the chunk already exists, since a discount would let anyone probe what Spark holds.

**Receipts free shared chunks without identities.** On upload the store issues an opaque random receipt, kept in the uploader's keyring; returning it releases the chunk and refunds quota. The store counts receipts per chunk and frees the bytes at zero, learning only how many unknown parties hold something. Media needs that count because it is shared; a room chunk cannot be referenced by any other room, so at dissolve the owner's client derives the names from the room key and has the server delete them outright. For room chunks the receipt is a quota instrument only.

**Uploads are listed, never judged.** The client shows everything a key uploaded, labelled with its room or marked unknown when that room is no longer visible. It deliberately does not decide what is unused: "no room references this" is indistinguishable from "a room references this but I left it," and the second is ordinary. A client that guessed would tell people to release content others are still reading.

**Scale.** A stored message costs roughly 300 bytes with MLS framing, signature, and tag, so 128 MB is on the order of 400,000 messages sent — and since receiving is free, ordinary users never approach it. Chinese text runs about three times more per character. On the media side, 128 MB is 30–60 photos or a minute or two of 1080p video, which pushes anything longer toward links. The client nudges users that way as copy rather than code, keeping clear of the integration ban.

When media fills, attachments block while chat continues. Nothing is auto-evicted and nothing expires. A receipt whose holder lost their seed is never returned, so those bytes are held indefinitely — the storage working as sold rather than a leak, since the space was bought outright and total stored bytes cannot exceed total quota sold.

**Cost:** bulk deletion at dissolve tells the server that a set of chunks belonged to one room, revealing that a room of some size ended and nothing about who was in it. Blind tokens need a spent-serial list, and enough accounts drawing tokens concurrently that a withdrawal is not itself identifying. Receipts must survive recovery inside the keyring, since a lost one strands a chunk. Deduplication tells the operator that a chunk has several holders, with no identities to attach. Append-only history means a deleted message leaves a replaced chunk. A link from a real-name account can bridge your key to your identity; Spark warns and leaves the choice to the user.

### F8. Tor
Traffic can be routed over Tor, hiding your IP from the server and from network observers. Three modes: always on, always off, and text over Tor with media direct, which is the default.

**Cost:** the mode you pick is itself a signal, and three modes make each group smaller than two would (W5). In mixed mode, media fetches still expose your IP alongside a content-derived chunk name. See D2.

### F9. Paid tiers (any crypto + blind vouchers)
Users buy names and quota with any cryptocurrency. Blind-signed vouchers do the privacy work: pay, receive a blinded token, redeem it against any key, leaving no payment-to-key record. Since unlinkability comes from the voucher rather than the coin, the choice of rail is the user's.

Coins differ in what they leak to third parties, not to Spark. A transparent chain lets an observer tie a KYC'd withdrawal to a payment, revealing that someone bought a voucher; the voucher still hides which account redeemed it. Monero avoids even that. The app should say which is which rather than choose.

Payments settle through self-hosted nodes rather than a processor, which would see every transaction and reintroduce the record vouchers exist to avoid.

**Storage is bought once and kept forever.** No expiry, no renewal. Purchased space is the user's to use as they see fit; Spark does not police what it holds and could not inspect it anyway.

**Names are monthly with a 10-day grace period**, then reclaimed and returned to sale. Renewal is a manual payment each cycle, so there is no stored payment method and no customer record — the server holds a paid-until date against the name, nothing about the person.

**Quota belongs to the key, never to the name.** Buying a name grants permanent storage to the buying key; a lapsed name costs that key its name and nothing else. One rule instead of two kinds of quota, and D1 holds either way, since each grant costs a separate payment.

**Cost:** monthly renewal is high-friction on a crypto rail, and immediate resale after grace means a user inattentive for 40 days loses their name. That is the price of clearing dead accounts, and the client should warn loudly as the date approaches.

A ceiling exists, set by legal exposure rather than product purity: large volumes of encrypted files attract takedown demands and compliance regimes a messenger does not. See D10.

### F10. Open source
Client and server are both open source, so users can read, audit, fork, and self-host.

### F11. Self-hosted servers — deferred to post-v2
Power users may host rooms that don't consume Spark quota. E2EE makes this safer than Matrix-style federation, since a hostile operator still cannot read content.

**Cost:** self-hosting improves sovereignty while degrading anonymity. The operator sees timing, IPs, and activity for every member, and a twelve-person server has a poor anonymity set. Self-hosted rooms also fall outside seed-only recovery, since Spark stores nothing about which external servers a user connects to — the seed-backup screen must say so. Community servers may ship in a client-side bundle; a live directory endpoint would see which servers each user cares about.

**Why deferred:** it creates two classes of room with different storage, quota, delete, and recovery semantics — the split-brain complexity the single-primitive rule exists to prevent.

### F12. Hysteria mode (cover traffic)
An optional mode in which the client transmits on a fixed schedule whether or not the user is doing anything. Real messages occupy slots in place of dummies, so traffic looks the same whether the user is chatting constantly or asleep. Every transmission is padded to a uniform size and sent to the same endpoint, since an observer who can spot a dummy by length or destination gets the timing back for free.

This is the only mechanism that meaningfully attacks traffic-analysis correlation (W4), and it pairs with Tor: Tor hides where you are, Hysteria hides when you speak. The connection is already open, so push becomes unnecessary.

**Cost:** constant transmission is expensive in battery, mobile data, and server bandwidth, and it runs continuously rather than only while the app is open. Cover traffic conceals network timing but not keyring growth, which still correlates across accounts — smaller than under per-account storage, but not zero. See D12.

---

### What Spark actually guarantees

Spark provides pseudonymity against the server's stored data: content is unreadable and there is no social graph at rest. It does not provide anonymity against a network-level adversary or against Apple and Google. What remains:

- **W1 — IP at delivery (severe).** In the default mode media fetches still carry a real IP, and with Tor off the server sees it alongside `hash(pubkey)`. IP leads to ISP, subscriber, and name. → D2
- **W2 — Push notifications (severe).** APNs and FCM tokens are bound to real Apple and Google accounts, bridging key to person and leaking timing. Users may disable push or avoid it via Hysteria mode, though accounts with no token form a visible group. → D3
- **W3 — Long-term linkability (structural).** The price of cloud recovery. Key and keyring are permanent, so one careless session without Tor retroactively deanonymizes the entire history. Fixing this means abandoning recovery.
- **W4 — Traffic analysis.** Keyring updates still correlate in time across accounts in one room. Hysteria mode addresses the network-timing half; keyring-growth correlation remains open.
- **W5 — The chosen Tor mode is itself a signal**, and three modes split users into three groups rather than two. → D2
- **W6 — EXIF.** Clients must strip all metadata before encryption. Settled.
- **W7 — Links, names, and out-of-band invites.** Each can bind a key to a real name outside Spark's control, and each is the user's responsibility.

### The bet

Every existing app sits on one axis: those that give you recovery (Telegram, Matrix) leak metadata, and those that hide metadata (SimpleX, Session, Briar) cannot give you recovery. Spark picks a new point — MLS, an account-free content store, and seed-only self-custody — at a cost the others declined: permanent loss if you lose your seed.

---

# Part II — Decisions

## Settled

### D1. Resource exhaustion — the paid namespace
Free unlimited key generation would make Spark free unlimited cloud storage for anyone with a script. Every standard defense is ruled out by Spark's own principles: IP limiting dies to Tor, fingerprinting is deanonymization, attestation routes through Apple and Google, content inspection is impossible under E2EE, and CAPTCHA loses on arithmetic, since solving farms charge about $1 per 1,000 solves.

**The trilemma: at most two of {anonymous, free, server-side storage}.** Signal and SimpleX give up storage. Spark gives up free.

Spark owns every username from the outset and sells them, so there is nothing to squat. **Paying unlocks quota by either route:** a monthly name, or a one-time permanent storage purchase. An unpaid key holds the earned-quota minimum of ~1 MB until it shares a room with an established account. Buying storage without a name is the privacy-maximal path, since a key that never enters the namespace has no public identifier. Mass account creation then costs money per account, which is the floor no other defense provides, and payment runs through F9's vouchers so the fee is unlinkable to the key.

**Two tiers, because the fee has two jobs that pull apart.** Basic names are near-free and unmemorable, since blind tokens hide people in a crowd and a small paying userbase makes everyone more identifiable. Premium names carry a real price and fund the service. Both unlock full quota, so the paywall gates desirability rather than entry. Rate limits and bandwidth metering apply regardless.

**Cost:** Spark becomes an issuer, holding a list of sold names — a fixed public identifier per account, and the structural privacy price of this decision. A name is chosen rather than random, so a user reusing a handle from elsewhere links the two themselves; the client should say so at purchase.

### D2. Tor — three modes, chosen by the user
**Always on**, **always off**, and **text over Tor with media direct**, the last being the default: routing delivery and control traffic costs little, while bulk attachments over Tor are slow enough that many users would otherwise disable it entirely.

**Cost:** three modes fragment the anonymity set into three groups, so each is smaller and membership more distinguishing (W5). Mixed mode also lets an observer tie an IP to specific media chunks, and since those names are content-derived, that links a network address to identifiable content. Switching from off to on undoes nothing, because the server already recorded the IP against the keyring label.

### D3. Push notifications
Push is on by default, using content-free and identity-free wake-up signals, with an in-app switch to turn it off and a warning that states the leak plainly.

Off must mean never registering. Disabling notifications in the OS only stops them being displayed while the token persists, and a control that appears to close the leak while leaving it open is worse than none. Turning push off also costs real functionality — messages arrive on app open, or through background polling that iOS throttles by design. Hysteria mode avoids the tradeoff entirely by delivering over the connection it already holds.

Push stays its own switch rather than folding into a combined profile. The three protections cover different things, and bundling them invites the assumption that one setting covers everything.

### D4. Reproducible builds — adopted
Open source establishes that the source is clean; reproducible builds establish that the binary was built from it. Without them, anyone who compromises the pipeline can ship a client that leaks plaintext or logs keys, and nothing server-side would look wrong — the whole design assumes an honest client.

Build the pipeline this way from the first commit: pin compiler and dependency versions, remove every source of nondeterminism. Retrofitting after dozens of dependencies exist is far harder. This matters more once Spark is embedded in other applications, since those users trust a build made by someone else entirely.

### D5. Text ceiling — warn early, block at the cap
The client warns as the cap approaches and blocks sending once reached. Blocking mid-conversation is the worst failure a messenger has, so the warning must arrive early. Reaching the cap means roughly 400,000 messages sent, so it is rare.

**The cleanup prompt must offer buying storage first.** Freeing text space means deleting your own messages, and that takes effect for everyone, destroying history for the rest of the room. A user should not discover this by following a prompt that said "clean up."

### D7. Link previews — none
Pasted URLs stay inert text. Spark's own attachments render inline; this concerns third-party links only.

Sender-side generation was the alternative and is still rejected, because it puts an HTML fetcher and parser in the client — attack surface, and the first step toward the integrations F4 rules out. Anyone who wants to see a link can open it.

### D8. Deniability — accept MLS as it is
MLS signs every application message, inherent to the protocol rather than a cipher-suite option. Per RFC 9750, deniability depends on whether signature keys were exchanged over a deniable channel. Building anything else means deviating from the standard, so Spark accepts the default.

**Pseudonymity supplies most of the deniability anyway.** A signature proves the holder of key X wrote a message, not who holds key X. A transcript is strong evidence against a key and weak evidence against a human.

**Buying a name weakens this**, since the name-to-key mapping is public and durable, and anything linking the name to a person carries through to every message. Users wanting maximum deniability should buy storage instead, which F9 permits. The client should say so at purchase.

### D9. Username market
Spark pre-owns the namespace and sells names, which removes squatting and funds the service. Names resolve but are not browsable, per F5. Premium pricing scales with scarcity: single characters highest, then dictionary words and two-character names, then longer — a price table rather than a design question.

Resale is not forbidden, because a ban does not work: Instagram and TikTok both prohibit it and OGUsers trades anyway. Spark neither runs a market nor takes a fee, which keeps it clear of money transmission.

**Names transfer holder to holder.** The holding key signs a transfer naming a new key; the server verifies and overwrites the mapping. This exists because a seed cannot be handed over — only copied. A seller who sells their seed keeps permanent read access to everything the buyer does afterwards. Transfer moves the name to a key the seller has never seen, and the same operation moves a name onto a new key during migration.

Names lapse and return to sale after grace, so the namespace does not deplete. A recycled name means its new holder may receive requests meant for someone else, which F5's approval step reduces to a request they can decline.

Quota stays with the key that bought it. The server must overwrite the mapping rather than append, since a retained transfer history would link an old key to a new one.

Spark does not adjudicate between users. It does need a documented procedure for legal demands, since selling the namespace makes Spark the party a rights holder writes to. That belongs in D10.

### D12. Hysteria mode parameters — set for adoption
Cover traffic hides you inside a crowd transmitting on the same schedule, so its strength scales with how many people leave it on. Parameters are chosen to keep the mode tolerable to run continuously, not to maximise protection for a handful of users — a setting only a few hundred people enable makes those people a recognisable group.

- **60-second interval.** Shorter defends better but keeps the radio awake and visibly costs battery, so nobody leaves it on. A real message takes the next slot: 30 seconds average delay, 60 at worst.
- **4 KB uniform padding.** Covers most text messages; larger splits across slots. Roughly 5.6 MB a day.
- **Media stays out of the stream**, since large attachments make delay unusable. Its timing is observable, matching the D2 mixed-mode tradeoff.
- **Opt-in and independent of Tor.** The two defend different things, and bundling invites the assumption that one is enough.
- **Continues while backgrounded.** A stream that stops when the app closes reveals precisely what it exists to hide.

**Still open, and the hard part:** backgrounding is very likely impossible on iOS, which throttles persistent background execution by design. Verify during the mobile spike. If it cannot be done, the mode is desktop and Android only, stated in the UI rather than shipped as a setting that silently does less than it claims.

## Open

### D10. Legal posture — Spark is an operator; specifics await incorporation
Spark sells names, bills monthly, and maintains the mapping table, so it is a service with customers and revenue and the "we only publish code" position is not available to it. Tor can hold that position because it takes no money and holds nothing. Telegram tested the alternative and lost: its founder was arrested in France in 2024 despite the company being based in Dubai, because jurisdiction followed users and the corporate entity rather than server location. Even after F11 ships, Spark still holds the namespace, the billing relationship, and the mapping table.

So plan as a company that cannot read its users' content, in the manner of Proton or Threema:

- **Entity jurisdiction matters more than server location.** Servers affect seizure risk and uptime; the registered entity and founders' residence determine who can subpoena or enjoin.
- **Avoid mandatory-decryption regimes.** Spark does not need lax data-protection law, since it holds only ciphertext. It needs jurisdictions without compelled-decryption or mandated-backdoor powers — a different and narrower question.
- **Write the responses before they are needed:** law enforcement, app-store review, and trademark demands over sold names.
- **Set the storage ceiling here.** It is a legal-exposure figure.

Jurisdiction, ceiling figure, and entity form are deferred until incorporation and decided with a lawyer against the legal landscape as it stands then, since compelled-decryption powers, platform-liability rules, and crypto-payment regulation all move quickly.

---

**Build note.** This is an architectural spec. Stack choices, traps, and testable gates are in `Spark-build-notes.md`. Chunk format, sync protocol, and server API remain unspecified in both. An E2EE messenger is security-critical, so build in stages, review independently, and use audited libraries throughout.
