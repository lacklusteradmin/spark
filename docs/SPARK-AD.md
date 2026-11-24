# Spark

## Your conversations. Nobody's business.

Messaging apps forgot what they were for. One became a bank. One became a video feed. One became an entire economy. Somewhere in there, they stopped being a place to talk.

**Spark is a messaging app. That's all it is. That's the point.**

---

## No phone number. No email. No name.

Every other messenger starts by asking who you are.

Spark never asks.

Your identity is a **cryptographic key** — like a crypto wallet. You generate it in seconds, and it belongs to you alone. There's no phone number to leak, no email to trace, no real name sitting in a database waiting to be breached or subpoenaed.

**We don't know who you are. We built it that way on purpose.**

---

## Encrypted always. Not "if you remember to turn it on."

Some apps bury end-to-end encryption behind a menu, offer it only in one-on-one chats, or skip it entirely for groups — and let you assume you're covered.

Spark encrypts **everything, everywhere, always.**

Every room. Every group. Every message. Built on **MLS (RFC 9420)**, the open, peer-reviewed, IETF-standardized encryption protocol — not a home-grown scheme that's never survived real scrutiny.

There is no "off." There is no unencrypted mode. There is no second-class chat.

---

## Your history follows you. Even we can't read it.

Lose your phone, and most encrypted messengers lose your life.

Spark keeps your history safely in the cloud — but stored as **encrypted data that our servers cannot open.** Not "won't." **Can't.** Your key is the only key. We're just holding a locked box we have no way into.

Get a new phone, enter your **recovery phrase**, and everything comes back.

*Real self-custody: your seed phrase is your account. Guard it — because nobody, including us, can restore it for you.*

---

## We can't see who you talk to, either.

Encryption hides *what* you say. Most apps still record **who you said it to, and when** — and that map of your relationships is often more revealing than the words.

Spark doesn't keep that map.

Your conversations are stored as **a single sealed lump of encrypted data.** Who you talk to, how often, which rooms you're in — all of it lives *inside* the encryption, invisible to us. We can't hand over a social graph we never had.

---

## One idea: the room.

No feeds. No stories. No channels. No shopping tab. No crypto wallet. No algorithm.

Just **rooms**.

Create a room, invite one person or a few. A private chat is simply a room of two. There's no wall between "DM" and "group chat," because there was never any reason for one.

**One primitive. Learn it in five seconds. It never grows into something else.**

---

## Nobody reaches you without your say-so.

Spam and harassment mostly happen because strangers can reach you by default.

**In Spark, they can't.** Someone can send a request — by invite link, or by knowing your exact name — and it waits for your approval. Nothing reaches you until you say yes. There's no directory to browse, no autocomplete, and no way to work through a list of names looking for someone to bother.

Your inbox isn't a public square. It's your home.

---

## Lean by design. Not a 100 GB junk drawer.

Other messengers quietly balloon past 100 GB, hoarding every video anyone ever sent you.

Spark stays small. Text is text. Media is capped and cleanable. Identical files are stored once across the whole server, so a video ten people share takes one copy. Share big files as ordinary links — Spark never becomes a warehouse for other people's cat videos.

Want more room? Buy it with any cryptocurrency — no card, no name, no account record. It's your space to use however you like.

**A messenger should not need more storage than your entire music library.**

---

## Tor, one tap away.

Route Spark over **Tor** and hide your IP address from our servers and from anyone watching the network. Three modes: always on, always off, or text over Tor with media direct.

*Privacy at the network layer, not just the message layer.*

---

## Need chat inside your own app? Take the whole thing.

Building chat is a trap. Encryption, key rotation, group membership, history sync, recovery — months of work, and every shortcut becomes a breach later.

Spark is open source, and the hard part is a **Rust core with bindings for any platform**. Drop it into a game, a marketplace, a support desk, a hospital app. You get MLS encryption, sealed history, and seed-based recovery, without writing a line of cryptography.

- **Fork it, ship it.** No licence negotiation, no per-seat pricing, no vendor.
- **Audit it.** Your security team reads the same code we run.
- **Run your own server.** Your users' data stays on your infrastructure.

**Chat is a solved problem now. Stop rebuilding it.**

---

## What Spark will never do

- ❌ Ask for your phone number
- ❌ Read your messages
- ❌ Build a map of your relationships
- ❌ Show you an ad
- ❌ Add a feed, a store, a wallet, or an algorithm
- ❌ Pretend it's something other than a chat app

---

## What Spark asks of you

We believe in telling you the truth up front.

- **Your seed phrase is everything.** Lose it, and your account and history are gone — permanently. There is no reset, no support line, no backdoor. That's not a gap; it's the guarantee. A recovery path for you is a recovery path for everyone else, too.
- **Spark protects your conversations, not your carelessness.** Post a link tied to your real name and you've told people who you are. The encryption can't undo that.
- **Turn on Tor if your IP matters to you.** Without it, our servers see the address you connect from — like every other app you use.
- **A name is a public label.** Buying one is optional. It makes you findable and it stays linked to your key, so if maximum deniability is what you want, buy storage instead and stay out of the namespace.

---

## Spark

**Encrypted always. Pseudonymous by design. Recoverable by you alone.**

*A messaging app that only ever wants to be a messaging app.*
