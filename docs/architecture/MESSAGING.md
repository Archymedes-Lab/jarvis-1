# JARVIS messaging: architecture

Status: proposal, 2026-09-16. Nothing here is built yet.

JARVIS reaches you today by email only. Email is fine for digests and poor for
anything urgent or conversational. This adds a messaging channel that JARVIS
owns end to end: alerts in its voice on your phone, and a narrow set of replies.

## Goals and non-goals

Goals

- Push an alert to phone and desktop within seconds, including when the laptop
  is behind NAT and the phone is on mobile data.
- **The relay cannot read anything.** It stores and forwards ciphertext only.
- Replies are limited to *safe* intents: ask a question, mark a finding as
  expected, snooze notifications.
- Lean: one small cloud service, one installable web app, one Python module.
  No app store and no servers to patch.
- Email stays. Messaging complements it and falls back to it.

Non-goals

- Approving containment, undoing actions, running repairs or changing config
  from a message. JARVIS refuses these at the receiving end, whatever the client
  sends (see [Replies](#replies)).
- Group chat, multiple humans, or talking to other JARVIS installs.

## Shape

```
  laptop (WSL)                       cloud                          your devices
┌──────────────────┐   outbound    ┌───────────────────────┐    ┌──────────────────┐
│ jarvis serve     │   WebSocket   │ relay                 │    │ PWA (phone,      │
│  notifications ──┼──► outbox ────┼─► Worker             │    │ desktop)         │
│  voice.py        │               │   └─ Durable Object   │◄───┤  service worker  │
│  messaging/      │◄──────────────┼──── "Mailbox" (one per │────┼─► Web Push       │
│   crypto, replies│  ciphertext   │     install, SQLite)  │    │  libsodium       │
│ SQLite (jarvis.db)│   only       └───────────────────────┘    └──────────────────┘
└──────────────────┘
```

- **JARVIS never listens.** It opens an outbound WebSocket to the relay, so
  there are no new inbound ports on a machine whose firewall findings JARVIS
  already reports.
- **The phone never talks to the laptop directly.** Both connect to the relay,
  which queues ciphertext for whoever is offline.

## Components

### 1. JARVIS side: `jarvis/response/messaging/`

| module | job |
|---|---|
| `outbox.py` | Durable queue in `jarvis.db`. Notification decisions write here in the same transaction that updates alert state (transactional outbox), so a crash can't lose or duplicate a message. |
| `channels.py` | Routes a message kind to channels: `email`, `relay`, or both (see [Routing](#routing)). |
| `crypto.py` | Keys, sealing, signature checks. PyNaCl (libsodium). |
| `relay.py` | The outbound WebSocket client: drain the outbox, receive replies, reconnect with backoff. Runs as one scheduler job. |
| `replies.py` | The only door from a message to JARVIS state. Allowlisted intents, verified, rate-limited, audited. |
| `pairing.py` | `jarvis pair` and `jarvis devices [list\|revoke]`. |

Push text reuses `reporting/voice.py`: the checked in-character opener becomes
the notification body, and the deterministic headline becomes the title.

One new dependency: PyNaCl. The standard library has no X25519 or AEAD, and
hand-rolled crypto isn't an option.

### 2. Relay: Cloudflare Worker + Durable Objects (recommended)

- **Worker:** routing, device authentication, Web Push (VAPID), static PWA
  assets.
- **Durable Object `Mailbox`:** one per JARVIS install, each with its own
  embedded SQLite database. It holds envelopes, device push subscriptions and
  delivery receipts. WebSocket hibernation means an idle connection costs
  nothing.
- Deploy: `wrangler deploy`. You already have Wrangler configured on this
  machine.

**Why this database.** The data is a small per-install mailbox with no joins
across installs. A Durable Object's embedded SQLite matches that exactly:
strongly consistent, co-located with the WebSocket that uses it, no pool or
cluster to run, and sharded per install by design.

- Postgres would add a server to operate for a few rows a day.
- Redis isn't durable enough to be the only copy of an undelivered alert.
- Hosted realtime databases (Convex, Firebase) work, but you'd run a second
  platform to store ciphertext that SQLite already holds.

**Self-host option, same protocol:** a single Go binary (`relay/`) with SQLite
in WAL mode, continuously replicated with Litestream to R2 or S3, behind Caddy
for TLS. One `docker compose up`. Build it only if Cloudflare becomes
unacceptable.

### 3. Client: installable PWA

- Inbox, finding view, "ask JARVIS" box, and the three reply buttons.
- A service worker receives Web Push, decrypts on the device and shows the
  notification. The push service (Apple, Google, Mozilla) sees only an opaque
  blob.
- Keys stay in IndexedDB as non-extractable where the platform allows. The
  private key never leaves the device.
- iOS note: Web Push works only for a PWA added to the home screen (iOS 16.4+).

## Protocol

### Pairing

1. `jarvis pair` creates a one-time pairing secret (10 minutes, single use) and
   shows a QR code containing: relay URL, mailbox ID, JARVIS's public keys and
   the secret.
2. The PWA scans it and generates its own X25519 (encryption) and Ed25519
   (signing) key pairs. It sends its public keys to JARVIS, sealed to JARVIS's
   key and authenticated with the pairing secret.
3. JARVIS shows a 6-digit safety code derived from both public keys, and the
   phone shows the same code. You confirm on the laptop. **Trust comes from
   that local confirmation, never from the relay**, so a malicious relay can't
   insert a device.
4. JARVIS stores the device in `devices`. The relay only learns an opaque
   device ID and a push subscription.

### Envelopes

```json
{ "v": 1, "id": "01J…ULID", "mailbox": "…", "to": "device-id | jarvis",
  "sent": 1789500000, "expires": 1790104800,
  "nonce": "…", "box": "base64(crypto_box(payload))" }
```

- **Payload:** JSON `{kind, title, body, finding_id?, severity?, links?}`, sealed
  per recipient device with XChaCha20-Poly1305 (`crypto_box`).
- **Replies:** sealed to JARVIS and signed with the device's Ed25519 key over
  `id | sent | counter | payload`.
- **Relay-visible metadata**, kept minimal: mailbox, recipient device ID, size,
  timestamps. No title, no severity.
- **Expiry:** 7 days by default. The relay deletes on acknowledgement or expiry.

### Delivery

- **At-least-once, idempotent.** Envelope IDs are ULIDs, and receivers
  deduplicate on ID.
- **Receipts:** the device confirms `delivered`, then `read`. JARVIS records
  both per message and device.
- **Offline devices:** the relay sends a Web Push wake-up, and the service
  worker pulls and decrypts.

## Routing

| message | relay | email |
|---|---|---|
| urgent change (new critical, monitoring outage) | immediately | immediately if no device has read it within 10 minutes |
| change digest | immediately | on its existing hourly cadence |
| daily health | summary line | full report, as today |
| JARVIS itself unreachable | — | the independent health monitor path, unchanged |

The existing queue, escalation tiers and caps in `notifications.py` stay the
single source of truth for *whether* something is sent. Messaging only adds
*where* it goes.

## Replies

`replies.py` accepts exactly these intents. Anything else is rejected and logged.

| intent | effect | limits |
|---|---|---|
| `ask` | `assistant.answer()`, which is read-only; the answer comes back sealed | 20 per hour per device |
| `ack` | `acknowledge.acknowledge(finding, reason)` | reason required; at most 30 days (the CLI allows 90); not for critical findings or outages; a confirmation step in the client |
| `snooze` | pauses relay notifications for 1–24 hours | never pauses email or urgent outage alerts |

Every reply must pass, in order:

1. Sender is a paired, unrevoked device.
2. Signature is valid.
3. Timestamp is within 5 minutes.
4. The counter is strictly greater than the last one seen for that device
   (replay protection).
5. The intent is allowlisted.
6. Per-intent limits hold.

Each accepted reply is written to an append-only `reply_audit` table and
confirmed back to every paired device. A phone that didn't send the reply
therefore sees that one was made.

> **Updated 2026-11-04:** a phone paired by QR may approve one *reversible* defense proposal and undo what a phone approved,
> with Face ID / fingerprint bound to the exact action (see ARGUS-NOTIFY.md, "Approvals from the phone"). Everything below
> that says `approve` is excluded now applies to irreversible actions, repair and config changes only.

`approve`, `undo`, `repair` and config changes are **not in the allowlist**. A
compromised phone or chat account can't switch off a defence or trigger an
action. Those stay on the CLI and the local dashboard.

## Data model

JARVIS (`jarvis.db`, alongside the existing schema):

```sql
CREATE TABLE devices (
  id TEXT PRIMARY KEY, name TEXT, enc_pub BLOB, sign_pub BLOB,
  paired_at INTEGER, revoked_at INTEGER, last_counter INTEGER DEFAULT 0);

CREATE TABLE outbox (
  id TEXT PRIMARY KEY, kind TEXT, payload TEXT, created INTEGER,
  urgent INTEGER, email_after INTEGER);          -- NULL: email not needed

CREATE TABLE deliveries (
  message_id TEXT, device_id TEXT, sent INTEGER, delivered INTEGER, read INTEGER,
  PRIMARY KEY (message_id, device_id));

CREATE TABLE reply_audit (
  id TEXT PRIMARY KEY, device_id TEXT, intent TEXT, target TEXT,
  accepted INTEGER, reason TEXT, at INTEGER);
```

Relay (the Durable Object's SQLite, per install):

```sql
CREATE TABLE devices   (id TEXT PRIMARY KEY, push_sub TEXT, auth_pub BLOB, added INTEGER);
CREATE TABLE envelopes (id TEXT PRIMARY KEY, recipient TEXT, body BLOB,
                        created INTEGER, expires INTEGER, acked INTEGER);
CREATE INDEX envelopes_pending ON envelopes (recipient, acked, expires);
```

## Threat model

| threat | outcome |
|---|---|
| Relay operator or a breach reads the data | Ciphertext and minimal metadata only. |
| Relay forges or replays a reply | Rejected: device signature, timestamp window and counter. |
| Relay inserts a rogue device | Impossible without the on-laptop safety-code confirmation. |
| Stolen, unlocked phone | Can ask, ack non-critical findings for up to 30 days, and snooze. It can't approve, undo or repair, and every reply is announced to your other devices. `jarvis devices revoke` cuts it off. |
| Relay is down | Email fallback for urgent messages; the outbox holds everything else until it reconnects. |
| Prompt injection via finding text | `ask` answers go through the existing read-only assistant; model output has no route to any intent. |
| Push provider (Apple, Google) | Sees an opaque wake-up blob, not content. |

## Repository layout

```
jarvis/response/messaging/   outbox, channels, crypto, relay, replies, pairing
messaging/relay/             Worker + Durable Object (TypeScript), wrangler.toml
messaging/pwa/               static PWA: inbox, ask, replies, service worker
messaging/relay-go/          optional self-host binary (only if needed)
```

## Phases

1. **One-way push.** Outbox, channel routing, pairing, relay, and a PWA that
   receives and decrypts. Email fallback for urgent messages. *Done when a
   critical finding reaches a paired phone within 10 seconds and the relay's
   database holds no plaintext.*
2. **Ask.** Sealed questions through the read-only assistant.
3. **Ack and snooze.** Reply verification, limits, audit, and cross-device
   confirmation.
4. **Self-host relay**, only if Cloudflare is ruled out.

## Open questions

- Relay domain: a subdomain of one you already run on Cloudflare, or a
  `workers.dev` URL?
- Should desktop notifications come from the PWA, or keep using the Windows
  flash path (`response/flash.py`)?
