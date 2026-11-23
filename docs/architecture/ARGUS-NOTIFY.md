# Notifications to a phone: the sealed relay (v1)

Status: building, 2026-10-25. Supersedes the transport and crypto choices of MESSAGING.md
(2026-09-16) for its phase 1; the goals and threat model there still apply.

Owner decisions 2026-10-25: hosted at `argus.archymedes.xyz` (Cloudflare Worker + Durable
Objects); no accounts, a phone is a set of device keys; first release is one-way push, inbox and
pairing (no replies); the server uses `python3-cryptography` from the distribution.

## Shape

```
 server (Argus, never listens)      argus.archymedes.xyz                 phone (PWA)
 ─────────────────────────────      ──────────────────────               ───────────
 alert.deliver ─► notify channel    Worker ─ Mailbox DO (per server)     service worker
   seal per device (X25519,         stores ciphertext envelopes,         ◄─ Web Push (empty)
   HKDF-SHA256, AES-256-GCM),       device push subscriptions;           fetches its inbox,
   sign (Ed25519) ─HTTPS POST──►    sends an empty Web Push  ──────►     verifies, decrypts,
                                    PairSlot DO (per code, 10 min)       shows the notification
```

The relay stores and forwards ciphertext. The push service (Apple, Google, Mozilla) receives
an empty wake-up. Only the phone can read an alert, and only alerts signed by its paired
server are shown.

## Invariants

- **N1 Nothing listens on the server.** Argus only makes outbound HTTPS requests.
- **N2 The relay cannot read.** It sees mailbox and device ids, sizes, times and push
  endpoints; never titles, severities or text.
- **N3 The relay cannot impersonate.** Mailbox and device ids are hashes of their own Ed25519
  keys (self-certifying); every envelope is signed by the server key the phone pinned at pairing;
  a device becomes active only after the owner confirms a 6-digit code on the server that the
  phone also shows, derived from both sides' keys.
- **Limit of N2/N3 (security review 2026-10-30).** N2 and N3 hold against a relay that stores,
  drops or tampers with API traffic while serving the app unchanged. The relay also *serves* the
  phone app (`public/`, same origin, same deployment): whoever can change that deployment can
  ship app code that uses the phone's (non-extractable, but usable) keys to decrypt, or that
  shows the owner whatever 6-digit code the server shows. Against that operator the comparison
  proves nothing. A second, narrower gap: the SAS has no commitment step, so a relay that
  rewrites only API traffic sees the phone's keys before it must present device keys to the
  server and can grind an X25519 key (about 10^6 tries) whose SAS matches. Closing either needs
  app code delivered independently of the relay (a signed bundle or a native app) plus a
  commit-then-reveal nonce in the SAS; until then the relay deployment is trusted code.
- **N4 Bounded.** Envelope ≤ 8 KiB, ≤ 500 pending per device, ≤ 20 devices per mailbox, 7-day
  expiry, pairing codes single-use for 10 minutes with ≤ 10 attempts; request timestamps within
  300 s, replayed request signatures refused.
- **N5 Visible delivery.** The channel's outcome is recorded per send; it counts as a channel
  that can reach the owner only while at least one device is active and the last send worked.
- **N6 Nothing to steal on the relay.** No accounts, no emails, no passwords.
- **N7 Revocable.** `notify revoke` removes a device locally and on the relay; the phone can
  remove a server.

## Identifiers and keys

`b64u` = base64url without padding. `H(x)` = SHA-256.

| who | keys | id |
| --- | --- | --- |
| server (mailbox) | Ed25519 `S_sig`, X25519 `S_enc` (kept 0600 beside the store) | `mb = b64u(H(S_sig_pub))[:22]` |
| phone (device) | Ed25519 `D_sig`, X25519 `D_enc` (WebCrypto, non-extractable, IndexedDB) | `dev = b64u(H(D_sig_pub))[:22]` |

Public keys travel as b64u of their 32 raw bytes.

## Signed requests

Server → relay and phone → relay requests carry:

```
X-Notify-Key: b64u(sig_pub)            (the id must equal b64u(H(key))[:22])
X-Notify-Time: unix seconds
X-Notify-Nonce: b64u(16 random bytes)  (Ed25519 is deterministic: without it two identical
                                        requests in one second would share a signature)
X-Notify-Sig: b64u(Ed25519(sig_priv, "notify-req/1\n" + METHOD + "\n" + PATH + "\n" + TIME
                                     + "\n" + NONCE + "\n" + hex(H(body))))
```

The relay checks the id, the window (±300 s) and that the signature was not seen in the window.

## Pairing

1. Server: `notify pair --label NAME` creates a code (10 symbols of Crockford base32, 50 bits),
   and `PUT /v1/pair/{code}` (signed by `S_sig`) with
   `{mb, s_sig, s_enc, label, expires}`.
2. Phone: the owner types the code; `GET /v1/pair/{code}` returns that offer; the phone checks
   `mb == b64u(H(s_sig))[:22]`, makes its keys and push subscription, and
   `POST /v1/pair/{code}/claim` (signed by `D_sig`) with `{dev, d_sig, d_enc, push, name}`.
3. Both compute `SAS = int(H("notify-sas/1" | s_sig | s_enc | d_sig | d_enc)[:4]) mod 10^6`,
   shown as `123 456`. The server polls `GET /v1/mailbox/{mb}/claims` (signed), shows the
   device name and code; the owner answers yes only if the phone shows the same code.
4. Yes: the server records the device (`dev, d_sig, d_enc, name, paired_at`) and
   `POST /v1/mailbox/{mb}/devices/{dev}/activate` (signed). The phone polls the slot until
   active, then stores `{mb, label, s_sig, s_enc}`.

Robustness (2026-11-02): the server retries the activation 5 times over 30 s; if the relay
still does not confirm, the device stays recorded with `relay_pending: true`, `notify devices`
and `notify status` say so, and the Link Plane reports it (pair again to fix). The phone
stores the pending pairing (server, code, its keys, the 10-minute deadline) in IndexedDB
*before* claiming, so a reload or an app switch mid-pairing resumes the "compare this code"
screen with the same keys instead of losing them; Servers shows "pairing in progress" with a
cancel, and the entry is cleared on success, expiry or cancel.

### Pairing from the desktop app or dashboard (2026-11-03)

`notify pair` needs a terminal; the desktop app and the daemon's web interface
pair through `/api/phone/*` instead (`jarvis/web/phone.py`), with the same steps
(`jarvis/response/notify/pairing.py`, shared with the CLI). The daemon keeps one
pairing session in memory; the page polls it. Rules, tested in
`tests/test_phone_pairing.py`:

- A phone is paired only by `confirm` with the exact 6-digit code that this
  session showed, while it is `claimed`; a wrong, stale or repeated confirm is
  refused and changes nothing. "They don't match" deletes the claim on the relay.
- The page receives the session id, the pairing code, relay URL, expiry, device
  id, the claimed name (control characters removed) and the comparison code;
  never key material.
- One session at a time, 10 minutes, no thread of its own: each poll makes at
  most one relay call, at most every 2 s, never two at once.
- Every route needs the API credential; POSTs also pass the same-origin gate.
- A daemon restart loses the session; the claim stays pending on the relay and
  is never activated.

Not yet measured: a real phone paired through the desktop app.

## Envelopes

Per message and device, the server makes an ephemeral X25519 key `E`:

```
shared = X25519(E_priv, D_enc_pub)
key    = HKDF-SHA256(ikm=shared, salt=id_bytes, info="notify-seal/1", 32 bytes)
iv     = 12 random bytes
aad    = canonical JSON of {v, id, mb, dev, sent, expires, epk}
ct     = AES-256-GCM(key, iv, payload, aad)
sig    = Ed25519(S_sig, "notify-env/1\n" + aad + "\n" + b64u(iv) + "\n" + b64u(ct))
envelope = {v: 1, id, mb, dev, sent, expires, epk, iv, ct, sig}
```

`id` is 16 random bytes (b64u). Canonical JSON: keys sorted, no whitespace, UTF-8.
Payload (JSON, ≤ 4 KiB): `{kind: "alert"|"test", title, body, severity, finding?, host, at}`.

Server → relay: `POST /v1/mailbox/{mb}/envelopes` (signed) with `[envelope, ...]`.
Server ← relay: `GET /v1/mailbox/{mb}/devices` (signed) returns
`[{dev, name, state, added, last_seen, push}]`: liveness metadata only (`last_seen` is the
device's last inbox fetch, `push` whether a subscription is stored). The server's Link Plane
(`jarvis/service/links.py`) uses it to say "this phone has not checked in for 48 h" or
"this phone has no push subscription"; nothing it returns can read or forge an alert (N2, N3).
Phone ← relay: `GET /v1/device/{dev}/inbox` (signed by `D_sig`), then
`POST /v1/device/{dev}/ack` with the ids it stored. The relay deletes acked and expired ones.

The phone shows a message only if `sig` verifies with the pinned `s_sig` of `mb` and decryption
succeeds; anything else is dropped and counted.

## Push

The relay holds a VAPID key (Worker secret). After storing envelopes for a device it sends one
Web Push with no payload and TTL 7 days. The service worker, on `push`, fetches the inbox,
verifies, decrypts, stores and shows one notification per message (or a summary for more than 3).
iOS delivers Web Push only to a PWA added to the home screen (16.4+).

## Server side

`jarvis/response/notify/`: `crypto.py` (keys, seal, sign, SAS), `relay.py` (signed HTTPS client,
bounded), `devices.py` (local registry), `channel.py` (`send(subject, text, severity)` used by
`alert.deliver`). CLI: `notify pair | devices | revoke | test | status`. The relay URL defaults to
`https://argus.archymedes.xyz` and is set by `notify_url` in the alert config.

## Home-Screen app and QR pairing (v1.1, 2026-11-04)

The phone app is a web app added to the Home Screen from the relay's address; nothing is installed from a store.
iPhone (16.4+) delivers web push only to a Home-Screen app and keeps that app's storage apart from Safari's, so the
app is added first and **pairing happens inside it**. Android/Chrome works from the browser or the installed app.

`notify pair` now shows a QR (terminal) holding `https://<relay>/#/pair?c=CODE&k=SECRET&mb=MAILBOX`, and still prints
the code. In the app: Add a server -> scan -> allow notifications -> set up Face ID / fingerprint -> the server asks
"Add it? [y/N]". There are no digits to compare. What replaces the comparison:

- the phone checks that the offer's keys hash to `mb` from the QR (the server is pinned from the camera, not the relay);
- the claim carries `proof = HMAC-SHA256(k, "notify-qr/1" | d_sig | d_enc | passkey_spki)`. `k` is only in the QR, so the
  relay (which knows the code) cannot inject a device. A claim without a valid proof falls back to the 6-digit
  comparison and the phone gets **alerts only**.

This closes the SAS-grinding gap noted under N3 for QR pairing. The relay still serves the app code (same limit as before).

## Approvals from the phone (v1.1)

Scope: a phone may approve **one reversible defense proposal** that this server offered (`defense.pending`, actions with
`reversible = True`, `jarvis/response/actions/base.py`), and undo what a phone approved. Irreversible actions, spend, identity,
fix-apply and config changes are not reachable from a phone. A phone paired without the QR (no proof) cannot approve.

```
server: defense.process queues -> scheduler tick -> replies.offer -> sealed envelope kind "approval"
        {approval_id, eid, action, target, expires<=10min, challenge = SHA-256(canonical{ctx, approval_id, eid, action, target, expires})}
phone:  recomputes the challenge from what it shows; Approve = WebAuthn assertion (userVerification required) over that challenge
        reply = {type:"approval", approval_id, decision, counter, assertion}  sealed to S_enc, signed by D_sig   (notify-rep/1)
        POST /v1/device/{dev}/replies   ->  relay stores ciphertext (<=8 KiB, <=50 pending, 15 min)
server: polls GET /v1/mailbox/{mb}/replies (never listens), then ACK
```

The server checks, in order: known active device, device signature, timestamp window (15 min), counter greater than the last
seen (replay), request offered by this server and not expired, this phone was asked, WebAuthn (origin and relying-party id from
`notify_url`, challenge, user-present and user-verified flags, ES256 signature, signature counter), and that the proposal is still
`proposed`, still reversible, with the same action and target. Then `defense.approve(..., by="phone:<dev>")`. The request is single
use. Every outcome goes to the append-only audit list (`notify_approvals` meta) and a result envelope goes to every paired phone;
phones that can approve also get an **Undo** offer (valid 1 hour, only for entries a phone approved, passkey required).

Relay additions: `replies` table, `POST /v1/device/{dev}/replies`, `GET /v1/mailbox/{mb}/replies`, `POST .../replies/ack`;
claim fields `passkey` and `proof` are stored and forwarded unread. The relay's `Permissions-Policy` allows the camera and
WebAuthn for its own origin only.

Known limits: iOS web push has no action buttons (the tap opens the app); a Home-Screen web app is served by the relay, so a
hostile relay operator could change what the screen shows (the challenge check and the server-side re-validation bound what
that can do, but a signed app bundle remains future work); the main scheduler lane handles replies between collector runs,
so an answer can wait for a running collector (seconds, within the 10-minute request lifetime).
