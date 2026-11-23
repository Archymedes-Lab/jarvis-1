# Licences and payments (Stripe, Managed Payments)

Current source terms and commercial permissions are governed by [LICENSING.md](../LICENSING.md)
and [COMMERCIAL.md](../COMMERCIAL.md). The entitlement/payment mechanisms below
do not themselves grant commercial permission or change earlier customer terms.

Design: `docs/LICENSING-ARCHITECTURE.md`. Owner setup and deployment: `docs/STRIPE-HANDOFF.md`.

Argus is sold through Stripe Checkout with **Stripe Managed Payments**, so Stripe is the merchant of
record: it takes the card, calculates and remits sales tax / VAT, handles fraud and disputes, and sends
receipts and invoices through Link. Checkout and licences are served by one Cloudflare Worker,
`hosted/licence-cloudflare`, at **https://pay.archymedes.xyz** (the "Archymedes licence service").

| Offer (`/buy/…`) | Stripe Price lookup key | Seats | Key prefix |
|---|---|---|---|
| `argus-server` (Argus Server, $50 per server per year) | `argus_server_usd_5000_year` | 1 server | `ARGUS-SRV-` |
| `argus-desktop` (Argus Desktop, $79 per computer per year) | `argus_desktop_usd_7900_year` | 1 computer | `ARGUS-DSK-` |

Both are yearly subscriptions. A licence runs to the current period end plus a 14-day grace period (EULA §2.3) and moves forward on
every paid invoice. Seat counts live in one place: `OFFERS` in `hosted/licence-cloudflare/src/env.ts`.
Prices come from archymedes-gtm `scripts/stripe-setup.ts` (price book `catalog/stripe.ts`); the Worker only
looks them up by lookup key. Retired offers (Server Review, Watch, the free desktop beta) answer 404.

## What a licence never does

A licence never gates protection. Collectors, detection, alerts, evidence, the assistant and on-demand
checks run the same with no licence, an expired one or a forged one
(`tests/test_licence_never_gates_core.py`): there is no lock switch and no payment-required answer anywhere.
A licence unlocks premium content only: today the full server review report, plus any content pack the
server delivers (`POST /content/<pack>`).

## What licensing can and cannot do (read this before promising anything)

- **Cannot be done on the customer's machine:** stop someone who modifies the Argus program. Every check
  that runs locally (the signature, the fingerprint, the lease, the clock guard) can be removed by editing
  the code. This is licensing to keep honest customers honest and discourage casual key sharing. It is not
  DRM and must not be described as copy protection.
- **Done with cryptography or on the server:** a licence can only be created by a verified Stripe payment;
  certificates cannot be edited or forged without the Worker's private key; a copied certificate fails on
  another machine; a leaked key cannot renew someone else's machine; a database copy reveals no keys or
  emails (HMACs with a secret pepper); content the server delivers is refused to anyone without a live
  activation, whatever their copy of Argus does.

## From purchase to an activated machine

**A. Buy from inside Argus (no typing).** In the desktop app: Licence → *Buy Argus Desktop* (or *Server*).
On a server: `argus licence buy server`.
1. Argus makes a device key, sends `POST /licence/claim {dev, dpk, label}` and gets a claim id.
2. It opens `https://pay.archymedes.xyz/buy/argus-desktop?claim=clm_…`; the Checkout Session carries
   `metadata[claim]`.
3. After payment, the webhook (or the thank-you page, whichever comes first) creates the licence and gives
   that device the seat.
4. Argus polls `POST /licence/claim/poll` every 5 seconds, signed by its device key (only the device that
   opened the claim can collect), and installs the certificate. The key is still emailed.

**B. Bought on the website.** `https://pay.archymedes.xyz/buy/argus-server` → Stripe → back to
`https://pay.archymedes.xyz/thanks?session_id=cs_…`, which shows the key on the day of purchase with
**Copy key** and **Open in Argus** (`argus://activate?key=…`) and how to activate it. The same key is
emailed (Resend) with links to manage it and to recover it. Then:
- Desktop: Licence → paste the key → **Activate**. The paste box checks the key as it is typed (wrong
  check character, wrong prefix, stray characters) before anything is sent.
- Server: `argus licence activate ARGUS-SRV-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` (case, spaces and dashes do not
  matter; `argus licence activate "argus://activate?key=…"` also works).
- Headless server without the key at hand: `argus licence login` shows a code; open
  `https://pay.archymedes.xyz/link`, sign in with the purchase email and enter the code.

**C. What activation does.** `POST /licence/activate {key, dev, dpk, label}`:
- `dev` is this machine's fingerprint, `HMAC-SHA256("argus-fp-v1:" + device public key, machine id)`.
  The machine id is the Windows MachineGuid (desktop) or `/etc/machine-id` (Linux). The raw id never
  leaves the machine.
- `dpk` is the device's Ed25519 public key; `label` is the host name, shown on the manage page.
- The same device again gets the same activation and a fresh certificate. The same machine with a new
  device key (Argus reinstalled) takes its own seat back. Another machine, with the seat taken, gets
  **409 `seat_taken`** naming the machine that holds it and what to do: `argus licence deactivate` there, or
  release it at `/manage`.
- The answer is an Ed25519 JWS certificate (claims in the architecture doc, §4), stored owner-only in
  `licence.json` beside the store; the device key is `licence-device.key` (DPAPI-protected on native
  Windows, a 0600 file elsewhere).

**D. Offline checks.** `argus licence status` and the review report check, with no network, that: the
signature verifies under a public key this build ships (`jarvis/licensing/trust.py`) and its kid is known;
the audience is Argus; the certificate names this device key and this machine's fingerprint; the 30-day
lease has not ended; and the clock is not more than 10 minutes behind the last time Argus saw it. Each
failure has its own message (for example "the certificate belongs to another machine", "the system clock
is behind …; correct the clock").

**E. Renewal.** When Argus runs (the review command, the desktop app's Licence screen, `argus licence
status`) and the lease has under 7 days left, Argus makes one HTTPS call, `POST /licence/renew {act, nonce,
ts, sig}`, signed by the device key; the timestamp must be within 5 minutes and the nonce new. The new
certificate carries the subscription's current end (`invoice.paid` moves `lic_exp` forward in D1). If
renewal fails, Argus retries after 6 hours, then daily, and keeps working until the lease ends; after that
the review report shows **"licence needs checking"** with the reason and `argus licence refresh`. Turn
automatic renewal off with `argus licence auto-renew off` (then renew with `argus licence refresh`).
A cancelled or refunded licence fails at the next renewal; server content is refused from then on.

**F. Moving, releasing, recovering.**
- From the machine: `argus licence deactivate` (or **Deactivate** in the app) frees the seat at once.
- On the web: `https://pay.archymedes.xyz/manage` → purchase email → a sign-in link (one use, 15 minutes) →
  a 30-minute session that lists each licence, the machines using it, **Release this machine**, **Email
  me the key**, and **Billing and invoices** (the Stripe billing portal).
- Lost key: `https://pay.archymedes.xyz/recover` emails it again. It answers the same whether or not the
  email bought anything.
- Abuse limit: 3 releases per licence per 30 days; after that the answer asks the owner to email support.

## CLI

```
argus licence status                 offline: plan, renews/ends, offline lease, this machine, links
argus licence activate <key>         activate this machine (also accepts an argus://activate link)
argus licence buy [server|desktop]   buy in the browser; this machine activates by itself
argus licence login                  activate a headless server with a code approved on the web
argus licence refresh                renew now
argus licence deactivate             free this machine's seat
argus licence auto-renew on|off      the one automatic renewal call
argus licence content <pack>         fetch a server-delivered content pack (sample today)
argus licence remove                 forget the licence here without freeing the seat
```

Network use: HTTPS to `pay.archymedes.xyz` only, from the commands above and the automatic renewal. No API
token or seller secret is on any customer machine.

## Shared Stripe account

Orion sells from the same Stripe account and has its own webhook endpoint. The Argus Worker acts only on
objects carrying `metadata.app=argus` (or a subscription it issued a licence for). An event whose
`metadata.app` names another app (`orion`) is ignored before anything else, even if its subscription id
matched a licence.
