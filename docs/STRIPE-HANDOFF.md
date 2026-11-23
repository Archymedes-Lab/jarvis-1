# Stripe hand-off: deploying pay.archymedes.xyz

Everything below is done by the owner, on the seller machine. Nothing here has been run.
The Worker is `hosted/licence-cloudflare` (Cloudflare Worker + D1). Pinned Stripe API
version: **`2026-10-28.endive`** (`src/stripe.ts`); Managed Payments needs
`2025-03-31.basil` or later.

## 0. Stripe account (Dashboard)

1. Turn on Managed Payments: Dashboard → Settings → Managed Payments.
2. Run archymedes-gtm `scripts/stripe-setup.ts`, which creates the two products (tax code
   `txcd_10103101`, eligible for Managed Payments) and prices with these lookup keys:
   `argus_server_usd_5000_year` ($50 / year per server) and `argus_desktop_usd_7900_year`
   ($79 / year). The Worker never creates prices. With `--retire` it also deactivates the
   retired Server Review and Watch prices, if they were ever created.
3. Configure the customer billing portal (Settings → Billing → Customer portal) so
   `POST /licence/portal` can open it.
4. Create a **restricted key** (`rk_live_…`) with: `checkout_session_write`,
   `checkout_session_read`, `plan_read` (prices), `subscription_read`, `customer_portal_write`,
   `promotion_code_read` (Dashboard: **Promotion codes: Read**; for `?promo=` links, section 7).
   That is every Stripe call the Worker makes (archymedes-gtm `docs/stripe-restricted-keys.md`).
   Without `promotion_code_read` a prefilled code is never applied (the buyer can still type it on
   the Stripe page); nothing else breaks.

## 1. D1 database (and migration)

```sh
cd hosted/licence-cloudflare
bun install
npx wrangler d1 create argus-licence          # paste the printed database_id into wrangler.jsonc
npx wrangler d1 execute argus-licence --remote --file=schema.sql
```

`schema.sql` is idempotent and never drops anything; run it again after every update. The licence
tables are `licences_v2`, `activations_v2`, `claims`, `magic_links`, `manage_sessions`, `releases`,
`nonces`, `throttle`, `audit` and `processed_events`.

**Migration from the first payments schema.** The first version stored keys in plain text in tables
`licences` and `activations`. It was never deployed (pay.archymedes.xyz had no DNS record and
`wrangler.jsonc` still had `REPLACE_WITH_D1_ID`), so no `ARGUS-SERVER-<UUID>` key was ever issued and the
client no longer accepts that format. If a test database has those tables, check they are empty and drop
them:

```sh
npx wrangler d1 execute argus-licence --remote --command "SELECT COUNT(*) FROM licences"
npx wrangler d1 execute argus-licence --remote --command "DROP TABLE IF EXISTS activations; DROP TABLE IF EXISTS licences"
```

## 2. Signing keys and secrets (never in a file in the repo)

**Licence signing key (Ed25519).** Run once per environment (test and live get different keys):

```sh
bun scripts/licence-keygen.ts --kid 2026-11-a          # live
bun scripts/licence-keygen.ts --kid 2026-11-test --out ~/.config/archymedes/test   # test Worker
```

It writes the private key to `~/.config/archymedes/argus-licence-<kid>.secret` (mode 0600, outside the
repo; back it up in your password manager), adds the public key to `jarvis/licensing/trust.py`, and prints
the command below. Commit `trust.py` and ship that Argus release **before** the Worker signs with the new
kid: a build that does not know a kid refuses its certificates (it says "update Argus"). A test kid in a
release build is harmless (it only verifies test certificates) but remove it before a public release.

```sh
npx wrangler secret put LICENCE_SIGNING_KEY < ~/.config/archymedes/argus-licence-2026-11-a.secret
openssl rand -base64 48 | tr -d '\n' | npx wrangler secret put KEY_PEPPER   # once; keep a copy in the password manager
npx wrangler secret put STRIPE_SECRET_KEY      # rk_live_… or sk_live_…
npx wrangler secret put STRIPE_WEBHOOK_SECRET  # whsec_… from step 4
npx wrangler secret put RESEND_API_KEY         # emails keys, sign-in links and recoveries
```

`KEY_PEPPER` keys the HMACs for key hashes and email hashes and derives the keys themselves (so they can be
re-sent without being stored). **Never change it on a live database:** every existing key would stop
matching. Treat it like the signing key: if it leaks, keys can be computed from Checkout Session ids.

**Rotating the signing key:** make a new kid with the script, ship the release with both kids in
`trust.py`, `wrangler secret put LICENCE_SIGNING_KEY` with the new one, wait 30 days (the longest lease),
then remove the old kid from `trust.py` in a later release.

Vars in `wrangler.jsonc`: `SITE_ORIGIN=https://www.archymedes.xyz`, `PAY_ORIGIN=https://pay.archymedes.xyz`
(links in emails and pages), `SUPPORT_EMAIL`, `MANAGED_PAYMENTS="1"` (`"0"` falls back to
`automatic_tax[enabled]=true`), `MAIL_FROM` (a verified Resend sender on archymedes.xyz). Rate limits
(`RL_BUY`, `RL_LICENCE`, `RL_EMAIL`) are Workers rate-limiting bindings, per IP.

## 3. Deploy and custom domain

```sh
bun test && npx tsc --noEmit
npx wrangler deploy
```

`wrangler.jsonc` routes the custom domain `pay.archymedes.xyz` (the archymedes.xyz zone
must be on the same Cloudflare account). Check: `curl https://pay.archymedes.xyz/health`
→ `{"ok":true,"stripe":true,"stripe_mode":"live","managed_payments":true,"signing":true,"pepper":true}`
(`stripe_mode` is `test` with a test key; it is derived from the key prefix and never shows the key).

## 4. Webhook endpoint

Dashboard → Developers → Webhooks → Add endpoint, or:

```sh
stripe webhook_endpoints create \
  --url https://pay.archymedes.xyz/stripe/webhook \
  --api-version 2026-10-28.endive \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=checkout.session.async_payment_succeeded" \
  -d "enabled_events[]=invoice.paid" \
  -d "enabled_events[]=customer.subscription.deleted" \
  -d "enabled_events[]=charge.refunded"
```

Put its signing secret into `STRIPE_WEBHOOK_SECRET` (step 2). Orion's webhook on the same
account is separate; this endpoint ignores anything without `metadata.app=argus`.

## 5. Test mode first

Repeat steps 1–4 with `sk_test_`/`rk_test_`, a test signing kid and a test webhook, then buy with card
`4242 4242 4242 4242`: `/buy/argus-server` → the thank-you page at `/thanks` shows the key →
`argus licence activate <key>` → `argus review` is the full report. Then: `argus licence buy desktop` on
another machine (activates by itself), `/manage` with the purchase email (release a machine, resend the
key), `/recover`. Cancel the subscription in the Dashboard → `argus licence refresh` reports it cancelled.
In a sandbox Stripe sends no receipt email automatically (Dashboard → payment → Send receipt to preview).

**Local run without Stripe** (what was used to test this): put test values in `.dev.vars` (gitignored)
including `PAY_ORIGIN=http://127.0.0.1:9477` and `DEV_FAKE_UPSTREAM=http://127.0.0.1:<port of a fake
Stripe>`, then `npx wrangler dev --ip 127.0.0.1 --port 9477 --local-upstream 127.0.0.1:9477
--upstream-protocol http` (without the last two flags wrangler rewrites the browser's Origin header to
pay.archymedes.xyz and the manage forms are refused), and point the client at it with
`ARGUS_LICENCE_API=http://127.0.0.1:9477`. `DEV_FAKE_UPSTREAM` is ignored unless the Worker itself is on
127.0.0.1.

## 6. Verify live mode with one real purchase (and refund it)

The customer machine holds no Stripe key at all (`tests/test_no_seller_payment_key.py`); live mode is a property
of the Worker's secrets alone. Each licence row records the paying Checkout Session's own `livemode`
(`licences_v2.livemode`), which is the authority for that purchase.

1. Read-only first: `curl -s https://pay.archymedes.xyz/health` must say `"stripe_mode":"live"` (needs the
   Worker version with that field deployed). Stripe Dashboard → Developers → Webhooks: the
   `pay.archymedes.xyz/stripe/webhook` endpoint is listed in **live** mode.
2. Buy the cheapest offer for real: in the desktop app or the web dashboard, Pricing → Monthly → **Buy for this
   computer** (Argus Desktop monthly, $15). Pay with a real card. The computer activates by itself; the app shows
   *Active*.
3. Confirm it was live, read-only:
   `npx wrangler d1 execute argus-licence --remote --command "SELECT id, offer, livemode, status, substr(session_id,1,8) AS s FROM licences_v2 ORDER BY created_at DESC LIMIT 1"`
   → `livemode = 1`, session prefix `cs_live_`, status `active`. In the Stripe Dashboard (live), the payment
   appears under Payments with the Argus metadata.
4. Refund and end it: Dashboard (live) → the payment → **Refund** (full), then the subscription → **Cancel
   immediately**. Both current plans are subscriptions, so the licence is revoked by
   `customer.subscription.deleted` (a refund alone revokes only one-time payments).
5. Confirm the revocation: the same D1 query shows `status = revoked`; on the computer, `argus licence refresh`
   reports the subscription ended; protection keeps running exactly as before
   (`tests/test_licence_never_gates_core.py`). Stripe's fee on the refunded charge is not returned.

## 7. Promotion codes (discounts)

Discounts are made in the Stripe Dashboard only. The Worker holds no amounts, percentages or rules:
it shows Stripe's "Add promotion code" box on every Checkout Session (`allow_promotion_codes`), and
it can prefill one code from a link. The prices shown in the app, the dashboard and on the website
stay the list prices; Stripe shows the discounted total on its payment page.

**Where a code can come from**

- The buyer types it on the Stripe payment page (always possible).
- A marketing link: `https://pay.archymedes.xyz/buy/argus-desktop?promo=LAUNCH20` (also
  `argus-desktop-monthly`, `argus-server`; combine with `&computers=N` / `&servers=N`, `&ref=`,
  `&utm_…` as before).
- The **Promo code (optional)** field on Pricing in the desktop app and the classic dashboard. It rides
  on the in-app claim link (`/buy/<offer>?claim=clm_…&promo=CODE`) and on the "Buy on the website"
  buttons. The daemon refuses a malformed code (`bad_promo`) before opening a claim.

A prefilled code must be 1-40 characters of `A-Z a-z 0-9 - _` (Stripe itself allows more; codes
outside this set still work when typed on the Stripe page). The Worker looks it up with
`GET /v1/promotion_codes?code=…&active=true&limit=1`. If it is active, not expired and not used up,
the session gets `discounts[0][promotion_code]` instead of the box (Stripe refuses both together). In
every other case (malformed, unknown, inactive, expired, used up, lookup failed, or Stripe refuses it
for this price or customer when the session is created, after which the Worker retries once without
it) the buyer sees a short page "Your promo code was not applied" with **Continue to payment** to an
ordinary session where a code can be typed. A code never fails a purchase, and the code itself is
never logged, stored, put into Stripe metadata or echoed back on a page.

**Create one (live mode)**

1. Stripe Dashboard, **live** mode (the "Test mode" toggle off) → Product catalog → **Coupons** →
   **+ Create coupon**.
2. Type: **Percentage discount** or **Fixed amount discount** (fixed amounts: currency USD).
3. Duration, for these subscriptions: **Once** = the first invoice only (the first month of
   `argus-desktop-monthly`, the first year of `argus-desktop` and `argus-server`); **Multiple
   months** = every invoice in that many months; **Forever** = every renewal (rarely what you want).
4. **Apply to specific products**: pick Argus Desktop and/or Argus Server, so a desktop code cannot
   discount a server fleet. Without it the coupon applies to every product on the account,
   **including Orion's** (same Stripe account).
5. Coupon limits (optional): **Limit the date range when customers can redeem this coupon**, and
   **Limit the total number of times this coupon can be redeemed**.
6. Under **Codes**, tick **Use customer-facing coupon codes**, enter the code (e.g. `LAUNCH20`;
   stick to `A-Z 0-9 - _` and at most 40 characters so links work) and choose its restrictions:
   - **Eligible for first-time order only**: only a customer with no previous payment.
   - **Limit to a specific customer**: a one-off code for one buyer (needs the customer to exist).
   - **Limit number of times this code can be redeemed** (max redemptions).
   - **Add an expiration date**.
   - **Require minimum order value** (careful with fleet quantities; a refused code just falls back).
7. Save. Codes are case-insensitive for buyers. To stop a code: Coupons → the coupon → the code →
   **Archive** / deactivate. Subscriptions that already used it keep the discount for the coupon's
   duration; deleting the coupon does not change past invoices.

**Test it** (test mode first, as in section 5; nothing here was run against Stripe):

1. Create a test-mode coupon (e.g. 20% off, Once, Argus Desktop only) with code `TEST20`, and a second
   code `OLD20` that you then deactivate.
2. `…/buy/argus-desktop-monthly?promo=TEST20` → Stripe shows the 20% discount and no code box.
3. `…/buy/argus-desktop-monthly?promo=OLD20`, `?promo=NOPE` and `?promo=bad%20code` → the "not applied"
   page → Continue → the ordinary page with "Add promotion code"; typing `TEST20` there works.
4. `…/buy/argus-server?promo=TEST20` (a desktop-only coupon) → Stripe refuses the discount for that
   price, the Worker retries without it → the "not applied" page, then the ordinary checkout.
5. Desktop app → Pricing → Promo code `TEST20` → **Buy for this computer** → the discount on the Stripe
   page; pay with `4242 4242 4242 4242`; the computer activates as usual.
6. **Managed Payments**: confirm that a prefilled discount is accepted with `managed_payments[enabled]`.
   If Stripe refuses it, buyers still get the ordinary checkout (step 4's fallback), but say so here.
7. After a paid discounted purchase, the audit trail has Stripe's promotion code id and the amount off
   (minor units), never the code: `npx wrangler d1 execute argus-licence --remote --command "SELECT
   datetime(at,'unixepoch'), licence_id, action FROM audit WHERE action LIKE 'discount %' ORDER BY at DESC
   LIMIT 10"` → e.g. `discount promo_1Qx… 300 usd`. It is an audit row, not a licence column: a column needs an
   `ALTER TABLE` on the live D1 that would have to land before the Worker, or issuing licences fails.
   Stripe's own records (the session's `discounts`, the invoice) remain the authority.

## Support runbooks

Customers can do most of this themselves at `https://pay.archymedes.xyz/manage` (release a machine, resend
the key, billing) and `/recover` (lost key). The database holds no keys or emails, so support looks rows
up by hash with `scripts/support.ts` (needs `KEY_PEPPER` in the environment; it prints SQL and connects to
nothing). Run its SQL with `npx wrangler d1 execute argus-licence --remote --command "<sql>"`.

- **Find a licence:** `KEY_PEPPER=… bun scripts/support.ts key ARGUS-SRV-…` or `… email someone@example.com`.
  Then `SELECT id, label, created_at, released_at FROM activations_v2 WHERE licence_id = 'lic_…'`.
- **Move a licence** (the customer is over the 3-releases-in-30-days limit, or lost the old machine):
  `UPDATE activations_v2 SET released_at = unixepoch(), released_by = 'support' WHERE id = 'act_…'`, then
  `INSERT INTO audit (at, licence_id, action, actor) VALUES (unixepoch(), 'lic_…', 'released', 'support')`.
  Support releases do not count toward the limit. The customer then activates on the new machine.
- **Machine fingerprint changed** (Windows or Linux reinstalled, VM cloned, WSL interop turned off): the old
  activation cannot renew from the new install. The customer releases it at `/manage` (or support does, as
  above) and activates again. Reinstalling only Argus on the same machine needs nothing: the seat follows.
- **Resend a key:** ask the customer to use `/recover` (it goes to the purchase email only). Support cannot
  see keys; `support.ts reissue` is for leaked keys.
- **Leaked key:** `KEY_PEPPER=… bun scripts/support.ts reissue cs_… <current key_gen> server|desktop` prints a
  new key and the SQL that retires the old one. Send the new key to the purchase email; release strangers'
  activations as above.
- **Revoke** (chargeback or abuse outside Stripe's events): `UPDATE licences_v2 SET status = 'revoked',
  revoked_at = unixepoch(), updated_at = unixepoch() WHERE id = 'lic_…'`. Renewals and content stop at once;
  the machine is no longer licensed when its lease ends (at most 30 days) or at its next renewal. Refunds and
  cancellations in Stripe do this automatically (`customer.subscription.deleted`).
- **Complimentary licences** (cofounders, staff, reviewers; no Stripe):
  `KEY_PEPPER=… bun scripts/support.ts grant argus-desktop <their email> <seats> <days ≤ 366> <role>`, e.g.
  `… grant argus-desktop sonia@… 3 365 cofounder`. It prints the key once (hand it over in person or by a private
  channel; it is not stored) and the SQL to run. The grant always has an end date and an audit row (actor
  `support`, the role, never a name); no Stripe event, refund or thank-you page can reach it (its session id is
  `grant_…`). `/manage` and `/recover` work with the email given. Extend with the UPDATE it prints; to re-key a
  leaked grant, revoke it and grant again (`reissue` is for Checkout sessions). Tests: `tests/worker.test.ts`,
  "complimentary grants".
- **Complimentary licence without `KEY_PEPPER`** (the pepper is write-only in Cloudflare): the Worker makes it.
  One admin secret makes one grant; it signs the request and is never sent.
  ```
  cd hosted/licence-cloudflare
  AGS=$(openssl rand -base64 48 | tr -d '\n')
  printf %s "$AGS" | node node_modules/wrangler/bin/wrangler.js secret put ADMIN_GRANT_SECRET
  ADMIN_GRANT_SECRET="$AGS" bun scripts/admin-grant.ts argus-desktop <email> 3 365 cofounder; unset AGS
  node node_modules/wrangler/bin/wrangler.js secret delete ADMIN_GRANT_SECRET   # optional: route back to 404
  ```
  The secret is spent after one grant (a replay or second request gets 409); set a new one for the next grant.
  A refused request (bad input, bad signature) burns nothing. Design and tests: `src/admin.ts`, `tests/worker.test.ts`.
- Receipts and invoices come from Link (Stripe); buyers manage subscriptions at https://link.com or through
  "Billing and invoices" on `/manage`.
- Logs never contain keys, emails or IPs (at most the last 4 characters of a key).
