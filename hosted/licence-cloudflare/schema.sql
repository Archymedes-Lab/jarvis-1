-- D1 schema for pay.archymedes.xyz (src/). Idempotent: safe to run again, never drops anything.
-- docs/LICENSING-ARCHITECTURE.md §6. Times are unix seconds.
--
-- Hashes only: no licence key, email address, machine id or IP address is stored.
--   key_hash   = HMAC-SHA256(KEY_PEPPER, canonical key); key_last4 is for support.
--   email_hash = HMAC-SHA256(KEY_PEPPER, lower-cased purchase email), read from the Stripe session.
--   dev_hash   = the machine fingerprint the app sends (already an HMAC of the machine id, made on the machine).
--   claim, magic-link and session ids are stored as SHA-256 of the random value.
--
-- Migration from the first payments schema (tables `licences` and `activations`, which held keys in
-- plain text): those tables are left alone and no longer read. pay.archymedes.xyz was never deployed
-- (no DNS record; wrangler.jsonc still had REPLACE_WITH_D1_ID), so they hold nothing; drop them by hand
-- after checking (docs/STRIPE-HANDOFF.md, "D1 migration").

CREATE TABLE IF NOT EXISTS licences_v2 (
  id             TEXT PRIMARY KEY,                 -- lic_… (random; public inside certificates)
  key_hash       TEXT NOT NULL UNIQUE,
  key_last4      TEXT NOT NULL,
  key_gen        INTEGER NOT NULL DEFAULT 0,       -- bumped by a support re-issue (new key, old one dead)
  session_id     TEXT NOT NULL UNIQUE,             -- the Checkout Session: same session, same licence
  offer          TEXT NOT NULL,                    -- argus-server | argus-desktop
  plan           TEXT NOT NULL,                    -- server | desktop
  seats          INTEGER NOT NULL,                 -- copied from OFFERS at creation
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  lic_exp        INTEGER,                          -- paid-through + grace; invoice.paid moves it forward
  email_hash     TEXT,
  customer       TEXT,                             -- cus_… (billing portal)
  subscription   TEXT,                             -- sub_…
  payment_intent TEXT,                             -- pi_… (one-time payments; refunds)
  livemode       INTEGER NOT NULL DEFAULT 0,
  ref            TEXT,                             -- attribution ref from /buy, if any
  emailed_at     INTEGER,                          -- set once the key email went out
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  revoked_at     INTEGER
);
CREATE INDEX IF NOT EXISTS licences_v2_subscription ON licences_v2 (subscription);
CREATE INDEX IF NOT EXISTS licences_v2_payment_intent ON licences_v2 (payment_intent);
CREATE INDEX IF NOT EXISTS licences_v2_email ON licences_v2 (email_hash);

-- A machine holding a seat. Released rows stay (released_at set) for support and the audit trail.
CREATE TABLE IF NOT EXISTS activations_v2 (
  id              TEXT PRIMARY KEY,                -- act_…
  licence_id      TEXT NOT NULL REFERENCES licences_v2 (id),
  dev_hash        TEXT NOT NULL,
  device_pubkey   TEXT NOT NULL,                   -- Ed25519 public key, base64url (signs renew/release)
  label           TEXT NOT NULL,                   -- the machine's name, as the owner sees it on /manage
  created_at      INTEGER NOT NULL,
  last_renewed_at INTEGER,
  released_at     INTEGER,
  released_by     TEXT                             -- machine | owner | support
);
CREATE INDEX IF NOT EXISTS activations_v2_licence ON activations_v2 (licence_id);
-- One live activation per (licence, device key): re-activating the same device is the same row.
CREATE UNIQUE INDEX IF NOT EXISTS activations_v2_live ON activations_v2 (licence_id, device_pubkey) WHERE released_at IS NULL;

-- Device authorization claims (buy from inside Argus; `argus licence login`).
CREATE TABLE IF NOT EXISTS claims (
  id_hash        TEXT PRIMARY KEY,                 -- SHA-256(claim_id)
  code_hash      TEXT NOT NULL UNIQUE,             -- SHA-256(user code), for /link
  dev_hash       TEXT NOT NULL,
  device_pubkey  TEXT NOT NULL,
  label          TEXT NOT NULL,
  licence_id     TEXT,                             -- set when a purchase or the owner binds it
  activation_id  TEXT,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS magic_links (
  token_hash  TEXT PRIMARY KEY,
  email_hash  TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);

CREATE TABLE IF NOT EXISTS manage_sessions (
  id_hash     TEXT PRIMARY KEY,
  email_hash  TEXT NOT NULL,
  csrf        TEXT NOT NULL,
  expires_at  INTEGER NOT NULL
);

-- Releases per licence, for the abuse limit (3 per 30 days).
CREATE TABLE IF NOT EXISTS releases (
  licence_id  TEXT NOT NULL,
  at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS releases_licence ON releases (licence_id, at);

-- Device-signed request nonces, kept for the signature window (replay protection).
CREATE TABLE IF NOT EXISTS nonces (
  nonce       TEXT PRIMARY KEY,
  expires_at  INTEGER NOT NULL
);

-- Per-email throttle for /recover and /manage (bucket is an HMAC, never an address).
CREATE TABLE IF NOT EXISTS throttle (
  bucket  TEXT NOT NULL,
  at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS throttle_bucket ON throttle (bucket, at);

-- What happened to a licence. No keys, emails or IPs.
CREATE TABLE IF NOT EXISTS audit (
  at          INTEGER NOT NULL,
  licence_id  TEXT,
  action      TEXT NOT NULL,
  actor       TEXT NOT NULL                        -- stripe | machine | owner | support | system
);
CREATE INDEX IF NOT EXISTS audit_licence ON audit (licence_id, at);

-- Stripe event ids already handled (webhook idempotency).
CREATE TABLE IF NOT EXISTS processed_events (
  id           TEXT PRIMARY KEY,
  type         TEXT NOT NULL,
  processed_at INTEGER NOT NULL
);
