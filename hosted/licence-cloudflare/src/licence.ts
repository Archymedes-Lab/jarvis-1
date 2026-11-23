// Licences, activations, certificates, claims and server-gated content. docs/LICENSING-ARCHITECTURE.md §3-§7.
//
// What each /licence/* route trusts:
//   activate       the licence key (an HMAC lookup) and the seat count
//   renew/release  a live activation and a signature by that activation's device key over
//                  (action, activation, nonce, ts); ts within 5 minutes and the nonce never seen before
//   claim/poll     poll is signed by the device key that opened the claim
//   content        same as renew, plus the licence's plan; the pack comes back signed by the licence key
// Every route is rate-limited per IP, reads at most 4 KB of JSON, and answers with a stable `code`.
import { DEV, DPK, NONCE, SKEW, signJws, signedMessage, verifyDevice } from "./cert";
import { deriveKey, emailHash, keyHash, parseKey, randomId, sha256Hex } from "./keys";
import { PACKS } from "./packs";
import { idOf, periodEnd, stripe, StripeError, subscriptionQuantity } from "./stripe";
import { type Activation, audit, CLAIM_BIND_WINDOW, CLAIM_TTL, type Deps, type Env, fail, iso, json, LEASE, type Licence,
         limited, OFFERS, payOrigin, pepper, RELEASE_WINDOW, RELEASES_ALLOWED, RENEW_BEFORE, sec, standing,
         SUBSCRIPTION_GRACE, support, constantTimeEqual } from "./env";

const MAX_JSON = 4096;
const REF = /^[A-Za-z0-9_-]{1,64}$/;
export const CLAIM_ID = /^clm_[0-9A-Z]{32}$/;
const ACT_ID = /^act_[0-9A-Z]{20}$/;

// ---------------------------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------------------------
export async function keyOf(env: Env, lic: Licence): Promise<string> {
  return deriveKey(pepper(env), lic.session_id, lic.key_gen, OFFERS[lic.offer].kind);
}

/** The licence for a paid Argus Checkout Session: created on first call, the same row afterwards. */
export async function issue(env: Env, deps: Deps, session: any): Promise<{ lic: Licence; created: boolean }> {
  const email = typeof session.customer_details?.email === "string" ? session.customer_details.email : null;
  const eh = email ? await emailHash(pepper(env), email) : null;
  const existing = await env.DB.prepare("SELECT * FROM licences_v2 WHERE session_id = ?").bind(session.id).first<Licence>();
  if (existing) {
    if (!existing.email_hash && eh) {
      await env.DB.prepare("UPDATE licences_v2 SET email_hash = ? WHERE id = ?").bind(eh, existing.id).run();
      existing.email_hash = eh;
    }
    return { lic: existing, created: false };
  }
  const offerId = String(session.metadata?.offer || "");
  const offer = OFFERS[offerId];
  if (!offer) throw new Error("session has no known offer");
  const now = sec(deps);
  let expires: number;
  let seats = offer.seats;
  const subId = idOf(session.subscription);
  if (offer.mode === "payment") {
    expires = (typeof session.created === "number" ? session.created : now) + (offer.days ?? 30) * 86400;
  } else {
    const sub = typeof session.subscription === "object" && session.subscription
      ? session.subscription
      : await stripe(deps.fetch, env.STRIPE_SECRET_KEY, "GET", `/subscriptions/${encodeURIComponent(subId || "")}`);
    const end = periodEnd(sub);
    if (end == null) throw new Error("subscription has no period end");
    expires = end + SUBSCRIPTION_GRACE;
    if (offer.fleet) seats = subscriptionQuantity(sub) ?? offer.seats;
  }
  const key = await deriveKey(pepper(env), session.id, 0, offer.kind);
  const ref = typeof session.metadata?.ref === "string" && REF.test(session.metadata.ref) ? session.metadata.ref : null;
  const id = randomId("lic_");
  await env.DB.prepare(
    `INSERT OR IGNORE INTO licences_v2 (id, key_hash, key_last4, key_gen, session_id, offer, plan, seats, status, lic_exp,
       email_hash, customer, subscription, payment_intent, livemode, ref, created_at, updated_at)
     VALUES (?, ?, ?, 0, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, await keyHash(pepper(env), key), key.slice(-4), session.id, offerId, offer.plan, seats, expires, eh,
          idOf(session.customer), subId, idOf(session.payment_intent), session.livemode ? 1 : 0, ref, now, now).run();
  // A concurrent call may have won the insert; the session's row is the answer either way.
  const lic = await env.DB.prepare("SELECT * FROM licences_v2 WHERE session_id = ?").bind(session.id).first<Licence>();
  if (!lic) throw new Error("licence was not stored");
  const created = lic.id === id;
  if (created) {
    await audit(env, deps, lic.id, "issued", "stripe");
    console.log(`issued ${offerId} …${lic.key_last4}`);
    const d = discountOf(session);
    if (d) {
      // Bookkeeping only: a failure here must never cost the buyer their licence.
      try { await audit(env, deps, lic.id, `discount ${d.promotion ?? "coupon"} ${d.amount} ${d.currency}`, "stripe"); }
      catch { console.log("discount audit failed"); }
    }
  }
  return { lic, created };
}

/**
 * The discount a paid session carried, for the audit trail: Stripe's promotion code id (never the code a buyer
 * typed) and the amount taken off, in minor units. Null when the session had no discount or an odd shape.
 * Not a licence column: adding one needs an ALTER TABLE on the live D1 that must land before this code.
 */
export function discountOf(session: any): { promotion: string | null; amount: number; currency: string } | null {
  const amount = session?.total_details?.amount_discount;
  if (!Number.isInteger(amount) || amount <= 0) return null;
  const promo = idOf(session?.discounts?.[0]?.promotion_code);
  const currency = typeof session?.currency === "string" && /^[a-z]{3}$/.test(session.currency) ? session.currency : "xxx";
  return { promotion: promo && /^promo_[A-Za-z0-9]{1,255}$/.test(promo) ? promo : null, amount, currency };
}

/** "one server", "12 servers", "one computer". */
export const covers = (plan: string, seats: number) =>
  seats === 1 ? (plan === "server" ? "one server" : "one computer") : `${seats} ${plan === "server" ? "servers" : "computers"}`;

export function keyEmail(env: Env, lic: Licence, key: string): { subject: string; text: string } {
  const offer = OFFERS[lic.offer];
  const pay = payOrigin(env);
  const text = [
    `Thank you for buying ${offer.product}.`, "",
    `Your licence key: ${key}`, "",
    "To activate it:",
    offer.plan === "server"
      ? `  On ${lic.seats > 1 ? `each server (up to ${lic.seats})` : "the server"}, run:  argus licence activate ${key}`
      : "  In Argus, open Licence, paste the key and choose Activate.",
    `  Or open this on the computer that runs Argus: argus://activate?key=${key}`, "",
    `It covers ${covers(offer.plan, lic.seats)}. ` +
      "Argus renews its licence by itself while the subscription is paid.", "",
    `Move it to another machine, see where it is active, or manage billing: ${pay}/manage`,
    `Lost this email? ${pay}/recover`,
    "Receipts and invoices come from Stripe, the merchant of record.", "", "Archymedes",
  ].join("\n");
  return { subject: `Your ${offer.product} licence key`, text };
}

// ---------------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------------
export async function certificate(env: Env, deps: Deps, lic: Licence, act: Activation) {
  const now = sec(deps);
  const exp = lic.lic_exp == null ? now + LEASE : Math.min(now + LEASE, lic.lic_exp);
  const claims = { iss: "pay.archymedes.xyz", aud: "argus", sub: lic.id, plan: lic.plan, seats: lic.seats, act: act.id,
                   dev: act.dev_hash, dpk: act.device_pubkey, iat: now, exp, lic_exp: lic.lic_exp,
                   renew_after: Math.max(now, exp - RENEW_BEFORE) };
  return { certificate: await signJws(env.LICENCE_SIGNING_KEY, claims), activation_id: act.id, licence_id: lic.id,
           plan: lic.plan, product: OFFERS[lic.offer].product, lease_until: iso(exp), expires_at: iso(lic.lic_exp),
           renew_after: iso(claims.renew_after), label: act.label };
}

// ---------------------------------------------------------------------------------------------
// Seats
// ---------------------------------------------------------------------------------------------
const live = (env: Env, licenceId: string) =>
  env.DB.prepare("SELECT * FROM activations_v2 WHERE licence_id = ? AND released_at IS NULL ORDER BY created_at")
    .bind(licenceId).all<Activation>().then((r) => r.results ?? []);

export type Device = { dev: string; dpk: string; label: string };
export type Seat = { ok: true; act: Activation } | { ok: false; machines: { label: string; since: string | null }[] };

/**
 * Give `device` a seat on `lic`. The same device key gets its existing activation back. The same machine
 * with a new device key (Argus reinstalled) takes over its own seat. Otherwise a free seat, or a conflict.
 */
export async function seat(env: Env, deps: Deps, lic: Licence, device: Device, actor: string): Promise<Seat> {
  const now = sec(deps);
  const acts = await live(env, lic.id);
  const same = acts.find((a) => constantTimeEqual(a.device_pubkey, device.dpk));
  if (same) {
    if (!constantTimeEqual(same.dev_hash, device.dev)) return { ok: false, machines: acts.map(view) };
    await env.DB.prepare("UPDATE activations_v2 SET label = ? WHERE id = ?").bind(device.label, same.id).run();
    return { ok: true, act: { ...same, label: device.label } };
  }
  const sameMachine = acts.find((a) => constantTimeEqual(a.dev_hash, device.dev));
  if (sameMachine) {
    // Not a move: the seat stays on this machine, so it does not count toward the release limit.
    await env.DB.prepare("UPDATE activations_v2 SET released_at = ?, released_by = 'reinstall' WHERE id = ?").bind(now, sameMachine.id).run();
  } else if (acts.length >= lic.seats) {
    return { ok: false, machines: acts.map(view) };
  }
  const id = randomId("act_");
  await env.DB.prepare(`INSERT OR IGNORE INTO activations_v2 (id, licence_id, dev_hash, device_pubkey, label, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)`).bind(id, lic.id, device.dev, device.dpk, device.label, now).run();
  const after = await live(env, lic.id);
  const mine = after.find((a) => a.id === id);
  if (!mine) {
    // Lost a race to the same device key: that row is ours too.
    const other = after.find((a) => a.device_pubkey === device.dpk);
    return other ? { ok: true, act: other } : { ok: false, machines: after.map(view) };
  }
  if (after.length > lic.seats) {
    // Two machines raced for the last seat; the later one gives it back.
    await env.DB.prepare("DELETE FROM activations_v2 WHERE id = ?").bind(id).run();
    return { ok: false, machines: after.filter((a) => a.id !== id).map(view) };
  }
  await audit(env, deps, lic.id, "activated", actor);
  return { ok: true, act: mine };
}

const view = (a: Activation) => ({ label: a.label, since: iso(a.created_at) });

export async function releasesLeft(env: Env, deps: Deps, licenceId: string): Promise<number> {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM releases WHERE licence_id = ? AND at > ?")
    .bind(licenceId, sec(deps) - RELEASE_WINDOW).first<{ n: number }>();
  return Math.max(0, RELEASES_ALLOWED - (r?.n ?? 0));
}

/** Free a seat. "limit" when the licence has used its releases for this period. */
export async function release(env: Env, deps: Deps, act: Activation, actor: string): Promise<"released" | "already" | "limit"> {
  if (act.released_at) return "already";
  if ((await releasesLeft(env, deps, act.licence_id)) <= 0) return "limit";
  const now = sec(deps);
  const r = await env.DB.prepare("UPDATE activations_v2 SET released_at = ?, released_by = ? WHERE id = ? AND released_at IS NULL")
    .bind(now, actor, act.id).run();
  if (!r.meta?.changes) return "already";
  await env.DB.prepare("INSERT INTO releases (licence_id, at) VALUES (?, ?)").bind(act.licence_id, now).run();
  await audit(env, deps, act.licence_id, "released", actor);
  return "released";
}

export const releaseLimitText = (env: Env) =>
  `this licence has been moved ${RELEASES_ALLOWED} times in the last 30 days, the most allowed; ` +
  `email ${support(env)} and we will move it for you`;

// ---------------------------------------------------------------------------------------------
// Claims (device authorization: buy from inside Argus, `argus licence login`)
// ---------------------------------------------------------------------------------------------
export type Claim = { id_hash: string; code_hash: string; dev_hash: string; device_pubkey: string; label: string;
                      licence_id: string | null; activation_id: string | null; created_at: number; expires_at: number };

export const normCode = (c: unknown) => (typeof c === "string" ? c.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1") : "");

/** Bind a claim to a licence and seat its device. Used by a purchase that carried metadata[claim] and by /link. */
export async function bindClaim(env: Env, deps: Deps, claim: Claim, lic: Licence, actor: string): Promise<Seat | "expired" | "taken"> {
  const now = sec(deps);
  if (claim.licence_id) return "taken";
  if (now > claim.created_at + CLAIM_BIND_WINDOW) return "expired";
  const s = await seat(env, deps, lic, { dev: claim.dev_hash, dpk: claim.device_pubkey, label: claim.label }, actor);
  if (!s.ok) return s;
  await env.DB.prepare("UPDATE claims SET licence_id = ?, activation_id = ?, expires_at = MAX(expires_at, ?) WHERE id_hash = ? AND licence_id IS NULL")
    .bind(lic.id, s.act.id, now + CLAIM_TTL, claim.id_hash).run();
  return s;
}

export async function claimById(env: Env, claimId: string): Promise<Claim | null> {
  if (!CLAIM_ID.test(claimId)) return null;
  return env.DB.prepare("SELECT * FROM claims WHERE id_hash = ?").bind(await sha256Hex(claimId)).first<Claim>();
}

// ---------------------------------------------------------------------------------------------
// Device-signed requests
// ---------------------------------------------------------------------------------------------
/** null when `body` carries a fresh signature by `dpk` over (action, subject, nonce, ts); otherwise the refusal. */
async function proof(env: Env, deps: Deps, body: any, action: string, subject: string, dpk: string): Promise<Response | null> {
  const now = sec(deps);
  const ts = body.ts, nonce = body.nonce;
  if (typeof ts !== "number" || !Number.isInteger(ts) || typeof nonce !== "string" || !NONCE.test(nonce))
    return fail(400, "bad_request", "send ts (unix seconds), nonce and sig");
  if (Math.abs(now - ts) > SKEW)
    return fail(401, "clock", "this request's time is more than 5 minutes from the licence service's; check the computer's clock");
  if (!(await verifyDevice(dpk, signedMessage(action, subject, nonce, ts), body.sig)))
    return fail(401, "bad_signature", "this request is not signed by the device that holds the activation");
  await env.DB.prepare("DELETE FROM nonces WHERE expires_at < ?").bind(now).run();
  const r = await env.DB.prepare("INSERT OR IGNORE INTO nonces (nonce, expires_at) VALUES (?, ?)").bind(nonce, now + 2 * SKEW).run();
  if (!r.meta?.changes) return fail(401, "replay", "this request was already used");
  return null;
}

// ---------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------
async function readJson(req: Request): Promise<any> {
  const raw = await req.text();
  if (raw.length > MAX_JSON) return undefined;
  try { const v = JSON.parse(raw); return v && typeof v === "object" && !Array.isArray(v) ? v : undefined; } catch { return undefined; }
}

const cleanLabel = (v: unknown) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f<>]/g, "").trim().slice(0, 60) : "") || "unnamed";

function refusedStanding(st: string, env: Env): Response {
  return st === "revoked"
    ? fail(403, "revoked", `this licence was cancelled or refunded; buy a new one at ${payOrigin(env)}/buy/argus-server or ${payOrigin(env)}/buy/argus-desktop`)
    : fail(403, "expired", `this licence's subscription has ended; renew it from ${payOrigin(env)}/manage`);
}

function seatTaken(env: Env, machines: { label: string; since: string | null }[]): Response {
  const where = machines.map((m) => `"${m.label}"`).join(", ") || "another machine";
  return fail(409, "seat_taken",
    `this key is already active on ${where}. Deactivate it there (argus licence deactivate), or release that machine at ` +
    `${payOrigin(env)}/manage, then activate here again.`, { machines, manage_url: `${payOrigin(env)}/manage` });
}

export async function licenceRoute(req: Request, env: Env, deps: Deps, action: string): Promise<Response> {
  if (await limited(env.RL_LICENCE, req, "licence:")) return fail(429, "rate_limited", "too many requests; try again in a minute");
  const body = await readJson(req);
  if (!body) return fail(400, "bad_request", "send a JSON object");
  const now = sec(deps);

  if (action === "activate" || action === "portal") {
    const parsed = parseKey(body.key);
    if (!parsed.ok) return parsed.reason === "check"
      ? fail(400, "bad_check", "one character of this key is wrong (the check character does not match); compare it with your email")
      : fail(400, "bad_key", "that is not an Argus licence key (it starts with ARGUS-SRV- or ARGUS-DSK-)");
    const lic = await env.DB.prepare("SELECT * FROM licences_v2 WHERE key_hash = ?").bind(await keyHash(pepper(env), parsed.key)).first<Licence>();
    if (!lic) return fail(404, "unknown_key", "the licence service does not know this key; check it against your email");
    if (action === "portal") return portal(env, deps, lic);
    if (typeof body.dev !== "string" || !DEV.test(body.dev) || typeof body.dpk !== "string" || !DPK.test(body.dpk))
      return fail(400, "bad_request", "send dev (fingerprint) and dpk (device public key)");
    const st = standing(lic, now);
    if (st !== "active") return refusedStanding(st, env);
    const s = await seat(env, deps, lic, { dev: body.dev, dpk: body.dpk, label: cleanLabel(body.label) }, "machine");
    if (!s.ok) return seatTaken(env, s.machines);
    return json(await certificate(env, deps, lic, s.act));
  }

  if (action === "renew" || action === "release") {
    if (typeof body.act !== "string" || !ACT_ID.test(body.act)) return fail(400, "bad_request", "send act (the activation id)");
    const act = await env.DB.prepare("SELECT * FROM activations_v2 WHERE id = ?").bind(body.act).first<Activation>();
    if (!act) return fail(404, "not_activated", "this machine is not activated; activate it again with your key");
    const refused = await proof(env, deps, body, action, act.id, act.device_pubkey);
    if (refused) return refused;
    if (action === "release") {
      const r = await release(env, deps, act, "machine");
      if (r === "limit") return fail(429, "release_limit", releaseLimitText(env));
      return json({ released: true, already: r === "already" });
    }
    if (act.released_at) return fail(404, "not_activated", "this machine was released from the licence; activate it again with your key");
    const lic = await env.DB.prepare("SELECT * FROM licences_v2 WHERE id = ?").bind(act.licence_id).first<Licence>();
    if (!lic) return fail(404, "not_activated", "this activation has no licence");
    const st = standing(lic, now);
    if (st !== "active") return refusedStanding(st, env);
    await env.DB.prepare("UPDATE activations_v2 SET last_renewed_at = ? WHERE id = ?").bind(now, act.id).run();
    return json(await certificate(env, deps, lic, act));
  }

  if (action === "claim") {
    if (typeof body.dev !== "string" || !DEV.test(body.dev) || typeof body.dpk !== "string" || !DPK.test(body.dpk))
      return fail(400, "bad_request", "send dev (fingerprint) and dpk (device public key)");
    const claimId = randomId("clm_", 32);
    const raw = randomId("", 8);
    const code = `${raw.slice(0, 4)}-${raw.slice(4)}`;
    await env.DB.prepare(`INSERT INTO claims (id_hash, code_hash, dev_hash, device_pubkey, label, created_at, expires_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(await sha256Hex(claimId), await sha256Hex(raw), body.dev, body.dpk, cleanLabel(body.label), now, now + CLAIM_TTL).run();
    const pay = payOrigin(env);
    return json({ claim_id: claimId, user_code: code, verify_url: `${pay}/link`, expires_in: CLAIM_TTL, interval: 5,
                  buy: { server: `${pay}/buy/argus-server?claim=${claimId}`, desktop: `${pay}/buy/argus-desktop?claim=${claimId}` } });
  }

  if (action === "poll") {
    const claimId = typeof body.claim_id === "string" ? body.claim_id : "";
    const claim = await claimById(env, claimId);
    if (!claim) return fail(404, "unknown_claim", "this purchase link is not known; start again from Argus");
    const refused = await proof(env, deps, body, "poll", claimId, claim.device_pubkey);
    if (refused) return refused;
    if (!claim.licence_id) {
      if (now > claim.expires_at) return fail(410, "expired", "this purchase link has expired; start again from Argus, or enter the key from your email");
      return json({ status: "pending" }, 202);
    }
    const lic = await env.DB.prepare("SELECT * FROM licences_v2 WHERE id = ?").bind(claim.licence_id).first<Licence>();
    const act = await env.DB.prepare("SELECT * FROM activations_v2 WHERE id = ? AND released_at IS NULL").bind(claim.activation_id).first<Activation>();
    if (!lic || !act) return fail(404, "not_activated", "the purchase finished but this machine is no longer activated; enter the key from your email");
    const st = standing(lic, now);
    if (st !== "active") return refusedStanding(st, env);
    return json({ status: "active", key: await keyOf(env, lic), ...(await certificate(env, deps, lic, act)) });
  }
  return fail(404, "not_found", "not found");
}

async function portal(env: Env, deps: Deps, lic: Licence): Promise<Response> {
  const url = await portalUrl(env, deps, lic);
  return url ? json({ url }) : fail(502, "portal_unavailable", `the billing portal is not available right now; try ${payOrigin(env)}/manage later`);
}

export async function portalUrl(env: Env, deps: Deps, lic: Licence): Promise<string | null> {
  if (!lic.customer) return null;
  try {
    const s = await stripe<{ url?: string }>(deps.fetch, env.STRIPE_SECRET_KEY, "POST", "/billing_portal/sessions",
      new URLSearchParams({ customer: lic.customer, return_url: `${payOrigin(env)}/manage/home` }));
    return s.url || null;
  } catch (err) {
    console.log(`portal: ${err instanceof StripeError ? err.message : "error"}`);
    return null;
  }
}

/**
 * POST /content/:pack — premium content the server delivers, so a modified client gets nothing.
 * Needs a live activation, a fresh device signature over ("content", "<pack>:<act>") and a plan the pack is for.
 * The answer is a JWS (typ argus-pack+jwt) signed by the licence key, bound to the activation.
 */
export async function contentRoute(req: Request, env: Env, deps: Deps, packId: string): Promise<Response> {
  if (await limited(env.RL_LICENCE, req, "content:")) return fail(429, "rate_limited", "too many requests; try again in a minute");
  const pack = PACKS[packId];
  if (!pack) return fail(404, "unknown_pack", "there is no such content pack");
  const body = await readJson(req);
  if (!body || typeof body.act !== "string" || !ACT_ID.test(body.act)) return fail(400, "bad_request", "send act, nonce, ts and sig");
  const act = await env.DB.prepare("SELECT * FROM activations_v2 WHERE id = ? AND released_at IS NULL").bind(body.act).first<Activation>();
  if (!act) return fail(404, "not_activated", "this machine is not activated");
  const refused = await proof(env, deps, body, "content", `${packId}:${act.id}`, act.device_pubkey);
  if (refused) return refused;
  const lic = await env.DB.prepare("SELECT * FROM licences_v2 WHERE id = ?").bind(act.licence_id).first<Licence>();
  const st = lic ? standing(lic, sec(deps)) : "revoked";
  if (!lic || st !== "active") return refusedStanding(st, env);
  if (!pack.plans.includes(lic.plan)) return fail(403, "wrong_plan", `this content is part of ${pack.plans.map((p) => `Argus ${p}`).join(" or ")}`);
  const now = sec(deps);
  const signed = await signJws(env.LICENCE_SIGNING_KEY, { iss: "pay.archymedes.xyz", aud: "argus", sub: lic.id, act: act.id,
    pack: packId, version: pack.version, iat: now, data: pack.data }, "argus-pack+jwt");
  return json({ pack: signed, version: pack.version });
}

