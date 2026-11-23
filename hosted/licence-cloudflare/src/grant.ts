// Complimentary licences (cofounders, staff, reviewers): a licence with no Stripe payment behind it.
// Used by scripts/support.ts `grant` and the signed POST /admin/grant (src/admin.ts); tests/worker.test.ts.
//
// Invariants:
// - Same storage rules as a bought licence: only HMAC hashes of the key and email are stored; the key is
//   returned once for the operator to hand over and is never written anywhere.
// - No Stripe path can reach it: the session id is `grant_…`, which the webhook, the thank-you page and
//   refunds never match (they require `cs_test_`/`cs_live_`), and it has no customer, subscription or
//   payment intent.
// - It always ends (lic_exp is set, at most MAX_DAYS away), so the retention purge and renewal rules
//   apply exactly as for a bought licence. Extending it is an explicit, audited UPDATE.
// - Every grant writes an audit row (actor `support`) naming who it is for, by role only.
import { OFFERS } from "./env";
import { deriveKey, emailHash, keyHash, randomId } from "./keys";

export const MAX_DAYS = 366;
export const GRANT_ID = /^grant_[0-9A-Z]{20}$/;
const NOTE = /^[a-z0-9][a-z0-9 ._-]{0,39}$/;

export interface GrantOptions {
  offer: string;   // a key of OFFERS
  email: string;   // the holder's email: /manage and /recover work with it
  seats: number;   // computers or servers on one key
  days: number;    // until lic_exp, 1..MAX_DAYS
  note: string;    // role, e.g. "cofounder" (goes into the audit row; never a name)
  livemode: boolean;
}

export interface Grant { key: string; licenceId: string; sessionId: string; licExp: number; statements: [string, unknown[]][] }

export async function grant(pepper: string, o: GrantOptions, now: number): Promise<Grant> {
  const offer = OFFERS[o.offer];
  if (!offer) throw new Error(`unknown offer ${o.offer} (one of ${Object.keys(OFFERS).join(", ")})`);
  const max = offer.fleet?.max ?? offer.seats;
  if (!Number.isInteger(o.seats) || o.seats < 1 || o.seats > max) throw new Error(`seats must be 1..${max}`);
  if (!Number.isInteger(o.days) || o.days < 1 || o.days > MAX_DAYS) throw new Error(`days must be 1..${MAX_DAYS}`);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(o.email)) throw new Error("email does not look like an address");
  if (!NOTE.test(o.note)) throw new Error("note: a short lower-case role such as 'cofounder' (no names)");
  const sessionId = randomId("grant_");
  const licenceId = randomId("lic_");
  const key = await deriveKey(pepper, sessionId, 0, offer.kind);
  const licExp = now + o.days * 86400;
  return {
    key, licenceId, sessionId, licExp,
    statements: [
      [`INSERT INTO licences_v2 (id, key_hash, key_last4, key_gen, session_id, offer, plan, seats, status, lic_exp,
          email_hash, customer, subscription, payment_intent, livemode, ref, created_at, updated_at)
        VALUES (?, ?, ?, 0, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL, NULL, ?, 'grant', ?, ?)`,
       [licenceId, await keyHash(pepper, key), key.slice(-4), sessionId, o.offer, offer.plan, o.seats, licExp,
        await emailHash(pepper, o.email), o.livemode ? 1 : 0, now, now]],
      ["INSERT INTO audit (at, licence_id, action, actor) VALUES (?, ?, ?, 'support')",
       [now, licenceId, `granted (${o.note}, ${o.seats} seat(s), ${o.days} days)`]],
    ],
  };
}

/** The statements as SQL text for `wrangler d1 execute --command` (values are literals, quoted). */
export function asSql(statements: [string, unknown[]][]): string {
  const lit = (v: unknown) => v === null ? "NULL" : typeof v === "number" ? String(v) : `'${String(v).replace(/'/g, "''")}'`;
  return statements.map(([sql, args]) => {
    let i = 0;
    return sql.replace(/\?/g, () => lit(args[i++])).replace(/\s+/g, " ").trim() + ";";
  }).join(" ");
}
