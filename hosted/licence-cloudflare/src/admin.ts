// POST /admin/grant: a complimentary licence made inside the Worker, for an owner who does not hold
// KEY_PEPPER (it is write-only in Cloudflare). Client: scripts/admin-grant.ts. Tests: tests/worker.test.ts.
//
// Invariants:
// - Off unless ADMIN_GRANT_SECRET (32+ characters, a Worker secret) is set: the route is a plain 404.
// - The secret never crosses the network: the request carries HMAC-SHA256(secret, "<t>.<body>") in
//   X-Admin-Signature (`t=…,v1=…`, the Stripe format), compared in constant time, t within 5 minutes.
// - One secret, one grant: the secret's SHA-256 is burnt in processed_events before anything is written,
//   atomically (INSERT OR IGNORE), so a replayed or second request is refused even inside the 5 minutes.
//   Another grant needs a new secret (`wrangler secret put ADMIN_GRANT_SECRET`).
// - Input is validated (src/grant.ts limits) before the secret is burnt; a refused request burns nothing.
// - The licence row and its audit row are written in one D1 batch. The key is in the response only.
import { fail, json, limited, type Deps, type Env } from "./env";
import { grant } from "./grant";
import { sha256Hex } from "./keys";
import { verifyStripeSignature } from "./stripe";

export const ADMIN_TOLERANCE = 300;
const MAX_BODY = 2048;

export async function adminGrant(req: Request, env: Env, deps: Deps): Promise<Response> {
  const secret = env.ADMIN_GRANT_SECRET || "";
  if (secret.length < 32) return fail(404, "not_found", "not found");
  if (await limited(env.RL_LICENCE, req, "admin:")) return fail(429, "rate_limited", "too many requests");
  const raw = await req.text();
  if (raw.length > MAX_BODY) return fail(413, "too_large", "request too large");
  if (!(await verifyStripeSignature(secret, raw, req.headers.get("X-Admin-Signature"), deps.now(), ADMIN_TOLERANCE)))
    return fail(401, "bad_signature", "signature missing, wrong or older than 5 minutes");
  let body: any;
  try { body = JSON.parse(raw); } catch { return fail(400, "bad_request", "body is not JSON"); }
  const now = Math.floor(deps.now() / 1000);
  let g;
  try {
    g = await grant(env.KEY_PEPPER || "", {
      offer: String(body?.offer ?? ""), email: String(body?.email ?? ""), seats: Number(body?.seats),
      days: Number(body?.days), note: String(body?.note ?? ""), livemode: /^(sk|rk)_live_/.test(env.STRIPE_SECRET_KEY || ""),
    }, now);
  } catch (err) {
    return fail(400, "bad_request", (err as Error).message);
  }
  const burnt = await env.DB.prepare("INSERT OR IGNORE INTO processed_events (id, type, processed_at) VALUES (?, 'admin_grant', ?)")
    .bind(`admin-secret:${await sha256Hex(secret)}`, now).run();
  if (!burnt.meta?.changes) return fail(409, "secret_used", "this admin secret was already used for a grant; set a new one");
  await env.DB.batch(g.statements.map(([sql, args]) => env.DB.prepare(sql).bind(...args)));
  console.log(`admin grant ${body.offer} …${g.key.slice(-4)}`);
  return json({ key: g.key, licence_id: g.licenceId, ends: new Date(g.licExp * 1000).toISOString().slice(0, 10) });
}
