// Shared configuration and helpers for pay.archymedes.xyz. docs/LICENSING-ARCHITECTURE.md.
import type { Fetch } from "./stripe";
import type { Kind } from "./keys";

export interface Env {
  DB: D1Database;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_API_KEY?: string;
  SITE_ORIGIN: string;
  PAY_ORIGIN?: string;            // https://pay.archymedes.xyz (links in emails and pages)
  MANAGED_PAYMENTS?: string;
  MAIL_FROM?: string;
  SUPPORT_EMAIL?: string;
  LICENCE_SIGNING_KEY?: string;   // secret: "<kid>.<base64url PKCS#8 Ed25519>" (scripts/licence-keygen.ts)
  KEY_PEPPER?: string;            // secret: 32+ random characters; HMAC for key, email and seal keys
  ADMIN_GRANT_SECRET?: string;    // secret, optional: 32+ characters, one complimentary grant (src/admin.ts)
  RL_BUY?: RateLimit;
  RL_LICENCE?: RateLimit;
  RL_EMAIL?: RateLimit;
}

export interface Deps { fetch: Fetch; now: () => number /* ms */; promoLookupMs?: number }

export type Mode = "payment" | "subscription";
export type Plan = "server" | "desktop";
/** fleet: the buyer picks how many machines at checkout (1..max); the licence's seats follow the subscription quantity. */
export type Offer = { lookup: string; mode: Mode; kind: Kind; product: string; plan: Plan; seats: number; days?: number; fleet?: { max: number } };

/** Above this many machines the buyer talks to us (enterprise terms, invoicing). */
export const FLEET_MAX = 1000;
export const TEAM_MAX = 100;

// Owner decisions (archymedes-gtm docs/PRICE-BOOK.md, catalog/stripe.ts):
//   2026-11-04  Desktop $79/year per computer.
//   2026-11-05  Desktop also $15/month. Server is one fleet licence priced by size, graduated per server per year:
//               1-10 $50, 11-50 $40, 51-250 $30, 251-1000 $20; above 1000, enterprise terms by contact.
//   2026-11-06  Desktop can be bought for a team: 1-100 computers on one key, same price per computer.
// Seats live here, except for a fleet offer, where they are the subscription quantity.
export const OFFERS: Record<string, Offer> = {
  "argus-server": { lookup: "argus_server_fleet_usd_year_v1", mode: "subscription", kind: "SERVER", product: "Argus Server",
                    plan: "server", seats: 1, fleet: { max: FLEET_MAX } },
  "argus-desktop": { lookup: "argus_desktop_usd_7900_year", mode: "subscription", kind: "DESKTOP", product: "Argus Desktop",
                     plan: "desktop", seats: 1, fleet: { max: TEAM_MAX } },
  "argus-desktop-monthly": { lookup: "argus_desktop_usd_1500_month", mode: "subscription", kind: "DESKTOP", product: "Argus Desktop",
                             plan: "desktop", seats: 1, fleet: { max: TEAM_MAX } },
};

export const SUBSCRIPTION_GRACE = 14 * 86400;   // EULA §3: 14 days past the paid-through date (owner, 2026-11-09)
export const LEASE = 30 * 86400;              // a certificate is good offline for 30 days, never past lic_exp
export const RENEW_BEFORE = 7 * 86400;        // renew_after = exp - 7 days
export const RELEASES_ALLOWED = 3;            // releases (moves) per licence per RELEASE_WINDOW
export const RELEASE_WINDOW = 30 * 86400;
export const CLAIM_TTL = 30 * 60;             // a claim can be polled this long (from creation or binding)
export const CLAIM_BIND_WINDOW = 24 * 3600;   // a purchase can still bind a claim this long after it was made
export const MAGIC_TTL = 15 * 60;
export const SESSION_TTL = 30 * 60;
export const REVEAL_WINDOW = 24 * 3600;       // the thank-you page shows the key this long after purchase
export const EMAIL_PER_HOUR = 3;              // /recover and /manage mails per email per hour

export const SECURITY_HEADERS: Record<string, string> = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

export const json = (data: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...SECURITY_HEADERS, ...extra } });
export const fail = (status: number, code: string, error: string, more: Record<string, unknown> = {}, extra: Record<string, string> = {}) =>
  json({ code, error, ...more }, status, extra);

export const sec = (d: Deps) => Math.floor(d.now() / 1000);
export const iso = (s: number | null | undefined) => (s == null ? null : new Date(s * 1000).toISOString());
export const managed = (env: Env) => env.MANAGED_PAYMENTS !== "0";
export const siteOrigin = (env: Env) => (env.SITE_ORIGIN || "https://www.archymedes.xyz").replace(/\/+$/, "");
export const payOrigin = (env: Env) => (env.PAY_ORIGIN || "https://pay.archymedes.xyz").replace(/\/+$/, "");
export const support = (env: Env) => env.SUPPORT_EMAIL || "support@archymedes.xyz";
export const pricingUrl = (env: Env, lang = "en") => `${siteOrigin(env)}/${lang}/solutions/argus/#pricing`;

export function pepper(env: Env): string {
  if (!env.KEY_PEPPER || env.KEY_PEPPER.length < 32) throw new Error("KEY_PEPPER is not set (32+ characters)");
  return env.KEY_PEPPER;
}

export async function limited(rl: RateLimit | undefined, req: Request, scope = ""): Promise<boolean> {
  if (!rl) return false;
  try {
    const { success } = await rl.limit({ key: `${scope}${req.headers.get("CF-Connecting-IP") || "unknown"}` });
    return !success;
  } catch { return false; }
}

export async function audit(env: Env, deps: Deps, licenceId: string | null, action: string, actor: string): Promise<void> {
  await env.DB.prepare("INSERT INTO audit (at, licence_id, action, actor) VALUES (?, ?, ?, ?)")
    .bind(sec(deps), licenceId, action, actor).run();
}

export function constantTimeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

/** Licence row (licences_v2). */
export type Licence = { id: string; key_hash: string; key_last4: string; key_gen: number; session_id: string; offer: string;
  plan: Plan; seats: number; status: "active" | "revoked"; lic_exp: number | null; email_hash: string | null;
  customer: string | null; subscription: string | null; payment_intent: string | null; livemode: number; ref: string | null;
  emailed_at: number | null; created_at: number; updated_at: number; revoked_at: number | null };

/** Activation row (activations_v2). */
export type Activation = { id: string; licence_id: string; dev_hash: string; device_pubkey: string; label: string;
  created_at: number; last_renewed_at: number | null; released_at: number | null; released_by: string | null };

/** "active", "revoked" or "expired" for a licence at `now`. */
export const standing = (lic: Licence, now: number) =>
  lic.status === "revoked" ? "revoked" : lic.lic_exp != null && now >= lic.lic_exp ? "expired" : "active";
