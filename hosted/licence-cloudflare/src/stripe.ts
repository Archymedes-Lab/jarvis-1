// Stripe over fetch and Web Crypto: no SDK, nothing that depends on Node.
// Same approach as archymedes-site/workers/app/src/stripe.ts and orion/server/billing.ts.

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export const STRIPE_API = "https://api.stripe.com/v1";
// Pinned so payloads keep one shape. Managed Payments needs 2025-03-31.basil or later.
// Webhook endpoints are created with the same api_version (docs/STRIPE-HANDOFF.md).
export const STRIPE_VERSION = "2026-10-28.endive";

export class StripeError extends Error {
  constructor(public readonly status: number, public readonly code: string | undefined) {
    super(`Stripe answered HTTP ${status}${code ? ` (${code})` : ""}`);
  }
}

/** One Stripe API call. `form` is sent as application/x-www-form-urlencoded (POST) or a query (GET). */
export async function stripe<T = any>(fetcher: Fetch, secretKey: string, method: "GET" | "POST", path: string,
                                      form?: URLSearchParams): Promise<T> {
  if (!secretKey) throw new StripeError(0, "no_secret_key");
  const query = method === "GET" && form ? `?${form}` : "";
  const res = await fetcher(`${STRIPE_API}${path}${query}`, {
    method,
    headers: {
      Authorization: `Basic ${btoa(`${secretKey}:`)}`,
      "Stripe-Version": STRIPE_VERSION,
      ...(method === "POST" ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    },
    body: method === "POST" ? (form ?? new URLSearchParams()).toString() : undefined,
  });
  const body = (await res.json().catch(() => ({}))) as any;
  // Only the error code is kept: Stripe's messages can name a customer or an email.
  if (!res.ok) throw new StripeError(res.status, typeof body?.error?.code === "string" ? body.error.code : undefined);
  return body as T;
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const hex = (bytes: ArrayBuffer): string => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" },
                                            false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}

/**
 * Whether `header` (`t=…,v1=…[,v1=…]`) is Stripe's signature of `rawBody`: HMAC-SHA256 of `t.body`
 * with the endpoint secret, `t` within `toleranceSeconds` of now. Several v1 values appear during
 * a secret rotation; any one matching is enough. Compared in constant time.
 */
export async function verifyStripeSignature(secret: string, rawBody: string, header: string | null,
                                            nowMs = Date.now(), toleranceSeconds = 300): Promise<boolean> {
  if (!secret || !header) return false;
  let timestamp = "";
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim(), v = part.slice(i + 1).trim();
    if (k === "t") timestamp = v;
    else if (k === "v1" && v) signatures.push(v);
  }
  const seconds = Number(timestamp);
  if (!timestamp || !Number.isFinite(seconds) || signatures.length === 0) return false;
  if (Math.abs(nowMs / 1000 - seconds) > toleranceSeconds) return false;
  const expected = await hmacHex(secret, `${timestamp}.${rawBody}`);
  let ok = false;
  for (const candidate of signatures) ok = constantTimeEqual(expected, candidate) || ok;
  return ok;
}

/** Current period end of a subscription, in unix seconds; newer API versions keep it on the items. */
export function periodEnd(sub: any): number | null {
  if (typeof sub?.current_period_end === "number") return sub.current_period_end;
  const ends = (sub?.items?.data ?? []).map((i: any) => i?.current_period_end).filter((n: unknown) => typeof n === "number");
  return ends.length ? Math.max(...ends) : null;
}

/** Machines a subscription pays for: the quantity of its (single) item. */
export function subscriptionQuantity(sub: any): number | null {
  const q = sub?.items?.data?.[0]?.quantity;
  return Number.isInteger(q) && q >= 1 ? q : null;
}

/** Subscription id of an invoice, for both the older and the `parent.subscription_details` shape. */
export function invoiceSubscription(inv: any): string | null {
  const s = inv?.parent?.subscription_details?.subscription ?? inv?.subscription;
  if (typeof s === "string") return s;
  return typeof s?.id === "string" ? s.id : null;
}

export function invoiceMetadata(inv: any): Record<string, string> {
  return inv?.parent?.subscription_details?.metadata ?? inv?.subscription_details?.metadata ?? {};
}

/** End of the period an invoice paid for (the latest line period end). */
export function invoicePeriodEnd(inv: any): number | null {
  const ends = (inv?.lines?.data ?? []).map((l: any) => l?.period?.end).filter((n: unknown) => typeof n === "number");
  return ends.length ? Math.max(...ends) : null;
}

export const idOf = (v: any): string | null => (typeof v === "string" ? v : typeof v?.id === "string" ? v.id : null);
