// An empty Web Push (no payload) with VAPID (RFC 8292). The push service learns only
// that this device has something waiting; the app fetches, verifies and decrypts it.
import { b64u, unb64u } from "../public/lib/protocol.js";

// Only the browsers' own push services: a subscription pointing anywhere else would
// let a client make the relay send requests to hosts of its choosing.
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/,
  /^web\.push\.apple\.com$/, /(^|\.)push\.apple\.com$/, /(^|\.)notify\.windows\.com$/];

export interface PushSubscription { endpoint: string; keys?: { p256dh?: string; auth?: string } }

export function validSubscription(sub: unknown): sub is PushSubscription {
  if (!sub || typeof sub !== "object") return false;
  const ep = (sub as PushSubscription).endpoint;
  if (typeof ep !== "string" || ep.length > 1024) return false;
  let u: URL;
  try { u = new URL(ep); } catch { return false; }
  return u.protocol === "https:" && PUSH_HOSTS.some((re) => re.test(u.hostname));
}

async function vapidJwt(audience: string, subject: string, privateJwk: JsonWebKey, now: number) {
  const header = b64u(new TextEncoder().encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(new TextEncoder().encode(JSON.stringify({ aud: audience, exp: now + 12 * 3600, sub: subject })));
  const key = await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key,
    new TextEncoder().encode(`${header}.${claims}`));
  return `${header}.${claims}.${b64u(new Uint8Array(sig))}`;
}

// "ok", "gone" (the subscription no longer exists: drop it) or "failed".
export async function tickle(sub: PushSubscription, env: { VAPID_PUBLIC: string; VAPID_PRIVATE: string; VAPID_SUBJECT: string },
                             now: number, fetchImpl: typeof fetch = fetch): Promise<"ok" | "gone" | "failed"> {
  if (!validSubscription(sub)) return "gone";
  const audience = new URL(sub.endpoint).origin;
  const jwt = await vapidJwt(audience, env.VAPID_SUBJECT, JSON.parse(env.VAPID_PRIVATE), now);
  const res = await fetchImpl(sub.endpoint, {
    method: "POST",
    headers: { Authorization: `vapid t=${jwt}, k=${env.VAPID_PUBLIC}`, TTL: String(7 * 86400), Urgency: "high",
               "Content-Length": "0" },
  });
  if (res.status === 404 || res.status === 410) return "gone";
  return res.ok ? "ok" : "failed";
}

export { unb64u };
