// HTML pages, email and sealed values for the people-facing routes (thank-you, manage, recover, link).
import { b64url, unb64url } from "./cert";
import { hmac } from "./keys";
import { SECURITY_HEADERS, type Deps, type Env, payOrigin } from "./env";

export const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const STYLE = `body{font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;max-width:40rem;margin:3rem auto;padding:0 16px;color:#111;background:#fff}
a{color:#0b57d0}h1{font-size:1.6rem;margin:0 0 1rem}h2{font-size:1.1rem;margin:2rem 0 .5rem}
.key{font:600 1.15rem/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.02em;background:#f3f5f8;border:1px solid #d6dbe3;border-radius:8px;padding:.8rem 1rem;word-break:break-all}
.row{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.75rem 0}
button,.btn{font:inherit;border:1px solid #c5ccd6;background:#fff;border-radius:8px;padding:.45rem .9rem;cursor:pointer;color:#111;text-decoration:none;display:inline-block}
.primary{background:#0b57d0;border-color:#0b57d0;color:#fff}
input[type=email],input[type=text]{font:inherit;padding:.5rem .7rem;border:1px solid #c5ccd6;border-radius:8px;min-width:16rem}
.card{border:1px solid #e1e5eb;border-radius:10px;padding:1rem 1.1rem;margin:.9rem 0}
.muted{color:#555;font-size:.92rem}.ok{color:#0a6b2b}.bad{color:#a11}
code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#f3f5f8;padding:.1rem .3rem;border-radius:4px}
table{border-collapse:collapse;width:100%}td{padding:.35rem .25rem;border-top:1px solid #eef0f3;vertical-align:top}
@media (prefers-color-scheme:dark){body{background:#0e1116;color:#e8eaed}.key,code{background:#1a1f27;border-color:#2c333d}
.card{border-color:#2c333d}button,.btn{background:#1a1f27;color:#e8eaed;border-color:#3a424d}.primary{background:#3b82f6;border-color:#3b82f6;color:#fff}
input[type=email],input[type=text]{background:#1a1f27;color:#e8eaed;border-color:#3a424d}.muted{color:#9aa3ad}a{color:#8ab4f8}td{border-color:#222831}}`;

export type PageOpts = { status?: number; script?: string; refresh?: number; headers?: Record<string, string> };

/** A page. `body` must already be escaped HTML. An inline script runs only with this response's nonce. */
export function page(title: string, body: string, o: PageOpts = {}): Response {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    (o.refresh ? `<meta http-equiv="refresh" content="${o.refresh}">` : "") +
    `<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${STYLE}</style></head><body>${body}` +
    (o.script ? `<script nonce="${nonce}">${o.script}</script>` : "") + `</body></html>`;
  return new Response(html, { status: o.status ?? 200, headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS,
    "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; ` +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'", "X-Frame-Options": "DENY",
    // no-referrer would make browsers send `Origin: null` on our own form posts; same-origin keeps the
    // Origin header for the CSRF check and still sends nothing to other sites.
    "Referrer-Policy": "same-origin", ...(o.headers || {}) } });
}

export const simplePage = (status: number, title: string, text: string, link?: string, linkText?: string) =>
  page(title, `<h1>${esc(title)}</h1><p>${esc(text)}</p>` + (link ? `<p><a href="${esc(link)}">${esc(linkText)}</a></p>` : ""), { status });

export const redirect = (to: string, headers: Record<string, string> = {}) =>
  new Response(null, { status: 303, headers: { Location: to, ...SECURITY_HEADERS, ...headers } });

/** A form POST from our own pages only: the browser's Origin must be ours (CSRF, with SameSite=Strict and the token). */
export function sameOrigin(req: Request, env: Env): boolean {
  const origin = req.headers.get("Origin");
  if (origin && origin !== "null") return origin === payOrigin(env);
  return req.headers.get("Sec-Fetch-Site") === "same-origin";
}

export async function formOf(req: Request): Promise<URLSearchParams | null> {
  const raw = await req.text();
  if (raw.length > 4096) return null;
  return new URLSearchParams(raw);
}

/** Send one plain-text email through Resend. False if mail is not configured or it failed. Never logs the address. */
export async function sendMail(env: Env, deps: Deps, to: string, subject: string, text: string): Promise<boolean> {
  if (!env.RESEND_API_KEY || !to.includes("@")) return false;
  try {
    const res = await deps.fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: env.MAIL_FROM || "Archymedes <licences@archymedes.xyz>", to: [to], subject, text }),
    });
    return res.ok;
  } catch { return false; }
}

// Sealed values (AES-256-GCM under a key derived from KEY_PEPPER): magic-link tokens and the manage
// cookie carry the email address this way, so the address reaches the browser and back without D1 ever holding it.
async function sealKey(pepper: string, use: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", await hmac(pepper, "argus-seal|v1"), { name: "AES-GCM" }, false, use);
}

export async function seal(pepper: string, value: Record<string, unknown>): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await sealKey(pepper, ["encrypt"]),
                                                          new TextEncoder().encode(JSON.stringify(value))));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return b64url(out);
}

export async function unseal(pepper: string, token: string): Promise<any | null> {
  const raw = unb64url(token);
  if (!raw || raw.length < 29 || raw.length > 2048) return null;
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, await sealKey(pepper, ["decrypt"]), raw.slice(12));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch { return null; }
}
