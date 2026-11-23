// Argus licence keys: ARGUS-SRV-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (or ARGUS-DSK-…).
//
// - 24 data characters in Crockford base32 (120 bits) and one check character, Luhn mod 32 over the
//   product code and the data, so every single mistyped character and most swapped neighbours are
//   caught before anything is sent. jarvis/licensing/keys.py is the same algorithm; the shared vectors
//   in tests/ keep the two in step.
// - Accepted case- and space-insensitively, with or without dashes; O reads as 0, I and L as 1.
// - The worker never stores a key. The data characters are HMAC-SHA256(KEY_PEPPER, session id, generation),
//   so the key can be re-sent (lost key, manage page) from the Checkout Session id alone, and D1 holds only
//   HMAC(KEY_PEPPER, key) and the last 4 characters. A support re-issue bumps the generation.
//   Consequence: KEY_PEPPER is as sensitive as the signing key (docs/LICENSING-ARCHITECTURE.md §9).
export const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export type Kind = "SERVER" | "DESKTOP";
export const CODE: Record<Kind, string> = { SERVER: "SRV", DESKTOP: "DSK" };
const KIND_OF: Record<string, Kind> = { SRV: "SERVER", DSK: "DESKTOP" };
const DATA = 24;

/** Luhn mod 32 check character for `s` (Crockford symbols only). */
export function checkChar(s: string): string {
  let factor = 2, sum = 0;
  for (let i = s.length - 1; i >= 0; i--) {
    const code = ALPHABET.indexOf(s[i]);
    if (code < 0) throw new Error("not a Crockford symbol");
    let add = factor * code;
    factor = factor === 2 ? 1 : 2;
    add = Math.floor(add / 32) + (add % 32);
    sum += add;
  }
  return ALPHABET[(32 - (sum % 32)) % 32];
}

export function formatKey(kind: Kind, data: string): string {
  const code = CODE[kind];
  const body = data + checkChar(code + data);
  return `ARGUS-${code}-${body.match(/.{5}/g)!.join("-")}`;
}

export type Parsed = { ok: true; key: string; kind: Kind } | { ok: false; reason: "format" | "check" };

/** The canonical key, or why it is not one. "check" means the shape is right but a character is wrong. */
export function parseKey(input: unknown): Parsed {
  if (typeof input !== "string" || input.length > 80) return { ok: false, reason: "format" };
  let s = input.toUpperCase().replace(/[\s\-_]/g, "");
  if (s.startsWith("ARGUS")) s = s.slice(5);
  const kind = KIND_OF[s.slice(0, 3)];
  if (!kind) return { ok: false, reason: "format" };
  const body = s.slice(3).replace(/O/g, "0").replace(/[IL]/g, "1");
  if (body.length !== DATA + 1 || [...body].some((c) => !ALPHABET.includes(c))) return { ok: false, reason: "format" };
  if (checkChar(CODE[kind] + body.slice(0, DATA)) !== body[DATA]) return { ok: false, reason: "check" };
  return { ok: true, key: formatKey(kind, body.slice(0, DATA)), kind };
}

const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

export async function hmac(secret: string, message: string): Promise<Uint8Array<ArrayBuffer>> {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(message)));
}

export function base32(bytes: Uint8Array, chars: number): string {
  let out = "", acc = 0, bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5 && out.length < chars) { bits -= 5; out += ALPHABET[(acc >> bits) & 31]; }
    acc &= (1 << bits) - 1;
    if (out.length >= chars) break;
  }
  return out;
}

/** The key for a Checkout Session: deterministic under the secret, so it can be re-sent without being stored. */
export async function deriveKey(secret: string, sessionId: string, gen: number, kind: Kind): Promise<string> {
  if (!secret || secret.length < 32) throw new Error("KEY_PEPPER is not set (32+ characters)");
  return formatKey(kind, base32(await hmac(secret, `argus-key|v1|${sessionId}|${gen}`), DATA));
}

export async function sha256Hex(s: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

/** What D1 stores for a key: HMAC under the pepper, so a database copy cannot be brute-forced offline. */
export async function keyHash(pepper: string, key: string): Promise<string> {
  return hex((await hmac(pepper, `argus-keyhash|v1|${key}`)).buffer as ArrayBuffer);
}

/** HMAC of a lower-cased email under the secret: lets /recover and /manage find a purchase without storing the address. */
export async function emailHash(secret: string, email: string): Promise<string> {
  return hex((await hmac(secret, `argus-email|v1|${email.trim().toLowerCase()}`)).buffer as ArrayBuffer);
}

export function randomId(prefix: string, chars = 20): string {
  return prefix + base32(crypto.getRandomValues(new Uint8Array(Math.ceil((chars * 5) / 8))), chars);
}
