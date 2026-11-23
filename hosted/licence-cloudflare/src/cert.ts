// Licence certificates (JWS compact, alg EdDSA) and device-key request signatures.
// docs/LICENSING-ARCHITECTURE.md §4 and §5d. WebCrypto Ed25519 is native in workerd and in Bun: no library.
//
// LICENCE_SIGNING_KEY (Worker secret) is "<kid>.<base64url PKCS#8 Ed25519 private key>", made by
// scripts/licence-keygen.ts. The kid travels with the key, so a rotation is one `wrangler secret put`.

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(s: string): Uint8Array<ArrayBuffer> | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch { return null; }
}

type Signer = { kid: string; key: CryptoKey };
let cached: { raw: string; signer: Signer } | null = null;

export async function signer(secret: string | undefined): Promise<Signer> {
  if (!secret) throw new Error("LICENCE_SIGNING_KEY is not set");
  if (cached?.raw === secret) return cached.signer;
  const dot = secret.indexOf(".");
  const kid = secret.slice(0, dot), der = unb64url(secret.slice(dot + 1).trim());
  if (dot < 1 || !/^[A-Za-z0-9-]{1,32}$/.test(kid) || !der) throw new Error("LICENCE_SIGNING_KEY is not <kid>.<pkcs8>");
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
  cached = { raw: secret, signer: { kid, key } };
  return cached.signer;
}

/** A compact JWS over `claims`, header {alg: EdDSA, kid, typ}. */
export async function signJws(secret: string | undefined, claims: Record<string, unknown>, typ = "argus-licence+jwt"): Promise<string> {
  const s = await signer(secret);
  const head = b64url(enc.encode(JSON.stringify({ alg: "EdDSA", kid: s.kid, typ })));
  const body = b64url(enc.encode(JSON.stringify({ ...claims, kid: s.kid })));
  const sig = await crypto.subtle.sign("Ed25519", s.key, enc.encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(sig)}`;
}

/** Decode a JWS without trusting it (tests and support tooling). */
export function decodeJws(jws: string): { header: any; claims: any } | null {
  const [h, p] = String(jws).split(".");
  const hb = unb64url(h || ""), pb = unb64url(p || "");
  if (!hb || !pb) return null;
  try { return { header: JSON.parse(dec.decode(hb)), claims: JSON.parse(dec.decode(pb)) }; } catch { return null; }
}

/** A device public key as sent by the app: 32 raw bytes, base64url. */
export const DPK = /^[A-Za-z0-9_-]{43}$/;
export const DEV = /^[0-9a-f]{64}$/;
export const NONCE = /^[A-Za-z0-9_-]{16,64}$/;
export const SKEW = 300; // seconds a signed request's timestamp may differ from the server's clock

/**
 * The exact bytes a device signs for one request: "argus|v1|<action>|<subject>|<nonce>|<ts>".
 * jarvis/licensing/device.py builds the same string. The action binds the signature to one endpoint.
 */
export const signedMessage = (action: string, subject: string, nonce: string, ts: number) =>
  `argus|v1|${action}|${subject}|${nonce}|${ts}`;

export async function verifyDevice(dpk: string, message: string, sig: unknown): Promise<boolean> {
  const pub = unb64url(dpk), s = typeof sig === "string" ? unb64url(sig) : null;
  if (!pub || pub.length !== 32 || !s || s.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, s, enc.encode(message));
  } catch { return false; }
}
