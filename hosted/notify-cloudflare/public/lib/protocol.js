// The sealed-notification protocol (docs/architecture/ARGUS-NOTIFY.md), one copy for
// the relay Worker, the app and its service worker. WebCrypto only: X25519, HKDF-SHA256,
// AES-256-GCM, Ed25519. tests/protocol.test.js checks it byte for byte against vectors
// produced by the server's Python implementation.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const REQ_CONTEXT = "notify-req/1";
export const ENV_CONTEXT = "notify-env/1";
export const SEAL_INFO = enc.encode("notify-seal/1");
export const SAS_CONTEXT = enc.encode("notify-sas/1");
export const REQUEST_WINDOW_S = 300;
export const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function b64u(bytes) {
  let s = "";
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(text) {
  const t = String(text).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export async function keyId(sigPubRaw) {
  return b64u(await sha256(sigPubRaw)).slice(0, 22);
}

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function requestMessage(method, path, stamp, nonce, body) {
  const digest = hex(await sha256(body || new Uint8Array()));
  return enc.encode([REQ_CONTEXT, method.toUpperCase(), path, String(stamp), nonce, digest].join("\n"));
}

// Ed25519 is deterministic: the random nonce keeps two identical requests in the
// same second from carrying the same signature (the relay refuses replays).
export async function signRequest(sigPriv, sigPubRaw, method, path, body, now) {
  const stamp = Math.floor(now);
  const nonce = b64u(crypto.getRandomValues(new Uint8Array(16)));
  const sig = await crypto.subtle.sign("Ed25519", sigPriv, await requestMessage(method, path, stamp, nonce, body));
  return { "X-Notify-Key": b64u(sigPubRaw), "X-Notify-Time": String(stamp), "X-Notify-Nonce": nonce, "X-Notify-Sig": b64u(sig) };
}

// {ok, id, key, reason}: the id is the hash of the key, so the caller compares
// it with the mailbox or device the path names.
export async function verifyRequest(get, method, path, body, now) {
  const key = get("X-Notify-Key"), stamp = get("X-Notify-Time"), sig = get("X-Notify-Sig"), nonce = get("X-Notify-Nonce");
  if (!key || !stamp || !sig || !nonce) return { ok: false, reason: "unsigned" };
  if (!/^[A-Za-z0-9_-]{22}$/.test(nonce)) return { ok: false, reason: "bad nonce" };
  if (!/^\d{1,12}$/.test(stamp) || Math.abs(now - Number(stamp)) > REQUEST_WINDOW_S) return { ok: false, reason: "stale" };
  let raw;
  try { raw = unb64u(key); } catch { return { ok: false, reason: "bad key" }; }
  if (raw.length !== 32) return { ok: false, reason: "bad key" };
  const pub = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  let good = false;
  try { good = await crypto.subtle.verify("Ed25519", pub, unb64u(sig), await requestMessage(method, path, stamp, nonce, body)); } catch { good = false; }
  return good ? { ok: true, id: await keyId(raw), key: raw, sig } : { ok: false, reason: "bad signature" };
}

export const HEADER_FIELDS = ["v", "id", "mb", "dev", "sent", "expires", "epk"];

export async function openEnvelope(env, encPriv, sSigPubRaw) {
  const header = {};
  for (const k of HEADER_FIELDS) header[k] = env[k];
  const aad = canonical(header);
  const signed = enc.encode([ENV_CONTEXT, aad, env.iv, env.ct].join("\n"));
  const sPub = await crypto.subtle.importKey("raw", sSigPubRaw, { name: "Ed25519" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("Ed25519", sPub, unb64u(env.sig), signed))) throw new Error("signature");
  const epk = await crypto.subtle.importKey("raw", unb64u(env.epk), { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: epk }, encPriv, 256);
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: unb64u(env.id), info: SEAL_INFO }, ikm,
    { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64u(env.iv), additionalData: enc.encode(aad) }, key, unb64u(env.ct));
  return JSON.parse(dec.decode(plain));
}

export async function sas(sSig, sEnc, dSig, dEnc) {
  const d = await sha256(concat(SAS_CONTEXT, sSig, sEnc, dSig, dEnc));
  const n = ((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3];
  return String(n % 1000000).padStart(6, "0");
}

// A device identity: private keys are non-extractable CryptoKeys (IndexedDB keeps them).
export async function generateDevice() {
  const sig = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const encKeys = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const sigPub = new Uint8Array(await crypto.subtle.exportKey("raw", sig.publicKey));
  const encPub = new Uint8Array(await crypto.subtle.exportKey("raw", encKeys.publicKey));
  return { sigPriv: sig.privateKey, encPriv: encKeys.privateKey, sigPub, encPub, dev: await keyId(sigPub) };
}

export function normalizeCode(text) {
  return String(text).toUpperCase().replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0").replace(/[IL]/g, "1");
}

export function validCode(code) {
  return code.length === 10 && [...code].every((ch) => CODE_ALPHABET.includes(ch));
}

export async function supported() {
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign"]);
    return true;
  } catch { return false; }
}

// --- approvals from the phone (ARGUS-NOTIFY.md, "Approvals") ----------------------------

export const REPLY_CONTEXT = "notify-rep/1";
export const REPLY_INFO = enc.encode("notify-reply/1");
export const PROOF_CONTEXT = enc.encode("notify-qr/1");
export const APPROVAL_CONTEXT = "notify-approval/1";

// The 32 bytes the passkey signs. The server computes the same from the same fields, so the
// biometric check is bound to exactly the action the phone showed.
export async function approvalChallenge(approvalId, eid, action, target, expires) {
  return sha256(enc.encode(canonical({ ctx: APPROVAL_CONTEXT, approval_id: approvalId, eid, action,
    target: String(target), expires: Number(expires) })));
}

// A reply to the server, sealed to the server's X25519 key and signed by this phone's Ed25519 key:
// the envelope, reversed. The relay stores it without being able to read it.
export async function sealReply(sigPriv, dev, mb, sEncPubRaw, payload, now, ttl = 900) {
  const plain = enc.encode(canonical(payload));
  if (plain.length > 4096) throw new Error("reply too large");
  const id = crypto.getRandomValues(new Uint8Array(16));
  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const sEnc = await crypto.subtle.importKey("raw", sEncPubRaw, { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: sEnc }, eph.privateKey, 256);
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: id, info: REPLY_INFO }, ikm,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const sent = Math.floor(now);
  const header = { v: 1, id: b64u(id), mb, dev, sent, expires: sent + ttl,
    epk: b64u(new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey))) };
  const aad = canonical(header);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, plain));
  const signed = enc.encode([REPLY_CONTEXT, aad, b64u(iv), b64u(ct)].join("\n"));
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", sigPriv, signed));
  return { ...header, iv: b64u(iv), ct: b64u(ct), sig: b64u(sig) };
}

// Proof, from the QR's secret (which the relay never sees), that a pairing claim is from the phone
// that scanned the QR. The server checks it; without it a phone cannot approve anything.
export async function qrProof(secret, dSig, dEnc, passkeySpki = new Uint8Array()) {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, concat(PROOF_CONTEXT, dSig, dEnc, passkeySpki))));
}
