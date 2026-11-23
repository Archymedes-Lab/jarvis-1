// argus.archymedes.xyz: the sealed relay API under /v1 and the phone app (static assets).
// docs/architecture/ARGUS-NOTIFY.md. The relay authenticates who sends (Ed25519 keys whose
// hash is the mailbox or device id) and stores what it cannot read.
import { b64u, normalizeCode, unb64u, validCode, verifyRequest } from "../public/lib/protocol.js";
import { LIMITS, Mailbox, PairSlot, type Env } from "./mailbox";

export { Mailbox, PairSlot };

const MAX_BODY = 200 * 1024;
const ID = /^[A-Za-z0-9_-]{22}$/;

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
    "connect-src 'self'; manifest-src 'self'; worker-src 'self'; font-src 'self'; base-uri 'none'; " +
    "form-action 'none'; frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  // camera: the app scans the pairing QR in-app; nothing else may use it. publickey-credentials-*: the passkey (Face ID / fingerprint).
  "Permissions-Policy": "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...SECURITY_HEADERS },
  });
}
const fail = (status: number, error: string) => json({ error }, status);
const now = () => Math.floor(Date.now() / 1000);

async function readBody(req: Request): Promise<Uint8Array | null> {
  const len = Number(req.headers.get("Content-Length") || "0");
  if (len > MAX_BODY) return null;
  const buf = new Uint8Array(await req.arrayBuffer());
  return buf.length > MAX_BODY ? null : buf;
}

function parse(body: Uint8Array) {
  try { return JSON.parse(new TextDecoder().decode(body)); } catch { return undefined; }
}

// Durable Object RPC stubs, loosely typed: their generated types recurse too deeply for tsc.
const mailboxFor = (env: Env, mb: string): any => env.MAILBOX.get(env.MAILBOX.idFromName(mb));

const b32 = (s: unknown) => typeof s === "string" && s.length === 43 && unb64u(s).length === 32;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/v1/")) {
      const res = await env.ASSETS.fetch(req);
      const out = new Response(res.body, res);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
      if (url.pathname.endsWith("sw.js")) out.headers.set("Service-Worker-Allowed", "/");
      return out;
    }
    try {
      return await api(req, url, env);
    } catch (err) {
      return fail(500, "relay error");
    }
  },
} satisfies ExportedHandler<Env>;

// Per client address, at the edge: pairing (unauthenticated lookups, offers, claims)
// is tight, the signed API looser. A missing binding (local tests) limits nothing.
async function limited(env: Env, req: Request, pairing: boolean): Promise<boolean> {
  const rl = pairing ? env.RL_PAIR : env.RL_API;
  if (!rl) return false;
  const ip = req.headers.get("CF-Connecting-IP") || "unknown";
  return !(await rl.limit({ key: ip })).success;
}

async function api(req: Request, url: URL, env: Env): Promise<Response> {
  if (await limited(env, req, url.pathname.startsWith("/v1/pair/"))) return fail(429, "too many requests; try again in a minute");
  const body = await readBody(req);
  if (body === null) return fail(413, "body too large");
  const t = now();
  const path = url.pathname + url.search;
  const parts = url.pathname.split("/").filter(Boolean);       // ["v1", ...]
  const signed = () => verifyRequest((k: string) => req.headers.get(k), req.method, path, body, t);

  if (req.method === "GET" && url.pathname === "/v1/vapid") return json({ key: env.VAPID_PUBLIC });

  // --- pairing ---------------------------------------------------------------
  if (parts[1] === "pair" && parts[2]) {
    const code = normalizeCode(parts[2]);
    if (!validCode(code)) return fail(400, "bad code");
    const slot = env.PAIR.get(env.PAIR.idFromName(code)) as any;
    if (req.method === "PUT" && parts.length === 3) {
      const v = await signed();
      const offer = parse(body);
      if (!v.ok) return fail(401, v.reason || "unauthorized");
      if (!offer || offer.mb !== v.id || offer.s_sig !== b64u(v.key) || !b32(offer.s_enc)
          || typeof offer.label !== "string" || !(offer.expires > t && offer.expires <= t + 900))
        return fail(400, "bad offer");
      const mailbox = mailboxFor(env, offer.mb);
      if (!(await mailbox.fresh(v.sig, t))) return fail(409, "replayed request");
      if (!(await mailbox.pinServer(offer.s_sig))) return fail(403, "mailbox key mismatch");
      const ok = await slot.put({ mb: offer.mb, s_sig: offer.s_sig, s_enc: offer.s_enc,
                                  label: offer.label.slice(0, 40), expires: offer.expires }, t);
      return ok ? json({ ok: true }) : fail(409, "code in use");
    }
    if (req.method === "GET" && parts.length === 3) {
      const offer = await slot.read(t);
      return offer ? json(offer) : fail(404, "unknown or expired code");
    }
    if (req.method === "POST" && parts[3] === "claim") {
      const v = await signed();
      const c = parse(body);
      if (!v.ok) return fail(401, v.reason || "unauthorized");
      if (!c || c.dev !== v.id || c.d_sig !== b64u(v.key) || !b32(c.d_enc) || typeof c.name !== "string"
          || (c.passkey !== undefined && typeof c.passkey !== "string") || (c.proof !== undefined && typeof c.proof !== "string"))
        return fail(400, "bad claim");
      const offer = await slot.claim(c.dev, t);
      if (!offer) return fail(404, "unknown, expired or already claimed code");
      const mailbox = mailboxFor(env, offer.mb);
      if (!(await mailbox.fresh(v.sig, t))) return fail(409, "replayed request");
      const err = await mailbox.addClaim({ ...c, code }, t);
      return err ? fail(409, err) : json({ ok: true });
    }
    if (req.method === "GET" && parts[3] === "status") {
      const dev = url.searchParams.get("dev") || "";
      if (!ID.test(dev)) return fail(400, "bad device");
      return json(await slot.status(dev));
    }
    return fail(404, "not found");
  }

  // --- the server's side -----------------------------------------------------
  if (parts[1] === "mailbox" && ID.test(parts[2] || "")) {
    const mb = parts[2];
    const mailbox = mailboxFor(env, mb);
    const v = await signed();
    if (!v.ok) return fail(401, v.reason || "unauthorized");
    const dev = parts[4] || "";
    // A phone may remove itself from a server; everything else is the server's.
    const byDevice = req.method === "DELETE" && parts[3] === "devices" && v.id === dev && parts.length === 5;
    if (v.id !== mb && !byDevice) return fail(403, "not this mailbox");
    if (!byDevice && !(await mailbox.pinServer(b64u(v.key)))) return fail(403, "mailbox key mismatch");
    if (!(await mailbox.fresh(v.sig, t))) return fail(409, "replayed request");

    if (req.method === "GET" && parts[3] === "devices" && parts.length === 4) return json(await mailbox.devices());
    if (req.method === "GET" && parts[3] === "claims") {
      const code = normalizeCode(url.searchParams.get("code") || "");
      return validCode(code) ? json(await mailbox.claims(code, t)) : fail(400, "bad code");
    }
    if (req.method === "POST" && parts[3] === "devices" && parts[5] === "activate" && ID.test(dev)) {
      const c = parse(body);
      const code = normalizeCode(c?.code || "");
      if (!validCode(code) || !(await mailbox.activate(dev, code))) return fail(404, "no pending claim");
      const slot = env.PAIR.get(env.PAIR.idFromName(code)) as any;
      await slot.markActive(dev);
      return json({ ok: true });
    }
    if (req.method === "DELETE" && parts[3] === "devices" && ID.test(dev) && parts.length === 5) {
      await mailbox.remove(dev);
      return json({ ok: true });
    }
    if (req.method === "GET" && parts[3] === "replies" && parts.length === 4) return json(await mailbox.replies(t));
    if (req.method === "POST" && parts[3] === "replies" && parts[4] === "ack" && parts.length === 5) {
      const ids = parse(body)?.ids;
      if (!Array.isArray(ids)) return fail(400, "bad ack");
      await mailbox.ackReplies(ids.filter((x: unknown) => typeof x === "string"));
      return json({ ok: true });
    }
    if (req.method === "POST" && parts[3] === "envelopes" && parts.length === 4) {
      const list = parse(body);
      if (!Array.isArray(list) || !list.length || list.length > LIMITS.postBatch) return fail(400, "bad batch");
      const r = await mailbox.deliver(mb, list, t);
      return r.error ? fail(400, r.error) : json(r);
    }
    return fail(404, "not found");
  }

  // --- the phone's side ------------------------------------------------------
  if (parts[1] === "device" && ID.test(parts[2] || "")) {
    const dev = parts[2];
    const mb = url.searchParams.get("mb") || "";
    if (!ID.test(mb)) return fail(400, "bad mailbox");
    const v = await signed();
    if (!v.ok) return fail(401, v.reason || "unauthorized");
    if (v.id !== dev) return fail(403, "not this device");
    const mailbox = mailboxFor(env, mb);
    const d = await mailbox.device(dev);
    if (!d || d.state !== "active" || d.d_sig !== b64u(v.key)) return fail(403, "not paired with this server");
    if (!(await mailbox.fresh(v.sig, t))) return fail(409, "replayed request");
    if (req.method === "GET" && parts[3] === "inbox") return json(await mailbox.inbox(dev, t));
    if (req.method === "POST" && parts[3] === "ack") {
      const ids = parse(body)?.ids;
      if (!Array.isArray(ids)) return fail(400, "bad ack");
      await mailbox.ack(dev, ids.filter((x: unknown) => typeof x === "string"));
      return json({ ok: true });
    }
    if (req.method === "POST" && parts[3] === "replies" && parts.length === 4) {
      const reply = parse(body);
      if (!reply || typeof reply !== "object") return fail(400, "bad reply");
      const r = await mailbox.postReply(dev, reply, t);
      return r.error ? fail(400, r.error) : json({ ok: true });
    }
    if (req.method === "PUT" && parts[3] === "push") {
      return (await mailbox.setPush(dev, parse(body))) ? json({ ok: true }) : fail(400, "push endpoint not allowed");
    }
    return fail(404, "not found");
  }
  return fail(404, "not found");
}
