// One Durable Object per server (mailbox). It knows the server's signing key, its
// devices (pending until the server activates them) and their sealed envelopes. It never
// holds anything it could read: envelopes are ciphertext signed by the server.
import { DurableObject } from "cloudflare:workers";
import { tickle, validSubscription, type PushSubscription } from "./webpush";

export const LIMITS = {
  envelopeBytes: 8 * 1024, pendingPerDevice: 500, devicesPerMailbox: 20, envelopeTtl: 7 * 86400,
  postBatch: 20, claimTtl: 600, nonceTtl: 600,
  replyBytes: 8 * 1024, pendingReplies: 50, replyTtl: 900,
};

export interface Env {
  RL_PAIR?: RateLimit;
  RL_API?: RateLimit;
  MAILBOX: DurableObjectNamespace<Mailbox>;
  PAIR: DurableObjectNamespace;
  ASSETS: Fetcher;
  VAPID_PUBLIC: string;
  VAPID_PRIVATE: string;
  VAPID_SUBJECT: string;
}

type Device = { dev: string; d_sig: string; d_enc: string; name: string; state: string; code: string;
  push: string | null; added: number; last_seen?: number | null; passkey: string | null; proof: string | null };

export class Mailbox extends DurableObject<Env> {
  sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
      CREATE TABLE IF NOT EXISTS devices (dev TEXT PRIMARY KEY, d_sig TEXT, d_enc TEXT, name TEXT, state TEXT,
        code TEXT, push TEXT, added INTEGER);
      CREATE TABLE IF NOT EXISTS envelopes (id TEXT PRIMARY KEY, dev TEXT, body TEXT, created INTEGER, expires INTEGER);
      CREATE INDEX IF NOT EXISTS envelopes_dev ON envelopes (dev, expires);
      CREATE TABLE IF NOT EXISTS nonces (sig TEXT PRIMARY KEY, at INTEGER);
      CREATE TABLE IF NOT EXISTS replies (id TEXT PRIMARY KEY, dev TEXT, body TEXT, created INTEGER, expires INTEGER);`);
    // Columns added after v1: when each device last fetched its inbox (liveness the server may
    // read), and for approvals the passkey / QR proof. Older mailboxes are upgraded in place.
    const cols = this.sql.exec("PRAGMA table_info(devices)").toArray().map((r) => r.name as string);
    if (!cols.includes("last_seen")) this.sql.exec("ALTER TABLE devices ADD COLUMN last_seen INTEGER");
    if (!cols.includes("passkey")) this.sql.exec("ALTER TABLE devices ADD COLUMN passkey TEXT");
    if (!cols.includes("proof")) this.sql.exec("ALTER TABLE devices ADD COLUMN proof TEXT");
  }

  // Metadata for the server: never keys, never envelopes.
  devices() {
    return this.sql.exec("SELECT dev, name, state, added, last_seen, push IS NOT NULL AS push FROM devices")
      .toArray().map((r) => ({ dev: r.dev, name: r.name, state: r.state, added: r.added,
        last_seen: r.last_seen ?? null, push: Boolean(r.push) }));
  }

  // A request signature may be used once: replays inside the time window are refused.
  fresh(sig: string, now: number): boolean {
    this.sql.exec("DELETE FROM nonces WHERE at < ?", now - LIMITS.nonceTtl);
    if (this.sql.exec("SELECT 1 FROM nonces WHERE sig = ?", sig).toArray().length) return false;
    this.sql.exec("INSERT INTO nonces (sig, at) VALUES (?, ?)", sig, now);
    return true;
  }

  // The server's key, pinned on first use; the mailbox id already commits to it.
  pinServer(sSig: string): boolean {
    const row = this.sql.exec("SELECT v FROM meta WHERE k = 's_sig'").toArray()[0];
    if (!row) { this.sql.exec("INSERT INTO meta (k, v) VALUES ('s_sig', ?)", sSig); return true; }
    return row.v === sSig;
  }

  device(dev: string): Device | null {
    return (this.sql.exec("SELECT * FROM devices WHERE dev = ?", dev).toArray()[0] as unknown as Device) ?? null;
  }

  addClaim(c: { dev: string; d_sig: string; d_enc: string; name: string; code: string; push: unknown;
                passkey?: unknown; proof?: unknown }, now: number) {
    const count = this.sql.exec("SELECT COUNT(*) AS n FROM devices").one().n as number;
    if (count >= LIMITS.devicesPerMailbox && !this.device(c.dev)) return "this server has the maximum number of devices";
    const push = validSubscription(c.push) ? JSON.stringify(c.push) : null;
    // The passkey's public key (DER, base64url) and the QR proof are opaque to the relay: it stores and
    // forwards them, the server decides what they mean.
    const passkey = typeof c.passkey === "string" && /^[A-Za-z0-9_-]{40,200}$/.test(c.passkey) ? c.passkey : null;
    const proof = typeof c.proof === "string" && /^[A-Za-z0-9_-]{43}$/.test(c.proof) ? c.proof : null;
    this.sql.exec(`INSERT OR REPLACE INTO devices (dev, d_sig, d_enc, name, state, code, push, added, passkey, proof)
      VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)`, c.dev, c.d_sig, c.d_enc, c.name.slice(0, 40), c.code, push, now,
      passkey, proof);
    return "";
  }

  claims(code: string, now: number) {
    this.sql.exec("DELETE FROM devices WHERE state = 'pending' AND added < ?", now - LIMITS.claimTtl);
    return this.sql.exec("SELECT dev, d_sig, d_enc, name, code, passkey, proof FROM devices WHERE state = 'pending' AND code = ?", code).toArray();
  }

  activate(dev: string, code: string): boolean {
    const d = this.device(dev);
    if (!d || d.state !== "pending" || d.code !== code) return false;
    this.sql.exec("UPDATE devices SET state = 'active', code = '' WHERE dev = ?", dev);
    return true;
  }

  remove(dev: string) {
    this.sql.exec("DELETE FROM envelopes WHERE dev = ?", dev);
    this.sql.exec("DELETE FROM replies WHERE dev = ?", dev);
    this.sql.exec("DELETE FROM devices WHERE dev = ?", dev);
  }

  setPush(dev: string, sub: unknown): boolean {
    if (!validSubscription(sub)) return false;
    this.sql.exec("UPDATE devices SET push = ? WHERE dev = ? AND state = 'active'", JSON.stringify(sub), dev);
    return true;
  }

  // Store envelopes for active devices and wake each device once.
  async deliver(mb: string, envelopes: any[], now: number) {
    // Validate the whole batch first: a bad envelope stores none of them.
    const rows: [string, string, string, number][] = [];
    const adding = new Map<string, number>();
    for (const e of envelopes) {
      const body = JSON.stringify(e);
      if (body.length > LIMITS.envelopeBytes) return { error: "envelope too large" };
      if (e?.mb !== mb || typeof e.id !== "string" || e.id.length > 32 || typeof e.dev !== "string")
        return { error: "envelope does not belong to this mailbox" };
      const d = this.device(e.dev);
      if (!d || d.state !== "active") return { error: "unknown or inactive device" };
      const pending = this.sql.exec("SELECT COUNT(*) AS n FROM envelopes WHERE dev = ?", e.dev).one().n as number;
      adding.set(e.dev, (adding.get(e.dev) ?? 0) + 1);
      if (pending + adding.get(e.dev)! > LIMITS.pendingPerDevice) return { error: "device inbox full" };
      rows.push([e.id, e.dev, body, Math.min(Number(e.expires) || 0, now + LIMITS.envelopeTtl)]);
    }
    const touched = new Set<string>();
    for (const [id, dev, body, expires] of rows) {
      this.sql.exec("INSERT OR IGNORE INTO envelopes (id, dev, body, created, expires) VALUES (?, ?, ?, ?, ?)",
        id, dev, body, now, expires);
      touched.add(dev);
    }
    await this.ctx.storage.setAlarm(Date.now() + 3600_000);
    const pushes = [];
    for (const dev of touched) {
      const d = this.device(dev);
      if (d?.push) pushes.push(tickle(JSON.parse(d.push) as PushSubscription, this.env, now)
        .then((r) => { if (r === "gone") this.sql.exec("UPDATE devices SET push = NULL WHERE dev = ?", dev); return r; })
        .catch(() => "failed"));
    }
    const results = await Promise.all(pushes);
    return { stored: envelopes.length, pushed: results.filter((r) => r === "ok").length };
  }

  // A phone's sealed answer to the server (approvals). The relay cannot read it and does not wake
  // anything: the server polls for replies, it never listens.
  async postReply(dev: string, reply: any, now: number) {
    const body = JSON.stringify(reply);
    if (body.length > LIMITS.replyBytes) return { error: "reply too large" };
    if (typeof reply?.id !== "string" || reply.id.length > 32 || reply.dev !== dev) return { error: "reply does not belong to this device" };
    const pending = this.sql.exec("SELECT COUNT(*) AS n FROM replies").one().n as number;
    if (pending >= LIMITS.pendingReplies) return { error: "too many unread replies" };
    this.sql.exec("INSERT OR IGNORE INTO replies (id, dev, body, created, expires) VALUES (?, ?, ?, ?, ?)",
      reply.id, dev, body, now, Math.min(Number(reply.expires) || 0, now + LIMITS.replyTtl));
    await this.ctx.storage.setAlarm(Date.now() + 3600_000);
    return { ok: true };
  }

  replies(now: number) {
    return this.sql.exec("SELECT body FROM replies WHERE expires > ? ORDER BY created LIMIT 50", now)
      .toArray().map((r) => JSON.parse(r.body as string));
  }

  ackReplies(ids: string[]) {
    for (const id of ids.slice(0, 100)) this.sql.exec("DELETE FROM replies WHERE id = ?", id);
  }

  inbox(dev: string, now: number) {
    this.sql.exec("UPDATE devices SET last_seen = ? WHERE dev = ?", now, dev);
    return this.sql.exec("SELECT body FROM envelopes WHERE dev = ? AND expires > ? ORDER BY created LIMIT 100", dev, now)
      .toArray().map((r) => JSON.parse(r.body as string));
  }

  ack(dev: string, ids: string[]) {
    for (const id of ids.slice(0, 200)) this.sql.exec("DELETE FROM envelopes WHERE dev = ? AND id = ?", dev, id);
  }

  async alarm() {
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec("DELETE FROM envelopes WHERE expires < ?", now);
    this.sql.exec("DELETE FROM replies WHERE expires < ?", now);
    this.sql.exec("DELETE FROM nonces WHERE at < ?", now - LIMITS.nonceTtl);
    this.sql.exec("DELETE FROM devices WHERE state = 'pending' AND added < ?", now - LIMITS.claimTtl);
    if (this.sql.exec("SELECT 1 FROM envelopes LIMIT 1").toArray().length
        || this.sql.exec("SELECT 1 FROM replies LIMIT 1").toArray().length) await this.ctx.storage.setAlarm(Date.now() + 3600_000);
  }
}

// One Durable Object per pairing code: the server's offer for 10 minutes, one claim,
// a capped number of reads so a code cannot be probed.
export class PairSlot extends DurableObject<Env> {
  async put(offer: any, now: number) {
    const existing = await this.ctx.storage.get<any>("offer");
    if (existing && existing.expires > now) return false;
    await this.ctx.storage.put({ offer, attempts: 0, claimed: null, active: false });
    await this.ctx.storage.setAlarm(offer.expires * 1000);
    return true;
  }

  async read(now: number) {
    const offer = await this.ctx.storage.get<any>("offer");
    // An unknown code writes nothing: probing random codes must not create storage.
    if (!offer || offer.expires <= now) return null;
    const attempts = (await this.ctx.storage.get<number>("attempts")) ?? 0;
    if (attempts >= 10) return null;
    await this.ctx.storage.put("attempts", attempts + 1);
    return offer;
  }

  async claim(dev: string, now: number) {
    const offer = await this.ctx.storage.get<any>("offer");
    if (!offer || offer.expires <= now) return null;
    const claimed = await this.ctx.storage.get<string>("claimed");
    if (claimed && claimed !== dev) return null;
    await this.ctx.storage.put("claimed", dev);
    return offer;
  }

  async status(dev: string) {
    const claimed = await this.ctx.storage.get<string>("claimed");
    return { active: claimed === dev && (await this.ctx.storage.get<boolean>("active")) === true };
  }

  async markActive(dev: string) {
    if ((await this.ctx.storage.get<string>("claimed")) === dev) await this.ctx.storage.put("active", true);
  }

  async alarm() {
    // Keep the activated flag briefly for the phone's last poll, then forget everything.
    if (await this.ctx.storage.get<boolean>("active")) {
      await this.ctx.storage.put("offer", { expires: 0 });
      if (!(await this.ctx.storage.get<boolean>("swept"))) {
        await this.ctx.storage.put("swept", true);
        await this.ctx.storage.setAlarm(Date.now() + 120_000);
        return;
      }
    }
    await this.ctx.storage.deleteAll();
  }
}
