import { beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { BATCH, purgeEnded, RETENTION } from "../src/retention";
import type { Env } from "../src/env";

const NOW = Math.floor(Date.UTC(2027, 10, 9) / 1000);
const DAY = 86400;

let db: Database;
let env: Env;

function fakeD1(d: Database) {
  const prepare = (sql: string) => {
    let args: any[] = [];
    const stmt = {
      bind(...a: any[]) { args = a.map((v) => (v === undefined ? null : v)); return stmt; },
      async first() { return (d.query(sql).get(...args) as any) ?? null; },
      async all() { return { results: d.query(sql).all(...args) }; },
      async run() { const r = d.query(sql).run(...args); return { meta: { changes: r.changes } }; },
    };
    return stmt;
  };
  // D1 runs a batch as one transaction; so does this fake (rolls back if any statement throws).
  const batch = async (stmts: { run(): Promise<unknown> }[]) => {
    d.exec("BEGIN");
    try { for (const s of stmts) await s.run(); d.exec("COMMIT"); }
    catch (e) { d.exec("ROLLBACK"); throw e; }
    return [];
  };
  return { prepare, batch } as unknown as D1Database;
}

function licence(id: string, o: { status?: string; lic_exp?: number | null; revoked_at?: number | null }) {
  db.query(`INSERT INTO licences_v2 (id, key_hash, key_last4, session_id, offer, plan, seats, status, lic_exp,
            created_at, updated_at, revoked_at) VALUES (?, ?, 'ABCD', ?, 'argus-desktop', 'desktop', 1, ?, ?, 0, 0, ?)`)
    .run(id, `kh_${id}`, `cs_${id}`, o.status ?? "active", o.lic_exp ?? null, o.revoked_at ?? null);
  db.query(`INSERT INTO activations_v2 (id, licence_id, dev_hash, device_pubkey, label, created_at)
            VALUES (?, ?, 'd', ?, 'pc', 0)`).run(`act_${id}`, id, `pk_${id}`);
  db.query("INSERT INTO releases (licence_id, at) VALUES (?, 0)").run(id);
  db.query(`INSERT INTO claims (id_hash, code_hash, dev_hash, device_pubkey, label, licence_id, created_at, expires_at)
            VALUES (?, ?, 'd', 'pk', 'pc', ?, 0, 0)`).run(`c_${id}`, `cc_${id}`, id);
  db.query("INSERT INTO audit (at, licence_id, action, actor) VALUES (0, ?, 'issued', 'stripe')").run(id);
}

const count = (table: string, id: string) =>
  (db.query(`SELECT COUNT(*) AS n FROM ${table} WHERE ${table === "licences_v2" ? "id" : "licence_id"} = ?`).get(id) as any).n;

beforeEach(() => {
  db = new Database(":memory:");
  db.exec(readFileSync(new URL("../schema.sql", import.meta.url), "utf8"));
  env = { DB: fakeD1(db) } as unknown as Env;
});

describe("retention purge", () => {
  test("deletes a licence and all its rows one year after it lapsed or was revoked", async () => {
    licence("lapsed", { lic_exp: NOW - RETENTION - DAY });
    licence("revoked", { status: "revoked", lic_exp: NOW + 100 * DAY, revoked_at: NOW - RETENTION - 1 });
    expect(await purgeEnded(env, NOW)).toBe(2);
    for (const id of ["lapsed", "revoked"])
      for (const t of ["licences_v2", "activations_v2", "releases", "claims", "audit"]) expect(count(t, id)).toBe(0);
    const note = db.query("SELECT licence_id, action, actor FROM audit").all() as any[];
    expect(note).toEqual([{ licence_id: null, action: "retention purge: 2 licence(s) ended over a year ago", actor: "system" }]);
  });

  test("keeps active, recently ended, revoked-recently and never-ending licences untouched", async () => {
    licence("active", { lic_exp: NOW + 30 * DAY });
    licence("recent", { lic_exp: NOW - RETENTION + DAY });          // ended 364 days ago
    licence("boundary", { lic_exp: NOW - RETENTION });              // exactly one year: not yet
    licence("revoked_recent", { status: "revoked", revoked_at: NOW - 10 * DAY, lic_exp: NOW - 2 * RETENTION });
    licence("perpetual", { lic_exp: null });
    licence("revoked_no_time", { status: "revoked", revoked_at: null, lic_exp: null });
    expect(await purgeEnded(env, NOW)).toBe(0);
    for (const id of ["active", "recent", "boundary", "revoked_recent", "perpetual", "revoked_no_time"]) {
      expect(count("licences_v2", id)).toBe(1);
      expect(count("activations_v2", id)).toBe(1);
      expect(count("audit", id)).toBe(1);
    }
    expect((db.query("SELECT COUNT(*) AS n FROM audit WHERE licence_id IS NULL").get() as any).n).toBe(0);
  });

  test("is bounded per run, continues on the next run, and is idempotent", async () => {
    for (let i = 0; i < BATCH + 5; i++) licence(`old${String(i).padStart(4, "0")}`, { lic_exp: NOW - 2 * RETENTION });
    expect(await purgeEnded(env, NOW)).toBe(BATCH);
    expect(await purgeEnded(env, NOW)).toBe(5);
    expect(await purgeEnded(env, NOW)).toBe(0);
    expect((db.query("SELECT COUNT(*) AS n FROM licences_v2").get() as any).n).toBe(0);
    expect((db.query("SELECT COUNT(*) AS n FROM activations_v2").get() as any).n).toBe(0);
  });

  test("a failure mid-run deletes nothing for that licence and the next run retries it", async () => {
    licence("a", { lic_exp: NOW - 2 * RETENTION });
    const real = env.DB as any;
    let fail = true;
    env = { DB: { batch: real.batch, prepare: (sql: string) => {
      const stmt = real.prepare(sql);
      if (sql.startsWith("DELETE FROM licences_v2") && fail)
        return { bind: () => ({ run: async () => { throw new Error("D1 unavailable"); } }) };
      return stmt;
    } } } as unknown as Env;
    await expect(purgeEnded(env, NOW)).rejects.toThrow("D1 unavailable");
    for (const t of ["licences_v2", "activations_v2", "releases", "claims", "audit"]) expect(count(t, "a")).toBe(1);
    fail = false;
    env = { DB: real } as unknown as Env;
    expect(await purgeEnded(env, NOW)).toBe(1);
    expect(count("licences_v2", "a")).toBe(0);
    expect(count("activations_v2", "a")).toBe(0);
  });

  test("the worker runs the purge daily and the privacy policy's one year matches", () => {
    const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
    expect(wrangler).toMatch(/"crons":\s*\["17 3 \* \* \*"\]/);
    const index = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
    expect(index).toMatch(/scheduled\([^)]*\)[^{]*\{\s*await purgeEnded\(/);
    expect(RETENTION).toBe(365 * DAY);
  });
});
