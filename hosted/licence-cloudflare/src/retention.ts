// Retention: licence records are deleted one year after the licence ends (privacy policy,
// owner decision 2026-11-09). Stripe keeps its own payment records; this removes ours.
//
// Invariants (tests/retention.test.ts):
// - A licence that has not ended, or ended less than RETENTION ago, is never touched.
//   Ended = revoked (revoked_at) or lapsed (lic_exp, which already includes the grace period).
//   A licence with no end (lic_exp NULL, not revoked) never ends here.
// - A purged licence leaves nothing behind: its activations, releases, claims and audit rows go
//   with it in one D1 batch (a transaction), children first, so a failure deletes nothing.
// - Bounded work per run (BATCH licences); the next run continues. Idempotent.
// - The purge records itself as one audit row with a count and no licence id.
import { type Env } from "./env";

export const RETENTION = 365 * 86400;
export const BATCH = 200;

const CHILDREN = ["activations_v2", "releases", "claims", "audit"] as const;

export async function purgeEnded(env: Env, now: number): Promise<number> {
  const cutoff = now - RETENTION;
  const due = await env.DB.prepare(
    `SELECT id FROM licences_v2
      WHERE (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at < ?)
         OR (status = 'active' AND lic_exp IS NOT NULL AND lic_exp < ?)
      ORDER BY id LIMIT ?`,
  ).bind(cutoff, cutoff, BATCH).all<{ id: string }>();
  const ids = (due.results ?? []).map((r) => r.id);
  for (const id of ids)
    // One D1 batch = one transaction: a licence and its rows go together or not at all.
    await env.DB.batch([
      ...CHILDREN.map((table) => env.DB.prepare(`DELETE FROM ${table} WHERE licence_id = ?`).bind(id)),
      env.DB.prepare("DELETE FROM licences_v2 WHERE id = ?").bind(id),
    ]);
  if (ids.length)
    await env.DB.prepare("INSERT INTO audit (at, licence_id, action, actor) VALUES (?, NULL, ?, 'system')")
      .bind(now, `retention purge: ${ids.length} licence(s) ended over a year ago`).run();
  return ids.length;
}
