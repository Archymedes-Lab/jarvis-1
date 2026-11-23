// What the sidebar shows of coverage: counts the daemon reports, nothing inferred.
// "Expected" is not "proven": the two are never added into one headline figure.
import type { Coverage } from "./api";

export const LEVELS = ["validated", "claimed", "blind", "regressed"] as const;
export type Level = (typeof LEVELS)[number];

export interface CoverageSummary {
  total: number;
  counts: Record<Level, number>;
  shares: Record<Level, number>;   // 0..1 of total, for the bar
  watched: number | null;          // 0..100, share of the last 24 h a sensor was reporting
  needsLook: boolean;              // something got worse
}

const n = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);

export function summarize(c: Coverage | null | undefined): CoverageSummary | null {
  const t = c?.totals;
  if (!t) return null;
  const counts = { validated: n(t.validated), claimed: n(t.claimed), blind: n(t.blind), regressed: n(t.regressed) };
  const total = Math.max(n(t.total), counts.validated + counts.claimed + counts.blind + counts.regressed);
  if (!total) return null;
  const shares = Object.fromEntries(LEVELS.map((l) => [l, counts[l] / total])) as Record<Level, number>;
  const pct = c?.uptime?.pct24;
  const watched = typeof pct === "number" && Number.isFinite(pct) ? Math.round(Math.min(1, Math.max(0, pct)) * 100) : null;
  return { total, counts, shares, watched, needsLook: counts.regressed > 0 };
}
