// Daemon answers as the views expect them. The views read lists and counts
// directly (`data.items.length`); an older, newer or busy service, or a partial
// answer, can leave a field out or send another type. Every read goes through
// one of these at the API boundary (lib/api.ts), so a missing field becomes an
// empty list or a zero instead of a crash that blanks the view. Pure, tested in
// shape.test.ts. Values that are present and well-typed pass through untouched.
import type { Coverage, Geo, PhoneDevice, ProcsSnapshot, World } from "./api";

const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const obj = (v: unknown): Record<string, any> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, any>) : {});
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

export function shapeWorld(v: unknown): World {
  const d = obj(v);
  const c = obj(d.counts);
  return { ...d, generated_at: num(d.generated_at), age_s: num(d.age_s), stale: d.stale === true, window_s: num(d.window_s),
    items: arr(d.items), zones: arr(d.zones), sources: arr(d.sources),
    counts: { ...c, reports: num(c.reports), mapped: num(c.mapped), unmapped: num(c.unmapped), country_level: num(c.country_level) } } as World;
}

export function shapeGeo(v: unknown): Geo {
  const d = obj(v);
  return { ...d, zones: arr(d.zones), devices: arr(d.devices), anomalies: arr(d.anomalies), generated_at: num(d.generated_at) } as Geo;
}

export function shapeCoverage(v: unknown): Coverage {
  const d = obj(v);
  const t = obj(d.totals);
  return { ...d, at: num(d.at), tactics: obj(d.tactics), techniques: arr(d.techniques),
    totals: { ...t, validated: num(t.validated), claimed: num(t.claimed), blind: num(t.blind), regressed: num(t.regressed), total: num(t.total) } } as Coverage;
}

export function shapeProcs(v: unknown): ProcsSnapshot {
  const d = obj(v);
  return { snaps: obj(d.snaps), status: d.status ?? null };
}

export function shapePhoneDevices(v: unknown): { devices: PhoneDevice[] } {
  return { ...obj(v), devices: arr(obj(v).devices) };
}

// The state document (/api/state). Its lists and objects, as the views read them.
const STATE_LISTS = ["jobs", "findings", "checks", "history", "peers", "events", "questions", "fix"] as const;
const STATE_OBJECTS = ["totals", "by_host", "by_category", "internet", "stats", "intel", "posture", "attack",
  "reliability", "detector_health", "assistant", "performance", "continuity"] as const;

export function shapeState(v: unknown): any {
  const d: Record<string, any> = { ...obj(v) };
  for (const k of STATE_LISTS) d[k] = arr(d[k]);
  for (const k of STATE_OBJECTS) d[k] = obj(d[k]);
  d.findings = d.findings.filter((f: unknown) => f && typeof f === "object");
  d.jobs = d.jobs.filter((j: unknown) => j && typeof j === "object");
  if ("security" in d) {
    const sec = obj(d.security);
    d.security = { ...sec, areas: arr(sec.areas), next_steps: arr(sec.next_steps), history: arr(sec.history) };
  }
  d.paused_until = num(d.paused_until);
  return d;
}
