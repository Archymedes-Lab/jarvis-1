// Pure view logic over the daemon's state document. No DOM, no I/O: every
// function here is tested in model.test.ts.

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface Finding {
  severity: string; title: string; detail?: string; where?: string;
  category?: string; job: string; host?: string; forensics?: string[];
  /** Ledger facts on the original finding: how long it has been open, and
   *  whether it came back after a clear (daemon 2026-11-08 and later). */
  ledger?: { state: "open" | "overdue" | "recurring"; age: string; age_days: number;
             deadline_days?: number | null; sent_count?: number; reopened?: number };
  /** On a ledger note: true when the original is not listed, so the note is
   *  the only place the problem shows and it keeps its full severity. */
  orphan?: boolean;
}
export interface Job {
  name: string; label: string; ts?: number | null; error?: string; stale?: boolean;
  running?: boolean; interval?: number; next?: number; duration?: number;
  counts?: Record<string, number>; ok?: number;
}
export interface Question { id: string; prompt: string; severity?: string; yes?: string; no?: string; title?: string; job?: string }
export interface Fix { id: string; title: string; status: string; problem?: string; generation_state?: string; generation_error?: string }

export function sevRank(s: string): number {
  const i = SEVERITIES.indexOf(s as Severity);
  return i < 0 ? 9 : i;
}

export interface FindingFilter { query?: string; severity?: string | null; host?: string; job?: string }

export function matches(f: Finding, q: string): boolean {
  if (!q) return true;
  const hay = `${f.title} ${f.detail ?? ""} ${f.where ?? ""} ${f.category ?? ""} ${f.job} ${f.host ?? ""}`.toLowerCase();
  return q.toLowerCase().split(/\s+/).filter(Boolean).every((w) => hay.includes(w));
}

export function filterFindings(findings: Finding[], f: FindingFilter): Finding[] {
  const q = (f.query ?? "").trim();
  return findings
    .filter((x) => (!f.severity || x.severity === f.severity)
      && (!f.host || x.host === f.host)
      && (!f.job || x.job === f.job)
      && matches(x, q))
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (f.severity in out) out[f.severity as Severity]++;
  return out;
}

/** A reminder is a ledger note about a finding that is listed on its own
 *  (job "ledger"): the same problem again, counted on its own, never as
 *  another problem. Since 2026-11-08 the daemon marks a note whose original
 *  is no longer listed as `orphan`; that one is the only place the problem
 *  shows, so it counts. An older daemon sends no flag: every note is a reminder. */
export const isReminder = (f: Finding): boolean => f.job === "ledger" && f.orphan !== true;

/** Argus's own detection gaps against intel (job "gaps"): about the tool, not
 *  the machine. A current daemon lists them under /api/coverage only; this
 *  keeps an older daemon's copy out of the problem counts. */
const COVERAGE_CATEGORIES = new Set(["coverage gap", "not observable", "not applicable"]);
export const isCoverageGap = (f: Finding): boolean => f.job === "gaps" || COVERAGE_CATEGORIES.has(f.category ?? "");

/** A finding about this machine that is not a restatement of another one. */
export const isProblem = (f: Finding): boolean => !isReminder(f) && !isCoverageGap(f);

/** Severity counts of distinct problems: reminders and coverage gaps left out. */
export function problemCounts(findings: Finding[]): Record<Severity, number> {
  return severityCounts(findings.filter(isProblem));
}

/** The findings list and the numbers beside its severity filter, by one rule
 *  shared with Home: a severity counts distinct-from-reminder problems only
 *  (`problemCounts`), and choosing a severity lists exactly those problems, so
 *  the number on the control, the rows under it and Home's number agree.
 *  With no severity chosen the whole list shows, reminders and coverage notes
 *  included, and `total` is its length. */
export function findingsView(all: Finding[], f: FindingFilter): { rows: Finding[]; counts: Record<Severity, number>; total: number } {
  const scope = f.severity ? all.filter(isProblem) : all;
  return { rows: filterFindings(scope, f), counts: problemCounts(all), total: all.length };
}

/** One row per distinct (job, title), with how many places it occurs. */
export function distinct(findings: Finding[], limit: number): (Finding & { count: number })[] {
  const by = new Map<string, Finding & { count: number }>();
  for (const f of findings) {
    const k = `${f.job}|${f.title}`;
    const hit = by.get(k);
    if (hit) hit.count++; else by.set(k, { ...f, count: 1 });
  }
  return [...by.values()].slice(0, limit);
}

/** Questions grouped by their prompt: the same question about three
 *  containers is one decision to look at, asked three times. */
export function groupQuestions(qs: Question[]): { prompt: string; ids: Question[]; severity?: string }[] {
  const by = new Map<string, { prompt: string; ids: Question[]; severity?: string }>();
  for (const q of qs) {
    const k = q.prompt || "A question from ARGUS-INSTINCT";
    const g = by.get(k);
    if (g) g.ids.push(q); else by.set(k, { prompt: k, ids: [q], severity: q.severity });
  }
  return [...by.values()];
}

export type Health = "running" | "error" | "never" | "stale" | "ok";
export function jobHealth(j: Job): Health {
  if (j.running) return "running";
  if (j.error) return "error";
  if (!j.ts) return "never";
  if (j.stale) return "stale";
  return "ok";
}

export function collectorSummary(jobs: Job[]) {
  const h = jobs.map(jobHealth);
  return {
    total: jobs.length,
    ok: h.filter((x) => x === "ok" || x === "running").length,
    stale: h.filter((x) => x === "stale" || x === "never").length,
    error: h.filter((x) => x === "error").length,
  };
}

export function ago(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return "never";
  const d = Math.max(0, Math.floor(now - ts));
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

export function every(seconds: number | undefined): string {
  if (!seconds) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} d`;
}

export type Tone = "red" | "amber" | "green" | "gray";
export function scoreTone(score: number | null | undefined): Tone {
  if (score == null) return "gray";
  return score >= 75 ? "green" : score >= 50 ? "amber" : "red";
}

export function sentence(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

/** A model note sometimes arrives as a JSON object such as {"security": "..."}; show its
 *  text, never the braces. Anything else is returned trimmed. */
export function noteText(note: unknown): string {
  const s = typeof note === "string" ? note.trim() : "";
  if (!s.startsWith("{")) return s;
  try {
    const v = JSON.parse(s);
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const parts = Object.values(v).filter((x): x is string => typeof x === "string" && x.trim().length > 0);
      if (parts.length) return parts.join(" ").trim();
    }
  } catch { /* not JSON after all */ }
  return s;
}
