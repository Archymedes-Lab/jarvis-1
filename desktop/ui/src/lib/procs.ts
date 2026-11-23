// Pure logic for the Processes screen. No DOM, no I/O; tested in procs.test.ts.
//
// A snapshot row from the daemon's live process feed is
// [key, pid, ppid, name, created_ms, cpu, rss_bytes, session, ident]. A name is
// judged against the names the scan collector has already recorded on this host
// (/api/procs/baseline): never seen is worth a look, seen before is calm. This
// mirrors the lens rules of the full /procs page for names; the deeper image
// checks (ident) stay on that page.

export type NameClass = "unknown" | "new" | "recent" | "known" | "approved";
export interface ProcRow { key: string; pid: number; ppid: number; name: string; created: number; cpu: number; rss: number; cls: NameClass }
export type Baseline = { ok?: boolean; recent_s?: number; hosts?: Record<string, { rows: number; names: Record<string, any[]> }> } | null;

/** The lens key for a name: lower case, a trailing process id folded to "(#)". */
export function norm(name: string): string {
  return String(name || "").trim().toLowerCase().replace(/\(\d+\)$/, "(#)");
}

export function hostReady(b: Baseline, host: string): boolean {
  return !!(b && b.ok && b.hosts && b.hosts[host] && b.hosts[host].rows > 0);
}

export function classify(b: Baseline, host: string, name: string, nowS: number): NameClass {
  if (!hostReady(b, host) || !name) return "unknown";
  const row = b!.hosts![host].names[norm(name)];
  if (!row) return "new";
  const [first, , , approved] = row;
  if (approved) return "approved";
  if (nowS - first < (b!.recent_s || 86400)) return "recent";
  return "known";
}

export function rowsFrom(snap: any[][] | undefined, b: Baseline, host: string, nowS: number): ProcRow[] {
  return (snap ?? []).map((r) => ({
    key: String(r[0]), pid: Number(r[1]), ppid: Number(r[2]), name: String(r[3] ?? ""),
    created: Number(r[4]) || 0, cpu: Number(r[5]) || 0, rss: Number(r[6]) || 0,
    cls: classify(b, host, String(r[3] ?? ""), nowS),
  }));
}

const ORDER: Record<NameClass, number> = { new: 0, recent: 1, unknown: 2, known: 3, approved: 4 };

export function filterProcs(rows: ProcRow[], query: string, onlyNew: boolean): ProcRow[] {
  const q = query.trim().toLowerCase();
  return rows
    .filter((r) => (!onlyNew || r.cls === "new" || r.cls === "recent") && (!q || r.name.toLowerCase().includes(q) || String(r.pid) === q))
    .sort((a, b) => ORDER[a.cls] - ORDER[b.cls] || a.name.localeCompare(b.name) || a.pid - b.pid);
}

export function procCounts(rows: ProcRow[]) {
  const out = { total: rows.length, fresh: 0 };
  for (const r of rows) if (r.cls === "new" || r.cls === "recent") out.fresh++;
  return out;
}

export function megabytes(bytes: number): string {
  return bytes >= 1048576 ? `${Math.round(bytes / 1048576)} MB` : bytes > 0 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : "—";
}
