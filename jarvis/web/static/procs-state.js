// The /procs live table: feed frames in, processes and changes out.
// No DOM and no WebGL here, so the rules run in Node (tests/test_procs_page.py).
//
// Frames (platform/procfeed.py): snap, d, ev, i, status. A process is keyed
// h + '|' + "pid:created_ms", so a reused pid is a different process.
//
// Real-time rules:
//   * A process is "born" when it arrives in a delta, or in a resynchronising
//     snapshot with a creation time after the last moment that host was live:
//     a start during a reconnect or a helper handoff is still a start.
//   * A Sysmon start that no table shows within GHOST_WAIT_MS lived and died
//     between two looks: it becomes a ghost, counted per host and, if its
//     startVerdict is alarm or notice, listed.
//   * The same change again (same kind, host, name and reason) within
//     REPEAT_MS updates one line with a count instead of adding lines, so a
//     process that starts every second cannot flood the list.
//   * Missing is judged only while that host's feed is live; a stale feed says
//     nothing is gone.
import { ROW, changeLine, classify, missing, norm, rank, startVerdict, verdict } from './procs-model.js';

export const GHOST_WAIT_MS = 1200;
export const EXIT_MEMORY_MS = 60 * 1000;   // a late Sysmon start for an exited pid is not a ghost
export const CHANGES_MAX = 120;
export const REPEAT_MS = 10 * 60 * 1000;
export const HOSTS = ['win', 'lin'];

export class ProcState {
  constructor({ wallMs = () => Date.now(), monoMs = () => performance.now() } = {}) {
    this.wallMs = wallMs;
    this.monoMs = monoMs;
    this.procs = new Map();
    this.sources = {};
    this.identity = null;
    this.baseline = null;
    this.changes = [];
    this.shortLived = { win: 0, lin: 0 };
    this.structural = true;      // the tree must be laid out again
    this.changed = true;         // lists and tallies must be redrawn
    this.liveAt = {};            // h -> wall ms of the last frame while live
    this.seenSnap = {};          // h -> a snapshot has been applied
    this.pendingStarts = [];
    this.exited = { win: new Map(), lin: new Map() };   // pid -> mono ms of its exit
    this.ghosts = [];            // new ghosts for the scene to draw
    this.everSeen = { win: new Set(), lin: new Set() };
    this.missingNow = { win: new Set(), lin: new Set() };
  }

  // ---- frames --------------------------------------------------------------

  apply(f) {
    if (!f || typeof f !== 'object') return;
    if (f.k === 'snap') this.onSnap(f);
    else if (f.k === 'd') this.onDelta(f);
    else if (f.k === 'i') this.onIdent(f);
    else if (f.k === 'ev') this.onStart(f);
    else if (f.k === 'status') this.onStatus(f);
    else return;
    if (f.h && this.isLive(f.h) && Number.isFinite(f.t)) this.liveAt[f.h] = f.t;
    this.changed = true;
  }

  onSnap(f) {
    const resync = !!this.seenSnap[f.h];
    const since = this.liveAt[f.h];
    const seen = new Set();
    for (const r of f.p || []) {
      const born = resync && Number.isFinite(since) && r[ROW.created] > since;
      this.upsert(f.h, r, born);
      seen.add(f.h + '|' + r[ROW.key]);
    }
    for (const [id, p] of this.procs) if (p.h === f.h && !seen.has(id)) this.exit(id);
    this.seenSnap[f.h] = true;
  }

  onDelta(f) {
    for (const r of f.a || []) this.upsert(f.h, r, true);
    for (const k of f.x || []) this.exit(f.h + '|' + k);
    for (const u of f.u || []) {
      const p = this.procs.get(f.h + '|' + u[0]);
      if (p) { p.cpu = +u[1] || 0; p.rss = +u[2] || 0; }
    }
  }

  onIdent(f) {
    for (const [key, ident] of f.i || []) {
      const p = this.procs.get(f.h + '|' + key);
      if (p) { p.ident = ident; this.judge(p); }
    }
  }

  onStart(f) {
    this.pendingStarts.push({ at: this.monoMs(), h: f.h || 'win', pid: f.pid, ppid: f.ppid,
      name: f.name || '?', ident: f.i || null });
  }

  onStatus(f) {
    Object.assign(this.sources, f.sources || {});
    if (f.identity) this.identity = f.identity;
  }

  isLive(h) { return !!(this.sources[h] && this.sources[h].state === 'live'); }

  // ---- processes -------------------------------------------------------------

  upsert(h, r, born) {
    const id = h + '|' + r[ROW.key];
    let p = this.procs.get(id);
    if (!p) {
      // born/dying are flags; bornAt/dyingAt are their monotonic times.
      p = { id, h, x: NaN, z: NaN, y: 0, tx: 0, tz: 0, born, bornAt: this.monoMs(), dying: false, dyingAt: 0,
        level: 'unknown', reason: null, logged: 'calm' };
      this.procs.set(id, p);
      this.structural = true;
    } else if (p.dying) {
      p.dying = false; this.structural = true;
    }
    const fresh = p.name === undefined;
    p.pid = r[ROW.pid]; p.ppid = r[ROW.ppid]; p.name = r[ROW.name] || '?'; p.created = r[ROW.created];
    p.cpu = +r[ROW.cpu] || 0; p.rss = +r[ROW.rss] || 0; p.session = r[ROW.session];
    if (r.length > ROW.ident && r[ROW.ident] !== null) p.ident = r[ROW.ident];
    if (fresh) {
      p.cls = classify(this.baseline, h, p.name, this.wallMs() / 1000);
      if (this.isWatched(h, p.name)) this.everSeen[h].add(p.name.toLowerCase());
    }
    this.judge(p);
  }

  exit(id) {
    const p = this.procs.get(id);
    if (!p || p.dying) return;
    p.dying = true;
    p.dyingAt = this.monoMs();
    if (this.exited[p.h]) this.exited[p.h].set(p.pid, p.dyingAt);
    this.structural = true;
    this.log('exit', p.h, p.name, p.level, p.reason, null);
  }

  // Re-derive a process's level; a born process is listed the first time its
  // level reaches notice or alarm, and again if it rises to alarm.
  judge(p) {
    const v = verdict(p.cls, p.ident);
    p.level = v.level; p.reason = v.reason;
    if (p.born && !p.dying && rank(v.level) > rank(p.logged) && rank(v.level) >= rank('notice')) {
      p.logged = v.level;
      this.log('start', p.h, p.name, v.level, v.reason, p.id);
    }
  }

  setBaseline(doc) {
    this.baseline = doc;
    const nowS = this.wallMs() / 1000;
    for (const p of this.procs.values()) {
      p.cls = classify(doc, p.h, p.name, nowS);
      this.judge(p);
      // the snapshot usually arrives before the baseline: watched processes
      // already running count as seen, or their exit could never be missed
      if (!p.dying && this.everSeen[p.h] && this.isWatched(p.h, p.name)) this.everSeen[p.h].add(p.name.toLowerCase());
    }
    this.changed = true;
  }

  isWatched(h, name) {
    const watch = this.baseline && this.baseline.watch && this.baseline.watch[h];
    return !!(watch && watch.includes(String(name).toLowerCase()));
  }

  log(kind, h, name, level, reason, id) {
    const k = changeLine(kind, level, kind === 'exit' && this.isWatched(h, name));
    if (!k) return;
    const at = this.wallMs();
    const i = this.changes.findIndex((c) => c.k === k && c.h === h && c.name === name && c.reason === reason
      && at - c.at < REPEAT_MS);
    const line = i < 0 ? { k, at, h, name, reason, id, count: 1 } : this.changes.splice(i, 1)[0];
    if (i >= 0) { line.count++; line.at = at; line.id = id || line.id; }
    this.changes.unshift(line);
    if (this.changes.length > CHANGES_MAX) this.changes.length = CHANGES_MAX;
    this.changed = true;
  }

  // ---- once per animation frame / second -------------------------------------------

  // Sysmon starts that no table showed in time become ghosts.
  settleStarts(now = this.monoMs()) {
    for (const exits of Object.values(this.exited)) {
      for (const [pid, at] of exits) if (now - at > EXIT_MEMORY_MS) exits.delete(pid);
    }
    while (this.pendingStarts.length && now - this.pendingStarts[0].at > GHOST_WAIT_MS) {
      const e = this.pendingStarts.shift();
      let found = !!(this.exited[e.h] && this.exited[e.h].has(e.pid)), parent = null;
      for (const p of this.procs.values()) {
        if (p.h !== e.h) continue;
        if (p.pid === e.pid) { found = true; break; }
        if (p.pid === e.ppid && !p.dying) parent = p;
      }
      if (found) continue;
      this.shortLived[e.h] = (this.shortLived[e.h] || 0) + 1;
      const v = startVerdict(e.ident);
      this.ghosts.push({ h: e.h, parent, level: v.level });
      this.log('short', e.h, e.name, v.level, v.reason, null);
      this.changed = true;
    }
  }

  // Watched processes gone or back, and the tallies.
  tally() {
    const present = { win: new Set(), lin: new Set() };
    const out = { win: 0, lin: 0, alarm: 0, notice: 0, missing: 0 };
    for (const p of this.procs.values()) {
      if (p.dying) continue;
      out[p.h]++;
      present[p.h].add(p.name.toLowerCase());
      if (p.level === 'alarm') out.alarm++; else if (p.level === 'notice') out.notice++;
    }
    for (const h of HOSTS) {
      if (this.isLive(h)) {
        const now = new Set(missing(this.baseline, h, present[h], this.everSeen[h]));
        for (const n of now) if (!this.missingNow[h].has(n)) this.log('missing', h, n, null, null, null);
        for (const n of this.missingNow[h]) if (!now.has(n)) this.log('back', h, n, null, null, null);
        this.missingNow[h] = now;
      }
      out.missing += this.missingNow[h].size;
    }
    return out;
  }

  remove(id) { this.procs.delete(id); this.structural = true; }

  alive() { return [...this.procs.values()].filter((p) => !p.dying); }

  matches(p, query) {
    return !query || p.name.toLowerCase().includes(query) || String(p.pid) === query || norm(p.name) === query;
  }
}
