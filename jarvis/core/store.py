"""SQLite-backed baseline of known-good processes and network peers."""

import os
import sqlite3
import time
import uuid

from . import incidents
from .schema import SCHEMA
from .util import now

DEFAULT_DB = os.path.expanduser("~/.jarvis/jarvis.db")

# Per-connection SQLite memory. Connections here are short-lived (one per job,
# one per API request), so a large private page cache is filled once and thrown
# away, and a memory map pins up to its size of the database file into every
# reader's resident set. The kernel page cache already holds the file once,
# shared and reclaimable. Measured 2026-11-06 on a 961 MB copy of the live store:
#   hunt          64 MiB cache + 256 MiB mmap: peak 305 MB;  4 MiB, no mmap: 38-44 MB
#   sysmon_linux  360 MB -> 87 MB;  /api/state build_state 406 MB -> 91 MB
# with CPU per call unchanged within noise (state 3-4 s in every setting).
CACHE_KIB = 4096          # 4 MiB private page cache per connection
MMAP_BYTES = 0            # no memory map: reads go through the shared page cache


class Store:
    def __init__(self, path=DEFAULT_DB):
        self.path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        # The indicator tables grow into the hundreds of thousands of rows and
        # are written in large batches by the feeds while the dashboard reads
        # from another thread. WAL keeps readers from blocking on those writes.
        # This database also contains response authority and incident evidence;
        # it is not just a replaceable feed cache. FULL syncs committed WAL data.
        for pragma in ("journal_mode=WAL", "synchronous=FULL",
                       f"cache_size=-{CACHE_KIB}", "temp_store=MEMORY",
                       f"mmap_size={MMAP_BYTES}", "busy_timeout=10000"):
            try:
                self.db.execute(f"PRAGMA {pragma}")
            except sqlite3.Error:
                pass
        self.db.executescript(SCHEMA)
        self._migrate()
        self.db.commit()

    def _migrate(self):
        """Add columns introduced after a database was first created."""
        beat = {r[1] for r in self.db.execute("PRAGMA table_info(input_beats)")}
        for col in ("real_moves", "injected_moves", "lat_avg_ms", "lat_max_ms",
                    "lat_over50", "lat_samples", "injected_keyups",
                    "injected_move_bursts", "real_key_gaps", "real_key_sub20",
                    "real_key_sub8", "cad_run_max"):
            if col not in beat:
                self.db.execute(
                    f"ALTER TABLE input_beats ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
        typing = {r[1] for r in self.db.execute(
            "PRAGMA table_info(input_typing_windows)")}
        for col in ("equals_keys", "slash_keys", "period_keys", "digit_keys"):
            if col not in typing:
                self.db.execute(
                    f"ALTER TABLE input_typing_windows ADD COLUMN {col} "
                    "INTEGER NOT NULL DEFAULT 0")
        events = {r[1] for r in self.db.execute("PRAGMA table_info(input_events)")}
        for col, decl in (("ms", "INTEGER NOT NULL DEFAULT 0"),
                          ("burst", "TEXT NOT NULL DEFAULT ''"),
                          ("record", "TEXT NOT NULL DEFAULT ''")):
            if col not in events:
                self.db.execute(f"ALTER TABLE input_events ADD COLUMN {col} {decl}")
        have = {r[1] for r in self.db.execute("PRAGMA table_info(indicators)")}
        for col, decl in (("source", "TEXT NOT NULL DEFAULT 'exa'"),
                          ("malware", "TEXT DEFAULT ''")):
            if col not in have:
                self.db.execute(f"ALTER TABLE indicators ADD COLUMN {col} {decl}")
        sounds = {r[1] for r in self.db.execute("PRAGMA table_info(sound_events)")}
        for col, decl in (("caller", "TEXT NOT NULL DEFAULT ''"),
                          ("caller_pid", "INTEGER NOT NULL DEFAULT 0"),
                          ("caller_app", "TEXT NOT NULL DEFAULT ''"),
                          ("caller_start", "TEXT NOT NULL DEFAULT ''"),
                          ("caller_blocked_new", "INTEGER NOT NULL DEFAULT -1"),
                          ("console_pid", "INTEGER NOT NULL DEFAULT 0"),
                          ("console_app", "TEXT NOT NULL DEFAULT ''"),
                          ("console_start", "TEXT NOT NULL DEFAULT ''"),
                          ("likely_pid", "INTEGER NOT NULL DEFAULT 0"),
                          ("likely_app", "TEXT NOT NULL DEFAULT ''"),
                          ("likely_start", "TEXT NOT NULL DEFAULT ''"),
                          ("likely_list", "TEXT NOT NULL DEFAULT ''"),
                          ("likely_n", "INTEGER NOT NULL DEFAULT 0")):
            if col not in sounds:
                self.db.execute(f"ALTER TABLE sound_events ADD COLUMN {col} {decl}")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_ind_source "
                        "ON indicators(source, last_seen)")
        # hunt joins the peer table against indicators by address, so the
        # address needs its own index once peers number in the tens of
        # thousands. Without it every hunt is a full scan of peers.
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_peers_ip "
                        "ON peers(remote_ip)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_peers_rdns "
                        "ON peers(rdns)")

    # -- alert ledger -------------------------------------------------------

    _SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

    def ledger_sent(self, key, finding, job, fix="", ts=None):
        """Record that an alert was mailed. Idempotent per (key, send)."""
        ts = int(ts if ts is not None else time.time())
        sev = str(finding.get("severity") or "")
        row = self.db.execute(
            "SELECT worst_sev, cleared_at, sent_count, reopened "
            "FROM alert_ledger WHERE key=?", (key,)).fetchone()
        if row is None:
            self.db.execute(
                "INSERT INTO alert_ledger (key, category, title, detail, locus,"
                " host, job, severity, worst_sev, fix, first_sent, last_sent,"
                " sent_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
                (key, finding.get("category", ""), finding.get("title", ""),
                 finding.get("detail", "")[:2000], finding.get("where", ""),
                 finding.get("host", ""), job, sev, sev, fix[:500], ts, ts))
            return
        worst = row["worst_sev"] or sev
        if self._SEV_RANK.get(sev, 9) < self._SEV_RANK.get(worst, 9):
            worst = sev
        # A row that had been cleared and is being sent again has reopened —
        # the single most important state this table exists to distinguish.
        reopened = row["reopened"] + (1 if row["cleared_at"] else 0)
        # host/category/locus are refreshed too, not just the volatile fields:
        # rows imported from the old alert state carry placeholders for them,
        # and the first genuine send of that finding is what corrects them.
        self.db.execute(
            "UPDATE alert_ledger SET detail=?, severity=?, worst_sev=?, fix=?,"
            " job=?, last_sent=?, sent_count=sent_count+1, cleared_at=0,"
            " reopened=?, category=?, locus=?,"
            " host=CASE WHEN ?<>'' THEN ? ELSE host END WHERE key=?",
            (finding.get("detail", "")[:2000], sev, worst, fix[:500], job, ts,
             reopened, finding.get("category", ""), finding.get("where", ""),
             finding.get("host", ""), finding.get("host", ""), key))

    def ledger_cleared(self, key, ts=None):
        ts = int(ts if ts is not None else time.time())
        self.db.execute(
            "UPDATE alert_ledger SET cleared_at=?, clear_count=clear_count+1 "
            "WHERE key=? AND cleared_at=0", (ts, key))

    def ledger_rows(self, open_only=False, limit=500):
        sql = "SELECT * FROM alert_ledger"
        if open_only:
            sql += " WHERE cleared_at=0"
        sql += " ORDER BY last_sent DESC LIMIT ?"
        return [dict(r) for r in self.db.execute(sql, (limit,))]

    def close(self):
        self.db.close()

    # -- meta ---------------------------------------------------------------

    def get_meta(self, key, default=None):
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def set_meta(self, key, value):
        self.db.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, str(value)),
        )
        self.db.commit()

    # -- processes ----------------------------------------------------------

    def known_fps(self):
        return {r["fp"] for r in self.db.execute("SELECT fp FROM procs")}

    def fp_status(self, fps, chunk=500):
        """(known, approved): which of `fps` are in procs, and which of those are approved.

        A scan needs these answers for the processes running now only; loading every
        fingerprint ever seen (and every approved row) each minute grew with history."""
        known, approved = set(), set()
        fps = list(dict.fromkeys(fps))
        for i in range(0, len(fps), chunk):
            part = fps[i:i + chunk]
            marks = ",".join("?" * len(part))
            for r in self.db.execute(f"SELECT fp, approved FROM procs WHERE fp IN ({marks})", part):
                known.add(r["fp"])
                if r["approved"] == 1:
                    approved.add(r["fp"])
        return known, approved

    def get_proc(self, fp):
        return self.db.execute("SELECT * FROM procs WHERE fp=?", (fp,)).fetchone()

    def upsert_proc(self, p, approved=0):
        """Record a sighting. An existing row keeps its approval and first_seen."""
        ts = now()
        self.db.execute(
            """INSERT INTO procs(fp,host,name,exe,script,cmdline,user,
                                 first_seen,last_seen,seen_count,approved)
               VALUES(?,?,?,?,?,?,?,?,?,1,?)
               ON CONFLICT(fp) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   seen_count=procs.seen_count+1""",
            (p["fp"], p["host"], p["name"], p["exe"], p.get("script", ""),
             p["cmdline"], p["user"], ts, ts, approved),
        )

    def set_approved(self, fp, approved=1, note=""):
        cur = self.db.execute(
            "UPDATE procs SET approved=?, note=? WHERE fp=?", (approved, note, fp)
        )
        self.db.commit()
        return cur.rowcount

    def list_procs(self, approved=None, limit=200):
        sql = "SELECT * FROM procs"
        args = []
        if approved is not None:
            sql += " WHERE approved=?"
            args.append(approved)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    # -- network peers ------------------------------------------------------

    def upsert_peer(self, host, fp, ip, port, scope, rdns=""):
        """Returns True the first time this process talks to this peer."""
        key = f"{host}|{fp}|{ip}|{port}"
        ts = now()
        existing = self.db.execute("SELECT key FROM peers WHERE key=?", (key,)).fetchone()
        if existing:
            self.db.execute(
                "UPDATE peers SET last_seen=?, seen_count=seen_count+1 WHERE key=?", (ts, key)
            )
            return False
        self.db.execute(
            """INSERT INTO peers(key,host,fp,remote_ip,remote_port,scope,rdns,
                                 first_seen,last_seen)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, host, fp, ip, port, scope, rdns, ts, ts),
        )
        return True

    def list_peers(self, scope=None, limit=200):
        sql = ("SELECT p.*, pr.name AS pname, pr.exe AS pexe FROM peers p "
               "LEFT JOIN procs pr ON pr.fp = p.fp")
        args = []
        if scope:
            sql += " WHERE p.scope=?"
            args.append(scope)
        sql += " ORDER BY p.last_seen DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    # -- events -------------------------------------------------------------

    def add_event(self, ev):
        self.db.execute(
            """INSERT INTO events(ts,host,severity,kind,fp,pid,name,exe,
                                  cmdline,user,reasons,remotes)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev["ts"], ev["host"], ev["severity"], ev["kind"], ev.get("fp"),
             ev.get("pid"), ev.get("name"), ev.get("exe"), ev.get("cmdline"),
             ev.get("user"), ev.get("reasons", ""), ev.get("remotes", "")),
        )

    def list_events(self, limit=50, severity=None, since=None):
        sql = "SELECT * FROM events WHERE 1=1"
        args = []
        if severity:
            sql += " AND severity=?"
            args.append(severity)
        if since:
            sql += " AND ts>=?"
            args.append(since)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    def commit(self):
        self.db.commit()

    # -- dashboard snapshots ------------------------------------------------

    def record_observation(self, kind, findings, *, coverage="complete", error="",
                           observed_at=None, run_id=None):
        """Commit evidence and incident changes before downstream response."""
        if self.db.in_transaction:
            raise RuntimeError("observation requires a connection without pending writes")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            return incidents.record(
                self.db, kind, findings, run_id=run_id or uuid.uuid4().hex,
                observed_at=time.time() if observed_at is None else observed_at,
                coverage=coverage, error=error)

    def save_snapshot(self, kind, payload, duration=0.0, error=""):
        """Store the latest result for one audit, plus a severity data point."""
        import json as _json

        self.db.execute(
            """INSERT INTO snapshots(kind,ts,duration,error,payload)
               VALUES(?,?,?,?,?)
               ON CONFLICT(kind) DO UPDATE SET
                   ts=excluded.ts, duration=excluded.duration,
                   error=excluded.error, payload=excluded.payload""",
            (kind, now(), duration, error, _json.dumps(payload, default=str)),
        )
        counts = {}
        if isinstance(payload, list):
            for f in payload:
                sev = (f or {}).get("severity")
                if sev in ("critical", "high", "medium", "low"):
                    counts[sev] = counts.get(sev, 0) + 1
        self.db.execute(
            """INSERT INTO history(ts,kind,critical,high,medium,low)
               VALUES(?,?,?,?,?,?)""",
            (now(), kind, counts.get("critical", 0), counts.get("high", 0),
             counts.get("medium", 0), counts.get("low", 0)),
        )
        # Keep the trend strip bounded; a week of points is plenty.
        self.db.execute("DELETE FROM history WHERE ts < ?", (now() - 7 * 86400,))
        self.db.commit()

    def get_snapshots(self):
        import json as _json

        out = {}
        for r in self.db.execute("SELECT * FROM snapshots"):
            try:
                payload = _json.loads(r["payload"])
            except Exception:
                payload = []
            out[r["kind"]] = {"ts": r["ts"], "duration": r["duration"],
                              "error": r["error"], "findings": payload}
        return out

    def get_history(self, hours=24):
        rows = self.db.execute(
            """SELECT ts, SUM(critical) c, SUM(high) h, SUM(medium) m, SUM(low) l
               FROM history WHERE ts >= ? GROUP BY ts/900 ORDER BY ts""",
            (now() - hours * 3600,),
        ).fetchall()
        return [{"ts": r["ts"], "critical": r["c"], "high": r["h"],
                 "medium": r["m"], "low": r["l"]} for r in rows]
