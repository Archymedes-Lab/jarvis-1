"""Replay recorded findings through the alert-quality code paths (ALERT-QUALITY-2026-11-08).

    python3 scripts/dev/replay_alert_quality.py extract DB OUTDIR   # read-only copy
    PYTHONPATH=<code root> python3 scripts/dev/replay_alert_quality.py replay OUTDIR

`extract` opens DB read-only (SQLite mode=ro) and writes the snapshots, the
alert ledger, the public peers with their timing, the peer/indicator matches
and the CIDR indicators to OUTDIR as JSON. The data is private (paths,
addresses): keep OUTDIR in a scratch directory, never in the repository.

`replay` rebuilds a throwaway store from OUTDIR and runs whichever code is on
PYTHONPATH: ledger.audit, hunt.check_peers and score.compute. Run it once
against the base commit (git archive) and once against the change to get the
before/after tables in the doc. It never touches the live store.
"""

import collections
import copy
import json
import os
import sqlite3
import sys
import tempfile


def extract(db_path, out):
    os.makedirs(out, exist_ok=True)
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    snaps = {r["kind"]: {"ts": r["ts"], "duration": r["duration"], "error": r["error"],
                         "findings": json.loads(r["payload"] or "[]")}
             for r in db.execute("SELECT kind, ts, duration, error, payload FROM snapshots")}
    dump = {
        "snapshots": snaps,
        "ledger_rows": [dict(r) for r in db.execute("SELECT * FROM alert_ledger")],
        "peers_public": [dict(r) for r in db.execute(
            "SELECT p.remote_ip ip, p.remote_port port, p.host host, p.rdns rdns, p.seen_count seen,"
            " p.first_seen first, p.last_seen last, pr.name pname, pr.exe exe"
            " FROM peers p LEFT JOIN procs pr ON pr.fp=p.fp WHERE p.scope='public'")],
        "peer_ip_hits": [dict(r) for r in db.execute(
            "SELECT DISTINCT i.norm ip, i.value value, i.context ctx, i.source_url src, i.malware fam,"
            " i.source feed, i.confidence confidence FROM peers p JOIN indicators i"
            " ON i.kind='ipv4' AND i.norm=p.remote_ip AND i.status='active' WHERE p.scope='public'")],
        "cidr": [dict(r) for r in db.execute(
            "SELECT norm, value, context, source_url, source, confidence FROM indicators"
            " WHERE kind='cidr' AND status='active'")],
    }
    db.close()
    for name, data in dump.items():
        with open(os.path.join(out, name + ".json"), "w") as fh:
            json.dump(data, fh, default=str)
    print(f"extracted {len(snaps)} snapshots, {len(dump['ledger_rows'])} ledger rows, "
          f"{len(dump['peers_public'])} public peers to {out}")


def _load(out, name):
    with open(os.path.join(out, name + ".json")) as fh:
        return json.load(fh)


def _store():
    from jarvis.core.store import Store
    return Store(os.path.join(tempfile.mkdtemp(prefix="aq-replay-"), "r.db"))


def _ledger(out, snaps):
    from jarvis.response import alert, ledger
    rows = _load(out, "ledger_rows")
    st = _store()
    if rows:
        cols = list(rows[0])
        st.db.executemany(f"INSERT INTO alert_ledger ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                          [[r[c] for c in cols] for r in rows])
    st.set_meta("ledger_backfilled", "1")
    st.commit()
    now = int(snaps["ledger"]["ts"])
    job_ts = {k: int(v.get("ts") or 0) for k, v in snaps.items() if not v.get("error")}
    try:
        found = ledger.audit(st, job_ts=job_ts, now_ts=now, snapshots=snaps)
    except TypeError:                       # base code: no snapshots parameter
        found = ledger.audit(st, job_ts=job_ts, now_ts=now)
    listed = {alert.finding_key(f) for j, s in snaps.items() if j != "ledger"
              for f in s["findings"] if f.get("severity") != "ok"}
    restating = sum(1 for f in found if f["severity"] in ("critical", "high", "medium")
                    and ": " in f["title"] and any(
                        k.split("|")[1] == f["title"].split(": ", 1)[1]
                        and k.split("|", 2)[2] == f.get("where") for k in listed))
    print("ledger:", dict(collections.Counter(f["severity"] for f in found)),
          f"| weighted notes restating a listed finding: {restating}"
          f" | orphans kept at full severity: {sum(1 for f in found if f.get('orphan') and f['severity'] != 'ok')}")
    if hasattr(ledger, "annotate"):
        rows_by_key = ledger.open_rows(st)
        ann = [f["ledger"]["state"] for j, s in snaps.items() if j != "ledger"
               for f in ledger.annotate(s["findings"], j, rows_by_key, now) if f.get("ledger")]
        print("  originals annotated:", dict(collections.Counter(a for a in ann if a != "open")))
    return found


def _hunt(out):
    from jarvis.intel import hunt
    st = _store()
    fps = {}
    for i, p in enumerate(_load(out, "peers_public")):
        fp = fps.setdefault((p["pname"], p["exe"], p["host"]), f"fp{len(fps)}") if p["pname"] else f"none{i}"
        if p["pname"]:
            st.db.execute("INSERT OR IGNORE INTO procs(fp,host,name,exe,first_seen,last_seen) VALUES(?,?,?,?,0,0)",
                          (fp, p["host"], p["pname"], p["exe"] or ""))
        st.db.execute("INSERT OR IGNORE INTO peers(key,host,fp,remote_ip,remote_port,scope,rdns,first_seen,"
                      "last_seen,seen_count) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (f"{fp}|{p['ip']}|{p['port']}|{i}", p["host"], fp, p["ip"], p["port"], "public",
                       p["rdns"] or "", p.get("first") or 0, p.get("last") or 0, p.get("seen") or 1))
    for h in _load(out, "peer_ip_hits"):
        st.db.execute("INSERT OR IGNORE INTO indicators(kind,value,norm,confidence,topic,context,source_url,"
                      "malware,first_seen,last_seen,status,source) VALUES('ipv4',?,?,?,?,?,?,?,0,0,'active',?)",
                      (h["value"], h["ip"], h["confidence"], h["feed"], h["ctx"], h["src"], h["fam"], h["feed"]))
    for c in _load(out, "cidr"):
        st.db.execute("INSERT OR IGNORE INTO indicators(kind,value,norm,confidence,topic,context,source_url,"
                      "first_seen,last_seen,status,source) VALUES('cidr',?,?,?,?,?,?,0,0,'active',?)",
                      (c["value"], c["norm"], c["confidence"], c["source"], c["context"], c["source_url"],
                       c["source"]))
    st.commit()
    c2 = [f for f in hunt._aggregate(hunt.check_peers(st)) if f["category"] == "c2 match"]
    print("hunt c2 match:", dict(collections.Counter(f["severity"] for f in c2)))
    for f in sorted(c2, key=lambda f: ("critical", "high", "medium", "low").index(f["severity"])):
        print(f"  {f['severity']:8} {f['title'][:90]}")
    return c2


def replay(out):
    from jarvis.response import alert
    from jarvis.response.reporting import score
    from jarvis.service.schedule import JOBS
    snaps = _load(out, "snapshots")
    new_ledger = _ledger(out, snaps)
    c2 = _hunt(out)
    gaps = [f for f in snaps.get("gaps", {}).get("findings", []) if f.get("severity") != "ok"]
    print("gaps job findings:", dict(collections.Counter(f["severity"] for f in gaps)),
          "| predicate present:", hasattr(alert, "is_coverage_gap"))
    after = copy.deepcopy(snaps)
    after["ledger"]["findings"] = new_ledger
    after["hunt"]["findings"] = [f for f in snaps["hunt"]["findings"] if f["category"] != "c2 match"] + c2
    now = max(int(s["ts"] or 0) for s in snaps.values())
    for label, sn in (("recorded", snaps), ("replayed", after)):
        r = score.compute(sn, JOBS, now=now, acks={})
        print(f"score {label}: {r['score']} (coverage {r['coverage']}%)")
    totals = collections.Counter()
    for j in JOBS:
        for f in (after.get(j) or {}).get("findings") or []:
            if f.get("severity") not in (None, "ok") and not (
                    hasattr(alert, "is_coverage_gap") and alert.is_coverage_gap(f)):
                totals[f["severity"]] += 1
    print("findings-list totals after replay:", dict(totals))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "replay":
        replay(sys.argv[2])
    else:
        sys.exit(__doc__)
