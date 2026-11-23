#!/usr/bin/env python3
"""Measure what each collector really costs: CPU seconds and peak memory per run.

    python3 scripts/dev/job_cost.py [--edition server] [--runs 2] [--json OUT]

Each collector the edition schedules on this host runs in its own child process,
exactly as the scheduler would call it (jobs.run_job), against a throwaway store
under a throwaway HOME, so the live install, its database and its alert channels
are never touched. Only the Linux domain is observed (no PowerShell into Windows).
Jobs whose work is a download are skipped (their cost is network, daily).

Reported per job: CPU seconds of the last run (user+sys, children included), peak
RSS, wall seconds, and duty = CPU / interval: the share of one core it costs at its
schedule. The sum of duty is the steady-state CPU the edition needs on this host.
Measurements, not estimates: rerun on the host you care about.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from jarvis.core import mechanisms  # noqa: E402
from jarvis.platform import facts as hostfacts  # noqa: E402
from jarvis.service import schedule  # noqa: E402

# Work that is a download or a delivery: measured by bytes and time, not here.
NETWORK = {"feeds", "intel", "osv", "distrovuln", "heartbeat", "report", "friday_defender", "model", "world"}
CHILD = ("import sys; sys.path.insert(0, %r)\n"
         "from jarvis.service.jobs import run_job\n"
         "run_job(sys.argv[1], ('wsl',), sys.argv[2])\n") % ROOT


def run_once(name, db, home, timeout):
    env = {"HOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
           "JARVIS_NO_ALERTS": "1"}
    t0 = time.monotonic()
    proc = subprocess.Popen([sys.executable, "-I", "-c", CHILD, name, db], env=env, cwd=home,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = t0 + timeout
    while True:
        pid, status, ru = os.wait4(proc.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() > deadline:
            proc.kill()
            pid, status, ru = os.wait4(proc.pid, 0)
            return {"timeout": True, "wall_s": round(time.monotonic() - t0, 1)}
        time.sleep(0.05)
    err = proc.stderr.read().decode("utf-8", "replace")[-300:] if os.waitstatus_to_exitcode(status) else ""
    return {"cpu_s": round(ru.ru_utime + ru.ru_stime, 3), "rss_mb": round(ru.ru_maxrss / 1024, 1),
            "wall_s": round(time.monotonic() - t0, 2), "exit": os.waitstatus_to_exitcode(status), "error": err}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--edition", choices=("server", "workstation"), default="server")
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--json")
    ap.add_argument("--seed-db", help="start from a consistent copy of this store (read with the SQLite backup API)")
    args = ap.parse_args(argv)
    server = args.edition == "server"
    keep, _absent = schedule.applicable(False, True, server=server, facts=hostfacts.current())
    names = [n for n in keep if n not in NETWORK and (not args.only or n in args.only)]
    rows = []
    with tempfile.TemporaryDirectory(prefix="jobcost-") as home:
        os.makedirs(os.path.join(home, ".jarvis"), mode=0o700)
        db = os.path.join(home, ".jarvis", "jarvis.db")
        if args.seed_db:
            import sqlite3
            src = sqlite3.connect(f"file:{args.seed_db}?mode=ro", uri=True, timeout=30)
            dst = sqlite3.connect(db)
            src.backup(dst)
            dst.close()
            src.close()
            print(f"seeded from {args.seed_db}: {os.path.getsize(db) / 1e6:.0f} MB", flush=True)
        for name in names:
            c = mechanisms.BY_NAME[name]
            result = {}
            for _ in range(max(1, args.runs)):
                result = run_once(name, db, home, timeout=max(60.0, c.timeout * 2))
            cpu = result.get("cpu_s")
            rows.append({"job": name, "interval_s": c.interval, "lane": c.lane, **result,
                         "duty_pct": round(cpu / c.interval * 100, 2) if cpu is not None else None})
            print(f"{name:<16} cpu {cpu if cpu is not None else '-':>7}s  rss {result.get('rss_mb', '-'):>6} MB  "
                  f"wall {result.get('wall_s', '-'):>6}s  every {c.interval:>6}s  duty "
                  f"{rows[-1]['duty_pct'] if rows[-1]['duty_pct'] is not None else '-'}%"
                  + (" TIMEOUT" if result.get("timeout") else "") + (" ERR" if result.get("error") else ""), flush=True)
    total = sum(r["duty_pct"] or 0 for r in rows)
    print(f"steady-state CPU for the {args.edition} edition on this host: {total:.1f}% of one core "
          f"({len(rows)} jobs measured, {len(NETWORK & set(keep))} network jobs skipped)")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"facts": hostfacts.current(), "rows": rows, "total_duty_pct": round(total, 2)}, fh, indent=1)


if __name__ == "__main__":
    main()
