#!/usr/bin/env python3
"""Resident memory of a daemon-shaped workload: lanes as threads, each holding one
store connection for its life and running real jobs, plus dashboard state builds,
in one process. Compares the store/allocator settings before and after
core/memory.py on a consistent copy of a real store; the live install, its
database and its alert channels are never touched (throwaway HOME).

    python3 scripts/dev/daemon_memory.py --seed-db ~/.jarvis/jarvis.db [--rounds 2]

Prints, per mode: peak resident (VmHWM), and at the end anonymous and file-backed
resident memory (RssAnon, RssFile) and CPU seconds. Linux only (reads /proc).
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Lane -> jobs it runs in turn (Linux domain; no PowerShell into Windows).
LANES = {"main": ["hunt", "evidence"], "frequent": ["sysmon_linux", "scan"],
         "bulk": ["rust_mirror"], "api": ["@state", "@state"]}

CHILD = r'''
import json, os, sys, threading, time, resource
sys.path.insert(0, ROOT)
mode, db, rounds, lanes = sys.argv[1], sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4])
from jarvis.core import memory, store as S
if mode == "before":
    S.CACHE_KIB, S.MMAP_BYTES = 65536, 268435456
    memory.trim = lambda *a, **k: False
else:
    memory.limit_arenas()
from jarvis.service.jobs import run_job
from jarvis.service.scheduler import Scheduler
from jarvis.web import server
sched = Scheduler(db, ("wsl",))
def lane(jobs):
    st = S.Store(db)                      # a lane keeps one connection for its life
    try:
        for _ in range(rounds):
            for job in jobs:
                if job == "@state":
                    server.build_state(db, sched)
                else:
                    run_job(job, ("wsl",), db)
                memory.trim(force=True)
    finally:
        st.close()
t = [threading.Thread(target=lane, args=(j,)) for j in lanes.values()]
[x.start() for x in t]; [x.join() for x in t]
memory.trim(force=True)
status = {l.split(":")[0]: int(l.split()[1]) // 1024 for l in open("/proc/self/status")
          if l.startswith(("VmHWM", "RssAnon", "RssFile"))}
u = resource.getrusage(resource.RUSAGE_SELF)
print(json.dumps({"mode": mode, "peak_mb": status["VmHWM"], "anon_mb": status["RssAnon"],
                  "file_mb": status["RssFile"], "cpu_s": round(u.ru_utime + u.ru_stime, 1)}))
'''


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed-db", required=True)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--modes", nargs="*", default=["before", "after"])
    args = ap.parse_args(argv)
    scratch = tempfile.mkdtemp(prefix="daemon-memory-", dir=os.path.expanduser("~/.cache"))
    try:
        seed = os.path.join(scratch, "seed.db")
        src = sqlite3.connect(f"file:{os.path.expanduser(args.seed_db)}?mode=ro", uri=True)
        dst = sqlite3.connect(seed)
        src.backup(dst)
        dst.close()
        src.close()
        results = []
        for mode in args.modes:
            home = os.path.join(scratch, mode)
            os.makedirs(home)
            db = os.path.join(home, "j.db")
            shutil.copyfile(seed, db)
            env = dict(os.environ, HOME=home)
            out = subprocess.run([sys.executable, "-I", "-c", CHILD.replace("ROOT", repr(ROOT)),
                                  mode, db, str(args.rounds), json.dumps(LANES)],
                                 env=env, capture_output=True, text=True, timeout=3600)
            line = (out.stdout.strip().splitlines() or [""])[-1]
            try:
                results.append(json.loads(line))
            except ValueError:
                results.append({"mode": mode, "error": (out.stderr or out.stdout)[-600:]})
            print(json.dumps(results[-1]), flush=True)
        return 0 if all("error" not in r for r in results) else 1
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
