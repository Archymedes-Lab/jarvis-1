"""Firewall snapshot for the daemon: `argus netstate` (ARGUS-SERVER.md W2/W5).

Run by the `argus-netstate` oneshot as the `argus-net` account with
CAP_NET_ADMIN only, which reading the netfilter ruleset needs. It runs a fixed
set of read-only commands, takes no arguments that reach them, bounds their
time and output, and writes one JSON snapshot. It never changes a rule: every
command here only lists.

Each source is recorded with ok/error so the daemon can tell "no firewall"
from "could not read the firewall" (I1).
"""

import json
import os
import shutil
import subprocess
import time

from jarvis.platform.netsensor import spool

TIMEOUT_S = 20
MAX_OUTPUT = 3 * 1024 * 1024
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}

# (name, argv, parse as JSON). Only listing commands; nothing here can write.
COMMANDS = (
    ("nft", ("nft", "-j", "list", "ruleset"), True),
    ("ufw", ("ufw", "status", "verbose"), False),
    ("firewalld", ("firewall-cmd", "--list-all"), False),
)


def _run(argv, run=subprocess.run, which=shutil.which):
    """{"ok": bool, ...} for one command: text or error, never raises."""
    exe = which(argv[0], path=CLEAN_ENV["PATH"])
    if not exe:
        return {"ok": False, "error": "not installed"}
    try:
        res = run((exe,) + tuple(argv[1:]), capture_output=True, timeout=TIMEOUT_S,
                  env=CLEAN_ENV, stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {TIMEOUT_S} s"}
    except OSError as exc:
        return {"ok": False, "error": f"could not run: {exc.strerror or exc}"}
    out = res.stdout[:MAX_OUTPUT + 1]
    if len(out) > MAX_OUTPUT:
        return {"ok": False, "error": f"output larger than {MAX_OUTPUT} bytes"}
    if res.returncode != 0:
        err = res.stderr.decode("utf-8", "replace").strip().splitlines()
        return {"ok": False, "error": f"exit {res.returncode}: " + (err[-1][:200] if err else "")}
    return {"ok": True, "text": out.decode("utf-8", "replace")}


def snapshot(run=subprocess.run, which=shutil.which, now=None):
    snap = {"ts": time.time() if now is None else now, "version": 1}
    for name, argv, as_json in COMMANDS:
        got = _run(argv, run=run, which=which)
        if got["ok"] and as_json:
            try:
                got = {"ok": True, "ruleset": json.loads(got.pop("text"))}
            except ValueError:
                got = {"ok": False, "error": "output is not JSON"}
        snap[name] = got
    # Kernel-side counters that need no privilege, for the daemon's context.
    for key, path in (("conntrack_count", "/proc/sys/net/netfilter/nf_conntrack_count"),
                      ("conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max")):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                snap[key] = int(fh.read().strip())
        except (OSError, ValueError):
            snap[key] = None
    return snap


def main(spool_dir=spool.SPOOL_DIR):
    snap = snapshot()
    os.makedirs(spool_dir, exist_ok=True)
    spool.write_json(os.path.join(spool_dir, "netstate.json"), snap)
    read = [k for k, _a, _j in COMMANDS if snap[k].get("ok")]
    print("netstate: wrote snapshot; read " + (", ".join(read) or "nothing"))
    return 0 if read else 1
