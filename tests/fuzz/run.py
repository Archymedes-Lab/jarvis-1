"""Run the fuzz targets serially, each in its own bounded child process.

    python3 -m tests.fuzz.run --budget-seconds 60            # all targets, 60 s in total
    python3 -m tests.fuzz.run --target gate.deb --budget-seconds 30
    python3 -m tests.fuzz.run --list

Safety (AGENTS.md: isolate adversarial scenarios from the protected user's
data): every child runs with HOME, TMPDIR and XDG dirs pointed at a fresh
temporary directory, so no module can resolve ~/.jarvis or ~/.argus; targets
never start the daemon, open sockets, run PowerShell or read system logs. Each
child gets a hard wall-clock kill (budget + grace) because a regex stuck in C
cannot be interrupted by the in-process alarm; the input being run at that
moment is written to a file first, so a hard hang still has a reproducer.

Exit status: 0 when no finding outside tests/fuzz/known.json was seen, 1 otherwise.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
KNOWN = os.path.join(HERE, "known.json")
GRACE_S = 20


def _isolated_env(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("JARVIS", "ARGUS", "TYPESAFE"))}
    env.update(HOME=home, TMPDIR=home, XDG_CONFIG_HOME=os.path.join(home, ".config"),
               XDG_DATA_HOME=os.path.join(home, ".local/share"), XDG_CACHE_HOME=os.path.join(home, ".cache"),
               PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")
    return env


def _encode(data):
    if isinstance(data, bytes):
        return {"bytes_hex": data.hex()} if len(data) <= 65536 else {"bytes_hex": data[:65536].hex(), "cut": True}
    return {"text": data}


def child(name, budget, seed, out_path, current_path):
    """Runs inside the isolated child: fuzz one target and write its result as JSON."""
    from tests.fuzz import engine
    from tests.fuzz.targets import all_targets
    target = next(t for t in all_targets() if t.name == name)
    fd = os.open(current_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    real_run = target.run

    def recorded(data):                     # last input on disk before it runs
        raw = data if isinstance(data, bytes) else data.encode("utf-8", "surrogatepass")
        os.ftruncate(fd, 0)
        os.pwrite(fd, raw, 0)
        return real_run(data)

    target.run = recorded
    res = engine.fuzz(target, budget, seed=seed, log=lambda m: print(m, flush=True))
    with open(out_path, "w") as fh:
        json.dump({"target": name, "executions": res.executions, "seconds": round(res.seconds, 1),
                   "corpus": res.corpus, "coverage_lines": res.coverage, "note": target.note,
                   "findings": [{"kind": f.kind, "signature": f.signature, "detail": f.detail,
                                 "count": f.count, "seconds": round(f.seconds, 3), **_encode(f.reproducer)}
                                for f in res.findings.values()]}, fh, indent=1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ARGUS-1 fuzz harness")
    ap.add_argument("--budget-seconds", type=float, default=20.0, help="total budget, split across targets")
    ap.add_argument("--per-target", type=float, help="seconds per target (overrides the split)")
    ap.add_argument("--target", action="append", help="run only this target (repeatable)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", help="directory for results (default: a new temporary directory)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--child", nargs=4, metavar=("NAME", "BUDGET", "OUT", "CURRENT"), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.child:
        name, budget, out_path, current = args.child
        return child(name, float(budget), args.seed, out_path, current)

    sys.path.insert(0, ROOT)
    home = tempfile.mkdtemp(prefix="argus-fuzz-home-")
    os.environ.update(_isolated_env(home))   # the listing imports targets too
    from tests.fuzz.targets import all_targets
    targets = all_targets()
    if args.list:
        for t in targets:
            print(f"{t.name:28} {t.kind:5} {t.note}")
        return 0
    if args.target:
        targets = [t for t in targets if t.name in args.target]
    per = args.per_target or max(1.0, args.budget_seconds / max(1, len(targets)))
    out_dir = args.out or tempfile.mkdtemp(prefix="argus-fuzz-out-")
    os.makedirs(out_dir, exist_ok=True)
    known = set(json.load(open(KNOWN))["signatures"]) if os.path.exists(KNOWN) else set()
    new, summary = 0, []
    for t in targets:
        out_path = os.path.join(out_dir, f"{t.name}.json")
        current = os.path.join(out_dir, f"{t.name}.current")
        cmd = [sys.executable, "-m", "tests.fuzz.run", "--seed", str(args.seed),
               "--child", t.name, str(per), out_path, current]
        t0 = time.monotonic()
        try:
            subprocess.run(cmd, cwd=ROOT, env=_isolated_env(home), timeout=per + t.timeout_s + GRACE_S)
            res = json.load(open(out_path))
        except subprocess.TimeoutExpired:
            with open(current, "rb") as fh:
                raw = fh.read()
            res = {"target": t.name, "executions": None, "seconds": round(time.monotonic() - t0, 1),
                   "findings": [{"kind": "hang", "signature": "hard-timeout", "count": 1,
                                 "detail": "child killed: one input never returned (stuck in C code?)",
                                 "bytes_hex": raw[:65536].hex()}]}
            with open(out_path, "w") as fh:
                json.dump(res, fh, indent=1)
        except (OSError, ValueError) as exc:
            res = {"target": t.name, "executions": None, "findings": [
                {"kind": "harness", "signature": "child-failed", "count": 1, "detail": str(exc)}]}
        for f in res["findings"]:
            key = f"{t.name}|{f['kind']}:{f['signature']}"
            f["known"] = key in known
            new += not f["known"]
        summary.append(res)
        flags = ", ".join(f"{f['kind']}:{f['signature']}{'' if f['known'] else ' NEW'}" for f in res["findings"])
        print(f"{t.name:28} execs={res.get('executions')!s:>7} cov={res.get('coverage_lines', '-')!s:>5} "
              f"{res.get('seconds')}s  {flags or 'no finding'}", flush=True)
    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    print(f"results: {out_dir}  ({new} finding(s) not in known.json)")
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
