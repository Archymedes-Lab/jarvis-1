#!/usr/bin/env python3
"""Run the unit suite: everything that can run on a plain CI runner, and, on the
right host, the host-bound tests.

    python3 scripts/dev/ci_suite.py            CI: every test not listed in tests/host-bound.txt
    python3 scripts/dev/ci_suite.py --host     only the host-bound tests; refuses to run elsewhere
    python3 scripts/dev/ci_suite.py --host --json OUT   also write the result as JSON

Every failure in a test that runs is a failure: nothing is skipped, retried or
excused. tests/host-bound.txt names the tests whose code decides what to do from
the host (WSL2 with the Windows side reachable); they cannot pass on a plain Linux
runner, so CI lists them as NOT RUN rather than counting them as passed, and
release.yml requires a signed result from that host (release/host_attest.py).
"""

import argparse
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOST_BOUND = ROOT / "tests" / "host-bound.txt"
ENVIRONMENT = "wsl2-windows-interop"


def host_bound_ids():
    if not HOST_BOUND.exists():
        return []
    return [line.strip() for line in HOST_BOUND.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def host_environment():
    """(ok, description): the environment the host-bound tests are written for."""
    try:
        kernel = Path("/proc/version").read_text()
    except OSError:
        kernel = ""
    wsl = "microsoft" in kernel.lower()
    mounted = Path("/mnt/c").is_dir()
    return wsl and mounted, f"kernel={kernel.strip()[:80]!r} /mnt/c={'yes' if mounted else 'no'}"


def flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from flatten(t)
        else:
            yield t


def discover():
    sys.path.insert(0, str(ROOT))
    return unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", action="store_true", help="run only the host-bound tests (WSL2 required)")
    ap.add_argument("--json", help="write the result here (with --host)")
    args = ap.parse_args()

    bound = set(host_bound_ids())
    every = list(flatten(discover()))
    ids = {t.id() for t in every}
    unknown = sorted(bound - ids)
    if unknown:
        # A listed test that no longer exists would silently shrink what the host must prove.
        print("tests/host-bound.txt lists tests that do not exist:")
        for t in unknown:
            print("  " + t)
        return 1

    ok, env = host_environment()
    if args.host:
        if not ok:
            print(f"NOT RUN: the host-bound tests need {ENVIRONMENT}; this is {env}")
            return 2
        chosen = [t for t in every if t.id() in bound]
    else:
        chosen = [t for t in every if t.id() not in bound]

    result = unittest.TextTestRunner(verbosity=1, buffer=True).run(unittest.TestSuite(chosen))
    failed = sorted({t.id() for t, _ in result.failures + result.errors} | {t.id() for t in result.unexpectedSuccesses})
    if args.host and args.json:
        record = {"environment": ENVIRONMENT, "ran": result.testsRun, "failed": failed,
                  "skipped": len(result.skipped), "host": env, "python": sys.version.split()[0],
                  "tests": sorted(t.id() for t in chosen)}
        Path(args.json).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"\nran {result.testsRun}, {len(failed)} failing, {len(result.skipped)} skipped by their own conditions")
    if not args.host and bound:
        print(f"NOT RUN here: {len(bound)} host-bound tests ({ENVIRONMENT}); run `python3 scripts/dev/ci_suite.py --host` "
              "on that host. A release needs its signed result.")
    for t in failed:
        print(f"FAILURE  {t}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
