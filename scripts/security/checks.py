"""Security campaign test adapters; only synthetic fixture suites are accepted."""

import json
import shutil
import subprocess
import sys
import threading
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def run_tests(modules, instrument=False):
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    counts = Counter()
    before_sys, before_thread = sys.getprofile(), threading.getprofile()
    from jarvis.web import server
    observed = {getattr(server.Handler, name).__code__: name
                for name in ("do_POST", "do_GET", "_authorized", "_same_origin", "_json_body")}

    def profile(frame, event, arg):
        # Never inspect arguments, locals, headers, tokens, bodies or return content.
        if event == "call" and frame.f_code in observed:
            counts[observed[frame.f_code]] += 1

    try:
        if instrument:
            sys.setprofile(profile)
            threading.setprofile(profile)
        result = unittest.TextTestRunner(verbosity=1, buffer=True).run(suite)
    finally:
        if instrument:
            sys.setprofile(before_sys)
            threading.setprofile(before_thread)
    print(json.dumps({"tests": result.testsRun, "skipped": len(result.skipped),
                      "failures": len(result.failures), "errors": len(result.errors),
                      "expected_failures": len(result.expectedFailures),
                      "unexpected_successes": len(result.unexpectedSuccesses),
                      "instrumented_calls": dict(counts)}))
    if not result.wasSuccessful() or result.expectedFailures:
        return 1
    if not result.testsRun or result.skipped:
        return 2
    if instrument and any(not counts[name] for name in ("do_POST", "_authorized", "_same_origin", "_json_body")):
        return 1
    return 0


def formal():
    z3 = shutil.which("z3")
    if not z3:
        print("Z3 unavailable; specification proof not run")
        return 2
    # Both the invariant and the planted overclaim must be checked: UNSAT then SAT.
    result = subprocess.run([z3, "-smt2", str(ROOT / "scripts/security/authority.smt2")],
                            capture_output=True, timeout=10, check=False)
    return 0 if result.returncode == 0 and result.stdout.split() == [b"unsat", b"sat"] else 1


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["formal"]:
        return formal()
    if args == ["iast"]:
        return run_tests(["tests.test_api_hardening", "tests.test_security_boundaries"], instrument=True)
    if len(args) >= 2 and args[0] == "tests":
        return run_tests(args[1:])
    return 2


if __name__ == "__main__":
    sys.exit(main())
