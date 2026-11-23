"""Process boundary for collectors that touch failure-prone kernel bridges.

This module is intentionally not a general command runner. The parent passes a
fixed collector name and ordinary data arguments; only collectors explicitly
listed here may execute. stdout is one JSON result so the scheduler can commit
the same observation receipt it would have produced in-process.
"""

import json
import sys
import time
import traceback

from jarvis.core import collection, mechanisms
from jarvis.service.jobs import run_job

# Only collectors declared isolated in the registry may run here; the parent
# passes a name, never a command.
ALLOWED = frozenset(mechanisms.names(isolated=True))


def _own_cost():
    """(CPU seconds, peak resident KiB) of this worker. `resource` is POSIX
    only: the Windows edition reports CPU time and no peak."""
    try:
        import resource
    except ImportError:
        return time.process_time(), 0
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime, int(usage.ru_maxrss)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 3 or argv[0] not in ALLOWED:
        return 2
    name, db_path, *hosts = argv
    findings, error, status = [], "", "unavailable"
    try:
        with collection.observe() as observation:
            findings = list(run_job(name, tuple(hosts), db_path) or [])
        error, status = observation.error, observation.status
    except Exception:
        error = traceback.format_exc()[-800:]
    # Its own cost, so the scheduler can report what each collector spends.
    cpu_s, peak_kib = _own_cost()
    sys.stdout.write(json.dumps({"findings": findings, "error": error, "status": status,
                                 "cpu_s": round(cpu_s, 3), "max_rss_kib": peak_kib},
                                separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
