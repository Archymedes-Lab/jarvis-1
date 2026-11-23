"""Which audits the daemon runs, and how often.

Pure data, so the scheduler, the coverage self-audit, the report cadence and the
dashboard can all read the one table without importing each other.

ALL_JOBS is every audit JARVIS has. JOBS is the part of it that applies to the
machine this process runs on (platform/host.py): a native Windows install has
no Linux domain to audit, a plain Linux one no Windows domain. A job outside
JOBS is never scheduled, never expected and never scored - it is listed in
NOT_APPLICABLE with the reason, so the absence is stated rather than silent.
"""

import os

from jarvis.core import mechanisms
from jarvis.platform import facts as hostfacts
from jarvis.platform import host

# name -> (interval seconds, label, callable(hosts) -> list[finding])
# Intervals have to fit through one worker. The scheduler runs jobs strictly
# one at a time on purpose — two concurrent powershell.exe launches are slower
# than running them back to back and fight over the same interop pipe — so the
# sum of (duration / interval) across every job is a duty cycle that must stay
# well under 1. Adding the intel and forensics collectors pushed it over, and
# the symptom was exactly what coverage.py is built to catch: short-interval
# checks silently starving behind a four-minute firewall audit and serving
# hour-old snapshots that still looked current.
#
# Measured on this machine, not estimated. The expensive collectors are the
# ones that cross the WSL interop boundary and ask Windows for a lot: the cost
# is the query, not the interop — a bare powershell.exe round trip is 0.5s.
#
#   hidden 14s   netwatch 10s   implant 15s   posture 14s   intrusion 106s
#   firewall 18s   control 16s   spy 22s   memscan 90s   feeds 90s
#   sysmon 1.5s (incremental; 23s before)   scan 2.2s   secrets 60s
#   toolchain 17s (bounded $HOME walk + one stat pass per extension)
#   coverage/hunt/gaps under 0.5s — they only touch SQLite
#
# Sysmon earned its short interval by reading only what happened since the
# last run instead of re-reading a day of log every time.

# The per-collector facts (interval, label, domain, lane, area, budgets) are
# declared once in core/mechanisms.py; these names are views of that registry.
ALL_JOBS = mechanisms.schedule_table()

# Audits of one execution domain only. Everything else either observes both
# domains (and narrows itself to the `hosts` it is given) or describes JARVIS
# itself. A collector belongs here only when it has nothing to observe without
# that domain - never because it is failing.
WINDOWS_ONLY = frozenset(mechanisms.names(domain="windows"))
LINUX_ONLY = frozenset(mechanisms.names(domain="linux"))
WORKSTATION_ONLY = frozenset(mechanisms.names(servers=False))

# Packaged JARVIS editions ship without the optional Rust runtime: there the
# mirror has nothing to run, which is not applicable rather than failing.
_RUST_RUNTIME = os.path.isdir(os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "rust-runtime"))


def applicable(windows, linux, jobs=None, server=None, facts=None):
    """(schedule, {job: reason}) for a machine with these execution domains.
    `server`: a plain Linux host (no Windows, not WSL), where workstation
    features are not applicable. `facts` (platform/facts.py): the measured host;
    a collector whose Collector.requires it does not satisfy is not applicable,
    with the missing fact as the reason. None keeps the domain rules only."""
    jobs = ALL_JOBS if jobs is None else jobs
    server = (linux and not windows) if server is None else server
    keep, absent = {}, {}
    for name, spec in jobs.items():
        if name in WORKSTATION_ONLY and server:
            absent[name] = "a workstation feature; not scheduled on servers"
        elif name in WINDOWS_ONLY and not windows:
            absent[name] = "this machine has no Windows domain to observe"
        elif name in LINUX_ONLY and not linux:
            absent[name] = "this machine has no Linux domain to observe"
        elif name == "rust_mirror" and not _RUST_RUNTIME:
            absent[name] = "the Rust evidence mirror is not included in this edition"
        elif facts is not None and name in mechanisms.BY_NAME and mechanisms.unmet(mechanisms.BY_NAME[name], facts):
            absent[name] = "not on this host: " + "; ".join(mechanisms.unmet(mechanisms.BY_NAME[name], facts))
        else:
            keep[name] = spec
    return keep, absent


JOBS, NOT_APPLICABLE = applicable(host.has_windows(), host.has_linux(),
                                  facts=hostfacts.current() if host.has_linux() else None)
