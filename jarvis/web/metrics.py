"""Prometheus text exposition for GET /metrics (docs/architecture/ARGUS-SERVER.md W7).

Operators already run Prometheus or a Grafana agent; this lets them graph and
alert on JARVIS itself without a bridge. What it may and may not say:

- Labels come only from fixed sets: a severity name or a scheduled job name.
  No finding text, address, path, user or host ever becomes a label or value,
  so a scrape leaks no evidence and series cardinality is bounded by JOBS.
- Unknown is not clean. A collector that has never reported has no age sample
  (and `jarvis_collector_observed 0`); a store that cannot be read makes the
  whole response 503 rather than a page of zeros.
- The score is the posture score shown by `jarvis status`, not a compromise
  verdict, and says so in its HELP line.
- Scrapes are cheap for the daemon: one rendering is shared for CACHE_S
  seconds however many scrapers ask, and only one rendering runs at a time.
"""

import threading
import time

from jarvis.core.store import Store
from jarvis.response import acknowledge, alert
from jarvis.response.reporting import score
from jarvis.service.protection import health
from jarvis.service.schedule import JOBS

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
CACHE_S = 15
SEVERITIES = ("critical", "high", "medium", "low")

_lock = threading.Lock()
_cache = {"at": 0.0, "body": None, "db": None}


class Unavailable(Exception):
    """The store could not be read; the scrape must fail, not report zeros."""


def _num(v):
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    return repr(float(v))


def _label(v):
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class _Doc:
    def __init__(self):
        self.lines = []

    def family(self, name, kind, help_text):
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")

    def sample(self, name, value, **labels):
        if labels:
            inner = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{inner}}} {_num(value)}")
        else:
            self.lines.append(f"{name} {_num(value)}")

    def text(self):
        return "\n".join(self.lines) + "\n"


def render(db_path, scheduler, stamp=None, jobs=JOBS):
    """The exposition text for this moment. Raises Unavailable when the store
    cannot be read."""
    stamp = time.time() if stamp is None else stamp
    try:
        store = Store(db_path)
    except Exception as exc:  # noqa: BLE001 - any store failure is "unavailable"
        raise Unavailable(type(exc).__name__) from exc
    try:
        try:
            snaps = store.get_snapshots()
            acks = acknowledge.load(store)
        except Exception as exc:  # noqa: BLE001
            raise Unavailable(type(exc).__name__) from exc
        try:
            posture = score.stable(store, jobs, now=int(stamp), acks=acks, snapshots=snaps)
        except Exception:  # noqa: BLE001 - the score is optional; its absence is visible
            posture = None
    finally:
        store.close()
    state = health(db_path, scheduler, stamp)

    d = _Doc()
    d.family("jarvis_up", "gauge", "1 while the daemon answers this endpoint.")
    d.sample("jarvis_up", 1)
    d.family("jarvis_live", "gauge",
             "1 while the scheduler lanes are making progress (same as /api/live).")
    d.sample("jarvis_live", bool(state.get("live")))
    d.family("jarvis_healthy", "gauge",
             "1 while required evidence sources are current (same as /api/health).")
    d.sample("jarvis_healthy", bool(state.get("healthy")))

    if posture is not None:
        d.family("jarvis_security_score", "gauge",
                 "Posture score 0-100, higher is better. Not a compromise verdict.")
        d.sample("jarvis_security_score", posture.get("score", 0))
        d.family("jarvis_monitoring_coverage_percent", "gauge",
                 "Share of scheduled collectors that currently observe, 0-100.")
        d.sample("jarvis_monitoring_coverage_percent", posture.get("coverage", 0))

    open_by, acked_by = dict.fromkeys(SEVERITIES, 0), dict.fromkeys(SEVERITIES, 0)
    for job, snap in snaps.items():
        for f in (snap or {}).get("findings") or ():
            sev = f.get("severity")
            if sev not in open_by or alert.is_coverage_gap(f):
                continue    # coverage gaps are about Argus, not the machine
            if acknowledge.is_acknowledged(acks, f, job, now=stamp):
                acked_by[sev] += 1
            else:
                open_by[sev] += 1
    d.family("jarvis_findings_open", "gauge",
             "Current findings not covered by an acknowledgement, by severity.")
    for sev in SEVERITIES:
        d.sample("jarvis_findings_open", open_by[sev], severity=sev)
    d.family("jarvis_findings_acknowledged", "gauge",
             "Current findings covered by a live acknowledgement, by severity.")
    for sev in SEVERITIES:
        d.sample("jarvis_findings_acknowledged", acked_by[sev], severity=sev)

    names = sorted(jobs)

    def ts_of(name):
        return float((snaps.get(name) or {}).get("ts") or 0)

    d.family("jarvis_collector_observed", "gauge",
             "1 when the collector has reported at least once, 0 when it never has.")
    for name in names:
        d.sample("jarvis_collector_observed", bool(ts_of(name)), job=name)
    d.family("jarvis_collector_interval_seconds", "gauge",
             "The collector's scheduled interval.")
    for name in names:
        d.sample("jarvis_collector_interval_seconds", int(jobs[name][0]), job=name)
    # Never-reported collectors get no age and no failing sample: no result is
    # not a fresh or passing one.
    reported = [n for n in names if ts_of(n)]
    d.family("jarvis_collector_last_run_age_seconds", "gauge",
             "Seconds since the collector last reported. Absent when it never has.")
    for name in reported:
        d.sample("jarvis_collector_last_run_age_seconds", max(0.0, stamp - ts_of(name)), job=name)
    d.family("jarvis_collector_failing", "gauge",
             "1 when the collector's last run recorded an error.")
    for name in reported:
        d.sample("jarvis_collector_failing", bool(snaps[name].get("error")), job=name)
    return d.text()


def cached(db_path, scheduler, now=None):
    """The shared rendering, refreshed at most every CACHE_S seconds."""
    now = time.monotonic() if now is None else now
    with _lock:
        body, at, db = _cache["body"], _cache["at"], _cache["db"]
        if body is not None and db == db_path and now - at < CACHE_S:
            return body
        body = render(db_path, scheduler)
        _cache.update(at=now, body=body, db=db_path)
        return body
