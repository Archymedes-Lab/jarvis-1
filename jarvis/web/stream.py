"""The live pulse: what an always-open window needs to know, pushed instead of polled.

`/api/state` is the whole dashboard (0.6-3 s to build, hundreds of KB). An
always-open client (the desktop app's tray, a pinned tab) only needs to know
when to look: the score, which areas are blind, which serious findings are
open, and whether the daemon itself is healthy. This module builds that
summary from the stored snapshots (~35 ms, measured 2026-09-25) and serves it
two ways:

  * `GET /api/pulse`  — one JSON summary, for clients that poll.
  * `GET /api/stream` — Server-Sent Events: the summary on connect and again
    whenever it changes, with keepalive comments in between.

Invariants (docs/architecture/DESKTOP-APP.md, "The app is a client, never the
monitor"):

  * Read-only. Nothing here changes state, runs a collector or acts; the stream
    carries no route back into the daemon.
  * Bounded. Every open stream costs the daemon one thread, so there are at
    most MAX_STREAMS at once and each ends after MAX_LIFETIME_S (EventSource and
    the desktop app reconnect on their own). However many clients listen, the
    summary is rebuilt at most once per PERIOD_S: every stream reads one shared,
    cached copy.
  * Blindness is never quiet. A failure to build the summary is itself sent as
    a pulse with `"ok": false`. A collector that stops reporting is listed under
    `blind`. Clients treat a missing or failed pulse as "unknown", never "clean".
  * Same trust boundary as the rest of the page: loopback listener and Host
    check (server.py), plus a same-origin check before a stream slot is taken,
    so a hostile web page cannot use up the slots even though it cannot read
    the responses.
"""

import hashlib
import json
import select
import socket
import threading
import time

from jarvis.core.store import Store
from jarvis.platform import admin_sensor
from jarvis.response import acknowledge, alert
from jarvis.response.reporting import score
from jarvis.service import reliability as reliability_mod
from jarvis.service.protection import health
from jarvis.service.schedule import JOBS

PERIOD_S = 5              # rebuild the shared summary at most this often
KEEPALIVE_S = 15          # comment line so proxies and dead peers surface
MAX_LIFETIME_S = 30 * 60  # then the client reconnects; bounds a leaked thread
MAX_STREAMS = 8
RETRY_MS = 5000           # EventSource reconnect delay, sent to the client
MAX_URGENT = 12

URGENT = ("critical", "high")
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build(db_path, scheduler, stamp=None):
    """The pulse summary. Never raises: a failure is reported as `ok: false`."""
    stamp = time.time() if stamp is None else stamp
    try:
        store = Store(db_path)
        try:
            snaps = store.get_snapshots()
            acks = acknowledge.load(store)
            live = score.compute(snaps, JOBS, acks=acks)
            sec = score.stable(store, JOBS, acks=acks, live=live, snapshots=snaps,
                               phase=_phase(scheduler))
        finally:
            store.close()
    except Exception as exc:
        return _stamp({"ok": False, "error": type(exc).__name__, "at": int(stamp)})

    totals, urgent, blind = {}, [], []
    for name, (interval, label) in JOBS.items():
        snap = snaps.get(name)
        age = (stamp - snap["ts"]) if snap and snap.get("ts") else -1
        fresh = reliability_mod.classify(age, interval)
        if fresh == "STALE" or (snap and snap.get("error")):
            blind.append({"job": name, "label": label,
                          "freshness": fresh, "error": bool(snap and snap.get("error"))})
        for f in (snap or {}).get("findings") or ():
            sev = f.get("severity") if isinstance(f, dict) else None
            if not sev or sev == "ok" or alert.is_coverage_gap(f):
                continue    # coverage gaps live in /api/coverage, not the pulse
            totals[sev] = totals.get(sev, 0) + 1
            if sev in URGENT:
                acked = acknowledge.is_acknowledged(acks, f, name, now=stamp)
                urgent.append({"id": acknowledge.finding_id(f, name), "job": name,
                               "severity": sev, "title": str(f.get("title", ""))[:200],
                               # Lets a client explain the kind of thing in plain words.
                               "category": str(f.get("category") or "")[:40],
                               "acknowledged": bool(acked)})
    # A release without the administrator sensor must not read as full coverage:
    # name every job it affects, with the same reason everywhere (platform/admin_sensor.py).
    admin_sensor.merge_blind(blind, {n: lbl for n, (_iv, lbl) in JOBS.items()})
    urgent.sort(key=lambda u: (u["acknowledged"], _RANK.get(u["severity"], 9), u["job"]))
    worst = min(totals, key=lambda s: _RANK.get(s, 9)) if totals else "ok"

    try:
        h = health(db_path, scheduler, stamp) if scheduler is not None else {}
    except Exception:
        h = {}

    return _stamp({
        "ok": True,
        "at": int(stamp),
        "score": sec.get("score"),
        "grade": sec.get("grade"),
        "coverage": sec.get("coverage"),
        "state": sec.get("state"),
        "acknowledged": sec.get("acknowledged", 0),
        "areas": [{"name": a.get("name"), "score": a.get("score"),
                   "blind": bool(a.get("blind"))} for a in sec.get("areas") or ()],
        "worst": worst,
        "totals": totals,
        "urgent": urgent[:MAX_URGENT],
        "urgent_total": len(urgent),
        "blind": blind,
        # None when unknown (no scheduler, or the check failed): never "healthy".
        "healthy": h.get("healthy"),
        "protection_healthy": h.get("protection_healthy"),
    })


def _phase(scheduler):
    fn = getattr(scheduler, "wake_phase", None)
    try:
        return fn() if callable(fn) else {}
    except Exception:
        return {}


def _stamp(pulse):
    """Add `version`: a digest of everything but the timestamp, so a client can
    tell a real change from a re-send."""
    body = {k: v for k, v in pulse.items() if k != "at"}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode())
    pulse["version"] = digest.hexdigest()[:16]
    return pulse


class Hub:
    """One cached pulse shared by every client, rebuilt at most once per period."""

    def __init__(self, db_path, scheduler, period=PERIOD_S, max_streams=MAX_STREAMS,
                 builder=build, clock=time.monotonic):
        self.db_path = db_path
        self.scheduler = scheduler
        self.period = period
        self._builder = builder
        self._clock = clock
        self._lock = threading.Lock()
        self._cached = None
        self._built_at = None
        self._slots = threading.BoundedSemaphore(max_streams)

    def latest(self):
        with self._lock:
            now = self._clock()
            if self._cached is None or now - self._built_at >= self.period:
                self._cached = self._builder(self.db_path, self.scheduler)
                self._built_at = now
            return self._cached

    def acquire(self):
        return self._slots.acquire(blocking=False)

    def release(self):
        self._slots.release()


def frame(pulse):
    """One SSE event carrying the pulse."""
    data = json.dumps(pulse, separators=(",", ":"), default=str)
    return f"id: {pulse.get('version', '')}\nevent: pulse\ndata: {data}\n\n".encode()


def peer_closed(sock):
    """True when the client has hung up. A write to a closed TCP peer can
    still succeed once (it only provokes the reset), so waiting for a write to
    fail would hold a stream slot for two keepalives."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable) and sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


BEAT = b"event: beat\ndata: {}\n\n"


def run_stream(hub, write, *, gone=None, stop=None, clock=time.monotonic, sleep=None,
               lifetime=MAX_LIFETIME_S, keepalive=KEEPALIVE_S, beat=False):
    """Write pulses to one client until it leaves or the lifetime ends.

    With `beat`, the line sent when nothing has changed is an event the page
    can see rather than a comment only the socket sees: a page that shows live
    state has to tell "nothing changed" from "nothing is arriving".

    `write(bytes)` raises OSError when the client is gone; `gone()`, checked on
    every tick, notices sooner. Returns the number of pulse events sent.
    `stop` (a threading.Event) ends it early.
    """
    stop = stop or threading.Event()
    sleep = sleep or (lambda s: stop.wait(s))
    start = last_io = clock()
    last_version, sent = None, 0
    write(f"retry: {RETRY_MS}\n\n".encode())
    while not stop.is_set():
        if gone is not None and gone():
            break
        pulse = hub.latest()
        now = clock()
        if pulse.get("version") != last_version:
            write(frame(pulse))
            last_version, last_io, sent = pulse.get("version"), now, sent + 1
        elif now - last_io >= keepalive:
            write(BEAT if beat else b": keepalive\n\n")
            last_io = now
        if now - start >= lifetime:
            break
        sleep(min(hub.period, keepalive))
    return sent
