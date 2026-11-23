"""Admission control for Windows launches over WSL interop.

Measured 2026-10-25 (docs/architecture/INTEROP-GATE.md): when the interop relay
slows down, every collector's PowerShell launch still goes out, each empty
result is retried at once, and the queue of half-started relays grows until the
owner's wake-jarvis watchdog reads /mnt/c as wedged and runs `wsl --shutdown`,
which stops the daemon, every session and every build. The gate turns that
pile-up into backpressure:

- at most MAX_SLOTS gated launches at a time, daemon-wide (one while degraded);
- a launch that cannot get a slot within its own budget is refused, never queued
  without bound;
- after TRIP_CONSECUTIVE transport failures the gate opens for a backoff that
  doubles from BACKOFF_START to BACKOFF_MAX; when it expires one probe launch
  goes through, and its success closes the gate again.

Every refusal is a Refused (an OSError) whose message says why, and callers
record it as a collection failure: nothing that was not observed is reported as
clean. The gate never decides what is safe; it only bounds load. Launches that
restore protection or wait on the owner (the input hook, an elevation prompt)
are not gated.
"""

import collections
import threading
import time

MAX_SLOTS = 2
DEGRADED_SLOTS = 1
TRIP_CONSECUTIVE = 4
BACKOFF_START = 30.0
BACKOFF_MAX = 300.0
WAIT_MAX = 60.0
WINDOW = 10                 # recent outcomes considered for "degraded"
WINDOW_S = 300.0
MIN_SAMPLES = 6
DEGRADED_RATIO = 0.5


class Refused(OSError):
    """A gated launch was not started; the message says why."""


class Gate:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._cond = threading.Condition()
        self.active = 0
        self.outcomes = collections.deque(maxlen=WINDOW)
        self.consecutive = 0
        self.backoff = 0.0          # 0 while closed
        self.open_until = 0.0
        self.probing = False
        self.trips = 0
        self.refused = 0
        self.last_refusal = ""

    # --- state -------------------------------------------------------------

    def _recent(self, now):
        return [ok for t, ok in self.outcomes if now - t <= WINDOW_S]

    def _degraded(self, now):
        if self.backoff:
            return True
        recent = self._recent(now)
        return (len(recent) >= MIN_SAMPLES
                and recent.count(False) / len(recent) >= DEGRADED_RATIO)

    def degraded(self):
        with self._cond:
            return self._degraded(self.clock())

    def _limit(self, now):
        return DEGRADED_SLOTS if self._degraded(now) else MAX_SLOTS

    def state(self):
        with self._cond:
            now = self.clock()
            recent = self._recent(now)
            return {
                "degraded": self._degraded(now),
                "open": bool(self.backoff) and self.open_until > now,
                "open_for_s": max(0, round(self.open_until - now)) if self.backoff else 0,
                "backoff_s": self.backoff,
                "active": self.active,
                "limit": self._limit(now),
                "recent": len(recent),
                "recent_failures": recent.count(False),
                "consecutive_failures": self.consecutive,
                "trips": self.trips,
                "refused": self.refused,
                "last_refusal": self.last_refusal,
            }

    # --- admission ---------------------------------------------------------

    def _refuse(self, why):
        self.refused += 1
        self.last_refusal = why
        raise Refused(why)

    def acquire(self, wait):
        """Take a slot, waiting at most `wait` seconds. Returns True when this
        caller is the half-open probe."""
        wait = max(0.0, min(float(wait), WAIT_MAX))
        with self._cond:
            now = self.clock()
            probe = False
            if self.backoff:
                if self.open_until > now:
                    self._refuse(f"Windows interop backing off for {round(self.open_until - now)} s "
                                 f"after {self.consecutive} failed launches")
                if self.probing:
                    self._refuse("Windows interop is being re-probed; launch deferred")
                self.probing = probe = True
            deadline = now + wait
            while self.active >= self._limit(self.clock()):
                remaining = deadline - self.clock()
                if remaining <= 0:
                    if probe:
                        self.probing = False
                    self._refuse(f"no Windows interop slot free within {round(wait)} s "
                                 f"({self.active} launches running)")
                self._cond.wait(remaining)
            self.active += 1
            return probe

    def release(self, ok):
        with self._cond:
            self.active = max(0, self.active - 1)
            self._record(ok)
            self._cond.notify_all()

    def _record(self, ok):
        now = self.clock()
        self.outcomes.append((now, bool(ok)))
        if ok:
            self.consecutive = 0
            self.backoff = 0.0
            self.open_until = 0.0
            self.probing = False
            return
        self.consecutive += 1
        if self.probing or self.consecutive >= TRIP_CONSECUTIVE:
            self.backoff = min(BACKOFF_MAX, self.backoff * 2 if self.backoff else BACKOFF_START)
            self.open_until = now + self.backoff
            self.probing = False
            self.trips += 1


GATE = Gate()
