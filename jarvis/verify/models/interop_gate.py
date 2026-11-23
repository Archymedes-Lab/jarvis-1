"""Interop admission gate (V11), checked against the real `interop_gate.Gate`.

Every Windows collector launches through this gate. If it could stay open
for good, every Windows source would read "unavailable" until the daemon
restarted, which is the failure the owner asked to rule out. Each action
rebuilds a real Gate from the state, calls the shipped method and reads the
fields back, so the invariants hold for the code, not for a restatement of it.

State: launches holding a slot, consecutive failures (capped one past the
trip count, which is all the gate compares), current backoff, whether the
backoff window is still open, whether a half-open probe is outstanding, the
recent outcomes, and whether the last acquire was refused without cause.

Invariants:
- slots stay within 0..MAX_SLOTS;
- the backoff never exceeds MAX_REFUSAL_S (300 s), so a refusal window is bounded;
- an acquire is refused only while the window is open, a probe is out, or
  every allowed slot is taken;
- from every reachable state the gate recovers: once the running launches
  finish (even all failing) and the window passes, one launch is admitted,
  and its success closes the gate.

Abstractions: all recorded outcomes are treated as inside WINDOW_S (the
"degraded" limit is then at its most restrictive); acquire never waits (the
bounded wait only delays the same decision); threads are interleaved one
action at a time, which the gate's single condition lock makes exact.
"""

import collections
from dataclasses import dataclass, replace

from jarvis.platform import interop_gate as ig
from jarvis.verify.mc import Model

NOW = 10_000.0
# The published worst-case refusal window, fixed here rather than read from the
# gate, so raising the gate's constant is a visible violation, not a new bound.
MAX_REFUSAL_S = 300.0


@dataclass(frozen=True)
class State:
    active: int = 0
    consecutive: int = 0
    backoff: float = 0.0
    open: bool = False
    probing: bool = False
    outcomes: tuple = ()
    bad_refusal: bool = False


def build(s, now=NOW):
    g = ig.Gate(clock=lambda: now)
    g.active = s.active
    g.consecutive = s.consecutive
    g.backoff = s.backoff
    g.open_until = (now + s.backoff if s.open else now - 1.0) if s.backoff else 0.0
    g.probing = s.probing
    g.outcomes = collections.deque(((now, ok) for ok in s.outcomes), maxlen=ig.WINDOW)
    return g


def read(g, s, now=NOW, **extra):
    return replace(s, active=g.active, consecutive=min(g.consecutive, ig.TRIP_CONSECUTIVE + 1),
                   backoff=g.backoff, open=bool(g.backoff) and g.open_until > now,
                   probing=g.probing, outcomes=tuple(ok for _t, ok in g.outcomes), **extra)


def act_acquire(s):
    g = build(s)
    with g._cond:
        cause = (s.open or (bool(s.backoff) and s.probing)
                 or s.active >= g._limit(NOW))
    try:
        g.acquire(wait=0)
    except ig.Refused:
        return (read(g, s, bad_refusal=not cause),)
    return (read(g, s, bad_refusal=False),)


def _release(ok):
    def step(s):
        if not s.active:
            return ()
        g = build(s)
        g.release(ok)
        return (read(g, s, bad_refusal=False),)
    return step


def act_expire(s):
    return (replace(s, open=False, bad_refusal=False),) if s.open else ()


def recovers(s):
    """Holders finish failing, the window passes, one launch succeeds."""
    g = build(s)
    for _ in range(s.active):
        g.release(False)
    later = NOW + MAX_REFUSAL_S + 1.0
    g.clock = lambda: later
    try:
        g.acquire(wait=0)
    except ig.Refused:
        return False
    g.release(True)
    return g.backoff == 0.0 and not g.probing and g.active == 0


def model():
    return Model(
        "interop gate",
        initial=State(),
        actions=[("acquire", act_acquire), ("release_ok", _release(True)),
                 ("release_fail", _release(False)), ("expire", act_expire)],
        invariants=[
            ("slots stay within 0..MAX_SLOTS", lambda s: 0 <= s.active <= ig.MAX_SLOTS),
            ("backoff is bounded by MAX_REFUSAL_S", lambda s: 0.0 <= s.backoff <= MAX_REFUSAL_S),
            ("refused only while open, probing or full", lambda s: not s.bad_refusal),
            ("the gate always recovers", recovers),
        ],
        deadlock_free=True,
    )
