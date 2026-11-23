"""Scheduler lanes: a fast-lane job is never queued behind a long main job.

This is an abstract model of the documented policy (LANE-FAIRNESS-AND-OUTAGE-
RECORD.md): the fast lane has its own worker, so a due fast job waits at most
one tick regardless of what the main lane runs. It does not execute the real
`Scheduler._due`, which needs a store, reliability state and the governor; the
real selection order is covered by tests/test_server.py. The model pins the
shape of the claim, and the membership test below pins that the protection
jobs are in the fast lane.

The frequent lane (2026-11-03) is modelled the same way: a due five-minute
collector waits at most for the frequent job already running (FREQ_LEN ticks),
whatever the main lane holds. tests/test_lane_fairness.py replays the measured
boot against the real `_due`.

Abstractions: time is discrete ticks; one main job of bounded length; one fast
job; one watched frequent job and at most one competitor ahead of it in its
lane (the real lane bounds this by one pass of its declared costs); no
governor pressure; no forced requests.
"""

from dataclasses import dataclass, replace

from jarvis.service import scheduler
from jarvis.verify.mc import Model

MAIN_LEN = 3
FREQ_LEN = 2
MAX_TICK = 12
REQUIRED_FAST = frozenset({"scan", "bridge", "native", "watchdogs"})
# The five-minute collectors that went STALE behind the main lane's post-boot
# sweep on 2026-11-03 (independent of the registry, like REQUIRED_FAST).
REQUIRED_FREQUENT = frozenset({"audio", "canary", "controls", "logins", "resources",
                               "sshwatch", "wslmanifest", "hidden", "privacy", "wsl",
                               "netwatch", "input"})


@dataclass(frozen=True)
class State:
    tick: int = 0
    main_remaining: int = 0
    fast_due: bool = False
    fast_wait: int = 0
    freq_busy: int = 0          # ticks left on the frequent job running now
    freq_due: bool = False      # the watched frequent job is due
    freq_wait: int = 0


def act_tick(s):
    if s.tick >= MAX_TICK:
        return ()
    nxt = replace(s, tick=s.tick + 1,
                  main_remaining=max(0, s.main_remaining - 1))
    if s.fast_due:
        # The fast worker runs it this tick; the main lane is irrelevant.
        nxt = replace(nxt, fast_due=False, fast_wait=0)
    busy = max(0, s.freq_busy - 1)
    if s.freq_due and busy == 0:
        # The frequent worker is free: the watched job starts; main is irrelevant.
        nxt = replace(nxt, freq_busy=FREQ_LEN, freq_due=False, freq_wait=0)
    elif s.freq_due:
        nxt = replace(nxt, freq_busy=busy, freq_wait=s.freq_wait + 1)
    else:
        nxt = replace(nxt, freq_busy=busy)
    return (nxt,)


def act_fast_arrives(s):
    return (replace(s, fast_due=True, fast_wait=0),) if not s.fast_due else ()


def act_main_starts(s):
    return (replace(s, main_remaining=MAIN_LEN),) if s.main_remaining == 0 else ()


def act_freq_arrives(s):
    return (replace(s, freq_due=True, freq_wait=0),) if not s.freq_due else ()


def act_freq_other_starts(s):
    # Another frequent job takes the free lane before the watched one is due.
    return ((replace(s, freq_busy=FREQ_LEN),)
            if s.freq_busy == 0 and not s.freq_due else ())


ACTIONS = [("tick", act_tick), ("fast_job_due", act_fast_arrives),
           ("main_job_starts", act_main_starts),
           ("frequent_job_due", act_freq_arrives),
           ("other_frequent_job_starts", act_freq_other_starts)]

INVARIANTS = [
    ("a due fast job waits at most one tick", lambda s: s.fast_wait <= 1),
    ("a due frequent job waits at most one frequent job, never a main one",
     lambda s: s.freq_wait <= FREQ_LEN),
]


def required_fast_jobs_are_in_the_fast_lane():
    return REQUIRED_FAST <= set(scheduler.FAST)


def five_minute_jobs_are_in_the_frequent_lane():
    return REQUIRED_FREQUENT <= set(scheduler.FREQUENT)


def model():
    return Model("scheduler_lanes", State(), ACTIONS, INVARIANTS, max_states=5_000)
