"""Typed observations: what a sensor saw, kept apart from how healthy it was.

A security conclusion has three honest outcomes, not two:

  KNOWN_SAFE    the evidence positively establishes the safe state
  KNOWN_UNSAFE  the evidence positively establishes the unsafe state
  UNKNOWN       the evidence does not establish either

and it is independent of whether the sensor itself worked (SensorHealth).
"Defender reported its not-initialized value" is UNKNOWN from a HEALTHY sensor;
"the query failed" is UNKNOWN from an UNAVAILABLE one; neither is 179 years of
signature age, and neither is safe. Collector health is never a verdict.

Race-prone observations (a socket with no visible owner, a pid no listing
admits) get exactly one bounded re-query through confirm(). The first
observation is always returned as evidence, even when the re-query shows it
was transient, so a security conclusion needs coherent confirmation without
the first sighting ever being erased.
"""

import time
from dataclasses import dataclass, field

KNOWN_SAFE = "known_safe"
KNOWN_UNSAFE = "known_unsafe"
UNKNOWN = "unknown"
VERDICTS = (KNOWN_SAFE, KNOWN_UNSAFE, UNKNOWN)

HEALTHY = "healthy"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"
HEALTH = (HEALTHY, DEGRADED, UNAVAILABLE)

# Outcomes of a bounded confirmation.
CONFIRMED = "confirmed"        # both views agree on the same identity
TRANSIENT = "transient"        # the second, valid view no longer shows it
INCONCLUSIVE = "inconclusive"  # the second view failed or crossed an epoch

# One re-query is the bound. More attempts would let a racing adversary
# retry until a view happens to miss it, and would cost unbounded time.
CONFIRM_ATTEMPTS = 1
CONFIRM_MAX_DELAY_S = 2.0


@dataclass(frozen=True)
class Observation:
    """One typed reading. `value` is None whenever it is not known."""
    subject: str
    verdict: str
    health: str
    value: object = None
    reason: str = ""
    source: str = ""
    observed_at: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}")
        if self.health not in HEALTH:
            raise ValueError(f"unknown sensor health {self.health!r}")
        if self.verdict != UNKNOWN and self.health == UNAVAILABLE:
            # An unavailable sensor observed nothing; it cannot know anything.
            raise ValueError("an unavailable sensor cannot produce a known verdict")

    @property
    def known(self):
        return self.verdict != UNKNOWN


def unknown(subject, reason, health=HEALTHY, source=""):
    return Observation(subject, UNKNOWN, health, None, reason, source)


def unavailable(subject, reason, source=""):
    return Observation(subject, UNKNOWN, UNAVAILABLE, None, reason, source)


def reading(subject, raw, sentinels, source="", kind=int):
    """A raw sensor value with its sentinel encodings decoded to UNKNOWN.

    `sentinels` maps a raw value (or, for ints, a floor: any value at or above
    the largest sentinel) to the sensor's meaning. The verdict is left UNKNOWN
    here: whether a real value is safe is the caller's policy, not the
    decoder's. Returns an Observation whose value is the decoded reading."""
    if raw is None:
        return unavailable(subject, "the sensor returned no value", source)
    if kind is int and (isinstance(raw, bool) or not isinstance(raw, int)):
        return unknown(subject, f"the sensor returned a non-integer ({type(raw).__name__})",
                       DEGRADED, source)
    if raw in sentinels:
        return unknown(subject, sentinels[raw], HEALTHY, source)
    if kind is int and sentinels:
        top = max(k for k in sentinels if isinstance(k, int))
        if raw >= top:
            return unknown(subject, sentinels[top], HEALTHY, source)
    return Observation(subject, UNKNOWN, HEALTHY, raw, "decoded; not yet judged", source)


def judge(obs, safe):
    """Apply a caller's policy to a decoded reading. Only a real value is judged;
    an unknown reading stays unknown whatever the policy says."""
    if obs.value is None:
        return obs
    verdict = KNOWN_SAFE if safe(obs.value) else KNOWN_UNSAFE
    return Observation(obs.subject, verdict, obs.health, obs.value, obs.reason,
                       obs.source, obs.observed_at)


@dataclass(frozen=True)
class Confirmation:
    """The first observation (always kept) and what one re-query made of it."""
    outcome: str
    first: dict
    second: object = None
    reason: str = ""
    first_at: float = 0.0
    second_at: float = 0.0


def confirm(first, requery, key=None, delay=0.35, same_epoch=None, clock=time.monotonic,
            sleep=time.sleep):
    """Bounded coherent confirmation of a race-prone observation.

    `first` is the original observation (a dict). `requery()` takes one fresh,
    independent view and returns a mapping of identity -> observation, or
    raises/returns None when the view itself failed. `key(first)` is the
    identity to look up (defaults to first["id"]). An observation is
    CONFIRMED only when the fresh view holds the same identity with identical
    content; absent from a valid view it is TRANSIENT; a failed view or an
    epoch change between the two views (`same_epoch()` returning False: the
    machine slept, rebooted or stepped its clock) is INCONCLUSIVE, which a
    caller must treat like the original, never as clean. Exactly one
    re-query is made, bounded by CONFIRM_MAX_DELAY_S."""
    ident = key(first) if key else first.get("id")
    t0 = clock()
    sleep(min(max(0.0, delay), CONFIRM_MAX_DELAY_S))
    try:
        view = requery()
    except Exception as exc:
        return Confirmation(INCONCLUSIVE, first, None,
                            f"re-query failed ({type(exc).__name__})", t0, clock())
    t1 = clock()
    if view is None:
        return Confirmation(INCONCLUSIVE, first, None, "re-query returned no view", t0, t1)
    if same_epoch is not None:
        try:
            coherent = bool(same_epoch())
        except Exception:
            coherent = False
        if not coherent:
            return Confirmation(INCONCLUSIVE, first, view.get(ident),
                                "the observation epoch changed between views", t0, t1)
    second = view.get(ident)
    if second is None:
        return Confirmation(TRANSIENT, first, None, "absent from a valid second view", t0, t1)
    if second != first:
        # Same identity, different content: something changed underneath.
        # That is not confirmation of the first view, and not clean either.
        return Confirmation(INCONCLUSIVE, first, second,
                            "the second view differs for the same identity", t0, t1)
    return Confirmation(CONFIRMED, first, second, "identical in two views", t0, t1)
