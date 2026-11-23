"""Seeded property checks with the standard library (no Hypothesis dependency).

    forall("score never exceeds 100", gen_snapshots, lambda s: 0 <= score(s) <= 100)

A failure reports the seed, the case index and a bounded repr of the input, so
any failure replays exactly with the same seed. There is no shrinking: cases
are kept small by construction instead, which keeps every failure readable.
"""

import random

DEFAULT_CASES = 200
REPR_LIMIT = 600


class PropertyFailure(AssertionError):
    pass


class Gen:
    """A seeded source of small values."""

    def __init__(self, seed):
        self.rng = random.Random(seed)

    def choice(self, items):
        return self.rng.choice(list(items))

    def int(self, lo, hi):
        return self.rng.randint(lo, hi)

    def bool(self, p_true=0.5):
        return self.rng.random() < p_true

    def subset(self, items, max_size=None):
        items = list(items)
        k = self.int(0, len(items) if max_size is None else min(max_size, len(items)))
        return self.rng.sample(items, k)

    def list(self, make, lo=0, hi=5):
        return [make(self) for _ in range(self.int(lo, hi))]


def forall(name, generate, prop, cases=DEFAULT_CASES, seed=0):
    """Run `prop(value)` for `cases` generated values. `prop` either returns a
    falsy-free value (True/None) or raises AssertionError. Returns the number
    of cases run, for the caller's own accounting."""
    for index in range(cases):
        gen = Gen(f"{seed}:{index}")
        value = generate(gen)
        try:
            ok = prop(value)
        except AssertionError as exc:
            raise PropertyFailure(
                f"{name}: case {index} (seed {seed}) failed: {exc}\n"
                f"input: {repr(value)[:REPR_LIMIT]}") from None
        if ok is False:
            raise PropertyFailure(
                f"{name}: case {index} (seed {seed}) returned False\n"
                f"input: {repr(value)[:REPR_LIMIT]}")
    return cases
