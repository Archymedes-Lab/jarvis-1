"""A small explicit-state model checker (breadth-first, exhaustive, bounded).

    model = Model("seal", initial=state0, actions=[("seal", seal), ...],
                  invariants=[("reported", lambda s: ...)])
    result = model.check()
    assert result.ok, result.counterexample

A state is any hashable value (tuples, frozen dataclasses). An action is a
function state -> iterable of successor states (empty when not enabled). The
checker explores every reachable state up to `max_states`, evaluates every
invariant on every state, and returns the shortest action path to the first
violation. Exhaustion without violation is a proof for the model as written,
and only for it: the model's abstractions are listed with each model.
"""

from collections import deque
from dataclasses import dataclass, field


@dataclass
class Result:
    name: str
    ok: bool
    states: int
    transitions: int
    exhausted: bool                 # False when max_states stopped the search
    violated: str | None = None
    counterexample: list = field(default_factory=list)   # [(action, state), ...]
    deadlocks: int = 0

    def __str__(self):
        head = (f"{self.name}: {'ok' if self.ok else 'VIOLATION ' + str(self.violated)}; "
                f"{self.states} states, {self.transitions} transitions"
                + ("" if self.exhausted else " (bound hit)")
                + (f", {self.deadlocks} deadlock state(s)" if self.deadlocks else ""))
        if self.counterexample:
            head += "\n  " + "\n  ".join(f"{a} -> {s}" for a, s in self.counterexample)
        return head


class Model:
    def __init__(self, name, initial, actions, invariants, max_states=200_000,
                 deadlock_free=False):
        self.name = name
        self.initial = initial
        self.actions = list(actions)
        self.invariants = list(invariants)
        self.max_states = max_states
        self.deadlock_free = deadlock_free

    def _violation(self, state):
        for name, pred in self.invariants:
            if not pred(state):
                return name
        return None

    def check(self):
        parent = {self.initial: None}
        queue = deque([self.initial])
        transitions = 0
        deadlocks = 0
        while queue:
            state = queue.popleft()
            bad = self._violation(state)
            if bad:
                return Result(self.name, False, len(parent), transitions, True, bad,
                              self._path(parent, state), deadlocks)
            enabled = 0
            for action, step in self.actions:
                for nxt in step(state) or ():
                    transitions += 1
                    enabled += 1
                    if nxt not in parent:
                        if len(parent) >= self.max_states:
                            return Result(self.name, True, len(parent), transitions, False,
                                          None, [], deadlocks)
                        parent[nxt] = (action, state)
                        queue.append(nxt)
            if not enabled:
                deadlocks += 1
                if self.deadlock_free:
                    return Result(self.name, False, len(parent), transitions, True,
                                  "deadlock", self._path(parent, state), deadlocks)
        return Result(self.name, True, len(parent), transitions, True, None, [], deadlocks)

    def reachable(self, goal):
        """Shortest action path to a state satisfying `goal`, or None."""
        parent = {self.initial: None}
        queue = deque([self.initial])
        while queue:
            state = queue.popleft()
            if goal(state):
                return self._path(parent, state)
            for action, step in self.actions:
                for nxt in step(state) or ():
                    if nxt not in parent and len(parent) < self.max_states:
                        parent[nxt] = (action, state)
                        queue.append(nxt)
        return None

    @staticmethod
    def _path(parent, state):
        path = []
        while parent.get(state) is not None:
            action, prev = parent[state]
            path.append((action, state))
            state = prev
        path.reverse()
        return path
