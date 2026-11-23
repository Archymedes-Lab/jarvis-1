"""Response ladder authority (V13), checked against the real `defense` code.

The ladder is the code that acts on the machine without a person: block an
address, suspend a process, ban a source. Each step rebuilds a ledger store
from the state, calls the shipped `defense.process`, `approve`, `undo` or
`expire`, and reads the ledger back, so the invariants hold for the code, not
for a restatement of it.

Invariants:
- authority: a collection pass applies an action only with autonomous_defense,
  the action's own flag, high severity and complete coverage;
- bounded blast radius: automatically applied actions never exceed the cap;
- time-bounded: every applied action carries an expiry, and the world (the
  rules the action created) matches the ledger exactly, so an action is
  "expired" or "undone" only after its undo really lifted it;
- human override: after a person undoes an action, no later collection pass
  applies it again; only a new approval does.

Abstractions: one synthetic reversible action, time-bounded and capped at one,
over two sources; evidence capture and apply always succeed; a lift fails
exactly when the world says so; a discrete clock of MAX_TICK ticks; one of
four flag combinations per run; interrupted actions (reconcile) are not
modelled.
"""

import json
from contextlib import contextmanager

from jarvis.response import defense
from jarvis.response.actions import base
from jarvis.verify.mc import Model

JOB = "verify-ladder"
CAP = 1
TTL = (2, 3)
MAX_TICK = 3                     # the clock runs 1..MAX_TICK; real timestamps are never 0
SOURCES = ("a", "b")
CONFS = tuple({"autonomous_defense": auto, "auto_verify_model": flag}
              for auto in (False, True) for flag in (False, True))


class ModelAction(base.Action):
    """A synthetic time-bounded action whose effect is a rule in `world`."""
    id = "verify_model_ban"
    title = "model ban"
    autonomy = base.AUTO
    reversible = True
    host = "win"
    enable_flag = "auto_verify_model"
    max_active = CAP
    world: dict = {}

    def match(self, finding, job):
        f = finding or {}
        return {"src": f["src"]} if job == JOB and f.get("category") == "verify-model" else None

    def identity(self, finding, target):
        return "src:" + target["src"]

    def ttl(self, target, prior):
        return TTL[min(max(int(prior), 0), len(TTL) - 1)]

    def auto_eligible(self, finding, job, target):
        return True

    def preview(self, target):
        return f"ban {target['src']}"

    def apply(self, target, case):
        self.world["rules"].add(target["src"])
        return True, {"src": target["src"]}, "banned"

    def undo(self, target, record):
        if self.world["fail"]:
            return False, "lift failed"
        self.world["rules"].discard(target["src"])
        return True, "lifted"


class _Store:
    def __init__(self, ledger):
        self.meta = {defense.LEDGER_META: ledger}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


class _Clock:
    tick = 0

    def time(self):
        return float(self.tick)

    def time_ns(self):
        return 0


CLOCK = _Clock()
ACTION = ModelAction()


@contextmanager
def _installed():
    """Register the synthetic action, a fixed clock and an always-complete
    evidence capture for the length of a check; restore everything after."""
    saved = (defense.time, defense._capture, dict(base._REGISTRY))
    defense.time = CLOCK
    defense._capture = lambda finding, job, action, target: ("case", [], True)
    base._REGISTRY[ACTION.id] = ACTION
    try:
        yield
    finally:
        defense.time, defense._capture = saved[0], saved[1]
        base._REGISTRY.clear()
        base._REGISTRY.update(saved[2])


# state: (conf index or -1, tick, ledger json, rules, lift fails, human-undone eids, violations)

# Bookkeeping the ladder writes but never reads back in these paths: dropping
# or folding it merges states the code cannot tell apart (counters such as
# expire_attempts and applications otherwise grow without bound). "at" is read
# only for failed-retry timing and ledger trimming, neither reachable here.
DROPPED = ("at", "attempts", "undone_at", "undo_detail", "expire_attempts", "expired_at",
           "recovered_at")


def _canon(ledger):
    for e in ledger.values():
        for key in DROPPED:
            e.pop(key, None)
        e["detail"] = ""
        if "applied_at" in e:
            e["applied_at"] = 1                       # presence is what the invariants read
        if "expire_error" in e:
            e["expire_error"] = "lift failed"
        # The TTL ladder reads applications only up to its last rung.
        e["applications"] = min(int(e.get("applications") or 0), len(TTL))
    return json.dumps(ledger, sort_keys=True)


def _run(state, call):
    conf_i, tick, ledger, rules, fail, undone, flags = state
    store = _Store(ledger)
    ACTION.world = {"rules": set(rules), "fail": fail}
    CLOCK.tick = tick
    result = call(store, CONFS[conf_i])
    after = json.loads(store.get_meta(defense.LEDGER_META, "{}"))
    return result, after, frozenset(ACTION.world["rules"])


def _applied(ledger):
    return {eid for eid, e in ledger.items() if e.get("status") == "applied"}


def configure(state):
    if state[0] == -1:
        for i in range(len(CONFS)):
            yield (i,) + state[1:]


def collect(state):
    conf_i, tick, ledger, rules, fail, undone, flags = state
    if conf_i == -1:
        return
    before = json.loads(ledger)
    for src in SOURCES:
        # Every way to the automatic rung and both ways to stop short of it.
        for sev, cov in (("high", "complete"), ("high", "partial"), ("medium", "complete")):
            finding = {"category": "verify-model", "severity": sev, "src": src, "host": "win",
                       "title": f"guessing from {src}", "where": "model"}
            _r, after, new_rules = _run(state, lambda store, conf, f=finding, c=cov:
                                        defense.process(store, conf, JOB, [f], coverage=c, now=tick))
            new = set(flags)
            conf = CONFS[conf_i]
            authorised = (conf["autonomous_defense"] and conf["auto_verify_model"]
                          and sev == "high" and cov == "complete")
            for eid in _applied(after) - _applied(before):
                if not authorised:
                    new.add("a collection pass applied an action without authority")
                if eid in undone:
                    new.add("a collection pass re-applied an action a person undid")
            yield (conf_i, tick, _canon(after), new_rules, fail, undone, frozenset(new))


def approve(state):
    conf_i, tick, ledger, rules, fail, undone, flags = state
    if conf_i == -1:
        return
    for eid, e in json.loads(ledger).items():
        if e.get("status") == "proposed":
            (ok, _d), after, new_rules = _run(state, lambda store, conf, eid=eid:
                                              defense.approve(store, eid, now=tick, conf=conf))
            yield (conf_i, tick, _canon(after), new_rules, fail,
                   undone - {eid} if ok else undone, flags)


def undo(state):
    conf_i, tick, ledger, rules, fail, undone, flags = state
    for eid in _applied(json.loads(ledger)):
        (ok, _d), after, new_rules = _run(state, lambda store, conf, eid=eid: defense.undo(store, eid))
        yield (conf_i, tick, _canon(after), new_rules, fail, undone | {eid} if ok else undone, flags)


def expire(state):
    conf_i, tick, ledger, rules, fail, undone, flags = state
    if conf_i == -1:
        return
    _r, after, new_rules = _run(state, lambda store, conf: defense.expire(store, now=tick))
    yield (conf_i, tick, _canon(after), new_rules, fail, undone, flags)


def _advance(max_tick):
    def advance(state):
        if state[0] != -1 and state[1] < max_tick:
            yield (state[0], state[1] + 1) + state[2:]
    return advance


def toggle_lift(state):
    if state[0] != -1:
        yield state[:4] + (not state[4],) + state[5:]


def no_violation(state):
    return not state[6]


def world_matches_ledger(state):
    ledger, rules = json.loads(state[2]), state[3]
    return {ledger[eid]["target"]["src"] for eid in _applied(ledger)} == set(rules)


def applied_actions_expire(state):
    ledger = json.loads(state[2])
    return all(ledger[eid].get("expires_at") for eid in _applied(ledger))


def automatic_actions_within_cap(state):
    ledger = json.loads(state[2])
    return sum(1 for eid in _applied(ledger) if "applied_at" not in ledger[eid]) <= CAP


class LadderModel(Model):
    def check(self):
        with _installed():
            return super().check()

    def reachable(self, goal):
        with _installed():
            return super().reachable(goal)


def model(max_states=200_000, max_tick=MAX_TICK):
    """The ladder model; a smaller max_tick gives a quicker, still exhaustive
    check over a shorter window (used where the full run is not the point)."""
    initial = (-1, 1, "{}", frozenset(), False, frozenset(), frozenset())
    return LadderModel(
        "response ladder", initial,
        actions=[("configure", configure), ("collect", collect), ("approve", approve), ("undo", undo),
                 ("expire", expire), ("tick", _advance(max_tick)), ("toggle lift failure", toggle_lift)],
        invariants=[("no authority, cap or override violation", no_violation),
                    ("the world matches the ledger", world_matches_ledger),
                    ("applied actions carry an expiry", applied_actions_expire),
                    ("automatic actions within the cap", automatic_actions_within_cap)],
        max_states=max_states)
