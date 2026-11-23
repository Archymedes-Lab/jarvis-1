"""Privacy seal lifecycle, checked against the real finding logic.

State: whether a seal is declared, the user-hive values for the microphone
(global and desktop apps), whether machine policy forces Allow, how many apps
used the microphone after the seal, whether the collector has sampled since
the last change, and whether its last sample reported a breach at high.

The `collect` action runs the real `privacyseal._seal_findings` on a snapshot
built from the state, so the invariant "every breach is reported high by the
next collection, and an intact seal reports nothing" is checked against the
shipped code, not a re-statement of it.

Abstractions (what this model does not cover): only the microphone capability
(the camera path is the same code with another key); at most two uses after
the seal; the registry writer and the five-minute sampling interval (a breach
undone before `collect` runs is invisible, by design); the store and CLI.
"""

from dataclasses import dataclass, replace

from jarvis.collectors.host import privacyseal as ps
from jarvis.verify.mc import Model

CAP = "microphone"
DECLARED_AT = 1_000_000        # unix seconds the seal was declared
MAX_USES = 2


def _filetime(unix):
    return int(unix * 1e7) + ps._FILETIME_EPOCH


@dataclass(frozen=True)
class State:
    declared: bool = False
    user_global: str = "Allow"
    user_desktop: str = "Allow"
    policy_force: bool = False
    uses_after: int = 0
    sampled: bool = False        # collect ran since the last change
    reported: bool = False       # the last collect produced a high seal finding

    @property
    def breached(self):
        return self.declared and (self.user_global == "Allow" or self.user_desktop == "Allow"
                                  or self.policy_force or self.uses_after > 0)


def snapshot(s):
    """The collector's view of the state, in the shape `_valid` accepts."""
    apps = [{"name": f"app{i}", "kind": "desktop", "hive": "user", "value": "Allow",
             "start": _filetime(DECLARED_AT + 60 * (i + 1)), "stop": 0}
            for i in range(s.uses_after)]
    row = {"user": {"global": s.user_global, "nonpackaged": s.user_desktop},
           "machine": {"global": None, "nonpackaged": None}, "apps": apps}
    return {"caps": {CAP: row},
            "policy": {ps.POLICY_OF[CAP]: ps.POLICY_FORCE_ALLOW if s.policy_force else None}}


def seal_record():
    return {"declared": DECLARED_AT, "caps": {CAP: {"global": "Allow", "nonpackaged": "Allow"}}}


def changed(s, **fields):
    """A state change the collector has not sampled yet."""
    return replace(s, **{"sampled": False, **fields})


def act_seal(s):
    if s.declared:
        return ()
    return (changed(s, declared=True, user_global="Deny", user_desktop="Deny", uses_after=0),)


def act_unseal(s):
    return (changed(s, declared=False, user_global="Allow", user_desktop="Allow",
                    policy_force=False, uses_after=0, reported=False),) if s.declared else ()


def act_reopen_global(s):
    return (changed(s, user_global="Allow"),) if s.user_global == "Deny" else ()


def act_reopen_desktop(s):
    return (changed(s, user_desktop="Allow"),) if s.user_desktop == "Deny" else ()


def act_force_policy(s):
    return (changed(s, policy_force=True),) if not s.policy_force else ()


def act_app_use(s):
    return (changed(s, uses_after=s.uses_after + 1),) if s.declared and s.uses_after < MAX_USES else ()


def act_collect(s):
    if not s.declared:
        return (replace(s, sampled=True, reported=False),)
    findings = ps._seal_findings(snapshot(s), seal_record(), previous={})
    high = any(f["severity"] == "high" for f in findings)
    return (replace(s, sampled=True, reported=high),)


ACTIONS = [("seal", act_seal), ("unseal", act_unseal), ("reopen_global", act_reopen_global),
           ("reopen_desktop", act_reopen_desktop), ("force_policy", act_force_policy),
           ("app_use_after_seal", act_app_use), ("collect", act_collect)]

INVARIANTS = [
    ("a breach is reported high by the next collection",
     lambda s: not s.sampled or not s.breached or s.reported),
    ("an intact seal never raises a seal alarm",
     lambda s: not s.sampled or s.breached or not s.reported),
    ("nothing is reported while no seal is declared",
     lambda s: s.declared or not s.sampled or not s.reported),
]


def model():
    return Model("privacy_seal", State(), ACTIONS, INVARIANTS, max_states=5_000)
