"""The response ladder: reversible actions JARVIS can take against a threat.

Every action here obeys the same contract, and the contract is what makes
automatic response safe enough to turn on:

  * evidence first — before anything changes, the exact target (file bytes,
    process command line, connection) is copied into an evidence case, so a
    later "was that a false positive?" can be answered from what was there;
  * reversible — every action records an undo token and can put the machine
    back the way it was (a quarantined file moves back, a blocked address is
    unblocked, a stopped process is resumed). Actions that cannot be undone
    (deleting, killing) are a different, approval-only class and live behind
    the ladder's PROPOSE path, never AUTO;
  * bounded and legible — one target, a plain-language preview a human can
    read before approving, and a result that says exactly what happened.

An action never decides *whether* to run. That is the ladder's job
(defense.py), which weighs severity, corroboration and your configuration.
An action only knows *how* to do one thing and how to undo it.
"""

from abc import ABC, abstractmethod

# Autonomy: the highest rung an action may be placed on. AUTO means the ladder
# is allowed to run it without asking when confidence is high and it is enabled;
# APPROVE means it always waits for you, however strong the evidence.
AUTO = "auto"
APPROVE = "approve"


class Action(ABC):
    id = ""                 # stable identifier, stored in the ledger and undo token
    title = ""              # short human label ("Quarantine a dropped file")
    autonomy = APPROVE      # AUTO or APPROVE — the ceiling, not a guarantee
    reversible = True       # AUTO requires this; the ABC enforces it below
    host = "wsl"            # "wsl" or "win" — where the action takes effect
    # config flag that must be true for this action to run automatically;
    # empty means it can only ever be proposed for approval.
    enable_flag = ""
    # most simultaneous applied instances before AUTO falls back to PROPOSE;
    # 0 means no bound beyond one per target.
    max_active = 0

    @abstractmethod
    def match(self, finding, job):
        """Return a target dict for a finding this action applies to, else None.

        The target holds only what apply()/undo() need (a path, an ip, a pid)
        and must be JSON-serialisable: it is persisted in the ledger.
        """

    def evidence(self, target):
        """Files worth preserving before acting. Missing ones are skipped."""
        return []

    def auto_eligible(self, finding, job, target):
        """Whether this exact evidence is strong enough for unattended use.

        Severity alone is not confidence. A high-severity filename collision,
        for example, still needs a person; an exact malware hash can qualify.
        Actions opt in with a narrow, detector-specific rule.
        """
        return False

    def identity(self, finding, target):
        """A stable ledger key for this target, or None to key on the finding.

        Override when the finding's title carries a changing count, so the
        same target stays one action rather than a new one every pass.
        """
        return None

    def permitted(self, target, conf):
        """(ok, reason): an owner rule that forbids acting on this target at all."""
        return True, ""

    def ttl(self, target, prior):
        """Seconds an applied action lasts before the ladder lifts it, or None.

        `prior` is how many times it was applied to this target before.
        """
        return None

    @abstractmethod
    def preview(self, target):
        """One sentence a human reads before approving. No side effects."""

    @abstractmethod
    def apply(self, target, case):
        """Perform the action. Return (ok: bool, record: dict, detail: str).

        `record` is everything undo() will need; it is stored with the target.
        `case` is an open evidence Case (or None) already holding evidence().
        Never raise for an expected failure — return ok=False with a reason.
        """

    def undo(self, target, record):
        """Reverse a prior apply(). Return (ok: bool, detail: str)."""
        return False, "this action cannot be undone"

    def recover(self, target, record):
        """Read-only crash recovery probe.

        Return ``(state, record, detail)`` where state is ``applied``,
        ``not_applied``, ``unknown`` or ``unavailable``.  This must never
        mutate the protected host.  A positive result must also return enough
        record data for ``undo()``; otherwise recovery remains unknown.
        """
        return "unknown", {}, "this action has no read-only recovery probe"


_REGISTRY = {}


def register(cls):
    action = cls()
    if not action.id:
        raise ValueError(f"{cls.__name__} has no id")
    if action.autonomy == AUTO and not action.reversible:
        raise ValueError(f"{action.id} is AUTO but not reversible")
    if action.id in _REGISTRY:
        raise ValueError(f"duplicate action id {action.id}")
    _REGISTRY[action.id] = action
    return cls


def registry():
    return dict(_REGISTRY)


def get(action_id):
    return _REGISTRY.get(action_id)
