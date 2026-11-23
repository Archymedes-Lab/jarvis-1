"""The gate every consequential agent step passes: design B, a session reference monitor.

The monitor does not read the agent's reasoning or trust its account of itself.
It sees the call (tool, arguments, the provenance label of each argument, the
live manifest digest) and the session's history folded into one label, and it
answers ALLOW, CONFIRM or DENY from operator policy alone.

Why a session high-water mark rather than per-value tracking: Argus must guard
agents it did not build, through an SDK hook or an MCP gateway, so it cannot
follow every value through the planner. It can follow the session. Anything the
session has read may have shaped any argument whose provenance the integration
cannot state, so an unlabelled argument carries everything the session saw.
That over-blocks some benign tasks; the cost is a confirmation, not a leak.

Verdicts only climb. Each rule can raise the verdict, none can lower it, and
the one path from CONFIRM to ALLOW is a grant from a registered human bound to
this exact call. DENY is final for the call: secret egress, an unknown or
changed tool, an exhausted budget, the kill switch, any internal failure, and a
decision the journal could not record.
"""

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum

from jarvis.argus.labels import UNKNOWN, Label, Sensitivity, Trust, join_all
from jarvis.argus.policy import ALWAYS_CONFIRM, EXTERNAL, OUTBOUND, Effect

# Calls awaiting a human answer; the oldest are forgotten first. A forgotten
# call is simply asked again.
MAX_PENDING = 64
# Free text an agent controls (tool names, argument names) is clipped before it
# reaches the journal.
NAME_LIMIT = 128


class Verdict(IntEnum):
    # Ordered by friction so combining rules is max().
    ALLOW = 0
    CONFIRM = 1
    DENY = 2


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict = field(default_factory=dict)
    arg_labels: dict = field(default_factory=dict)    # arg name -> Label
    manifest_digest: str = None                       # live description+schema digest


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reasons: tuple
    call_digest: str = None
    seq: int = None                                   # journal record, None if unrecorded

    @property
    def allowed(self):
        return self.verdict is Verdict.ALLOW


class ApprovalError(PermissionError):
    pass


def _canonical(obj):
    # No default=: a value that cannot be encoded exactly cannot be bound to an
    # approval, so it raises and the call is denied.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _clip(name):
    return str(name)[:NAME_LIMIT]


class Monitor:
    """One agent session. Not shared between sessions: taint is per session."""

    def __init__(self, policy, journal, clock=time.time):
        self.policy = policy
        self.journal = journal
        self.clock = clock
        # Digests are keyed per session so the journal cannot be used to test
        # guesses of a low-entropy argument (a PIN, a short code) offline.
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self.taint = None             # join of everything the session has seen
        self.killed = False
        self.calls = 0
        self.external = 0
        self.irreversible = 0
        self._pending = {}            # call digest -> tool name, awaiting a human
        self._grants = {}             # call digest -> (approver, expires)

    # -- session state ---------------------------------------------------

    def observe(self, label):
        """Fold an input or tool result into the session. Only ever worsens it."""
        if not isinstance(label, Label):
            label = UNKNOWN
        with self._lock:
            self.taint = label if self.taint is None else self.taint.join(label)

    def kill(self, reason="owner"):
        """Deny everything from now on. There is no un-kill: start a new session."""
        with self._lock:
            self.killed = True
            self._grants.clear()
            self._pending.clear()
        try:
            self.journal.append({"kind": "kill", "reason": _clip(reason)})
        except Exception:
            pass              # the switch holds whether or not it was recorded

    # -- digests ---------------------------------------------------------

    def _digest(self, obj):
        return hmac.new(self._key, _canonical(obj).encode(), hashlib.sha256).hexdigest()

    def _labels(self, call):
        """Each argument's label; an unlabelled one carries the whole session."""
        session = UNKNOWN if self.taint is None else UNKNOWN.join(self.taint)
        out = {}
        for name in call.args:
            lab = call.arg_labels.get(name)
            if lab is None:
                lab = session
            elif not isinstance(lab, Label):
                raise TypeError("argument label is not a Label")
            out[name] = lab
        return out

    def call_digest(self, call, labels=None):
        labels = self._labels(call) if labels is None else labels
        return self._digest({"tool": call.tool, "args": call.args,
                             "manifest": call.manifest_digest,
                             "labels": {k: v.summary() for k, v in labels.items()}})

    # -- the gate --------------------------------------------------------

    def check(self, call, detectors=()):
        with self._lock:
            return self._check(call, detectors)

    def _check(self, call, detectors):
        spec, digest, labels, grant = None, None, {}, None
        try:
            verdict, reasons, spec, digest, labels, grant = self._evaluate(call, detectors)
        except Exception as exc:
            verdict, reasons = Verdict.DENY, (f"monitor failure: {type(exc).__name__}",)
        try:
            payload = self._payload(call, spec, digest, labels, verdict, reasons, grant)
            seq = self.journal.append(payload)["seq"]
        except Exception as exc:
            # JournalError is the expected one; any failure to record counts.
            # Nothing is allowed or offered for approval that was not recorded.
            return Decision(Verdict.DENY, reasons + (f"journal failure: {type(exc).__name__}",),
                            digest, None)
        if verdict is Verdict.ALLOW:
            if grant is not None:
                self._grants.pop(digest, None)
                self._pending.pop(digest, None)
            self.calls += 1
            if spec.effect in EXTERNAL:
                self.external += 1
            if spec.effect is Effect.IRREVERSIBLE:
                self.irreversible += 1
            # A tool result is the world's, whatever the tool. Integrations
            # that know better may observe() a sharper label as well.
            result = Label(Trust.UNTRUSTED,
                           Sensitivity.PRIVATE if spec.reads_sensitive else Sensitivity.PUBLIC,
                           frozenset({"tool:" + _clip(spec.name)}))
            self.taint = result if self.taint is None else self.taint.join(result)
        elif verdict is Verdict.CONFIRM:
            self._pending[digest] = spec.name
            while len(self._pending) > MAX_PENDING:
                self._pending.pop(next(iter(self._pending)))
        return Decision(verdict, reasons, digest, seq)

    def _evaluate(self, call, detectors):
        if self.killed:
            return Verdict.DENY, ("kill switch engaged",), None, None, {}, None
        spec = self.policy.tools.get(call.tool) if isinstance(call.tool, str) else None
        if spec is None:
            return Verdict.DENY, ("unknown tool",), None, None, {}, None
        if call.manifest_digest != spec.digest:
            return (Verdict.DENY, ("tool manifest differs from the pinned digest; re-pin required",),
                    spec, None, {}, None)
        if not isinstance(call.args, dict) or not isinstance(call.arg_labels, dict):
            raise TypeError("args and arg_labels must be dicts")
        labels = self._labels(call)
        digest = self.call_digest(call, labels)
        effect = spec.effect

        deny = []
        if self.calls >= self.policy.max_calls:
            deny.append("call budget exhausted")
        if effect in EXTERNAL and self.external >= self.policy.max_external:
            deny.append("external-effect budget exhausted")
        if effect is Effect.IRREVERSIBLE and self.irreversible >= self.policy.max_irreversible:
            deny.append("irreversible-action budget exhausted")
        if effect in OUTBOUND:
            secret = sorted(_clip(n) for n, lab in labels.items()
                            if lab.sensitivity >= Sensitivity.SECRET)
            if secret:
                deny.append("secret value to an outbound call: " + ",".join(secret))
        if deny:
            return Verdict.DENY, tuple(deny), spec, digest, labels, None

        confirm = []
        if effect in ALWAYS_CONFIRM:
            confirm.append(f"{effect.value} always needs a human")
        combined = join_all(labels.values(), self.taint)
        if (effect in EXTERNAL and combined is not None
                and combined.trust < Trust.TRUSTED
                and combined.sensitivity >= Sensitivity.PRIVATE):
            confirm.append("rule of two: untrusted input and sensitive data with an external effect")
        if effect in OUTBOUND:
            confirm.extend(self._destination_reasons(call, spec))

        verdict = Verdict.CONFIRM if confirm else Verdict.ALLOW
        # Detectors can only add friction: their answer is capped at CONFIRM and
        # combined by max, so nothing they return lowers the verdict.
        for det in detectors:
            try:
                signal = det(call)
            except Exception as exc:
                signal = Verdict.CONFIRM
                confirm.append(f"detector failed: {type(exc).__name__}")
            else:
                if signal is None or signal is Verdict.ALLOW:
                    continue
                confirm.append("detector raised friction")
            verdict = max(verdict, Verdict.CONFIRM)

        grant = None
        if verdict is Verdict.CONFIRM:
            held = self._grants.get(digest)
            if held is not None:
                approver, expires = held
                if self.clock() < expires:
                    grant = approver
                    verdict = Verdict.ALLOW
                else:
                    self._grants.pop(digest, None)
                    confirm.append("approval expired")
        reasons = tuple(confirm)
        if grant is not None:
            reasons += ("approved by a registered human",)
        return verdict, reasons, spec, digest, labels, grant

    def _destination_reasons(self, call, spec):
        if not spec.destination_args:
            return ["outbound tool declares no destination argument"]
        out = []
        for name in spec.destination_args:
            value = call.args.get(name)
            values = value if isinstance(value, (list, tuple)) else [value]
            if not values or any(not isinstance(v, str) or v not in self.policy.destinations
                                 for v in values):
                out.append(f"destination not approved: {_clip(name)}")
        return out

    def _payload(self, call, spec, digest, labels, verdict, reasons, grant):
        payload = {"kind": "decision", "verdict": verdict.name, "reasons": list(reasons),
                   "tool": _clip(call.tool), "call_digest": digest,
                   "policy": self.policy.version,
                   "session": self.taint.summary() if self.taint is not None else None}
        if spec is not None:
            payload["effect"] = spec.effect.value
        if labels:
            payload["args"] = {_clip(n): {"digest": self._digest(call.args[n]),
                                          "label": lab.summary()}
                               for n, lab in labels.items()}
        if grant is not None:
            payload["approver"] = grant
        return payload

    # -- human authority -------------------------------------------------

    def approve(self, call_digest, approver):
        """A registered human approves the one pending call with this digest.

        The grant is single use and expires after policy.approval_ttl_s. It is
        recorded before it exists; an unrecordable approval is refused.
        """
        with self._lock:
            if self.killed:
                raise ApprovalError("kill switch engaged")
            if not isinstance(approver, str) or approver not in self.policy.approvers:
                raise ApprovalError("approver is not registered")
            if call_digest not in self._pending:
                raise ApprovalError("no pending call with that digest")
            expires = self.clock() + self.policy.approval_ttl_s
            try:
                self.journal.append({"kind": "approval", "call_digest": call_digest,
                                     "tool": _clip(self._pending[call_digest]),
                                     "approver": approver, "expires": expires})
            except Exception as exc:
                raise ApprovalError(f"approval not recorded: {type(exc).__name__}") from exc
            self._grants[call_digest] = (approver, expires)
            return {"call_digest": call_digest, "approver": approver, "expires": expires}
