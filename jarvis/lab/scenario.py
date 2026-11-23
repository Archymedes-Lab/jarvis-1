"""Declarative adversarial scenarios and their safety classification.

A scenario names an adversary behavior, how to produce it (synthetic telemetry,
or a real primitive), what JARVIS should observe and conclude, and — the field
that governs automation — how dangerous producing it is.

The safety tier is not a hint. `isolation.guard` reads it and refuses to run
anything above the machine's proven containment, so an autonomous agent cannot
walk a benign ATT&CK test up into detonating untrusted code.
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Lowest to highest containment required.
SAFETY = ("synthetic", "safe_emulation", "isolated_emulation", "high_risk_detonation",
          "prohibited_in_automation")
SAFETY_RANK = {name: i for i, name in enumerate(SAFETY)}

# How a scenario's telemetry is produced.
#   synthetic  a generator writes events straight into a throwaway event log;
#              nothing runs on the OS. Runnable anywhere.
#   replay     an existing recorded event-log window is scored again.
#   live       a real primitive runs and the sensor observes it (sandbox only).
SOURCES = ("synthetic", "replay", "live")

# The defensive properties every scenario is scored against, in chain order.
PROPERTIES = ("observed", "understood", "correlated", "classified", "intervened",
              "contained", "removed", "restored", "verified")


class ScenarioError(ValueError):
    pass


@dataclass
class Expect:
    """What JARVIS should do. Absent properties are not exercised, not failures."""
    observed: list = field(default_factory=list)      # [{kind, value}] indicators
    techniques: list = field(default_factory=list)    # ATT&CK IDs, e.g. "T1003.001"
    classified: dict = field(default_factory=dict)    # {category, min_severity, title?}
    intervened: bool = False
    contained: bool = False
    removed: bool = False
    restored: bool = False
    verified: bool = False


@dataclass
class Scenario:
    id: str
    title: str
    platform: str                       # win | linux
    safety: str
    source: str
    techniques: list = field(default_factory=list)
    provider: str = "synthetic"         # provider module name (providers/<provider>.py)
    spec: dict = field(default_factory=dict)   # provider input (e.g. events to generate)
    expect: Expect = field(default_factory=Expect)
    detector: str = "sysmon"            # which detector classifies (win: sysmon)
    origin: str = "builtin"             # builtin | atomic | caldera | exa-candidate
    trigger_events: list = field(default_factory=list)   # source event IDs that constitute the attack
    timeout: int = 120

    def __post_init__(self):
        if self.safety not in SAFETY_RANK:
            raise ScenarioError(f"{self.id}: unknown safety tier {self.safety!r}")
        if self.source not in SOURCES:
            raise ScenarioError(f"{self.id}: unknown source {self.source!r}")
        if self.platform not in ("win", "linux"):
            raise ScenarioError(f"{self.id}: unknown platform {self.platform!r}")
        if isinstance(self.expect, dict):
            self.expect = Expect(**self.expect)
        if self.source == "live" and self.safety == "synthetic":
            raise ScenarioError(f"{self.id}: a live scenario cannot be classified synthetic")

    @property
    def exercised(self):
        """Properties this scenario actually tests (has an expectation for)."""
        out = []
        if self.expect.observed:
            out.append("observed")
            out += ["understood", "correlated"]
        if self.expect.classified:
            out.append("classified")
        for prop in ("intervened", "contained", "removed", "restored", "verified"):
            if getattr(self.expect, prop):
                out.append(prop)
        return [p for p in PROPERTIES if p in out]

    def to_dict(self):
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            raise ScenarioError("scenario must be an object")
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(d) - known
        if unknown:
            raise ScenarioError(f"{d.get('id', '?')}: unknown fields {sorted(unknown)}")
        for req in ("id", "title", "platform", "safety", "source"):
            if not d.get(req):
                raise ScenarioError(f"scenario missing required field {req!r}")
        return cls(**d)


def load_file(path):
    path = Path(path)
    data = json.loads(path.read_text())
    items = data if isinstance(data, list) else [data]
    return [Scenario.from_dict(d) for d in items]


def load_dir(directory):
    out = []
    for path in sorted(Path(directory).glob("*.json")):
        out.extend(load_file(path))
    ids = [s.id for s in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ScenarioError(f"duplicate scenario ids: {sorted(dupes)}")
    return out
