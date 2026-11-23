"""Structural containment for the Arena. Refusal, not advice.

The Arena assumes JARVIS can fail completely and the target can be fully
compromised. So anything that runs a real primitive on the operating system is
allowed only inside an approved, marked sandbox, and detonation of untrusted
code is never allowed from automation.

Telemetry-only scenarios — synthetic generation and replay of recorded events —
execute nothing on the OS and are always allowed, whatever behavior they
describe. That is deliberate: it is how the Arena tests detection of the most
dangerous techniques on an ordinary machine without ever performing them.
"""

import os
from pathlib import Path

from .scenario import SAFETY_RANK

SANDBOX_MARKER = Path("/etc/jarvis-arena-sandbox")


class Refused(RuntimeError):
    """Raised when containment cannot support what a scenario asks to run."""


def is_sandbox():
    """True only in an environment explicitly marked as a disposable sandbox."""
    if os.environ.get("JARVIS_ARENA_SANDBOX", "").strip() in ("1", "true", "yes"):
        return True
    try:
        return SANDBOX_MARKER.is_file()
    except OSError:
        return False


def why_not_sandbox():
    return ("this is not a marked Arena sandbox. Live scenarios execute real "
            "attack primitives and must run only in a disposable, isolated VM "
            "with no production credentials, network or data. Mark it with "
            "JARVIS_ARENA_SANDBOX=1 or touch /etc/jarvis-arena-sandbox.")


def guard(scenario, allow_detonation=False):
    """Raise Refused unless this scenario is safe to run here and now."""
    if scenario.source in ("synthetic", "replay"):
        return                                   # no OS execution
    # source == "live": a real primitive runs and the sensor observes it.
    if not is_sandbox():
        raise Refused(f"{scenario.id}: {why_not_sandbox()}")
    if scenario.safety == "prohibited_in_automation":
        raise Refused(f"{scenario.id}: classified prohibited_in_automation; it cannot be "
                      f"run by the Arena at all.")
    if SAFETY_RANK[scenario.safety] >= SAFETY_RANK["high_risk_detonation"] and not allow_detonation:
        raise Refused(f"{scenario.id}: {scenario.safety} needs an explicit, interactive "
                      f"detonation approval (allow_detonation), never an automated run.")
