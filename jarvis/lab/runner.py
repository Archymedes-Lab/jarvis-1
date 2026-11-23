"""Run one scenario through the real engine and score the chain.

Synthetic and replay scenarios need no privilege and touch nothing on the OS,
so they run anywhere. Live scenarios are gated by `isolation.guard`.

Detection is the actual detector, reading the actual event log — not a mock.
For a synthetic scenario a throwaway event log and store are built, the
telemetry is generated into them, and the detector reads it exactly as it would
read the sensor's output. Whatever the detector concludes is what is scored.

The response half of the chain (intervened → verified) is scored only when a
response is actually exercised: a `response` callable is invoked after
detection and returns what it did. Without one — every synthetic scenario
today — those properties read "not exercised" rather than a false pass.
"""

import tempfile
from contextlib import contextmanager
from pathlib import Path

from jarvis.collectors.telemetry import sysmon
from jarvis.core.eventlog import EventLog
from jarvis.core.store import Store

from . import isolation, scoring
from . import providers as providers_mod


def _integrity(store, root):
    """Detector for self-defense scenarios: does recorded history still verify?"""
    from jarvis.core.finding import win_finding
    with EventLog(root) as log:
        result = log.verify()
    if result["ok"]:
        return [win_finding("telemetry", "ok", "Recorded event history verifies",
                            f"{result['segments']} segments intact", str(root))]
    return [win_finding("tampering", "critical", "Recorded event history does not verify",
                        "; ".join(result["problems"][:5]), str(root))]


DETECTORS = {
    "sysmon": lambda store, root: sysmon.audit(store, hosts=("win",), incremental=False,
                                               eventlog=root),
    "integrity": _integrity,
}

CHANNEL_OF = {"sysmon": "Microsoft-Windows-Sysmon/Operational"}


@contextmanager
def _scratch():
    with tempfile.TemporaryDirectory(prefix="arena-") as tmp:
        tmp = Path(tmp)
        log = EventLog(tmp / "eventlog", writer=True)
        store = Store(str(tmp / "arena.db"))
        try:
            yield log, store, tmp
        finally:
            store.db.close()
            log.close()


def _window(scenario, log, produced):
    spec_window = (scenario.spec or {}).get("window") or {}
    after = (produced[0] - 1) if produced else spec_window.get("first_seq", 0) - 1 \
        if spec_window.get("first_seq") else 0
    until = produced[1] if produced else spec_window.get("last_seq")
    channel = CHANNEL_OF.get(scenario.detector)
    events = [e for e in log.iter_events(after=after, until=until)
              if channel is None or e.get("channel") == channel]
    return events


def _detect_and_score(scenario, log, store, produced, response):
    # Only read the event window when the scenario scores telemetry. A
    # self-defense scenario deliberately corrupts the log, so parsing it back as
    # events would fail — and it has nothing to observe anyway.
    events = _window(scenario, log, produced) if scenario.expect.observed else []
    findings = DETECTORS[scenario.detector](store, str(log.root))
    result = None
    if response is not None:
        result = response(scenario, events, findings)
    return scoring.score(scenario, events, findings, response=result)


def run(scenario, *, store=None, log=None, allow_detonation=False, response=None):
    """Run and score one scenario. -> the scorecard.

    `store`/`log` override the scratch pair (e.g. replay against the live log
    with the real corpus). `response(scenario, events, findings) -> dict` lets a
    caller exercise and score containment/recovery. Live scenarios are refused
    outside a sandbox by `isolation.guard`.
    """
    isolation.guard(scenario, allow_detonation=allow_detonation)
    provider = providers_mod.get(scenario.provider)
    if scenario.detector not in DETECTORS:
        raise ValueError(f"{scenario.id}: no runnable detector {scenario.detector!r}")

    if store is not None and log is not None:
        produced = provider.produce(scenario, log) if scenario.source != "replay" else None
        return _detect_and_score(scenario, log, store, produced, response)

    with _scratch() as (slog, sstore, _):
        if scenario.source == "live":
            # A real primitive, only reachable past isolation.guard (sandbox).
            # The provider both performs it and delivers the telemetry it caused.
            produced = provider.run_live(scenario, slog, sstore)
        else:
            produced = provider.produce(scenario, slog) if scenario.source != "replay" else None
        slog.seal(force=True)
        if hasattr(provider, "post_seal"):
            provider.post_seal(scenario, slog)      # e.g. self-defense tampering
        return _detect_and_score(scenario, slog, sstore, produced, response)
