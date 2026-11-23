"""Import Atomic Red Team tests as scenario *specifications* — never executables.

Atomic Red Team publishes ATT&CK-organized tests as YAML (redcanaryco). This
maps each `atomic_test` into a JARVIS scenario so the Arena can track coverage
against a recognised technique library. It records the executor command as
reference text; it does not run it. Every imported scenario is classified so
that automation cannot execute it:

  - a `manual` executor            -> prohibited_in_automation
  - any command executor           -> high_risk_detonation, source "live"

Turning one into a runnable check is a deliberate, reviewed step: rewrite it as
a `synthetic` scenario that reproduces the technique's telemetry, or run it
`live` only inside a marked sandbox (`isolation.py`).

YAML parsing uses PyYAML when present; it is an optional import used only by
this offline tool, so the daemon keeps its stdlib-only runtime. `from_tests`
works on already-parsed dicts and needs nothing.
"""

from ..scenario import Scenario

PLATFORM = {"windows": "win", "linux": "linux"}
# ATT&CK techniques whose observable is process execution Sysmon 1 records.
EXEC_TECHNIQUES_HINT = "process execution; refine trigger_events per technique"


def _scenario_from_test(technique, display, test, index):
    platforms = [PLATFORM[p] for p in test.get("supported_platforms", []) if p in PLATFORM]
    if not platforms:
        return None
    executor = (test.get("executor") or {}).get("name", "manual")
    live = executor != "manual"
    guid = test.get("auto_generated_guid") or f"{technique}-{index}"
    spec = {
        "executor": executor,
        "command": (test.get("executor") or {}).get("command")
                   or (test.get("executor") or {}).get("steps", ""),
        "input_arguments": test.get("input_arguments") or {},
        "note": "reference only; not executed by the Arena",
    }
    return Scenario(
        id=f"atomic-{guid}",
        title=f"{technique}: {test.get('name', display)}"[:200],
        platform=platforms[0],
        safety="high_risk_detonation" if live else "prohibited_in_automation",
        source="live" if live else "synthetic",
        techniques=[technique],
        provider="atomic",
        spec=spec,
        origin="atomic",
        detector="sysmon" if platforms[0] == "win" else "sysmon_linux",
        timeout=int(test.get("timeout", 120)) if str(test.get("timeout", "")).isdigit() else 120,
    )


def from_tests(technique_file):
    """Atomic technique dict (already parsed) -> [Scenario]. Never executes."""
    technique = technique_file.get("attack_technique", "")
    display = technique_file.get("display_name", "")
    out = []
    for i, test in enumerate(technique_file.get("atomic_tests") or [], start=1):
        scenario = _scenario_from_test(technique, display, test, i)
        if scenario is not None:
            out.append(scenario)
    return out


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        raise RuntimeError("importing Atomic YAML needs PyYAML (pip install pyyaml); "
                           "the JARVIS daemon itself needs no such dependency") from None
    import pathlib
    with open(path, encoding="utf-8", errors="replace") as fh:
        return from_tests(yaml.safe_load(fh)) if not pathlib.Path(path).is_dir() else []


def produce(scenario, log):
    # Atomic scenarios are specifications. Running one means either rewriting it
    # as synthetic telemetry or executing it live in a sandbox — never here.
    raise RuntimeError(f"{scenario.id} is an imported Atomic specification and is not "
                       f"runnable directly; convert it to a synthetic scenario or run "
                       f"it live inside a marked sandbox.")
