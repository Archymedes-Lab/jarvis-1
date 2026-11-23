"""Import MITRE CALDERA abilities as scenario *specifications* — never executables.

CALDERA (apache/caldera) describes adversary abilities in YAML: an ATT&CK
tactic and technique, and per-platform executors with commands. Like the Atomic
importer, this maps each ability to a JARVIS scenario for coverage tracking and
records the command as reference text only. Every imported ability is a
`high_risk_detonation`/`live` spec that automation cannot run; making it usable
means rewriting it as synthetic telemetry or running it in a marked sandbox.

CALDERA also groups abilities into adversary profiles (ordered ability ids);
`from_adversary` preserves that order as a chained-operation note for when
chained emulation is built.
"""

from ..scenario import Scenario

# CALDERA platform keys -> JARVIS platform.
PLATFORM = {"windows": "win", "linux": "linux", "darwin": None}


def _first_platform(executors):
    for key in ("windows", "linux"):
        if key in (executors or {}):
            return key
    return None


def from_ability(ability):
    """One CALDERA ability dict (already parsed) -> Scenario, or None if unusable."""
    executors = ability.get("platforms") or ability.get("executors") or {}
    key = _first_platform(executors)
    if key is None:
        return None
    platform = PLATFORM.get(key)
    if platform is None:
        return None
    technique = (ability.get("technique") or {}).get("attack_id") or ability.get("technique_id", "")
    aid = ability.get("ability_id") or ability.get("id") or ability.get("name", "ability")
    body = executors[key]
    # platforms: {windows: {psh: {command: ...}}} or {windows: {command: ...}}
    command = ""
    if isinstance(body, dict):
        inner = next(iter(body.values())) if body and isinstance(next(iter(body.values()), None), dict) else body
        command = (inner or {}).get("command", "") if isinstance(inner, dict) else ""
    return Scenario(
        id=f"caldera-{aid}",
        title=f"{technique or ability.get('tactic', '')}: {ability.get('name', aid)}"[:200],
        platform=platform,
        safety="high_risk_detonation",
        source="live",
        techniques=[technique] if technique else [],
        provider="caldera",
        spec={"executor": key, "command": command, "tactic": ability.get("tactic"),
              "note": "reference only; not executed by the Arena"},
        origin="caldera",
        detector="sysmon" if platform == "win" else "sysmon_linux",
    )


def from_adversary(adversary, abilities_by_id):
    """A CALDERA adversary profile -> ordered [Scenario], recording chain order."""
    out = []
    for order, aid in enumerate(adversary.get("atomic_ordering") or [], start=1):
        ability = abilities_by_id.get(aid)
        if not ability:
            continue
        scenario = from_ability(ability)
        if scenario is not None:
            scenario.spec["chain_position"] = order
            scenario.spec["adversary"] = adversary.get("name")
            out.append(scenario)
    return out


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        raise RuntimeError("importing CALDERA YAML needs PyYAML (pip install pyyaml)") from None
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = yaml.safe_load(fh)
    items = data if isinstance(data, list) else [data]
    return [s for s in (from_ability(a) for a in items) if s is not None]


def produce(scenario, log):
    raise RuntimeError(f"{scenario.id} is an imported CALDERA specification; convert it to a "
                       f"synthetic scenario or run it live inside a marked sandbox.")
