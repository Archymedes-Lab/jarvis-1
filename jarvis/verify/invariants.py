"""The invariant registry: what the verification framework guards, and by what.

Every invariant names at least one executable check, and every check in the
framework maps back to a registered invariant (conformance below), so nothing
is claimed without a check and no check proves something nobody wrote down.
The table in docs/architecture/VERIFICATION-LADDER.md lists the same ids
(tests/test_verify_invariants.py).

Check references, by kind:
    property:<name>     jarvis/verify/properties.py PROPERTIES (L1, seeded search)
    model:<name>        jarvis/verify/models MODELS (L2, exhaustive)
    static:<rule id>    jarvis/verify/static.py RULES (L0, shipped rules)
    membership:<name>   a declaration check run by the report
    test:<path>         a unit test in the tree (only where tests/ ships)
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Invariant:
    id: str
    statement: str
    checks: tuple[str, ...]


INVARIANTS = (
    Invariant("V1", "Score is in 0..100; a blind area reads 0; losing a collector never raises the score",
              ("property:score range", "property:blindness never improves the score")),
    Invariant("V2", "Adding a finding never raises the score; the same fact twice counts once",
              ("property:findings never improve the score", "property:duplicate findings do not double count")),
    Invariant("V3", "Stale or incomplete observations never count as evidence and are listed as degraded",
              ("property:assess well-formed", "property:missing evidence never counts")),
    Invariant("V4", "Adding positive evidence never lowers a verdict",
              ("property:evidence is monotone",)),
    Invariant("V5", "A valid signature never raises an input watcher's severity; exit never launders it; "
                    "the product's own supervised hook never counts",
              ("property:signature only lowers severity", "property:exit does not launder a watcher",
               "property:own hook never counts", "property:failed hooks are not watchers")),
    Invariant("V6", "Under a declared privacy seal, any reopen, policy override or use is reported high by the "
                    "next collection; an intact seal never alarms; nothing is reported without a seal",
              ("model:privacy seal lifecycle",)),
    Invariant("V7", "A release staged on a base that is no longer live is refused; rollback restores the "
                    "previous release",
              ("model:release switch",)),
    Invariant("V8", "A due fast-lane job never waits behind a main-lane job; protection jobs are in the fast lane",
              ("model:scheduler lanes", "membership:fast lane")),
    Invariant("V9", "Every collector is declared once with a complete contract; every mechanism primitive "
                    "names existing code and tests",
              ("membership:mechanisms", "test:tests/test_mechanisms.py")),
    Invariant("V10", "A health source reads unavailable only when its collection failed; a named coverage gap "
                     "reads partial; nothing with an error or gap reads complete",
              ("test:tests/test_source_status.py",)),
    Invariant("V11", "The interop gate always recovers: bounded slots and backoff, refusals only for a reason, "
                     "and one success closes the gate",
              ("model:interop gate recovery",)),
    Invariant("V12", "Collectors, the service and core launch Windows programs only through the gated path",
              ("static:S1", "test:tests/test_windows_launch_gate.py")),
    Invariant("V13", "A containment action is applied only by a human approval or by the automatic rung with "
                     "its flags, high severity and complete coverage; automatic actions stay under their cap; "
                     "a time-bounded action carries an expiry and is lifted only by a verified undo; after a "
                     "human undo a recurrence is only proposed",
              ("model:response ladder", "test:tests/test_verify_ladder_model.py",
               "test:tests/test_defense.py", "test:tests/test_ban_source.py")),
    Invariant("V14", "An elevated shell runs only inline code fixed at launch or files it verified in an "
                     "administrator-only folder; no command line goes through a shell; launchers start "
                     "PowerShell by full path",
              ("static:S2", "static:S3", "static:S4", "test:tests/test_sensor_installer.py")),
    Invariant("V15", "Text the observed party controls never chooses a containment target",
              ("property:a guessed user name never chooses the banned address", "test:tests/test_ban_source.py")),
)
KINDS = ("property", "model", "static", "membership", "test")


def declared_checks():
    """{"kind:name": invariant id} for every check the framework runs."""
    from jarvis.verify import models, properties, static
    out = {f"property:{name}": inv for inv, name, _g, _p in properties.PROPERTIES}
    out.update({f"model:{name}": inv for inv, name, _b in models.MODELS})
    out.update({f"static:{r.id}": r.invariant for r in static.RULES})
    out.update({"membership:fast lane": "V8", "membership:mechanisms": "V9"})
    return out


def conformance(root=None, registry=INVARIANTS):
    """Problems, as sentences; empty when registry and checks agree.

    test: references are resolved only in a tree that ships tests/; an installed
    copy states nothing about them either way."""
    tree = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    tests = (tree / "tests").is_dir()
    declared = declared_checks()
    ids = {i.id for i in registry}
    problems = []
    for inv in registry:
        if not inv.checks:
            problems.append(f"{inv.id} has no executable check")
        for ref in inv.checks:
            kind, _, name = ref.partition(":")
            if kind not in KINDS:
                problems.append(f"{inv.id}: unknown check kind in {ref!r}")
            elif kind == "test":
                if tests and not (tree / name).is_file():
                    problems.append(f"{inv.id}: test file {name} does not exist")
            elif ref not in declared:
                problems.append(f"{inv.id}: check {ref!r} does not exist")
            elif declared[ref] != inv.id:
                problems.append(f"{inv.id}: check {ref!r} declares {declared[ref]}")
    for ref, inv_id in sorted(declared.items()):
        if inv_id not in ids:
            problems.append(f"{ref} proves {inv_id}, which is not registered")
    return problems
