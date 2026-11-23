"""The Arena as a scheduled collector: run the suite, surface failures.

This is how the Arena wires into the running daemon. Every cycle it runs the
built-in synthetic scenarios — which execute nothing on the OS — records each
result in the permanent regression store, and returns findings in the common
shape so the scheduler, dashboard and score treat a validation failure like any
other security finding:

  - a scenario that no longer passes, or scores below its recorded best, is a
    high finding: JARVIS's own defence has regressed
  - an all-clear is one `ok` finding (weight zero), so a healthy Arena never
    inflates the score

Live/detonation scenarios are never touched here; `isolation.guard` refuses
them, and this job runs them only if they were runnable, which the built-ins
are not.
"""

from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import PACKAGE_DIR

from . import isolation, regression, runner
from .scenario import load_dir

SCENARIO_DIR = PACKAGE_DIR / "lab" / "scenarios"


def audit(store=None, hosts=("win",)):
    findings = []
    reg = regression.Regression()
    try:
        scenarios = load_dir(SCENARIO_DIR) if SCENARIO_DIR.is_dir() else []
        passed = 0
        for s in scenarios:
            reg.remember(s)
            try:
                card = runner.run(s)
            except isolation.Refused:
                continue                       # not runnable here; not a failure
            except Exception as exc:           # a broken scenario must not kill the job
                findings.append(_finding(
                    "validation", "medium", f"Arena scenario {s.id} could not run",
                    str(exc)[:200], s.id))
                continue
            reg.record(card)
            if card["ok"]:
                passed += 1
            else:
                failed = [p for p in card["exercised"]
                          if card["properties"][p]["status"] != "pass"]
                findings.append(_finding(
                    "validation", "high", f"Arena validation failed: {s.id}",
                    f"scored {card['score']}%; not passing: "
                    + ", ".join(f"{p} ({card['properties'][p]['detail']})" for p in failed),
                    s.id))
        for r in reg.regressions():
            findings.append(_finding(
                "validation", "high", f"Arena regression: {r['id']}",
                f"now scores {r['now']}% against a recorded best of {r['best']}% — a "
                f"defence that used to hold has weakened.", r["id"]))
        findings.append(_finding(
            "validation", "ok",
            f"Arena: {passed}/{len(scenarios)} validation scenarios pass",
            "continuous adversarial validation of the Defender; every scenario is a "
            "permanent regression test.", "arena"))
    finally:
        reg.close()
    return findings
