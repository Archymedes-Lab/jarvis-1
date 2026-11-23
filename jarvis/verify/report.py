"""Run the whole in-tree verification ladder (L1 properties, L2 models) over
the code that is actually installed, and report. Standard library only; no
test runner, no network, no state. Used by `python -m jarvis.verify`, by the
daily `verify` job and by the release builders and installers.

Evidence, not a verdict: a pass says no generated case and no reachable
model state broke a documented invariant of this copy of the code. A failure
means this copy violates one, which is a bug or a modification, and a copy
that fails must not be trusted to score the machine."""

import json
import platform
import sys
import time
from pathlib import Path

from jarvis.core import mechanisms
from jarvis.verify import invariants, properties, static
from jarvis.verify.models import MODELS, lanes
from jarvis.verify.models.release import NotApplicable


def _model(invariant, name, build):
    try:
        r = build().check()
    except NotApplicable as exc:
        # The real code this model drives is not in this copy: stated, not
        # counted as a pass and not as a failure. The build gate runs over
        # the full tree, where every model applies.
        return {"invariant": invariant, "name": name, "ok": True, "applicable": False,
                "exhausted": False, "states": 0, "transitions": 0, "error": "",
                "reason": str(exc)[:300]}
    except Exception as exc:
        return {"invariant": invariant, "name": name, "ok": False, "applicable": True,
                "exhausted": False, "states": 0, "transitions": 0,
                "error": f"{type(exc).__name__}: {exc}"[:800]}
    return {"invariant": invariant, "name": name, "ok": bool(r.ok and r.exhausted),
            "applicable": True, "exhausted": bool(r.exhausted), "states": r.states,
            "transitions": r.transitions,
            "error": "" if r.ok else f"violated: {r.violated}; path: "
                     + " > ".join(a for a, _ in (r.counterexample or []))[:600]}


def run(cases=properties.CASES, seed=0):
    started = time.time()
    props = properties.run(cases, seed)
    models = [_model(i, n, b) for i, n, b in MODELS]
    try:
        fast = bool(lanes.required_fast_jobs_are_in_the_fast_lane())
        frequent = bool(lanes.five_minute_jobs_are_in_the_frequent_lane())
        membership = fast and frequent
        membership_error = ("" if membership else
                            "a protection job is not in the fast lane" if not fast else
                            "a five-minute collector is not in the frequent lane")
    except Exception as exc:
        membership, membership_error = False, f"{type(exc).__name__}: {exc}"[:300]
    mech = mechanism_conformance()
    registry = invariant_registry()
    rules = static_rules()
    ok = (all(p["ok"] for p in props) and all(m["ok"] for m in models) and membership
          and mech["ok"] and registry["ok"] and rules["ok"])
    return {"ok": ok, "at": int(started), "seconds": round(time.time() - started, 2),
            "python": platform.python_version(), "platform": sys.platform,
            "properties": props, "models": models,
            "lane_membership": {"ok": membership, "error": membership_error},
            "mechanisms": mech, "invariants": registry, "static": rules}


def invariant_registry():
    """Every registered invariant has a check and every check maps to one."""
    try:
        problems = invariants.conformance()
    except Exception as exc:
        problems = [f"{type(exc).__name__}: {exc}"[:300]]
    return {"ok": not problems, "count": len(invariants.INVARIANTS), "problems": problems[:20]}


def static_rules():
    """The shipped rules over this copy's sources (n/a on a sourceless copy).
    A crash of the engine is a failure, never a pass."""
    try:
        return static.run()
    except Exception as exc:
        return {"ok": False, "applicable": True, "files": 0, "rules": [], "violations": [],
                "errors": [f"{type(exc).__name__}: {exc}"[:300]]}


def mechanism_conformance(root=None):
    """V9: every collector declaration and mechanism primitive keeps its contract.

    The declaration checks always run. The file checks (each primitive's code
    and tests exist) need a tree that ships tests/; an installed package
    without them states that, the way an inapplicable model does, and is
    neither a pass nor a failure of those checks."""
    tree = Path(root) if root is not None else Path(mechanisms.__file__).resolve().parents[2]
    files = (tree / "tests").is_dir()
    try:
        problems = mechanisms.conformance(tree if root is not None else None, files=files)
    except Exception as exc:
        problems = [f"{type(exc).__name__}: {exc}"[:300]]
    return {"ok": not problems, "files_checked": files,
            "collectors": len(mechanisms.COLLECTORS),
            "primitives": len(mechanisms.PRIMITIVES), "problems": problems[:20]}


def summary(report):
    props = report["properties"]
    models = [m for m in report["models"] if m.get("applicable", True)]
    skipped = len(report["models"]) - len(models)
    return (f"{sum(p['ok'] for p in props)}/{len(props)} properties"
            f" ({sum(p['cases'] for p in props)} cases), "
            f"{sum(m['ok'] for m in models)}/{len(models)} models exhausted"
            f" ({sum(m['states'] for m in models)} states)"
            + (f", {skipped} not applicable to this copy" if skipped else ""))


def text(report):
    lines = [f"verification {'PASSED' if report['ok'] else 'FAILED'}: {summary(report)}"
             f" in {report['seconds']}s on Python {report['python']} ({report['platform']})"]
    for p in report["properties"]:
        lines.append(f"  {'ok  ' if p['ok'] else 'FAIL'} {p['invariant']} {p['name']}"
                     + (f": {p['error']}" if p["error"] else ""))
    for m in report["models"]:
        if not m.get("applicable", True):
            lines.append(f"  n/a  {m['invariant']} {m['name']}: {m['reason']}")
            continue
        lines.append(f"  {'ok  ' if m['ok'] else 'FAIL'} {m['invariant']} {m['name']}:"
                     f" {m['states']} states, {m['transitions']} transitions"
                     + ("" if m["exhausted"] else " (bound hit)")
                     + (f": {m['error']}" if m["error"] else ""))
    lm = report["lane_membership"]
    lines.append(f"  {'ok  ' if lm['ok'] else 'FAIL'} V8 protection jobs are in the fast lane"
                 + (f": {lm['error']}" if lm["error"] else ""))
    mc = report["mechanisms"]
    lines.append(f"  {'ok  ' if mc['ok'] else 'FAIL'} V9 mechanism conformance:"
                 f" {mc['collectors']} collectors, {mc['primitives']} primitives"
                 + ("" if mc["files_checked"] else " (no tests/ in this copy: files n/a)")
                 + "".join(f"\n         {p}" for p in mc["problems"]))
    reg = report.get("invariants") or {}
    lines.append(f"  {'ok  ' if reg.get('ok') else 'FAIL'} invariant registry: {reg.get('count', 0)} invariants,"
                 " each with a check, every check registered"
                 + "".join(f"\n         {p}" for p in reg.get("problems", [])))
    st = report.get("static") or {}
    if not st.get("applicable", True):
        lines.append("  n/a  static rules: no sources in this copy")
    else:
        for r in st.get("rules", []):
            lines.append(f"  {'ok  ' if not r['violations'] else 'FAIL'} {r['id']} {r['invariant']} {r['summary']}"
                         f" ({st.get('files', 0)} files)")
        for v in st.get("violations", [])[:20]:
            lines.append(f"         {v['rule']} {v['path']}:{v['line']} {v['text']}")
        for e in st.get("errors", []):
            lines.append(f"  FAIL static rules: {e}")
    return "\n".join(lines)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="python -m jarvis.verify",
                                 description="run the in-tree verification ladder over this copy")
    ap.add_argument("--cases", type=int, default=properties.CASES, help="cases per property")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--json", metavar="PATH", help="also write the report here")
    ap.add_argument("--quiet", action="store_true", help="exit status only")
    args = ap.parse_args(argv)
    report = run(max(1, args.cases), args.seed)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
    if not args.quiet:
        print(text(report))
    return 0 if report["ok"] else 1
