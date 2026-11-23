"""`jarvis arena` — continuous adversarial validation of the Defender.

    jarvis arena list                    the scenario library and safety tiers
    jarvis arena run [ID]                run one or all runnable scenarios, score them
    jarvis arena suite                   rerun everything ever recorded; report regressions
    jarvis arena show ID                 the last scorecard for a scenario
    jarvis arena coverage                ATT&CK techniques covered vs. gaps
    jarvis arena import PATH             import Atomic Red Team / CALDERA YAML as specs
    jarvis arena candidates PATH         turn researched behaviors into coverage candidates

Only synthetic and replay scenarios run here; anything that executes a real
primitive is refused outside a marked sandbox (see jarvis.lab.isolation).
"""

import json
from pathlib import Path

from jarvis.core.paths import PACKAGE_DIR
from jarvis.lab import intel, isolation, regression, runner
from jarvis.lab.scenario import PROPERTIES, load_dir

SCENARIO_DIR = PACKAGE_DIR / "lab" / "scenarios"
MARK = {"pass": "✓", "partial": "~", "fail": "✗", "not_exercised": "·"}


def _library():
    return load_dir(SCENARIO_DIR) if SCENARIO_DIR.is_dir() else []


def _print_card(card, verbose=True):
    flag = "PASS" if card["ok"] else "FAIL"
    print(f"[{flag}] {card['scenario']}  {card['score']}%  "
          f"({','.join(card['techniques']) or 'no technique'})")
    if verbose:
        for p in PROPERTIES:
            prop = card["properties"].get(p)
            if prop:
                print(f"    {MARK[prop['status']]} {p:11} {prop['detail']}")
        ed = card["earliest_decision"]
        if ed:
            print(f"    earliest decision point: event #{ed['seq']} ({ed['action']}) at {ed['time']}")


def cmd_arena(args, store=None):
    action = args.action
    reg = regression.Regression()
    try:
        if action == "list":
            for s in _library():
                print(f"  {s.id:34} [{s.safety:12}] {s.source:9} {s.title}")
            extra = reg.scenarios()
            imported = [r for r in extra if r["origin"] != "builtin"]
            if imported:
                print(f"\n  {len(imported)} imported/candidate specs (not run here): "
                      + ", ".join(r["id"] for r in imported[:8]) + ("…" if len(imported) > 8 else ""))
            return 0

        if action == "coverage":
            covered = {}
            for s in _library():
                for t in s.techniques:
                    covered.setdefault(t, []).append(s.id)
            print("Techniques with an Arena test:")
            for t, ids in sorted(covered.items()):
                c = intel.coverage(t)
                print(f"  {t:12} detector={'yes' if c['has_detector'] else 'NO '}  {', '.join(ids)}")
            gaps = [t for t in intel.TECHNIQUE_TELEMETRY if t not in covered]
            if gaps:
                print("Mapped but no Arena test yet: " + ", ".join(sorted(gaps)))
            return 0

        if action == "import":
            if not args.target:
                print("give a path to an Atomic Red Team or CALDERA YAML file")
                return 1
            from jarvis.lab.providers import atomic, caldera
            text = Path(args.target).read_text(errors="replace")
            loader = caldera if ("atomic_ordering" in text or "\ntactic:" in text
                                 or "tactic:" in text.split("\n", 1)[0]) else atomic
            scenarios = loader.load_yaml(args.target)
            for s in scenarios:
                reg.remember(s)
            print(f"imported {len(scenarios)} {loader.__name__.rsplit('.', 1)[-1]} "
                  f"specification(s); none are runnable until reviewed.")
            for s in scenarios[:20]:
                print(f"  {s.id:40} [{s.safety}] {s.techniques}")
            return 0

        if action == "candidates":
            if not args.target:
                print("give a path to a JSON list of structured behaviors "
                      "(report_id, technique, title, observed…) from research")
                return 1
            behaviors = json.loads(Path(args.target).read_text())
            cands = intel.candidates_from(behaviors)
            for c in cands:
                reg.remember(c)
            summary = intel.coverage_summary(cands)
            print(f"{summary['total']} candidate(s): {summary['has_detector']} JARVIS can "
                  f"classify today, {len(summary['gaps'])} coverage gap(s).")
            for g in summary["gaps"]:
                print(f"  GAP {g['id']} ({g['technique']}): {g['verdict']}")
            print("None are runnable; rewrite a candidate as a synthetic scenario to test it.")
            return 0

        if action == "show":
            row = reg.latest(args.target) if args.target else None
            if not row:
                print("no recorded run for that scenario")
                return 1
            _print_card(json.loads(row["card"]))
            hist = reg.history(args.target, 10)
            print("  history: " + " ".join(f"{int(r['score'])}%" for r in reversed(hist)))
            return 0

        # run / suite
        library = {s.id: s for s in _library()}
        if action == "run" and args.target:
            if args.target not in library:
                print(f"unknown scenario {args.target}")
                return 1
            targets = [library[args.target]]
        else:
            targets = list(library.values())

        results, refused = [], []
        for s in targets:
            reg.remember(s)
            try:
                card = runner.run(s, allow_detonation=args.allow_detonation)
            except isolation.Refused as exc:
                refused.append((s.id, str(exc)))
                continue
            reg.record(card)
            results.append(card)
            _print_card(card, verbose=(args.target is not None or args.verbose))

        for sid, why in refused:
            print(f"[skip] {sid}: {why}")
        passed = sum(1 for c in results if c["ok"])
        print(f"\n{passed}/{len(results)} scenarios passed"
              + (f", {len(refused)} refused (need a sandbox)" if refused else ""))
        if action == "suite":
            regs = reg.regressions()
            if regs:
                print("REGRESSIONS:")
                for r in regs:
                    print(f"  {r['id']}: was {r['best']}%, now {r['now']}%")
                return 1
            print("no regressions against recorded bests")
        return 0 if passed == len(results) else 1
    finally:
        reg.close()


def add_parser(sub):
    p = sub.add_parser("arena", help="adversarial validation: score the Defender, keep regressions")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "run", "suite", "show", "coverage", "import", "candidates"])
    p.add_argument("target", nargs="?", help="a scenario id, or a path for import")
    p.add_argument("-v", "--verbose", action="store_true", help="full scorecard for every scenario")
    p.add_argument("--allow-detonation", action="store_true",
                   help="permit high-risk live scenarios (sandbox only; still gated)")
    p.set_defaults(fn=cmd_arena)
    return p
