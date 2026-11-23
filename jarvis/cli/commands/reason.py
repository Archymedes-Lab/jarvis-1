"""jarvis reason: think about spyware and hidden processes with explicit limits."""

import json

from jarvis.response import reasoning

HOST = {"win": ("win",), "wsl": ("wsl",), "all": ("win", "wsl")}


def _print_report(rep, limit):
    c = rep["counts"]
    print(f"examined {rep['subjects_examined']} process instances: "
          + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
    print("sources: " + ", ".join(f"{k}={v}" for k, v in sorted(rep["coverage"].items())))
    if rep["coverage_incomplete"]:
        print("  incomplete: " + ", ".join(rep["coverage_incomplete"]) + " (unknown, not clean)")
    for r in rep["focus"][:limit]:
        print(f"\n[{r['verdict']}] {r['label'] or r['key']}  ({r['host']}, depth {r['observation_depth']}"
              + (", needs your authorization" if r["depth_needs_human"] else "") + ")")
        for line in r["reasons"]:
            print("   - " + line)
        for a in r["archetypes"][:2]:
            print(f"   how a {a['title'].lower()} works: {a['mechanism']}")
            if a["not_yet_observed"]:
                print("   not yet observed: " + ", ".join(a["not_yet_observed"]))
            print("   next: " + "; ".join(a["next_checks"]))
        adv = r.get("advice")
        if adv:
            if adv.get("available"):
                bp = adv.get("benign_probability")
                print("   advisory (untrusted, not validated): plausible-for-ordinary-software "
                      + (f"{bp:.2f}" if isinstance(bp, float) else "n/a")
                      + (f", class {adv['archetype']}" if adv.get("archetype") else "")
                      + (f" - {adv['disagreement']}" if adv.get("disagreement") else ""))
            else:
                print("   advisory unavailable: " + str(adv.get("reason")))
    if not rep["focus"]:
        print("\nnothing observable matched a spyware or concealment pattern.")
    plan = rep["plan"]
    print(f"\nplan (executes nothing): {plan['reason']}")
    if plan["awaiting_human_authorization"]:
        print(f"  awaiting your authorization for a forensic trace: "
              f"{len(plan['awaiting_human_authorization'])}")
    print("\nnot observed at all (absence proves nothing here):")
    for line in rep["not_connected"]:
        print("  - " + line)
    print("\n" + rep["reading"])


def _controls(args):
    from jarvis.lab import spyware_controls as sc
    from jarvis.lab import vmlab
    sub = args.name or "plan"
    if sub == "plan":
        cfg = vmlab.Config()
        load = vmlab.pressure()
        stop = vmlab.blockers(cfg, load, image_ok=vmlab.verify_base_image(cfg))
        out = {"controls": [{"id": c.id, "platform": c.platform, "expects": c.expect_verdict,
                             "known_blind": c.known_blind, "telemetry": c.telemetry} for c in sc.ALL],
               "linux_lab_blockers": stop, "host_load": load}
        if args.json:
            print(json.dumps(out))
        else:
            for c in sc.ALL:
                tag = " (known blind spot)" if c.known_blind else ""
                print(f"{c.id:34} {c.platform:5} expects {c.expect_verdict}{tag}")
            print("linux lab: " + ("ready" if not stop else "not now: " + "; ".join(stop)))
        return 0
    if sub == "linux":
        cfg = vmlab.Config()
        if args.max_pressure is not None:
            cfg.max_cpu_pressure = float(min(90, max(5, args.max_pressure)))
        data, report = vmlab.run_linux(sc.by_platform("linux"), cfg)
        if data is None:
            out = {"ran": False, "blocked": report["blocked"], "problems": report["problems"],
                   "lab": report}
            print(json.dumps(out) if args.json else "lab did not run: "
                  + "; ".join(report["blocked"] + report["problems"]))
            return 2
        results = [sc.evaluate(c, next((r for r in data["results"] if r.get("id") == c.id), None))
                   for c in sc.by_platform("linux")]
        summary = sc.summarize(results)
        baseline = [sc.subject_from_evidence(b) for b in data["baseline"].get("with_observations", [])]
        from jarvis.core.reasoning import engine
        base_rows = [engine.assess(s) for s in baseline if s]
        flagged = [r for r in base_rows if r["verdict"] not in ("NO_SIGNAL", "EXPECTED_DECLARED")]
        out = {"ran": True, "summary": summary, "results": results, "lab": report,
               "guest": {"kernel": data.get("kernel"), "offers": data.get("offers"),
                         "uptime_s": data.get("uptime_s")},
               "baseline": {"processes": data["baseline"].get("processes"),
                            "flagged": [{"label": r["label"], "verdict": r["verdict"],
                                         "capture": r["capture"]} for r in flagged]}}
        if args.json:
            print(json.dumps(out, default=str))
        else:
            for r in results:
                lat = f"{r['latency_s']:.2f}s" if r.get("latency_s") is not None else "-"
                print(f"{r['id']:34} {r['outcome']:16} verdict={r.get('verdict', '-'):26} latency={lat}"
                      + (f"  ({r['reason']})" if r.get("reason") else ""))
            print(f"passed={summary['passed']} complete={summary['complete']} problems={summary['problems']}")
            print(f"clean-guest baseline: {out['baseline']['processes']} processes, "
                  f"{len(flagged)} flagged: " + (", ".join(f"{f['label']}={f['verdict']}" for f in out['baseline']['flagged']) or "none"))
            iso = report["isolation"]
            print(f"isolation: container removed={iso['container_removed']} run dir removed={iso['run_dir_removed']} "
                  f"base image unchanged={iso['base_image_unchanged']}")
        return 0 if summary["passed"] and not flagged else 1
    print("controls: plan | linux")
    return 2


def cmd_reason(args, _store):
    if args.action == "controls":
        return _controls(args)
    if args.action == "selftest":
        r = reasoning.selftest()
        if args.json:
            print(json.dumps(r, default=str))
        else:
            print(f"positive controls detected {r['detected']}/{r['positives']}; "
                  f"look-alike false positives {len(r['false_positives'])}/{r['lookalikes']}; "
                  f"expectation drift {len(r['expectation_drift'])}")
            print(r["scope"])
        return 0 if not (r["missed"] or r["false_positives"] or r["expectation_drift"]) else 1
    if args.action == "calibrate":
        r = reasoning.calibrate()
        if args.json:
            print(json.dumps(r))
        else:
            print(f"advisory calibration over {r['cases']} synthetic cases ({r['failures']} unavailable)")
            for k, v in r["summary"].items():
                print(f"  {k:36} " + ("no data" if not v else
                                       f"n={v['n']} mean={v['mean']:.2f} min={v['min']:.2f} max={v['max']:.2f}"))
            print("  controls vs explained look-alikes separable on 'benign': "
                  + str(r["controls_and_explained_separable_on_benign"]))
            print(r["reading"])
        return 0 if r["cases"] else 2
    if args.action == "explain":
        info = reasoning.explain(args.name or "")
        if not info:
            from jarvis.core.reasoning import knowledge
            print("archetypes: " + ", ".join(sorted(knowledge.ARCHETYPES)))
            return 2
        if args.json:
            print(json.dumps(info))
        else:
            print(f"{info['title']}\n  {info['mechanism']}")
            print("  must eventually: " + (", ".join(info["must_eventually"]) or "(nothing fixed)"))
            print("  next checks: " + "; ".join(info["next_checks"]))
            for m, (status, why) in info["observability"].items():
                print(f"  can JARVIS see {m}? {status} - {why}")
            print("  legitimate look-alikes: " + (", ".join(info["benign_lookalikes"]) or "none"))
        return 0
    rep = reasoning.run(HOST[args.host], deep=args.deep, use_jev=not args.no_jev, limit=args.limit)
    if args.json:
        print(json.dumps(rep, default=str))
    else:
        _print_report(rep, args.limit)
    return 1 if any(r["verdict"] in ("SUSPECT_CHAIN", "VISIBILITY_CONTRADICTION") for r in rep["focus"]) else 0


def add_parser(sub):
    p = sub.add_parser("reason", help="reason about spyware and hidden processes (read-only)")
    p.add_argument("action", nargs="?", default="spyware", choices=["spyware", "explain", "selftest", "calibrate", "controls"])
    p.add_argument("name", nargs="?", help="controls: plan | linux;  explain: keylogger, screen_spy, av_spy, infostealer, rat, covert_process")
    p.add_argument("--host", choices=list(HOST), default="all")
    p.add_argument("--deep", action="store_true",
                   help="also run the cross-view hidden-process audits (about 10 s)")
    p.add_argument("--no-jev", action="store_true", help="deterministic reasoning only, no remote advisory")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--max-pressure", type=int, default=None,
                   help="controls linux: allow the lab to start below this CPU pressure percent (5-90)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_reason)
