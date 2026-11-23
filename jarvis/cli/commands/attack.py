"""`jarvis attack` — ATT&CK coverage, validated by probing the real detectors.

    jarvis attack            per-tactic validated / claimed / blind
    jarvis attack --blind    also list every blind technique
"""

from jarvis.service import attackmap


def cmd_attack(args, store):
    out, data = attackmap.measure(store)
    t = data["totals"]
    print(f"ATT&CK coverage: {t['validated']} validated, {t['claimed']} claimed, "
          f"{t['regressed']} regressed, {t['blind']} blind of {t['total']}")
    for tactic, v in data["tactics"].items():
        print(f"  {tactic:22} {v['validated']:3} validated {v['claimed']:3} claimed "
              f"{v['blind']:3} blind")
    for f in out:
        if f["severity"] == "high":
            print("REGRESSION:", f["title"], "—", f["detail"])
    if args.blind:
        for r in data["techniques"]:
            if r["level"] == "blind":
                print(f"  {r['tid']:7} {r['name']}  [{', '.join(r['tactics'])}]")
    return 1 if t["regressed"] else 0


def add_parser(sub):
    p = sub.add_parser("attack", help="ATT&CK coverage map, validated by detector probes")
    p.add_argument("--blind", action="store_true", help="list the blind techniques")
    p.set_defaults(fn=cmd_attack)
    return p
