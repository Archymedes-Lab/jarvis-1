"""`jarvis retention` — report or apply the database retention policy.

Policies are read from core/retention.POLICIES, so adding one needs no change
here.
"""

import json
import sys

from jarvis.core.retention import POLICIES, apply, db_size, plan, vacuum


def _human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or unit == "GiB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0


def cmd_retention(args, store):
    overrides = {}
    if args.days is not None:
        overrides = {p.name: args.days for p in POLICIES}

    if args.vacuum:
        res = vacuum(store)
        if args.json:
            json.dump(res, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print("vacuum reclaimed %s (%s -> %s)"
                  % (_human(res["reclaimed"]), _human(res["before"]["bytes"]),
                     _human(res["after"]["bytes"])))
        return 0

    rows = apply(store, overrides) if args.apply else plan(store, overrides)
    size = db_size(store)
    if args.json:
        json.dump({"policies": rows, "db": size, "applied": bool(args.apply)},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    verb = "removed" if args.apply else "would remove"
    print("database %s (%s reclaimable without VACUUM)"
          % (_human(size["bytes"]), _human(size["free_bytes"])))
    print()
    total = 0
    for r in rows:
        total += r["rows"]
        flag = "  ERROR %s" % r["error"] if r["error"] else ""
        print("%10d  %-22s %-14s >%4dd  %s%s"
              % (r["rows"], r["name"], r["table"], r["days"], r["why"], flag))
    print()
    print("%s %d rows" % (verb, total))
    if not args.apply and total:
        print("re-run with --apply to remove them, "
              "then --vacuum to return the space")
    return 0


def add_parser(sub):
    p = sub.add_parser(
        "retention",
        help="report or apply database retention policy (dry run by default)")
    p.add_argument("--apply", action="store_true",
                   help="actually delete; without this it only reports")
    p.add_argument("--vacuum", action="store_true",
                   help="rewrite the database to return freed space to disk")
    p.add_argument("--days", type=int, metavar="N",
                   help="override every policy's age threshold")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_retention)
    return p
