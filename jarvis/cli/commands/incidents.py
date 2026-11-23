"""Read durable incident history without collecting or taking response actions."""

import json

from jarvis.core import incidents
from jarvis.core.util import iso


def cmd_incidents(args, store):
    result = (incidents.detail(store.db, args.incident_id, args.limit) if args.incident_id
              else incidents.overview(store.db, args.limit))
    if result is None:
        print(json.dumps({"error": "unknown incident"}) if args.json else "unknown incident")
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    if args.incident_id:
        print(f"{result['id']}  [{result['severity']}] {result['title']}")
        print(f"{result['job']} / {result['host']}: {result['state']}")
        print(f"First seen {iso(result['first_seen'])}; last seen {iso(result['last_seen'])}")
        print(f"{result['seen_count']} observations; {result['recurrences']} reappearances")
        for event in reversed(result["transitions"]):
            print(f"  {iso(event['observed_at'])}  {event['state']}: {event['reason']}")
        if result["transitions_truncated"]:
            print("Older transitions omitted; increase --limit (maximum 500).")
    else:
        print(f"{result['total']} tracked incidents: " + ", ".join(
            f"{n} {state}" for state, n in result["counts"].items()))
        for item in result["incidents"]:
            print(f"  {item['id']}  [{item['severity']}] [{item['state']}] "
                  f"{item['job']}/{item['host']} {item['title']}")
        if result["truncated"]:
            print("More incidents exist; increase --limit (maximum 500).")
    print("States describe the last collector result, not verified remediation.")
    print("Check jarvis coverage for current visibility; a stopped collector cannot refresh history.")
    return 0


def add_parser(sub):
    parser = sub.add_parser("incidents", help="durable findings, visibility loss and reappearances")
    parser.add_argument("incident_id", nargs="?", help="show one incident and its transitions")
    parser.add_argument("--limit", type=int, default=100, help="maximum rows, capped at 500")
    parser.add_argument("--json", action="store_true", help="print structured evidence")
    parser.set_defaults(fn=cmd_incidents)
