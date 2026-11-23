"""`jarvis rules` — community detection rules on this computer.

    jarvis rules                 what was learned as existing activity, and what awaits review
    jarvis rules reviewed        mark everything listed as reviewed (asks at a terminal)
    jarvis rules forget KEY      drop one learned kind, so it alerts the next time it happens

Community (Sigma) rules that match what already happens on a computer during
their first week are recorded instead of alerting. This command is how a person
looks at that list: learning demotes a match, it never hides it.
"""

from jarvis.collectors.telemetry import community
from jarvis.core import sigma
from jarvis.core.util import iso

from ..output import typed_confirmation


def cmd_rules(args, store):
    rules, source, error = sigma.load()
    total = sum(len(v) for v in rules.values())
    if error:
        print(f"community rules could not be loaded: {error}")
        return 2
    state = community.load_state(store)
    if args.action == "forget":
        if not args.key:
            print("name the kind to forget (the key shown by  jarvis rules )")
            return 2
        if community.forget(store, args.key):
            print(f"forgotten: {args.key}; it alerts the next time it happens")
            return 0
        print(f"nothing learned under {args.key}")
        return 1
    waiting = community.unreviewed(state)
    if args.action == "reviewed":
        if not waiting:
            print("nothing awaits review")
            return 0
        what = (f"{len(waiting)} kind(s) of existing activity match community rules. Marking them reviewed "
                "removes the reminder; they keep not alerting.")
        if not typed_confirmation("reviewed", what):
            print("not marked: this needs the word typed at an interactive terminal")
            return 2
        print(f"marked {community.review(store)} as reviewed")
        return 0
    print(f"{total} community rules loaded"
          + (f" (Sigma {source['commit'][:12]}, {source['license']})" if source else ""))
    if not state:
        print("community rules have not run on this computer yet")
        return 0
    shapes = state["shapes"]
    print(f"learning since {iso(state['since'])}; {len(shapes)} kind(s) of existing activity learned, "
          f"{len(waiting)} not yet reviewed")
    for key, entry in sorted(shapes.items()):
        _rid, program, parent = (key.split("|") + ["", ""])[:3]
        mark = " " if entry.get("reviewed") else "*"
        print(f" {mark} {entry.get('title', '?')}  ({program or 'unknown'} under {parent or 'unknown'})")
        print(f"     rule by {entry.get('author') or 'its Sigma author'}; key: {key}")
    if waiting:
        print("\n* not yet reviewed. After looking:  jarvis rules reviewed")
    return 0


def add_parser(sub):
    p = sub.add_parser("rules", help="community detection rules: what was learned here and what awaits review")
    p.add_argument("action", nargs="?", choices=["reviewed", "forget"])
    p.add_argument("key", nargs="?", help="for forget: the key of one learned kind")
    p.set_defaults(fn=cmd_rules)
    return p
