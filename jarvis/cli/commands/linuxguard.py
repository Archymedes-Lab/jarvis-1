"""`jarvis linuxguard` — Linux system integrity baseline.

    jarvis linuxguard            what is new, changed or removed since the baseline
    jarvis linuxguard accept     make the current state the baseline (typed at a terminal)
"""

from jarvis.collectors.persistence import linuxguard

from ..output import typed_confirmation


def cmd_linuxguard(args, store):
    if args.action == "accept":
        what = ("Every change to PAM, sessions, sudo, the loader, udev, APT, login messages and module "
                "configuration since the baseline becomes the new normal and stops being reported.")
        if not typed_confirmation("accept", what):
            print("not accepted: this needs the word typed at an interactive terminal")
            return 2
        try:
            n = linuxguard.accept(store)
        except RuntimeError as exc:
            print(f"not accepted: {exc}")
            return 2
        print(f"baseline replaced: {n} files recorded")
        return 0
    found = [f for f in linuxguard.audit(store) if f.get("severity") != "ok"]
    if not found:
        print("no change since the baseline, and no invariant broken")
        return 0
    for f in found:
        print(f"[{f['severity'].upper()}] {f['title']}")
        print(f"    {f['detail']}")
    return 0


def add_parser(sub):
    p = sub.add_parser("linuxguard", help="Linux system integrity: changes since the baseline; accept them")
    p.add_argument("action", nargs="?", choices=["accept"])
    p.set_defaults(fn=cmd_linuxguard)
    return p
