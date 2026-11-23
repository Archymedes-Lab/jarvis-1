"""Outdated software on every package manager, and installing the fixes.

    update plan [--all] [--json]   what is outdated, important first (reads only)
    update apply [--important] [--manager M ...] [--only ID ...] [--yes-i-am-here]
                                   install, one at a time, then verify
    update log                     what was updated, by whom, verified or not
    update revert ID               put a winget program back to its recorded version
    update auto [off|notify|important|all]   show or set the automatic policy

apply asks for a typed confirmation at a terminal: installing software is the
owner's decision, and the list it confirms is the list that runs. apt and snap
items go through sudo (its password prompt); machine-scope winget and
Chocolatey installers show Windows' own administrator prompt.
"""

import json
import os
import sys
import time

from jarvis.collectors.host import updates
from jarvis.response import alert, updater


def _plan(store):
    print("  listing outdated packages (about a minute: winget and Chocolatey are slow) ...", flush=True)
    p = updates.plan()
    store.set_meta(updates.STATE_META, json.dumps(p, sort_keys=True)[:200_000])
    return p


def _rows(items):
    for i in items:
        flags = ("important" if i["important"] else "routine") + (
            ", security" if i["security"] else "") + (", needs admin" if i["needs_admin"] else "") + (
            ", pinned" if i["pinned"] else "")
        print(f"  {i['manager']:<7} {i['id'][:38]:<38} {str(i['installed'])[:16]:>16} -> "
              f"{str(i['available'])[:16]:<16} {flags}")


def _ordered(items):
    return sorted(items, key=lambda i: (not i["important"], i["manager"], i["id"].lower()))


def cmd_plan(args, store):
    p = _plan(store)
    if args.json:
        print(json.dumps(p, indent=1, sort_keys=True))
        return
    pol = updates.policy(alert.load_conf())
    for name, err in sorted(p["failed"].items()):
        print(f"  ! {name}: could not be listed ({err})")
    items = _ordered(p["items"])
    if not args.all:
        shown = [i for i in items if i["important"]]
        hidden = len(items) - len(shown)
    else:
        shown, hidden = items, 0
    if not items:
        print(f"  nothing outdated in: {', '.join(p['managers']) or 'no package manager found'}")
        return
    _rows(shown)
    if hidden:
        print(f"  ... and {hidden} routine update(s); `jarvis update plan --all` lists them")
    auto = [i for i in items if updates.auto_eligible(i, pol)]
    print(f"\n  automatic policy: {pol['mode']}" + (f"; {len(auto)} of these update by themselves" if auto else ""))
    print("  install: jarvis update apply            (important only: --important)")


def _select(p, args):
    items = [i for i in p["items"] if not i["pinned"]]
    if args.important:
        items = [i for i in items if i["important"]]
    if args.manager:
        items = [i for i in items if i["manager"] in set(args.manager)]
    if args.only:
        wanted = {x.lower() for x in args.only}
        items = [i for i in items if i["id"].lower() in wanted or i["name"].lower() in wanted]
    return _ordered(items)


def _cli_runners():
    def linux(argv, timeout):
        if argv[0] in ("apt-get", "snap") and os.geteuid() != 0:
            argv = ["sudo", *argv]
        return updater._run_linux(argv, timeout)
    return {"linux": linux, "ps": updater._run_ps}


def cmd_apply(args, store):
    if not sys.stdin.isatty():
        # No flag skips this: installing software is confirmed by a person at
        # a terminal, never by a script or a model driving one.
        sys.exit("update apply needs a terminal: installing software is confirmed by you, not by a script")
    p = _plan(store)
    items = _select(p, args)
    if not items:
        print("  nothing to install with these filters")
        return
    _rows(items)
    print(f"\n  {len(items)} update(s). Windows may show administrator prompts; sudo may ask for your password.")
    if not args.yes_i_am_here:
        answer = input("  Type 'update' to install exactly these: ")
        if answer.strip().lower() != "update":
            sys.exit("  nothing installed")

    def progress(row):
        state = "done" if row["exit"] == 0 else f"exit {row['exit']}"
        print(f"  {row['manager']:<7} {row['id'][:38]:<38} {state} ({row['seconds']} s)", flush=True)

    result = updater.apply(items, "owner", runners=_cli_runners(), on_item=progress)
    ok = [r for r in result["results"] if r["verified"]]
    bad = [r for r in result["results"] if not r["verified"]]
    print(f"\n  verified by a fresh listing: {len(ok)} updated, {len(bad)} not")
    for r in bad:
        print(f"    {r['manager']} {r['id']}: {r.get('error')}")
    store.set_meta(updates.STATE_META, json.dumps(result["plan"], sort_keys=True)[:200_000])
    if bad:
        sys.exit(1)


def cmd_log(args, store):
    rows = updater.read_log(limit=args.limit)
    if not rows:
        print("  no updates recorded yet")
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("at", 0)))
        state = "verified" if r.get("verified") else f"NOT verified ({r.get('error') or '?'})"
        print(f"  {when} {r.get('actor'):<5} {r.get('manager'):<7} {r.get('id', '')[:34]:<34} "
              f"{r.get('from')} -> {r.get('to')}  {state}")


def cmd_revert(args, store):
    rows = [r for r in updater.read_log(limit=2000)
            if r.get("id", "").lower() == args.id.lower() and r.get("verified")]
    if not rows:
        sys.exit(f"  no verified update of {args.id} on record")
    last = rows[-1]
    try:
        kind, script = updater.revert_command(last)
    except ValueError as exc:
        sys.exit(f"  {exc}")
    if not sys.stdin.isatty():
        sys.exit("update revert needs a terminal")
    if input(f"  Put {last['name']} back to {last['from']} (it is a known-older version)? Type 'revert': "
             ).strip().lower() != "revert":
        sys.exit("  nothing changed")
    code, tail = updater._run_ps(script, updater.ITEM_TIMEOUT_S)
    updater._append([{"at": time.time(), "actor": "owner", "manager": "winget", "id": last["id"],
                      "name": last["name"], "from": last["to"], "to": last["from"], "revert": True,
                      "exit": code, "tail": tail[-400:], "verified": code == 0}])
    print("  reverted" if code == 0 else f"  revert failed (exit {code}): {tail.splitlines()[-1] if tail else ''}")


def cmd_auto(args, store):
    from jarvis.response import alert as alert_mod
    conf = alert_mod.load_conf()
    if not args.mode:
        pol = updates.policy(conf)
        print(f"  auto_update = {pol['mode']}; excluded: {', '.join(sorted(pol['exclude'])) or 'none'}")
        print("  off: nothing; notify: tell you; important: also install important user-scope updates;"
              " all: every user-scope update. Never anything that needs administrator rights.")
        return
    path = alert_mod.CONFIG_PATH
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        doc = {}
    doc["auto_update"] = args.mode
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    print(f"  auto_update = {args.mode} (takes effect at the next `updates` run, within 6 hours)")


def add_parser(sub):
    p = sub.add_parser("update", help="outdated software on every package manager; install fixes")
    s = p.add_subparsers(dest="update_cmd", required=True)
    pp = s.add_parser("plan", help="what is outdated, important first")
    pp.add_argument("--all", action="store_true", help="include routine updates")
    pp.add_argument("--json", action="store_true")
    pp.set_defaults(fn=cmd_plan)
    ap = s.add_parser("apply", help="install updates you confirm, then verify them")
    ap.add_argument("--important", action="store_true", help="only important updates")
    ap.add_argument("--manager", action="append", choices=["apt", "snap", "brew", "winget", "choco"])
    ap.add_argument("--only", action="append", metavar="ID", help="only this package (repeatable)")
    ap.add_argument("--yes-i-am-here", action="store_true",
                    help="skip the typed confirmation (you are at the terminal and read the list)")
    ap.set_defaults(fn=cmd_apply)
    lp = s.add_parser("log", help="what was updated and whether it was verified")
    lp.add_argument("--limit", type=int, default=50)
    lp.set_defaults(fn=cmd_log)
    rp = s.add_parser("revert", help="put a winget program back to its recorded version")
    rp.add_argument("id")
    rp.set_defaults(fn=cmd_revert)
    up = s.add_parser("auto", help="show or set the automatic update policy")
    up.add_argument("mode", nargs="?", choices=list(updates.MODES))
    up.set_defaults(fn=cmd_auto)
