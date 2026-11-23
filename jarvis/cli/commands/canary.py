"""`jarvis canary` — plant, list and retire canary tokens; see coverage.

    jarvis canary status                  armed tokens, trips, coverage, listener
    jarvis canary list [--json]           every token in the journal
    jarvis canary plant file_decoy LABEL --path FILE
                                          watch a decoy file you wrote yourself
    jarvis canary plant doc_url LABEL [--url-base URL]
                                          a tracking URL on a host YOU control
    jarvis canary plant credential LABEL  a fake key to place as bait
    jarvis canary retire TOKEN_ID         stop watching a token (kept in history)
    jarvis canary notice                  a monitoring notice that names nothing
    jarvis canary verify                  check the journal's hash chain

A decoy is something you create and place; JARVIS records it and watches it. It
never writes to a planted decoy, never contacts anyone, and a doc_url points only
at a host you configured (canary.url_base). Keep decoy locations to yourself:
the bait works because an intruder cannot tell it from the real thing.
"""

import json

from jarvis.collectors.host import canary as canary_job
from jarvis.core import canary


def _root():
    # Read at call time, so a test can point the CLI at a temporary journal.
    return canary.DEFAULT_ROOT


def _conf():
    from jarvis.response import alert
    return (alert.load_conf() or {}).get("canary", {}) or {}


def _cmd_plant(args):
    if not args.rest:
        print("usage: jarvis canary plant KIND LABEL [--path FILE | --url-base URL]")
        return 1
    kind, label = args.rest[0], " ".join(args.rest[1:]) or args.rest[0]
    try:
        token = canary.plant(kind, label, path=args.path, root=_root(),
                             url_base=args.url_base or _conf().get("url_base"))
    except canary.CanaryError as exc:
        print(f"not planted: {exc}")
        return 1
    print(f"planted {token['kind']} {token['id']} ({token['label']})")
    if token.get("url"):
        print(f"  embed this URL in the bait document: {token['url']}")
    if token.get("bait_value"):
        # Shown once: the journal keeps only its fingerprint.
        print(f"  place this fake key as bait (shown once): {token['bait_value']}")
    if token.get("bait_hint"):
        print(f"  {token['bait_hint']}")
    return 0


def _cmd_list(args):
    state = canary.CanaryJournal(_root()).state()
    rows = []
    for tid, token in sorted(state["tokens"].items(),
                             key=lambda kv: kv[1].get("created_at", 0)):
        rows.append({"id": tid, "kind": token.get("kind"), "label": token.get("label"),
                     "where": token.get("path") or token.get("url") or "",
                     "active": tid in state["active"],
                     "tripped": sorted(state["tripped"].get(tid, ())),
                     "callbacks": len(state["callbacks"].get(tid, ()))})
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no canary tokens planted")
    for r in rows:
        flag = ("TRIPPED " + ",".join(r["tripped"]) if r["tripped"] else
                f"{r['callbacks']} CALLBACK(S)" if r["callbacks"] else
                "armed" if r["active"] else "retired")
        print(f"{r['id']}  {r['kind']:<10} {flag:<20} {r['label']}  {r['where']}")
    return 0


def _cmd_status(args, store):
    conf = _conf()
    journal = canary.CanaryJournal(_root())
    broken = journal.verify()
    state = journal.state()
    gaps = canary.coverage_gaps(conf.get("protect"), state["active"])
    listener = canary.listener_state(conf.get("callback_inbox"),
                                     conf.get("listener_heartbeat"),
                                     max_age=int(conf.get("listener_max_age", 900)))
    last = canary_job._summary(store) or {}
    out = {"chain_ok": broken is None, "broken": broken, "head": journal.head(),
           "active": len(state["active"]), "tripped": sorted(state["tripped"]),
           "callbacks": sorted(state["callbacks"]),
           "coverage_gaps": [g["class"] for g in gaps],
           "listener": listener, "last_run": last.get("at"),
           "last_anchor": last.get("last_anchor")}
    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0
    print(f"journal: {'verifies' if broken is None else 'BROKEN ' + json.dumps(broken)}"
          f" (head seq {out['head']['seq']})")
    print(f"armed: {out['active']}  tripped: {len(out['tripped'])}  "
          f"opened off-box: {len(out['callbacks'])}")
    print("coverage: " + ("every protected class has bait" if conf.get("protect") and not gaps
                          else "no protected classes configured (canary.protect)"
                          if not conf.get("protect")
                          else "MISSING bait for " + ", ".join(out["coverage_gaps"])))
    print(f"listener: {listener['status']} ({listener['detail']})")
    anchor = out["last_anchor"]
    print("last anchor: " + (f"{anchor.get('digest', '')[:16]}… at {anchor.get('at')}"
                             if anchor else "none yet"))
    return 0 if broken is None else 1


def cmd_canary(args, store):
    if args.action == "plant":
        return _cmd_plant(args)
    if args.action == "list":
        return _cmd_list(args)
    if args.action == "retire":
        if not args.rest:
            print("usage: jarvis canary retire TOKEN_ID")
            return 1
        canary.retire(args.rest[0], root=_root())
        print(f"retired {args.rest[0]}; its history stays in the journal")
        return 0
    if args.action == "notice":
        print(canary.NOTICE)
        return 0
    if args.action == "verify":
        broken = canary.CanaryJournal(_root()).verify()
        print("journal verifies" if broken is None else "journal BROKEN: " + json.dumps(broken))
        return 0 if broken is None else 1
    return _cmd_status(args, store)


def add_parser(sub):
    p = sub.add_parser("canary", help="canary tokens: plant decoys and watch them")
    p.add_argument("action", nargs="?", default="status",
                   choices=["status", "list", "plant", "retire", "notice", "verify"])
    p.add_argument("rest", nargs="*", help="plant: KIND LABEL · retire: TOKEN_ID")
    p.add_argument("--path", help="plant file_decoy: the decoy file you created")
    p.add_argument("--url-base", help="plant doc_url: a URL base on a host you control")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_canary)
    return p
