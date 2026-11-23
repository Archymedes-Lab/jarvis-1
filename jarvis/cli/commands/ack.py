"""`jarvis ack` — confirm a finding as expected, so it stops counting against you.

    jarvis ack                          open findings that need you, with their ids
    jarvis ack <id> --reason "…"        confirm one (90 days unless --days)
    jarvis ack list                     every confirmation and when it expires
    jarvis ack --revoke <id>            take a confirmation back
"""

import time

from jarvis.core.util import iso
from jarvis.response import acknowledge
from jarvis.response.reporting import triage

from ..output import color, is_tty, typed_confirmation


def cmd_ack(args, store):
    t = is_tty()
    now = int(time.time())
    if args.revoke:
        entry = acknowledge.revoke(store, args.revoke)
        print(f"revoked {args.revoke}: {entry['title']}" if entry
              else f"no confirmation with id {args.revoke}")
        return 0 if entry else 1

    if args.target == "list":
        acks = acknowledge.load(store)
        if not acks:
            print("nothing confirmed")
            return 0
        for fid, e in sorted(acks.items(), key=lambda kv: kv[1].get("expires", 0)):
            state = "expired" if e.get("expires", 0) <= now else f"until {iso(e['expires'])}"
            sev = e.get("severity") or "low"
            print(f"{fid}  {color(f' {sev.upper():8} ', sev, t)} "
                  f"{e.get('title', '')}  ({e.get('job')}, {state})")
            print(f"          reason: {e.get('reason', '')}")
            if acknowledge.awaiting_confirmation(e) and e.get("expires", 0) > now:
                print("          NOT APPLYING: a critical finding must be confirmed at a terminal; "
                      f'run  jarvis ack {fid} --reason "..."  again')
        return 0

    snapshots = store.get_snapshots()
    if args.target:
        hit = acknowledge.resolve(snapshots, args.target)
        if not hit:
            print(f"no current finding has id {args.target} (ids change if the finding changes)")
            return 1
        finding, job = hit
        confirmed_by = None
        if acknowledge.needs_confirmation(finding) and acknowledge.can_acknowledge(finding) \
                and (args.reason or "").strip():
            what = (f"CRITICAL: {finding.get('title', '')} ({job})\n"
                    "Confirming it as expected stops alerts about it and lowers what it costs the score.")
            if not typed_confirmation(args.target, what):
                print("not confirmed: a critical finding can only be confirmed by typing its id "
                      "at an interactive terminal")
                return 2
            confirmed_by = acknowledge.TERMINAL
        try:
            fid, entry = acknowledge.acknowledge(store, finding, job, args.reason, args.days, now,
                                                 confirmed_by=confirmed_by)
        except ValueError as exc:
            print(f"not confirmed: {exc}")
            return 2
        print(f"confirmed {fid}: {entry['title']} ({job}) until {iso(entry['expires'])}")
        print("it no longer counts against the security score; if it comes back at a worse "
              "severity, the confirmation stops applying")
        return 0

    acks = acknowledge.load(store)
    items = triage.current(snapshots, levels=("critical", "high", "medium"), acks=acks, now=now)
    grouped = {owner: [] for owner in triage.ORDER}
    for finding, job in items:
        r = triage.classify(finding, job)
        grouped[r["owner"]].append((finding, job, r))
    shown = 0
    for owner in (triage.YOU_CONFIRM, triage.YOU_DO):
        unique = {}
        for entry in grouped[owner]:
            unique.setdefault(entry[2]["id"], entry)
        entries = list(unique.values())
        if not entries:
            continue
        print(color(f"\n{triage.LABEL[owner]} ({len(entries)})", "bold", t))
        for finding, job, r in entries[:40]:
            sev = finding.get("severity", "?")
            print(f"  {r['id']}  {color(f' {sev.upper():8} ', sev, t)} {finding.get('title', '')}  ({job})")
            shown += 1
    if not shown:
        print("nothing needs you")
    else:
        print('\nconfirm one with: jarvis ack <id> --reason "why this is expected"')
    return 0


def add_parser(sub):
    p = sub.add_parser("ack", help="confirm a finding as expected so it stops counting against you")
    p.add_argument("target", nargs="?", help="a finding id, or 'list'")
    p.add_argument("--reason", default="", help="why this finding is expected (required to confirm)")
    p.add_argument("--days", type=int, default=acknowledge.DEFAULT_DAYS,
                   help=f"how long the confirmation holds (default {acknowledge.DEFAULT_DAYS})")
    p.add_argument("--revoke", metavar="ID", help="take back a confirmation")
    p.set_defaults(fn=cmd_ack)
    return p
