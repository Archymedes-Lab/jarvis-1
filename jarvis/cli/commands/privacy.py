"""`jarvis privacy` — read, seal and unseal the microphone and camera surface.

    jarvis privacy status            seal state, latest posture sample, history
    jarvis privacy seal [--mic] [--camera] [--yes]
                                     deny microphone/camera access to every app
                                     in your Windows account; reversible
    jarvis privacy unseal            restore the values recorded at seal time
    jarvis privacy audit [--json]    run the posture collector once, now

Sealing closes the Windows consent gate: calls, voice chat, dictation and
camera apps lose the device until you unseal. It is your explicit action,
never automatic, and the previous values are kept so unseal restores exactly
them. The gate is user-mode: a kernel-level capture, a driver or an
administrator editing the registry are seen as drift, not stopped.
"""
import json
import sys

from jarvis.cli.output import render_findings
from jarvis.collectors.host import privacyseal


def _confirm(args, caps):
    labels = ", ".join(privacyseal.LABEL[c] for c in caps)
    print(f"This denies {labels} access to every Store and desktop app in your "
          "Windows account until you run: jarvis privacy unseal")
    print("Calls and voice apps will not hear you while sealed.")
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print("refusing without --yes on a non-interactive terminal")
        return False
    return input("Seal now? [y/N] ").strip().lower() in ("y", "yes")


def _cmd_seal(args, store):
    caps = tuple(c for c, wanted in (("microphone", args.mic), ("webcam", args.camera))
                 if wanted) or privacyseal.SEALABLE
    if not _confirm(args, caps):
        return 1
    try:
        record = privacyseal.seal(store, caps)
    except privacyseal.SealError as exc:
        print(f"seal not applied: {exc}")
        return 1
    sealed = ", ".join(privacyseal.LABEL[c] for c in sorted(record["caps"]))
    print(f"sealed: {sealed} read back as Deny (global and desktop apps)")
    print("previous values recorded; undo with: jarvis privacy unseal")
    print("the privacy collector now reports any reopening as high within five minutes")
    return 0


def _cmd_unseal(args, store):
    try:
        restored = privacyseal.unseal(store)
    except privacyseal.SealError as exc:
        print(f"unseal not applied: {exc}")
        return 1
    for cap, value in sorted(restored.items()):
        print(f"restored {privacyseal.LABEL[cap]}: {value}")
    return 0


def _cmd_status(args, store):
    state = privacyseal.status(store)
    if args.json:
        print(json.dumps(state, indent=2))
        return 0
    seal = state["seal"]
    if seal:
        caps = ", ".join(privacyseal.LABEL.get(c, c) for c in sorted(seal["caps"]))
        print(f"seal declared: {caps} denied since {privacyseal._stamp(seal)}")
    else:
        print("no seal declared; microphone and camera follow your Windows settings")
    latest = state["latest"]
    if latest:
        for cap in privacyseal.SEALABLE:
            glob, desktop = privacyseal._effective(latest["caps"][cap])
            print(f"  {privacyseal.LABEL[cap]:11} global={glob or 'unset'} "
                  f"desktop apps={desktop or 'unset'}")
    else:
        print("  no posture sample yet (the privacy collector has not run)")
    for event in state["history"]:
        print(f"  {event.get('event'):7} at {event.get('ts'):.0f}")
    return 0


def _cmd_audit(args, store):
    findings = privacyseal.audit(store, hosts=("win",))
    if args.json:
        print(json.dumps(findings, indent=2))
        return 0
    render_findings(findings, show_ok=True, empty="no posture returned")
    return 0


def cmd_privacy(args, store):
    return {"seal": _cmd_seal, "unseal": _cmd_unseal, "audit": _cmd_audit,
            "status": _cmd_status}[args.action](args, store)


def add_parser(sub):
    p = sub.add_parser("privacy", help="seal or inspect microphone and camera access")
    p.add_argument("action", nargs="?", default="status",
                   choices=["status", "seal", "unseal", "audit"])
    p.add_argument("--mic", action="store_true", help="seal: microphone only")
    p.add_argument("--camera", action="store_true", help="seal: camera only")
    p.add_argument("--yes", action="store_true", help="seal: skip the confirmation")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_privacy)
    return p
