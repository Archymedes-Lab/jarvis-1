"""`jarvis capsule`, `jarvis provenance` and `jarvis release`.

See docs/architecture/EVIDENCE-FABRIC.md. Provenance is attribution, never
permission: nothing here lowers a finding or authorizes an action.
"""

import argparse
import json
import os
import sys

from jarvis.core.paths import REPO_ROOT, SOURCE_ROOT


def _capsule(args, _store):
    from jarvis.platform.provenance import capsule, identity
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        status = capsule.run(args.actor, command, session=args.session,
                             capabilities=args.capability or (), purpose=args.purpose or "",
                             ttl_s=args.ttl)
    except identity.ProvenanceError as exc:
        print(f"jarvis capsule: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    raise SystemExit(status if status >= 0 else 128 - status)


def _provenance(args, _store):
    from jarvis.platform.provenance import authority, identity, persistence, release
    if args.action == "who":
        stat = identity.proc_stat(args.pid)
        found = identity.attribute(args.pid)
        out = {"pid": args.pid, "alive": bool(stat),
               "provenance": found.as_dict() if found else None,
               "meaning": "attribution only; None means no provenance, not benign"}
    elif args.action == "persistence":
        out = persistence.manifest(args.local_app_data, REPO_ROOT, SOURCE_ROOT)
    else:
        manifest = release.read_manifest(REPO_ROOT)
        try:
            rid = release.manifest_release_id(manifest) if manifest else None
        except ValueError as exc:
            rid = f"inconsistent: {exc}"
        public = identity.load_public_key()
        index = identity.default_index()
        index.get(0, 0)                      # load, to count rejected rows
        out = {"release_id": rid, "code_root": str(REPO_ROOT), "checkout": str(SOURCE_ROOT),
               "public_key": identity.key_id(public) if public else None,
               "authority_socket": authority.SOCKET.exists(),
               "ledger": str(identity.LEDGER), "ledger_rows_rejected": index.rejected,
               "issuance": "possible only inside the sealed daemon"}
    print(json.dumps(out, indent=1))


def _release(args, _store):
    from jarvis.platform.provenance import stage
    try:
        info = stage.stage(args.file or (), args.remove or (), checkout=SOURCE_ROOT)
    except (stage.StageError, OSError) as exc:
        print(f"jarvis release stage: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    print(f"staged {info['stage']}\n  on base {info['base_release_id']}")
    for kind in ("changed", "added", "removed"):
        if info[kind]:
            print(f"  {kind}: " + ", ".join(info[kind]))
    print("\nReview the staged tree, then deploy it (refuses if the live release moved):\n  "
          + " ".join(info["deploy"]))


def add_parser(sub):
    c = sub.add_parser("capsule", help="run an agent or test session as one attributable tree")
    c_act = c.add_subparsers(dest="action", required=True)
    r = c_act.add_parser("run", help="run a command inside a capsule")
    r.add_argument("--actor", required=True, choices=("claude", "codex", "test_suite", "user"))
    r.add_argument("--session", help="session name (default: timestamp)")
    r.add_argument("--capability", action="append", metavar="NAME",
                   help="declared capability (recorded, not yet enforced; repeatable)")
    r.add_argument("--purpose", help="short description recorded in the identity")
    r.add_argument("--ttl", type=int, default=4 * 3600, help="identity lifetime in seconds")
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(fn=_capsule)

    p = sub.add_parser("provenance", help="execution identities and managed persistence")
    p_act = p.add_subparsers(dest="action", required=True)
    p_act.add_parser("status", help="release identity, key and ledger state")
    w = p_act.add_parser("who", help="which verified identity a live process belongs to")
    w.add_argument("pid", type=int)
    m = p_act.add_parser("persistence", help="expected state of JARVIS-managed tasks")
    m.add_argument("--local-app-data", default=os.environ.get(
        "JARVIS_LOCALAPPDATA", r"C:\Users\<user>\AppData\Local"))
    p.set_defaults(fn=_provenance)

    s = sub.add_parser("release", help="stage a narrow release for the root deploy")
    s_act = s.add_subparsers(dest="action", required=True)
    st = s_act.add_parser("stage", help="live sealed release + named reviewed files")
    st.add_argument("--file", action="append", metavar="PATH",
                    help="checkout-relative reviewed file to include (repeatable)")
    st.add_argument("--remove", action="append", metavar="PATH",
                    help="release file to drop (repeatable)")
    s.set_defaults(fn=_release)
