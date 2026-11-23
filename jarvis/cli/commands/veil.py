"""Pair a deliberately opt-in browser sensor with local JARVIS Veil."""

import secrets

from jarvis.core.veil import TOKEN_KEY


def cmd_veil(args, store):
    if args.action == "pair":
        token = secrets.token_urlsafe(32)
        store.set_meta(TOKEN_KEY, token)
        print("JARVIS Veil pairing token (keep this private):")
        print(token)
        print("Paste it into the unpacked JARVIS Veil extension. It sends only "
              "coarse local metadata to the loopback dashboard; it does not enable blocking.")
        return 0
    configured = bool(store.get_meta(TOKEN_KEY))
    print("Veil browser sensor: " + ("paired" if configured else "not paired"))
    print("Current release is observe-only; browser enforcement requires separately "
          "validated native browser controls or narrowly scoped user rules.")
    return 0


def add_parser(sub):
    p = sub.add_parser("veil", help="browser privacy sensor pairing and status")
    p.add_argument("action", nargs="?", choices=("status", "pair"), default="status")
    p.set_defaults(fn=cmd_veil)
    return p
