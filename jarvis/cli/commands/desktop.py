"""Paired API clients: the desktop app, the CLI, supervisors and scrapers.

    jarvis desktop pair --name NAME [--out FILE]   issue a client token (shown once)
    jarvis desktop clients                         list paired clients
    jarvis desktop revoke ID                       revoke one client
    jarvis desktop save [--out FILE]               store a token read from stdin, 0600
    jarvis desktop browser [--page P] [--no-open]  open the dashboard in a browser that pairs itself

`pair`, `clients` and `revoke` change the daemon's store, so they run where it is
writable: as the daemon's account once it has one (`sudo jarvis-svc desktop pair ...`).
"""

import sys
import time
import urllib.error

from jarvis.web import apiclient, clients

# Pages a browser link may lead to (desktop/src/api.rs page_path keeps the same list).
BROWSER_PAGES = {"dashboard": "/ui/", "coverage": "/coverage", "procs": "/procs",
                 "world": "/world", "geo": "/geo"}


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def browser_url(port, path, code):
    """The one-time link: the code in the fragment, never in what reaches a server."""
    return f"http://127.0.0.1:{int(port)}/pair?next={path}#code={code}"


def cmd_browser(args, opener=None):
    """Ask the running daemon for a one-time pairing link and open it."""
    path = BROWSER_PAGES[args.page]
    try:
        status, body = apiclient.request("POST", "/api/session/link", port=args.port, body={})
    except apiclient.Unpaired as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"could not reach ARGUS-INSTINCT on port {args.port} ({exc}); is it running?", file=sys.stderr)
        return 1
    code = (body or {}).get("code") if status == 200 else None
    if not (isinstance(code, str) and clients._LINK_RE.match(code)):
        why = (body or {}).get("error") or f"HTTP {status}"
        print(f"ARGUS-INSTINCT would not give a pairing link ({why})", file=sys.stderr)
        return 1
    url = browser_url(args.port, path, code)
    ttl = int((body or {}).get("expires_in") or clients.LINK_TTL_S)
    print(f"Open this within {ttl} seconds; it works once and pairs that browser:", file=sys.stderr)
    print(url)
    if not args.no_open:
        import webbrowser
        try:
            (opener or webbrowser.open)(url)
        except Exception:  # no browser here (a server): the printed link still works
            pass
    return 0


def cmd_desktop(args, store):
    if args.action == "browser":
        return cmd_browser(args)
    if args.action == "save":
        value = sys.stdin.readline().strip()
        path = args.out or apiclient.client_token_path()
        try:
            apiclient.save_private(path, value)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"saved to {path} (owner-only)")
        return 0
    if store is None:
        print("this needs the daemon's store", file=sys.stderr)
        return 2
    if args.action == "pair":
        try:
            cid, token = clients.pair(store, args.name or "")
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.out:
            apiclient.save_private(args.out, token)
            print(f"paired client {cid} ({args.name}); token written to {args.out} (owner-only)",
                  file=sys.stderr)
            return 0
        # The token alone on stdout, so it can be piped to `jarvis desktop save`
        # or pasted into the /pair page; the explanation goes to stderr.
        print(f"paired client {cid} ({args.name}). Token below, shown once; keep it private. "
              f"Revoke with: jarvis desktop revoke {cid}", file=sys.stderr)
        print(token)
        return 0
    if args.action == "revoke":
        if not args.id:
            print("which client? jarvis desktop revoke ID", file=sys.stderr)
            return 2
        if clients.revoke(store, args.id):
            print(f"revoked {args.id}; it is refused from now on")
            return 0
        print(f"no active client {args.id}", file=sys.stderr)
        return 1
    rows = clients.listing(store)
    if not rows:
        print("no paired clients")
        return 0
    for r in rows:
        state = f"revoked {_when(r['revoked_at'])}" if r.get("revoked_at") else "active"
        print(f"  {r['id']}  {r['name']:<20} paired {_when(r['created_at'])}  {state}")
    return 0


def add_parser(sub):
    p = sub.add_parser("desktop", help="pair, list and revoke API clients (desktop app, CLI, probes)")
    p.add_argument("action", nargs="?", default="clients",
                   choices=("pair", "clients", "revoke", "save", "browser"))
    p.add_argument("id", nargs="?", help="client id (revoke)")
    p.add_argument("--name", help="what this client is, e.g. desktop, cli, prometheus")
    p.add_argument("--out", help="write the token to this file, owner-only, instead of printing it")
    p.add_argument("--page", choices=sorted(BROWSER_PAGES), default="dashboard", help="page to open (browser)")
    p.add_argument("--port", type=int, default=8787, help="port of the running daemon (browser)")
    p.add_argument("--no-open", action="store_true", help="print the one-time link instead of opening it (browser)")
    p.set_defaults(fn=cmd_desktop)
    return p
