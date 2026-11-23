"""`jarvis brief` — JARVIS's protocols for securing this machine.

    jarvis brief                 the one thing JARVIS would raise with you now
    jarvis brief list            every protocol, its state and what it earns
    jarvis brief show <id>       the full briefing and steps
    jarvis brief yes|no [<id>]   answer the question JARVIS is waiting on
    jarvis brief check [<id>]    have the daemon re-run the verifying collectors
    jarvis brief email           mail yourself the full action plan, personalised
"""

import time
import urllib.error
import urllib.request

from jarvis.response import alert, protocols
from jarvis.response.reporting import emails
from jarvis.service.schedule import JOBS

from ..output import color, is_tty

CHECK_TIMEOUT = 300


def _print(item, full=True):
    lines = protocols.render(item, full)
    print(color(lines[0], "bold", is_tty()))
    for line in lines[1:]:
        print(line)


def _find(store, protocol_id):
    items = protocols.evaluate(store, JOBS)
    if not protocol_id:
        return protocols.next_briefing(store, JOBS), items
    return next((i for i in items if i["protocol"].id == protocol_id), None), items


def _check(store, item, port):
    """Ask the running daemon to re-observe, then wait for fresh snapshots."""
    jobs = item["protocol"].jobs
    started = time.time()          # compared with snapshot timestamps (wall clock)
    waited_from = time.monotonic()  # bounds the wait; the wall clock can step here
    for job in jobs:
        from urllib.parse import quote

        from jarvis.web import apiclient
        try:
            status, body = apiclient.request("POST", f"/api/run?job={quote(job)}", port=port,
                                             body={})
            if status != 200 or not (body or {}).get("queued"):
                print(f"the daemon would not queue {job} (HTTP {status})")
                return 1
        except apiclient.Unpaired as exc:
            print(str(exc))
            return 1
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"could not reach jarvis serve on port {port} ({exc}); is the daemon running?")
            return 1
    print(f"re-running {', '.join(jobs)} — this takes a minute or two", flush=True)
    while time.monotonic() - waited_from < CHECK_TIMEOUT:
        snapshots = store.get_snapshots()
        if all(int((snapshots.get(job) or {}).get("ts") or 0) >= started for job in jobs):
            refreshed, _ = _find(store, item["protocol"].id)
            _print(refreshed)
            return 0 if refreshed["state"] == protocols.DONE else 2
        time.sleep(5)
    print("the collectors have not reported back yet; try again shortly")
    return 1


def cmd_brief(args, store):
    action, target = args.action, args.id
    if action in ("yes", "no"):
        item, _ = _find(store, target)
        if not item:
            print("nothing is waiting on an answer")
            return 1
        ok, message = protocols.answer(store, item["protocol"].id, action)
        print(message)
        return 0 if ok else 1

    if action == "email":
        conf = alert.load_conf()
        if not alert.email_enabled(conf):
            print("email is not configured (see alert settings in ~/.jarvis/config.json)")
            return 1
        print("composing the action plan — the local model writes the notes, "
              "this can take a minute", flush=True)
        err, subject, personalized = emails.action_plan_email(store, conf, JOBS)
        if err:
            print(f"not sent: {err}")
            return 1
        print(f"sent: {subject}  ({personalized} line(s) personalised by the local model)")
        return 0

    if action == "list":
        for item in protocols.evaluate(store, JOBS):
            p = item["protocol"]
            gain = item["score_after"] - item["score_now"]
            print(f"  {p.id:18} {item['state']:10} {p.title}"
                  + (f"  (+{gain} score)" if gain > 0 else ""))
        now_score, after = protocols.projected_all(store, JOBS)
        if after > now_score:
            print(f"\nAll of them together: security score {now_score}% → {after}%.")
        return 0

    item, _ = _find(store, target)
    if action in ("show", "check") and target and not item:
        print(f"no protocol named {target}; see jarvis brief list")
        return 1
    if action == "check":
        if not item:
            print("no protocol is open; nothing to check")
            return 0
        return _check(store, item, args.port)
    if not item:
        print("No protocol needs you right now — well done. I shall go looking for the next small victory.")
        return 0
    _print(item, full=True)
    return 0


def add_parser(sub):
    p = sub.add_parser("brief", help="JARVIS's step-by-step protocols for securing this machine")
    p.add_argument("action", nargs="?", default="next",
                   choices=["next", "list", "show", "yes", "no", "check", "email"])
    p.add_argument("id", nargs="?", help="protocol id (default: the one JARVIS raises now)")
    p.add_argument("--port", type=int, default=8787, help="port of the running jarvis serve")
    p.set_defaults(fn=cmd_brief)
    return p
