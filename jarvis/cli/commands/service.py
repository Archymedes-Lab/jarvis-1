"""Subcommands that drive the daemon and its notifications."""

import json
import sys
import time

from jarvis.collectors.persistence import control
from jarvis.collectors.process import monitor
from jarvis.core.util import iso
from jarvis.platform import windows as collect_windows
from jarvis.response import acknowledge, alert, fixit
from jarvis.response.reporting import score
from jarvis.service import selfcheck, supervisors
from jarvis.service.schedule import JOBS

from ..output import color, is_tty, print_process_finding, selected_hosts


def cmd_watch(args, store):
    print(f"Watching every {args.interval}s — Ctrl-C to stop.  "
          f"(hosts: {'+'.join(selected_hosts(args))})")
    if args.interval < 30 and "win" in selected_hosts(args):
        print(color("  note: Windows collection takes a few seconds per pass; "
                    "intervals under 30s will lag.", "dim", is_tty()))
    try:
        while True:
            res = monitor.scan(store, hosts=selected_hosts(args), enrich=args.enrich)
            alerts = [f for f in res["findings"]
                      if monitor.SEV_ORDER[f["severity"]] <= 2]  # medium and worse
            if alerts or res["new_public_peers"]:
                print("\n" + monitor.summarize(res))
                for f in alerts[: args.limit]:
                    print_process_finding(f)
                for p in res["new_public_peers"][:10]:
                    print(f"          new peer {p['ip']}:{p['port']} ← "
                          f"{p['proc']['name']}")
            elif args.verbose:
                print(monitor.summarize(res))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")


def cmd_control(args, store):
    print(f"Auditing control surfaces on {'+'.join(selected_hosts(args))}…\n")
    findings = control.audit(hosts=selected_hosts(args))

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    if args.category:
        findings = [f for f in findings if f["category"] == args.category]
    if args.severity:
        keep = control.SEV_ORDER[args.severity]
        findings = [f for f in findings if control.SEV_ORDER[f["severity"]] <= keep]

    t = is_tty()
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    last_cat = None
    for f in findings:
        if f["category"] != last_cat:
            titles = {
                "persistence": "PERSISTENCE — things arranged to run without you",
                "remote": "REMOTE CONTROL — ways in from outside",
                "defense": "DEFENSES — the state of the controls themselves",
            }
            print(f"\n{color(titles.get(f['category'], f['category']), 'bold', t)}")
            last_cat = f["category"]
        tag = color(f" {f['severity'][:4].upper():4} ", f["severity"], t)
        print(f"  {tag} [{f['host']}] {f['title']}: {f['detail']}")
        if args.verbose and f["where"]:
            print(f"          {color(f['where'], 'dim', t)}")
        fix = fixit.suggest(f)
        if fix:
            print(f"          {color('fix: ' + fix, 'ok', t)}")

    tally = "  ".join(f"{k}={counts[k]}" for k in
                      ("critical", "high", "medium", "low") if k in counts)
    print(f"\n{len(findings)} findings   {tally or 'none'}")
    if not args.verbose:
        print(color("  (-v shows the exact location of each item)", "dim", t))


def cmd_serve(args, store):
    # Lazy: the daemon's full job graph is not needed by any other subcommand.
    from jarvis.platform import host as _host
    reason = _host.unsupported_reason()
    if reason:
        print(reason, file=sys.stderr)
        return 2
    from jarvis.web import server
    store.close()  # the daemon opens its own handles per thread
    server.serve(db_path=args.db, port=args.port, hosts=selected_hosts(args))


def cmd_alert(args, store):
    """Outbound email alerts through Resend — status, or a test send."""
    if args.test:
        print("Sending a test alert…")
        err = alert.test(store)
        print(color(f"  {err}", "high", is_tty()) if err
              else "  sent — check the inbox")
        return 1 if err else 0
    s = alert.status(store)
    t = is_tty()
    on = color("enabled", "ok", t) if s["enabled"] else color(
        "not configured", "medium", t)
    print(f"alerts        {on}")
    print(f"transport     Resend  (key {'present' if s['have_key'] else 'missing'})")
    print(f"from          {s['from'] or '—'}")
    print(f"to            {', '.join(s['to']) or '—'}")
    print(f"min severity  {s['min_severity']}  (outage findings always page)")
    print(f"change digest every {s['digest_interval'] // 60}m when changes are queued")
    print("critical/outage changes send immediately; age escalations send once per threshold")
    print(f"on clear      {'yes' if s['on_clear'] else 'no'}")
    print(f"retries       {s['send_attempts']} attempts per email")
    cap = s["hourly_cap"] or "unlimited"
    print(f"hourly cap    {cap}  (outages: {s['outage_hourly_cap']}) — "
          f"{s['sent_last_hour']} sent in the last hour")
    print(f"last sent ok  {iso(s['last_ok']) if s['last_ok'] else '—'}")
    print(f"daily report  last sent "
          f"{iso(s['report_last_ok']) if s['report_last_ok'] else '—'}")
    print(f"AI depth      {s['advisory_model'] if s['advisory_ai'] else 'not configured'}")
    if s["report_last_error"]:
        print(color(f"report error  {s['report_last_error']}", "high", t))
    if s["last_error"]:
        print(color(f"last error    {s['last_error']}", "high", t))
    if s["capped_at"]:
        print(color(f"last capped   {iso(s['capped_at'])}", "medium", t))
    if s["outages"]:
        print(color("ACTIVE OUTAGES — JARVIS is not watching something:", "high", t))
        for k in s["outages"]:
            print(color(f"  ! {k.replace('|', ' — ')}", "high", t))
    if s["active"]:
        print("active alerts:")
        for k in s["active"]:
            print(f"  - {k.replace('|', ' — ')}")
    if not s["enabled"]:
        print(f"\nSet resend_api_key, alert_from and alert_to in "
              f"{alert.CONFIG_PATH} (0600). alert_from must be a "
              f"Resend-verified sender.")


def _print_windows_monitor(t):
    """The other half of the supervision loop.

    `jarvis selfcheck` is the command JARVIS's own alerts name when the
    Windows monitor stalls, so it has to actually show that monitor's state --
    otherwise the report sends you to a command that cannot answer the
    question it was raised about.
    """
    for f in supervisors.audit_health_monitor():
        key = f["severity"] if f["severity"] != "ok" else "ok"
        print(color("  windows monitor", key, t) + f" — {f['detail']}")


def cmd_selfcheck(args, store):
    """Is the daemon actually monitoring? Run from a timer outside it."""
    t = is_tty()
    store.close()          # selfcheck opens its own handles
    res = selfcheck.run(db_path=args.db, do_restart=args.restart,
                        notify=not args.no_mail, attempts=args.attempts)
    if args.json:
        print(json.dumps(res, indent=2))
        return 0 if res["healthy"] else 1
    if args.quiet:
        return 0 if res["healthy"] else 1

    if res["healthy"]:
        print(color("  JARVIS is monitoring", "ok", t)
              + f" — {selfcheck.UNIT} active, newest snapshot "
                f"{res['newest_kind']} {res['age']}s ago")
        _print_windows_monitor(t)
        return 0
    print(color("  JARVIS is NOT monitoring this machine", "critical", t))
    _print_windows_monitor(t)
    for p in res["problems"]:
        print(color(f"    - {p}", "high", t))
    if res["restarted"]:
        print("    restart: "
              + (color(res["restart_error"], "high", t) if res["restart_error"]
                 else color("issued", "ok", t)))
        after = res.get("after_restart")
        if after:
            print("    after restart: "
                  + (color("healthy", "ok", t) if after["healthy"]
                     else color("still unhealthy", "high", t)))
    if res["mail_error"]:
        print(color(f"    alert mail failed: {res['mail_error']}", "high", t))
    elif not args.no_mail:
        print("    alert mailed")
    return 1


def cmd_status(args, store):
    b = store.get_meta("baseline_at")
    total = len(store.known_fps())
    appr = len(store.list_procs(approved=1, limit=100000))
    ev = store.list_events(limit=1)
    print(f"database      {store.path}")
    print(f"baseline      {iso(int(b)) if b else 'not taken — run `jarvis baseline`'}")
    print(f"fingerprints  {total} known, {appr} approved")
    print(f"peers         {len(store.list_peers(limit=100000))} recorded")
    print(f"last event    {iso(ev[0]['ts']) if ev else '—'}")
    health = score.stable(store, JOBS, acks=acknowledge.load(store))
    print(f"security      {score.bar(health['score'])} {health['score']}% "
          f"{health['grade']} (monitoring coverage {health['coverage']}%)")
    if health.get("state") == "verifying":
        live = health["live"]
        print(f"              last verified {iso(int(health['verified_at']))}; "
              f"re-checking after a gap, {live['observed']}/{live['jobs']} "
              f"collectors current (partial sweep reads {live['score']}%)")
    print(f"windows side  "
          f"{'reachable' if collect_windows.available() else 'unavailable'}")
