"""Subcommands that read and curate the stored baseline."""

import json
import time

from jarvis.collectors.process import detect, monitor
from jarvis.core import collection
from jarvis.core.util import iso, now, short
from jarvis.intel import feeds
from jarvis.intel import research as intel
from jarvis.response import ledger as ledger_mod

from ..output import color, is_tty, selected_hosts


def cmd_baseline(args, store):
    if args.reset:
        store.db.execute("DELETE FROM procs")
        store.db.execute("DELETE FROM peers")
        store.commit()
        print("Cleared the previous baseline.")
    print("Learning the current state as your known-good baseline…")
    res = monitor.scan(store, hosts=selected_hosts(args), enrich=False, learn=True)
    store.set_meta("baseline_at", now())
    total = len(store.known_fps())
    print(f"  {res['scanned']} processes captured, {total} unique fingerprints approved.")
    print(f"  Database: {store.path}")
    print("\nFrom now on, anything new shows up as drift. Re-run `jarvis baseline` "
          "after you install software you trust — it adds to what's already there.")


def cmd_procs(args, store):
    if args.live:
        from jarvis.platform import linux, windows

        from ..output import selected_hosts

        hosts = selected_hosts(args)
        with collection.observe() as observation:
            rows = []
            if "wsl" in hosts:
                rows.extend(linux.collect(with_sockets=False))
            if "win" in hosts:
                rows.extend(windows.collect())
        # A failed source must not make a partial list look exhaustive.
        counts = {host: sum(p.get("host") == host for p in rows) for host in hosts}
        errors = list(observation.failures)
        for host in hosts:
            if counts[host] == 0:
                errors.append(f"{host}: no process observations")
        rows.sort(key=lambda p: (p.get("host", ""), int(p.get("pid") or 0),
                                 p.get("started") or ""))
        total = len(rows)
        if args.limit is not None:
            rows = rows[:max(0, args.limit)]
        # This is local metadata only: no command lines, sockets or credentials.
        items = [{"host": p.get("host"), "pid": p.get("pid"),
                  "name": p.get("name"), "exe": p.get("exe"),
                  "started": p.get("started"),
                  "observed_at": p.get("observed_at")}
                 for p in rows]
        result = {"completed_at": int(time.time()), "sources": counts,
                  "total": total, "shown": len(items), "errors": errors,
                  "processes": items}
        if args.json:
            print(json.dumps(result, default=str))
        else:
            for p in items:
                print(f"{p['host']:<4} {str(p['pid']):>7}  "
                      f"{p['name'] or '?':<28} {p['started'] or '?'}  {p['exe'] or ''}")
            print(f"{len(items)} of {total} observed processes; "
                  + ("source errors: " + "; ".join(errors) if errors else "all requested sources returned rows"))
        return 1 if errors else 0

    rows = store.list_procs(approved=args.approved, limit=60 if args.limit is None else args.limit)
    print(f"{'FP':<18}{'HOST':<6}{'APPR':<6}{'SEEN':<6}{'LAST':<21}NAME / CMD")
    for r in rows:
        print(f"{r['fp']:<18}{r['host']:<6}{'yes' if r['approved'] else 'no':<6}"
              f"{r['seen_count']:<6}{iso(r['last_seen']):<21}"
              f"{short(r['name'] + '  ' + (r['cmdline'] or ''), 60)}")
    print(f"\n{len(rows)} rows")


def cmd_peers(args, store):
    rows = store.list_peers(scope=args.scope, limit=args.limit)
    print(f"{'REMOTE':<44}{'SCOPE':<10}{'HOST':<6}{'SEEN':<6}{'LAST':<21}PROCESS")
    for r in rows:
        endpoint = f"{r['remote_ip']}:{r['remote_port']}"
        print(f"{endpoint:<44}{r['scope']:<10}{r['host']:<6}{r['seen_count']:<6}"
              f"{iso(r['last_seen']):<21}{short(r['pname'] or r['fp'], 30)}"
              f"{('  ' + r['rdns']) if r['rdns'] else ''}")
    print(f"\n{len(rows)} rows")


def cmd_events(args, store):
    since = now() - args.since * 3600 if args.since else None
    rows = store.list_events(limit=args.limit, severity=args.severity, since=since)
    t = is_tty()
    for r in rows:
        tag = color(f" {r['severity'][:4].upper():4} ", r["severity"], t)
        print(f"{iso(r['ts'])} {tag} [{r['host']}/{r['pid']}] {r['name']} "
              f"— {detect.explain((r['reasons'] or '').split(',')) if r['reasons'] else r['kind']}")
        if args.verbose:
            print(f"    {short(r['cmdline'] or '', 110)}")
    print(f"\n{len(rows)} events")


def cmd_approve(args, store):
    n = 0
    for fp in args.fingerprint:
        n += store.set_approved(fp, 1, args.note)
    print(f"approved {n} fingerprint(s)")


def cmd_outstanding(args, store):
    """What has been reported and never resolved."""
    snaps = store.get_snapshots()
    job_ts = {k: int(v.get("ts") or 0) for k, v in snaps.items()
              if not v.get("error")}
    ledger_mod.backfill(store)
    rows = store.ledger_rows(limit=2000)
    if args.json:
        print(json.dumps(ledger_mod.classify(rows, job_ts=job_ts), indent=2))
        return
    states = ledger_mod.classify(rows, job_ts=job_ts)
    t = is_tty()
    if not rows:
        print(color("No alerts have been sent yet, so there is nothing to "
                    "chase. This is only meaningful once alerting is "
                    "configured and has run.", "dim", t))
        return

    titles = {
        "recurring": ("CAME BACK — cleared before, reported again since",
                      "the fix did not hold, or something is re-establishing it"),
        "outstanding": ("STILL OPEN — reported and never resolved", ""),
        "stale": ("UNVERIFIED — the collector has not run since it was mailed",
                  "not resolved: nobody has looked"),
        "resolved": ("RESOLVED", ""),
    }
    order = ["recurring", "outstanding", "stale"]
    if args.all:
        order.append("resolved")

    shown = 0
    for state in order:
        group = states[state]
        if not group:
            continue
        head, note = titles[state]
        print(f"\n{color(head, 'bold', t)}")
        if note:
            print(color(f"  {note}", "dim", t))
        for row in group[: args.limit]:
            sev = row.get("severity") or "low"
            if args.severity and ledger_mod.SEV_ORDER.get(sev, 9) > \
                    ledger_mod.SEV_ORDER[args.severity]:
                continue
            shown += 1
            tag = color(f" {sev[:4].upper():4} ", sev, t)
            age = ledger_mod._phrase_age(row["age_days"])
            flag = color(" OVERDUE", "high", t) if ledger_mod.overdue(row) else ""
            print(f"  {tag} [{row.get('host') or '—'}] {row.get('title')}"
                  f"{flag}")
            print(color(f"          first mailed {age} ago · "
                        f"{row.get('sent_count')} email(s) · job "
                        f"{row.get('job') or '?'}"
                        + (f" · reopened {row.get('reopened')}×"
                           if row.get("reopened") else ""), "dim", t))
            if args.verbose and row.get("detail"):
                print(f"          {short(row['detail'], 150)}")
            if row.get("fix"):
                print(f"          {color('fix: ' + row['fix'], 'ok', t)}")
        if len(group) > args.limit:
            print(color(f"  … {len(group) - args.limit} more (--limit)", "dim", t))

    counts = {k: len(v) for k, v in states.items()}
    print(f"\n{len(rows)} on record   "
          f"outstanding={counts['outstanding']}  "
          f"recurring={counts['recurring']}  "
          f"unverified={counts['stale']}  resolved={counts['resolved']}")
    if not args.all and counts["resolved"]:
        print(color("  (--all also lists the resolved ones)", "dim", t))


def cmd_intel(args, store):
    """Refresh the threat-intelligence knowledge base."""
    t = is_tty()
    if args.set_key:
        path = intel.save_key(args.set_key)
        print(f"key stored in {path} (mode 0600, outside the repository)")
        return
    if args.revet:
        st = intel.revet(store)
        print(f"re-vetted {st['checked']} indicators — "
              f"{st['dropped']} dropped, {st['moved']} reclassified")
        for why, n in sorted(st["reasons"].items(), key=lambda kv: -kv[1])[:12]:
            print(f"  {n:4}  {why}")
        return
    if args.show:
        info = intel.summary(store)
        print(f"documents     {info['docs']}")
        print(f"indicators    {info['total']} active")
        for kind, n in sorted(info["by_kind"].items(), key=lambda kv: -kv[1]):
            print(f"  {kind:10} {n}")
        last = info["last_refresh"]
        print(f"last refresh  {iso(last) if last else 'never'}")
        print(f"api spend     ${info['spend']:.3f} total")
        return

    topics = args.topic or None
    if args.all:
        topics = list(intel.CORPUS)
    label = ", ".join(topics) if topics else "the least recently refreshed topic"
    print(f"Fetching threat intelligence for {label}…\n")

    def progress(topic, query):
        print(color(f"  [{topic}] {short(query, 64)}", "dim", t))

    try:
        stats = intel.refresh(store, topics=topics, per_query=args.results,
                              days=args.days, on_progress=progress)
    except intel.IntelError as exc:
        print(color(f"intel refresh failed: {exc}", "high", t))
        return 1

    print()
    print(f"  {stats['queries']} queries · {stats['docs']} documents "
          f"· ${stats['cost']:.3f}")
    print(f"  {stats['kept']} indicators kept, {stats['rejected']} rejected "
          f"of {stats['seen']} candidates")
    if stats["not_research"]:
        print(color(f"  {stats['not_research']} documents were not threat research",
                    "dim", t))
    if args.verbose and stats["reasons"]:
        print(color("\n  why candidates were rejected:", "dim", t))
        for why, n in sorted(stats["reasons"].items(), key=lambda kv: -kv[1])[:12]:
            print(color(f"    {n:4}  {why}", "dim", t))
    for err in stats["errors"]:
        print(color(f"  {err}", "medium", t))


def cmd_feeds(args, store):
    """Refresh the free bulk indicator feeds."""
    t = is_tty()
    if args.status:
        rows = feeds.status(store)
        if not rows:
            print("no feed has run yet — run `jarvis feeds`")
            return
        for r in rows:
            when = iso(r["last_run"]) if r["last_run"] else "never"
            line = (f"  {r['name']:16} {when}  {r['kept']:>7} kept "
                    f"of {r['rows']:>7}  {r['bytes'] / 1024:>8.0f} KiB")
            print(line + (color("  " + r["error"], "high", t) if r["error"] else ""))
        return
    if args.prune:
        n = feeds.prune(store, days=args.days)
        print(f"retired {n} feed indicators not seen in {args.days} days")
        return

    print("Refreshing bulk indicator feeds…\n")

    def progress(name, desc):
        print(color(f"  {name:16} {desc}", "dim", t))

    results = feeds.refresh(store, names=args.feed or None, force=args.force,
                            on_progress=progress)
    if args.attack or args.force:
        print(color("  attack           MITRE ATT&CK technique catalogue", "dim", t))
        results.append(feeds.refresh_attack(store, force=args.force))

    print()
    total = 0
    for r in results:
        if r.get("skipped"):
            continue
        if r.get("error"):
            print(color(f"  {r['name']:16} failed: {r['error']}", "medium", t))
            continue
        total += r.get("kept", 0)
        print(f"  {r['name']:16} {r.get('kept', 0):>7} kept "
              f"of {r.get('rows', 0):>7} rows")
    if not results:
        print("  every feed is still within its refresh interval "
              "(use --force to override)")
    else:
        print(f"\n  {total} indicators added or refreshed")
