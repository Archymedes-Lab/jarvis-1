"""Read the temporal event log: what happened, in order, and what caused what."""

import json

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.platform import host
from jarvis.platform.native import ingest


def _line(ev):
    p, t = ev.get("process") or {}, ev.get("target") or {}
    who = (p.get("image") or "").replace("/", "\\").rsplit("\\", 1)[-1] or "-"
    what = (t.get("query") or t.get("path") or t.get("image") or t.get("key")
            or t.get("name") or (f"{t.get('ip')}:{t.get('port')}" if t.get("ip") else "")
            or (p.get("cmdline") or "")[:100])
    return (f"#{ev['seq']:<8} {(ev.get('time') or '')[:23]:23}  "
            f"{ev['category']}.{ev['action']:<16} {who:<24} {what}")


def _open(root):
    try:
        return EventLog(root)
    except (LogError, OSError) as exc:
        print(f"event log unavailable: {exc}")
        return None


def _wsl_boundary(args):
    import os
    from pathlib import Path

    from jarvis.core.execution import wsl_drift
    from jarvis.platform import wsl_boundary
    path = Path(args.checkpoint or Path.home() / ".jarvis" / "wsl-checkpoints.jsonl")
    entries, read_error = [], None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            entries = [json.loads(line) for line in fh.read().splitlines()
                       [-wsl_drift.MAX_ENTRIES:] if line.strip()]
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        read_error = type(exc).__name__
    wslconfig = args.wslconfig
    if not wslconfig:
        user = os.environ.get("USER") or ""
        candidate = Path(host.users_dir() or "/nonexistent") / user / ".wslconfig"
        wslconfig = str(candidate) if user and candidate.exists() else None
    snap = wsl_boundary.snapshot(windows_config=wslconfig)
    result = ({"status": "checkpoint_invalid", "reason": read_error, "findings": []}
              if read_error else wsl_drift.compare(entries, snap))
    result["sources"] = {k: v["status"] for k, v in snap["sources"].items()}
    if args.accept:
        if result["status"] == "checkpoint_invalid":
            result["accepted"] = False
        else:
            try:
                entry = wsl_drift.make_entry(snap, entries[-1] if entries else None)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                result["accepted"] = True
                result["accepted_seq"] = entry["seq"]
            except (OSError, ValueError) as exc:
                result["accepted"] = False
                result["accept_error"] = str(exc)[:120]
    if args.json:
        print(json.dumps(result, default=str))
    else:
        print(f"WSL boundary: {result['status']}"
              + (f" ({result['reason']})" if result.get("reason") else ""))
        for f in result["findings"][:max(0, args.limit)]:
            print(f"  [{f['kind']}{' critical' if f['critical'] else ''}] "
                  f"{f['fact']}: {f['change']} {f['before']!r} -> {f['after']!r}")
        print("sources: " + ", ".join(f"{k}={v}" for k, v in result["sources"].items()))
        if "accepted" in result:
            print("checkpoint " + ("recorded" if result["accepted"] else "NOT recorded"))
    return 1 if result["status"] in ("checkpoint_invalid",) else 0


def _clock(args):
    from jarvis.core.execution import clock_integrity
    from jarvis.platform import clock
    samples = clock.collect(args.watch)
    result = clock_integrity.analyze(
        samples, journal_backward=clock.journal_backward_count())
    if args.json:
        print(json.dumps(result))
    else:
        print(f"wall clock: {result['status']} over {result['window_s']}s; "
              f"{result['backward_steps']} backward step(s) sampled, "
              f"journald reports {result['journal_backward']} in the last hour")
        for step in result["steps"][:max(0, args.limit)]:
            print(f"  step {step['step_s']:+.2f}s ({step['direction']})")
        for effect in result["effects"]:
            print(f"  effect: {effect}")
    return 1 if result["status"] == "unstable" else 0


def _holds(args):
    """List the active retention holds, or release one (owner action, exact match)."""
    import sys
    root = args.log or DEFAULT_ROOT
    if args.action == "holds":
        log = EventLog(root)
        rows = log.hold_records()
        if args.json:
            print(json.dumps(rows))
        for h in ([] if args.json else rows):
            print(f"  events {h['first_seq']}-{h['last_seq']}  at={h.get('at')}  {h.get('reason', '')}")
        if not rows and not args.json:
            print("  no active holds")
        return 0
    if args.first is None or args.last is None or args.at is None:
        print("release-hold needs --first, --last and --at exactly as `timeline holds` lists them")
        return 2
    if not sys.stdin.isatty():
        print("release-hold asks for confirmation; run it in a terminal")
        return 2
    answer = input(f"Release the hold on events {args.first}-{args.last}? Retention may then reduce "
                   "the normal events in that range (suspicious ones stay). Type 'release' to confirm: ")
    if answer.strip() != "release":
        print("not released")
        return 1
    try:
        log = EventLog(root, writer=True)
    except LogError as exc:
        print(f"could not open the event log for writing: {exc}")
        return 1
    try:
        log.release_hold(args.first, args.last, args.at, by="owner (timeline release-hold)")
    except LogError as exc:
        print(f"not released: {exc}")
        return 1
    finally:
        log.close()
    print(f"released the hold on events {args.first}-{args.last}; the release is on record")
    return 0


def cmd_timeline(args, store):
    action = args.action
    if action in ("holds", "release-hold"):
        return _holds(args)
    if action == "clock":
        return _clock(args)
    if action == "wsl-boundary":
        return _wsl_boundary(args)
    if action == "linux-truth":
        from jarvis.core.execution.linux_truth import reconcile
        from jarvis.platform.linux_truth import executable_mappings, snapshot
        current = snapshot()
        result = {"snapshot": current, "reconciliation": reconcile(current)}
        if args.deep_pid:
            row = next((p for p in current.get("processes", [])
                        if p["pid"] == args.deep_pid), None)
            result["deep_mappings"] = (
                executable_mappings(args.deep_pid,
                                    expected_start_ticks=row["start_ticks"])
                if row else {"status": "unavailable", "reason": "process not observed",
                             "mappings": []})
        if args.json:
            print(json.dumps(result, default=str))
        else:
            c = result["reconciliation"]["counts"]
            print(f"Linux /proc snapshot: {c['represented']} process instances, "
                  f"{current.get('represented_threads', 0)} threads; "
                  f"lifecycle source {result['reconciliation']['lifecycle_source']}")
            for row in current.get("processes", [])[:max(0, args.limit)]:
                print(f"  {row['pid']:>7} {row['entity_type']:<23} "
                      f"{row['name']:<20} {row['key']}")
            print("visibility: " + "; ".join(result["reconciliation"]["limitations"]))
            if args.deep_pid:
                deep = result["deep_mappings"]
                print(f"executable mappings for {args.deep_pid}: "
                      f"{len(deep['mappings'])} sampled, status {deep['status']}")
        return 1 if current["status"] == "unavailable" else 0
    if action == "ingest":
        try:
            log = EventLog(args.log or DEFAULT_ROOT, writer=True)
        except LogError as exc:
            print(f"{exc} (the daemon's native job ingests every minute)")
            return 1
        with log:
            result = ingest.run(log=log, spool=args.spool or ingest.SPOOL)
        print(json.dumps(result, indent=2, default=str) if args.json else
              f"{result['events']} events from {result['batches']} batches"
              + ("" if result["installed"] else " — no sensor spool at " + result["spool"]))
        return 1 if any(c["error"] for c in result["channels"]) else 0
    log = _open(args.log or DEFAULT_ROOT)
    if log is None:
        return 1
    with log:
        if action == "changes":
            from jarvis.core.change_query import summarize
            try:
                result = summarize(log, seconds=args.seconds,
                                   scan_limit=args.scan_limit)
            except ValueError as exc:
                print(f"invalid change query: {exc}")
                return 2
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"observed {result['observed_total']} changes in the "
                      f"source-time window of {result['window_seconds']}s "
                      f"(through committed event #{result['last_committed_seq']})")
                for kind, count in result["observed_changes"].items():
                    print(f"  {count:>6}  {kind}")
                print("coverage: partial; " + "; ".join(result["limitations"]))
            return 0
        if action == "status":
            stats = log.stats()
            stats["health"] = ingest.read_health(args.spool or ingest.SPOOL)
            if args.json:
                print(json.dumps(stats, indent=2, default=str))
                return 0
            print(f"event log {stats['root']}: events 1–{stats['last_seq']}, "
                  f"{stats['segments']} sealed segments ({stats['sealed_bytes'] // 1048576} MiB), "
                  f"{stats['unsealed_events']} unsealed, {stats['pruned']} pruned")
            for c in stats["cursors"]:
                print(f"  {c.get('channel', '?')}: batch {c.get('sequence', '?')} ({c.get('status', '?')}), "
                      f"through event #{c.get('through_seq', '?')}" + (f" — gap: {c['gap']}" if c.get("gap") else ""))
            h = stats["health"]
            print("  sensor: " + ("not installed" if h is None else
                                  f"health {int(h['age'] or 0)}s old, boot {h.get('boot_id')}"))
            if log.db is not None:
                print("  most frequent:")
                for r in log.counts()[:12]:
                    print(f"    {r['n']:>8}  {r['category']}.{r['action']} (source {r['source_event']})")
            return 0
        if action == "verify":
            anchor = json.loads(args.anchor) if args.anchor else None
            result = log.verify(anchor=anchor)
            print(json.dumps(result, indent=2))
            if result["ok"]:
                print("Chain intact. Keep this head somewhere this machine cannot write "
                      "(a phone note, another device) and pass it back with --anchor.")
            return 0 if result["ok"] else 2
        if action == "search":
            kind, value = next(((k, getattr(args, k)) for k in ("sha256", "dns", "ip", "image")
                                if getattr(args, k)), (None, None))
            if not kind:
                print("give one of --sha256, --dns, --ip, --image")
                return 1
            row = log.sighting(kind, value)
            if not row:
                print(f"never recorded: {kind} {value}")
                return 0
            print(f"{kind} {value}: {row['count']}× between {row['first_time']} and {row['last_time']}")
            shown = 0
            needle = row["value"]
            for ev in log.iter_events(after=row["first_seq"] - 1, until=row["last_seq"]):
                text = json.dumps([ev.get("process"), ev.get("target")]).lower()
                if needle.lower() in text:
                    print("  " + _line(ev))
                    shown += 1
                    if shown >= args.limit:
                        print(f"  … limited to {args.limit}")
                        break
            return 0
        if action == "tree":
            ancestry = log.ancestry(args.guid)
            for depth, p in enumerate(reversed(ancestry)):
                name = p.get("image") or ("(not recorded)" if p.get("unrecorded") else "?")
                print("  " * depth + f"{name}  pid {p.get('pid')}  {p.get('started') or ''}  {p['guid']}")
            for child in log.children(args.guid, args.limit):
                print("  " * len(ancestry) + f"└ {child.get('image')}  pid {child.get('pid')}  "
                      f"{child.get('started') or ''}  {child['guid']}")
            return 0
        if action == "show":
            for ev in log.iter_events(after=args.seq - 1, until=args.seq):
                if not args.raw:
                    ev = {k: v for k, v in ev.items() if k != "raw"}
                print(json.dumps(ev, indent=2))
                return 0
            print("no such event (or its segment was pruned)")
            return 1
        if action == "tail":
            start = max(0, log.last_seq - args.limit * (20 if args.category else 1))
            rows = [ev for ev in log.iter_events(after=start)
                    if not args.category or ev["category"] == args.category]
            for ev in rows[-args.limit:]:
                print(json.dumps(ev) if args.json else _line(ev))
            return 0
        if action in ("state", "detect"):
            # One ordered feed, many consumers: the same recent window
            # answers the state projection and the detectors without
            # rescanning the machine.
            from jarvis.core import temporal as temporal_mod
            start = max(0, log.last_seq - args.limit * 20)
            window = list(log.iter_events(after=start))[-args.limit * 5:]
            projection = temporal_mod.project(window)
            if action == "state":
                if args.json:
                    print(json.dumps(projection, indent=2, default=str))
                else:
                    print(f"folded {projection['events_folded']} events "
                          f"#{projection['first_seq']}–#{projection['last_seq']}"
                          + (" (truncated)" if projection["truncated"] else ""))
                    print(f"alive {len(projection['alive'])} processes, "
                          f"{len(projection['peers'])} peers, "
                          f"{len(projection['dns'])} dns names, "
                          f"{len(projection['files'])} files, "
                          f"{len(projection['tasks'])} tasks, "
                          f"{len(projection.get('registry', {}))} registry keys, "
                          f"{len(projection.get('drivers', {}))} drivers")
                    for line in temporal_mod.changes(
                            temporal_mod.reduce(window[:0]), projection)[:args.limit]:
                        print("  " + line)
                return 0
            found = temporal_mod.detectors(window, projection)
            if args.json:
                print(json.dumps(found, indent=2, default=str))
            else:
                if not found:
                    print("no detector fired on this window")
                for f in found:
                    seqs = ",".join(str(s) for s in f.get("seqs", [])[:8])
                    print(f"[{f['severity']}] {f['detector']}: {f['detail']} (seqs {seqs})")
            return 0
    return 1


def add_parser(sub):
    p = sub.add_parser("timeline", help="the recorded event history: search, lineage, integrity")
    p.add_argument("action", choices=["status", "ingest", "verify", "search", "tree", "show", "tail", "changes", "linux-truth", "wsl-boundary", "clock",
                                      "state", "detect", "holds", "release-hold"])
    p.add_argument("guid", nargs="?", help="tree: a process GUID")
    p.add_argument("--sha256"); p.add_argument("--dns"); p.add_argument("--ip")
    p.add_argument("--image", help="full image path")
    p.add_argument("--seq", type=int, help="show: event sequence number")
    p.add_argument("--category", help="tail: only this category")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--seconds", type=int, default=10,
                   help="changes: source-time window in seconds (1..3600)")
    p.add_argument("--scan-limit", type=int, default=5000,
                   help="changes: maximum recent events to inspect (1..20000)")
    p.add_argument("--deep-pid", type=int,
                   help="linux-truth: inspect executable mappings for this observed PID")
    p.add_argument("--watch", type=int, default=5,
                   help="clock: seconds to sample (0..120); use 65 to span two 30 s sync cycles")
    p.add_argument("--checkpoint", help="wsl-boundary: checkpoint chain file (default ~/.jarvis/wsl-checkpoints.jsonl)")
    p.add_argument("--wslconfig", help="wsl-boundary: path to the Windows .wslconfig (default: current user's)")
    p.add_argument("--accept", action="store_true",
                   help="wsl-boundary: explicitly append the current state as the new checkpoint")
    p.add_argument("--raw", action="store_true", help="show: include the source record")
    p.add_argument("--anchor", help="verify: a previously exported head, as JSON")
    p.add_argument("--spool", help="sensor spool directory (default: ProgramData)")
    p.add_argument("--log", help="event log directory, e.g. a preserved copy (default: ~/.jarvis/eventlog)")
    p.add_argument("--first", type=int, help="release-hold: first event of the hold")
    p.add_argument("--last", type=int, help="release-hold: last event of the hold")
    p.add_argument("--at", type=float, help="release-hold: the hold's `at` as `timeline holds` shows it")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_timeline)
