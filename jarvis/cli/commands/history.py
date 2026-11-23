"""Persistent history review and local forensic case preservation."""
import json

from jarvis.core import historybook
from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError


def cmd_history(args, store):
    try:
        if args.action == "verify-case":
            result = historybook.verify_case(args.case, anchor=args.anchor)
        else:
            with EventLog(args.log or DEFAULT_ROOT) as log:
                if args.action == "status":
                    result = log.stats()
                    result["legacy_missing_ranges"] = log.missing()
                    custody = store.get_meta("evidence_v1") if store else None
                    result["custody"] = json.loads(custody) if custody else None
                elif args.action == "verify":
                    result = log.verify(anchor=json.loads(args.anchor) if args.anchor else None)
                    result["limitations"] = "local hashes detect changes against a retained anchor; no administrator deletion prevention"
                elif args.action == "export":
                    result = historybook.export_case(log, args.case, after=args.after,
                                                     until=args.until)
                else:
                    result = historybook.query(
                        log, after=args.after, until=args.until, host=args.source_host,
                        category=args.category, image=args.image, since=args.since,
                        before=args.before, limit=args.limit, scan_limit=args.scan_limit,
                        raw=args.raw)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok", True) else 2
    except (LogError, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:300]}))
        return 2


def add_parser(sub):
    p = sub.add_parser("history", help="persistent history book: review, verify, preserve forensic cases")
    p.add_argument("action", choices=("status", "query", "verify", "export", "verify-case"))
    p.add_argument("--log", help="canonical log or preserved copy; default ~/.jarvis/eventlog")
    p.add_argument("--after", type=int, default=0, help="exclusive ingest sequence; pagination cursor")
    p.add_argument("--until", type=int, help="inclusive ingest sequence")
    p.add_argument("--source-host", choices=("wsl", "win"))
    p.add_argument("--category")
    p.add_argument("--image", help="case-insensitive substring of process image")
    p.add_argument("--since", help="inclusive source timestamp with timezone")
    p.add_argument("--before", help="inclusive source timestamp with timezone")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--scan-limit", type=int, default=historybook.MAX_SCAN)
    p.add_argument("--raw", action="store_true", help="local query: include original fields and raw source records")
    p.add_argument("--case", help="export: new directory; verify-case: existing directory")
    p.add_argument("--anchor", help="verify: chain head JSON; verify-case: independently retained manifest SHA-256")
    p.set_defaults(fn=cmd_history)
