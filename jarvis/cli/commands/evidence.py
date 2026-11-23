"""`jarvis evidence` — collect, verify and search persistent case material.

Kept in the evidence package rather than in jarvis/cli.py so the subcommand
and the code it drives stay in one place.
"""

import json
import os
import sys

from jarvis.response.evidence import scan as scan_mod
from jarvis.response.evidence import sources
from jarvis.response.evidence.case import Case, adopt, list_cases
from jarvis.response.evidence.collect import collect_profile, profile_names
from jarvis.response.evidence.paths import EVIDENCE_ROOT


def _human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def _emit(args, payload, lines):
    if getattr(args, "json", False):
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for line in lines:
            print(line)


def _do_list(args):
    cases = list_cases()
    lines = ["evidence root: %s" % EVIDENCE_ROOT, ""]
    if not cases:
        lines.append("no cases yet — start one with: jarvis evidence collect "
                     "--case <name> --profile windows-logs")
    for c in cases:
        lines.append("%-28s %3d files  %10s  %s"
                     % (c["case"], c["files"], _human(c["bytes"]), c["dir"]))
    _emit(args, cases, lines)


def _do_collect(args):
    case = Case(args.case)
    results = []
    lines = ["case %s -> %s" % (case.name, case.dir), ""]
    for profile in args.profile or []:
        try:
            got = collect_profile(case, profile)
        except KeyError as exc:
            print(exc.args[0], file=sys.stderr)
            return 2
        results.extend(got)
        lines.append("profile %s:" % profile)
        for r in got:
            lines.append(_result_line(r))
        lines.append("")
    for path in args.file or []:
        r = case.add_file(path, kind=args.kind or "", note=args.note or "")
        results.append(r)
        lines.append(_result_line(r))
    lines.append("total %s in %d files"
                 % (_human(case.size()), len(case.files())))
    _emit(args, results, lines)
    return 0


def _result_line(r):
    if not r.get("ok"):
        return "  FAIL %-46s %s" % (r["name"], r.get("error", "unreadable"))
    flag = "CHANGED" if r.get("changed") else "ok"
    via = "" if r.get("how") == "direct" else "  via %s" % r.get("how")
    return "  %-7s %-46s %10s  %s%s" % (
        flag, r["name"], _human(r["size"]), r["sha256"][:16], via)


def _do_adopt(args):
    case, added = adopt(args.case, note=args.note or "")
    lines = ["case %s -> %s" % (case.name, case.dir)]
    lines += ["  adopted %s" % n for n in added] or ["  nothing new to adopt"]
    _emit(args, {"case": case.name, "adopted": added}, lines)
    return 0


def _do_verify(args):
    case = Case(args.case, create=False)
    ok, changed, missing = case.verify()
    lines = ["case %s" % case.name,
             "  verified %d" % len(ok)]
    for n in changed:
        lines.append("  CHANGED  %s — bytes differ from what was collected" % n)
    for n in missing:
        lines.append("  MISSING  %s" % n)
    if not changed and not missing:
        lines.append("  all artefacts match the manifest")
    _emit(args, {"ok": ok, "changed": changed, "missing": missing}, lines)
    return 1 if (changed or missing) else 0


def _do_scan(args):
    case = Case(args.case, create=False)
    if not scan_mod.tools_available() and \
            any(n.lower().endswith(".evtx") for n in case.files()):
        print("note: event logs present but python-evtx is not installed.\n"
              "      %s" % scan_mod.INSTALL, file=sys.stderr)
    payload = scan_mod.scan_case(case, args.needle or [])
    lines = []
    for r in payload["results"]:
        if r.get("error"):
            lines.append("%-52s %s" % (r["file"], r["error"]))
            continue
        total = r.get("records", r.get("lines", 0))
        window = ("%s .. %s" % (r["first"], r["last"])) if r.get("first") else ""
        lines.append("%-52s %7d  matches=%d  %s"
                     % (r["file"], total, len(r["matches"]), window))
        for m in r["matches"][:20]:
            where = m.get("time") or ("line %s" % m.get("line"))
            lines.append("    %s  %s  %s"
                         % (where, ",".join(m["hits"]),
                            (m.get("text") or str(m.get("data", "")))[:120]))
    lines.append("")
    lines.append("results saved in the case: %s"
                 % os.path.join(case.dir, "scan-results.json"))
    _emit(args, payload, lines)
    return 0


def _do_where(args):
    lines = []
    payload = {}
    for path in args.file:
        readable, how = sources.resolve(path)
        payload[path] = {"readable": readable, "how": how,
                         "diagnosis": sources.diagnose(path)}
        lines.append("%s\n  %s\n  %s" % (path, how, payload[path]["diagnosis"]))
    _emit(args, payload, lines)
    return 0


def cmd_evidence(args, store):
    return {
        "list": _do_list, "collect": _do_collect, "verify": _do_verify,
        "scan": _do_scan, "where": _do_where, "adopt": _do_adopt,
    }[args.action](args) or 0


def add_parser(sub):
    p = sub.add_parser(
        "evidence",
        help="collect and verify persistent investigation material")
    p.add_argument("--json", action="store_true")
    act = p.add_subparsers(dest="action", required=True)

    act.add_parser("list", help="cases on disk")

    c = act.add_parser("collect", help="copy artefacts into a case")
    c.add_argument("--case", required=True, metavar="NAME")
    c.add_argument("--profile", action="append",
                   choices=profile_names(),
                   help="a named set of artefacts (repeatable)")
    c.add_argument("--file", action="append", metavar="PATH",
                   help="collect one extra file (repeatable)")
    c.add_argument("--kind", help="label for --file artefacts")
    c.add_argument("--note", help="why this artefact was collected")

    a = act.add_parser(
        "adopt", help="index files already in a case directory")
    a.add_argument("--case", required=True, metavar="NAME")
    a.add_argument("--note", help="provenance of the adopted files")

    v = act.add_parser("verify", help="re-hash a case against its manifest")
    v.add_argument("--case", required=True, metavar="NAME")

    s = act.add_parser("scan", help="search a case for indicators")
    s.add_argument("--case", required=True, metavar="NAME")
    s.add_argument("--needle", action="append", metavar="TEXT",
                   help="string to search for (repeatable)")

    w = act.add_parser("where",
                       help="show whether a path is readable, and how")
    w.add_argument("file", nargs="+")

    p.set_defaults(fn=cmd_evidence)
    return p
