"""Read-only file and process investigation with the local defense tools."""

import json
import time

from jarvis.response import tools
from jarvis.response.evidence.case import Case


def cmd_inspect(args, store):
    report = tools.inspect(args.path or "", args.pid, args.yara_rules or "")
    case = Case(args.case or f"inspect-{time.time_ns()}")
    case.add_text("inspection.json", report, kind="tool-output",
                  note="read-only Defender, signature, hash, YARA and process context")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"evidence case: {case.name}")
    return 0


def add_parser(sub):
    p = sub.add_parser("inspect", help="scan a file or Linux process with local defense tools")
    p.add_argument("path", nargs="?", help="WSL or Windows file path")
    p.add_argument("--pid", type=int, help="Linux process id for ancestry and children")
    p.add_argument("--yara-rules", help="local YARA rules file or directory")
    p.add_argument("--case", help="evidence case name")
    p.set_defaults(fn=lambda args, store: cmd_inspect(args, store))
    return p
