"""Running every tracking and capture check together."""

from jarvis.core.finding import win_finding as finding

from . import mail, screen, web
from .common import sort_findings

# Modules, not bound functions: each module's audit is resolved at call
# time so the surface stays substitutable.
CHECKS = (
    ("screen capture", screen),
    ("mail tracking", mail),
    ("web tracking", web),
)


def audit(hosts=("wsl", "win")):
    out = []
    for name, module in CHECKS:
        try:
            out.extend(module.audit(hosts=hosts))
        except Exception as exc:
            # One failing surface must not read as a clean result for the rest.
            out.append(finding(
                "screen" if "screen" in name else "tracking-web", "medium",
                "%s check failed" % name,
                "%s: %s — that surface is unaudited this run"
                % (type(exc).__name__, exc), "", host="wsl"))
    return sort_findings(out)
