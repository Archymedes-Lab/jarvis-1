"""The product is ARGUS-INSTINCT: the display rule for text that leaves the daemon.

Same rule as the web pages (`// brand:begin` in jarvis/web/static), kept equal
by tests/test_ui_brand.py. Daemon text can still say JARVIS where the word is
part of an identity (finding titles match acknowledgements and history; the
Windows monitors check `service: JARVIS` in /api/health), so the name is
changed where text is shown: email, webhook, ntfy, syslog, phone, toasts.
Real Windows objects keep their spelling so they can be found in Task
Scheduler and Services; lowercase commands (jarvis ..., jarvis.service) are
never touched. Idempotent: "ARGUS-INSTINCT" is never turned into "ARGUS-INSTINCT-1".
"""

import re

BRAND = "ARGUS-INSTINCT"
_KEEP = re.compile(r" (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)")
_NAME = re.compile(r"\bJARVIS\b(?!-(?:1|INSTINCT)\b)")


def brand(text):
    """`text` with the old product name shown as ARGUS-INSTINCT."""
    s = "" if text is None else str(text)
    return _NAME.sub(lambda m: m.group(0) if _KEEP.match(s, m.end()) else BRAND, s)
