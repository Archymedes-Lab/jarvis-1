"""Searching collected evidence for indicators.

Windows event logs are the expensive case: a 67 MB .evtx holds tens of
thousands of records, and parsing each one to XML to look for a hostname is
wasteful. Every record's raw bytes are tested first, in both UTF-16LE and
ASCII, and only a record that already contains the needle is parsed.
"""

import os
import sys

from .paths import TOOLS_ROOT, tools_root

# python-evtx is the only known pure-Python .evtx reader. JARVIS is otherwise
# stdlib-only, so it is installed on demand into the state root and imported
# from there rather than becoming a hard dependency of the service.
INSTALL = ("python3 -m pip install --target %s python-evtx" % TOOLS_ROOT)


def _load_evtx():
    if os.path.isdir(TOOLS_ROOT) and TOOLS_ROOT not in sys.path:
        sys.path.insert(0, TOOLS_ROOT)
    try:
        from Evtx.Evtx import Evtx
        return Evtx
    except ImportError:
        return None


def tools_available():
    return _load_evtx() is not None


def _needle_bytes(needles):
    """Each needle in the encodings event records actually use."""
    out = []
    for n in needles:
        low = n.lower()
        out.append((n, low.encode("utf-8"), low.encode("utf-16le")))
    return out


def scan_evtx(path, needles, limit=200):
    """Summarise one event log and the records matching `needles`."""
    Evtx = _load_evtx()
    if Evtx is None:
        return {"file": os.path.basename(path), "error":
                "python-evtx not installed; run: %s" % INSTALL}

    import xml.etree.ElementTree as ET
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    pats = _needle_bytes(needles)
    out = {"file": os.path.basename(path), "records": 0, "errors": 0,
           "first": None, "last": None, "matches": []}

    with Evtx(path) as log:
        for rec in log.records():
            out["records"] += 1
            try:
                ts = rec.timestamp().isoformat()
                if out["first"] is None or ts < out["first"]:
                    out["first"] = ts
                if out["last"] is None or ts > out["last"]:
                    out["last"] = ts
                if not pats:
                    continue
                raw = rec.data().lower()
                hits = [n for n, a, w in pats if a in raw or w in raw]
                if not hits or len(out["matches"]) >= limit:
                    continue
                tree = ET.fromstring(rec.xml())
                out["matches"].append({
                    "time": ts,
                    "id": tree.findtext("e:System/e:EventID", namespaces=ns),
                    "hits": hits,
                    "data": {d.get("Name", str(i)): (d.text or "")[:400]
                             for i, d in
                             enumerate(tree.findall("e:EventData/e:Data", ns))},
                })
            except Exception:
                # A single malformed record must not abandon the log; the
                # count is reported so a high error rate is visible.
                out["errors"] += 1
    return out


def scan_text(path, needles):
    """Line-oriented search, for history files and plain logs."""
    low = [n.lower() for n in needles]
    out = {"file": os.path.basename(path), "lines": 0, "matches": []}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            out["lines"] = i
            hay = line.lower()
            hits = [n for n in low if n in hay]
            if hits:
                out["matches"].append({"line": i, "hits": hits,
                                       "text": line.rstrip()[:400]})
    return out


def scan_case(case, needles, save_as="scan-results.json"):
    """Scan every artefact in `case`, and keep the result inside the case.

    The output is written back as a case artefact so the finding and the
    evidence it came from stay together and survive a restart.
    """
    results = []
    for name, entry in sorted(case.files().items()):
        if entry.get("source") == "derived":
            continue
        path = case.path(name)
        if not os.path.isfile(path):
            continue
        if name.lower().endswith(".evtx"):
            results.append(scan_evtx(path, needles))
        elif entry.get("kind") in ("history", "syslog") or \
                name.lower().endswith((".txt", ".log")):
            results.append(scan_text(path, needles))
    payload = {"needles": list(needles), "results": results}
    case.add_text(save_as, payload, kind="scan",
                  note="indicator search over collected evidence")
    return payload


def ensure_tools_dir():
    return tools_root()
