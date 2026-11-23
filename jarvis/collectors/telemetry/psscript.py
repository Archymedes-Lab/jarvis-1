"""PowerShell script blocks (event 4104): what PowerShell actually ran.

A command typed into a PowerShell session that is already open starts no
process, so process rules never see it. Of 758 PowerShell tests in the Atomic
Red Team replay most are invisible for that reason (DETECTION-BENCHMARK-
2026-11-10). When Windows script-block logging is on, PowerShell records the
text of every block it compiles; this collector reads those records and checks
them against the community rules written for them.

It only reads what Windows already wrote. It never turns logging on, never
changes the log, and never stores or forwards script text: the text of a block
is matched in memory and dropped; a finding carries the rule, the script path
if there is one, the time and a SHA-256 of the text.

Invariants
  1. Cursor integrity: the record cursor moves only after a pass that read and
     validated its records; a failed or malformed pass changes nothing.
  2. Evidence continuity: records overwritten before they were read are counted
     and reported (the log is a ring; on a busy machine it wraps in seconds).
     Logging switched off is reported, never read as "nothing happened".
  3. Privacy: script text is never stored, logged or put in a finding.
  4. The monitor's own scripts are left out exactly: by the SHA-256 of the text
     it launched (platform.windows.own_scripts). Never by name or process id.
  5. Bounded: records, blocks and characters per pass are capped; what a cap
     cut is reported.
  6. Content is not authority: matches go through collectors/telemetry/community
     (capped severity, per-install judgement, author named, never acted on).

Limits, stated: script-block logging must already be on; scripts run before a
pass that the ring has since overwritten are lost; a block longer than the cap
is checked only up to the cap; a script launched by another Argus process (a
command-line run, a Windows task) is not in this process's own list and is
judged like anyone else's; an attacker who can turn logging off or clear the
log blinds this collector (both are reported by other collectors).
"""

import hashlib
import json

from jarvis.collectors.telemetry import community
from jarvis.core import collection, sigma
from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.core.util import now
from jarvis.platform import windows

CHANNEL = "Microsoft-Windows-PowerShell/Operational"
META = "psscript_v1"
PS_READER = load_win_script("psscript.ps1")
MAX_EVENTS = 3000
MAX_BLOCKS = 200
MAX_TEXT = 16384
MAX_TOTAL = 1_500_000
KEEP_HITS = 100
KEEP_FOR_S = 24 * 3600
RAISE_LOG = "wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456"


def _state(store):
    try:
        state = json.loads(store.get_meta(META, "") or "{}")
    except (TypeError, ValueError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    cursor = state.get("cursor")
    hits = state.get("hits")
    return {"cursor": cursor if isinstance(cursor, int) and cursor >= 0 else 0,
            "hits": [h for h in hits if isinstance(h, dict)] if isinstance(hits, list) else []}


def _valid(data):
    """The reader's answer in exactly the expected shape, or None."""
    if not isinstance(data, dict) or not isinstance(data.get("errors"), (list, str, type(None))):
        return None
    try:
        out = {"enabled": data["enabled"] if isinstance(data.get("enabled"), bool) else None,
               "first": int(data["first"]), "last": int(data["last"]), "read": int(data["read"]),
               "own": int(data["own"]), "more": bool(data["more"]),
               "errors": [str(e)[:120] for e in windows.aslist(data.get("errors"))][:8]}
        log = data.get("log")
        out["newest"] = int(log["newest"]) if isinstance(log, dict) and "newest" in log else None
        out["oldest"] = int(log["oldest"]) if isinstance(log, dict) else 0
        out["log_bytes"] = int(log["max_bytes"]) if isinstance(log, dict) else 0
        blocks = []
        for b in windows.aslist(data.get("blocks")):
            if not isinstance(b, dict):
                return None
            text = b["text"]
            if not isinstance(text, str) or len(text) > 65536:
                return None
            blocks.append({"rec": int(b["rec"]), "time": str(b["time"])[:40], "level": int(b["level"]),
                           "path": str(b.get("path") or "")[:400], "sha": str(b["sha"])[:64],
                           "len": int(b["len"]), "complete": bool(b["complete"]),
                           "truncated": bool(b["truncated"]), "text": text})
        out["blocks"] = blocks[:MAX_BLOCKS]
    except (KeyError, TypeError, ValueError):
        return None
    if out["last"] < out["first"] or min(out["first"], out["last"], out["read"], out["own"]) < 0:
        return None
    return out


def read(cursor):
    """One bounded read after `cursor`. -> validated answer, or (None, why)."""
    script = windows.stdin_text("jarvisReq") + PS_READER
    own = dict(windows.own_scripts())
    own[hashlib.sha256(script.encode("utf-8")).hexdigest()] = now()      # this reader itself
    request = json.dumps({"after": cursor, "own": sorted(own), "max_events": MAX_EVENTS,
                          "max_blocks": MAX_BLOCKS, "max_text": MAX_TEXT, "max_total": MAX_TOTAL})
    data = windows.ps_json(script, timeout=45, payload=request)      # below the job's 60 s deadline
    if data is None:
        return None, "Windows did not answer"
    answer = _valid(data)
    if answer is None:
        return None, "the reader's answer was malformed"
    return answer, ""


def _recent(hits, at):
    return [h for h in hits if isinstance(h.get("ts"), (int, float)) and at - h["ts"] < KEEP_FOR_S][-KEEP_HITS:]


def audit(store, hosts=("wsl", "win"), reader=read):
    if "win" not in hosts:
        return []
    at = now()
    state = _state(store)
    answer, why = reader(state["cursor"])
    kept = _recent(state["hits"], at)
    replay = [_finding(h["category"], h["severity"], h["title"], h["detail"], h.get("where") or CHANNEL)
              for h in kept]
    if answer is None:
        collection.failed("psscript", why)
        return replay + [_finding("visibility", "low", "PowerShell script blocks were not read",
                                  f"{why}; nothing was checked this pass and the read position was kept.",
                                  CHANNEL)]
    out = []
    reset = answer.get("newest") is not None and answer["newest"] < state["cursor"]
    if reset and not answer["errors"]:
        reread, why = reader(0)
        if reread is None or reread["errors"]:
            collection.failed("psscript", "log reset; reread failed")
            return replay + [_finding("visibility", "low", "PowerShell log reset could not be read",
                                      "The log record sequence reset; the previous cursor is retained until a valid reread.", CHANNEL)]
        answer = reread
        out.append(_finding("visibility", "low", "PowerShell log record sequence reset",
                            "The log was cleared or recreated. Earlier script evidence is unavailable; "
                            "reading restarted from the oldest retained record.", CHANNEL))
    if answer["errors"]:
        collection.failed("psscript", "; ".join(answer["errors"])[:160])
        return replay + [_finding("visibility", "low", "PowerShell script blocks were not read",
                                  "; ".join(answer["errors"]) + "; the read position was kept.", CHANNEL)]
    if answer["enabled"] is False and not answer["read"]:
        collection.failed("psscript", "script-block logging is off")
        return replay + [_finding(
            "visibility", "low", "PowerShell script-block logging is off",
            "Windows is not recording what PowerShell runs, so commands typed or run inside PowerShell "
            "are not seen by this check. Argus does not turn it on by itself: it records the text of "
            "every script on this computer. The hardening guide shows how to enable it.", CHANNEL)]
    if answer["enabled"] is False:
        out.append(_finding("visibility", "low", "PowerShell script-block logging is off",
                            "Only retained records were read. New scripts may not be recorded; logging was not enabled by Argus.", CHANNEL))
    cursor = 0 if reset else state["cursor"]
    lost = answer["oldest"] - cursor - 1 if cursor and answer["oldest"] > cursor + 1 else 0
    if lost > 0:
        out.append(_finding(
            "visibility", "low", "PowerShell history was overwritten before it was read",
            f"About {lost} records of the PowerShell log were overwritten between two passes, so scripts "
            f"run in that gap were not checked. The log holds {answer['log_bytes'] // (1024 * 1024)} MB and "
            f"is a ring. A larger log closes the gap (administrator): {RAISE_LOG}", CHANNEL))
    blocks = answer["blocks"]
    rows = [{"text": b["text"], "path": b["path"], "time": b["time"], "sha": b["sha"]} for b in blocks if b["complete"] and not b["truncated"]]

    def make(severity, title, detail, image):
        return _finding("technique", severity, title, detail, image or CHANNEL)

    found = community.findings(
        sigma.WIN_PS, rows,
        lambda r: (r["path"] or "PowerShell (no script file)", "", r["time"], ""),
        make, store=store, now=at)
    # A finding from this pass describes blocks read once; keep it for a day.
    new_hits = [{"ts": at, "category": f["category"], "severity": f["severity"], "title": f["title"][:300],
                 "detail": f["detail"][:700], "where": f.get("where") or CHANNEL}
                for f in found if "(community rule)" in f["title"]]
    fresh_titles = {(h["title"], h["where"]) for h in new_hits}
    replay = [f for f, h in zip(replay, kept) if (h["title"], h.get("where") or CHANNEL) not in fresh_titles]
    kept = [h for h in kept if (h["title"], h.get("where") or CHANNEL) not in fresh_titles]
    out = replay + found + out
    cut = sum(1 for b in blocks if b["truncated"] or not b["complete"])
    if cut:
        out.append(_finding(
            "visibility", "low", "Some PowerShell scripts were only partly checked",
            f"{cut} script block(s) were longer than {MAX_TEXT} characters or arrived incomplete; only the "
            "partial content was not evaluated because absence conditions would be unreliable.", CHANNEL))
    if answer["more"]:
        out.append(_finding(
            "visibility", "low", "PowerShell script blocks: more than one pass could read",
            f"This pass reached its limit ({MAX_EVENTS} records or {MAX_BLOCKS} blocks). The rest is read on "
            "the next pass unless the log overwrites it first.", CHANNEL))
    new_cursor = max(cursor, answer["last"]) if answer["read"] else cursor
    store.set_meta(META, json.dumps({"cursor": new_cursor, "hits": (kept + new_hits)[-KEEP_HITS:]},
                                    sort_keys=True))
    if cut or lost or answer["more"] or reset or answer["enabled"] is False:
        collection.failed("psscript", "script-block coverage incomplete; see visibility findings")
    else:
        collection.succeeded("psscript")
    return out
