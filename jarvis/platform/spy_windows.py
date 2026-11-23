"""Windows spyware evidence: parse the read-only payload into reasoning subjects.

`collect()` runs the payload; `build()` is pure and takes its JSON, so every
mapping is testable against fixtures. Capture consent history is per
executable and only says a capability was used recently, not by whom in what
way. A capability that is not consent-gated is not represented at all.
"""

import re

from jarvis.core.paths import load_win_script
from jarvis.core.reasoning.vocab import SCRIPT_HOSTS, Observation, Subject, is_masquerade
from jarvis.platform.windows import ps_json

PS_SPY = load_win_script("spy_evidence.ps1")
SOURCE = "windows"
RECENT_HOURS = 24
CONSENT_KINDS = {"microphone": "cap.audio.mic", "webcam": "cap.video.camera",
                 "graphicsCaptureProgrammatic": "cap.screen.capture",
                 "graphicsCaptureWithoutBorder": "cap.screen.capture"}
MAX_PROCESSES = 4096


def collect(timeout=240):
    return ps_json(PS_SPY, timeout=timeout)


def path_class(path):
    p = (path or "").lower().replace("/", "\\")
    if not p:
        return "unknown"
    if "\\appdata\\local\\temp\\" in p or p.startswith(("c:\\windows\\temp\\", "c:\\temp\\")):
        return "temp"
    if p.startswith("c:\\program files\\windowsapps\\"):
        return "store_package"
    if p.startswith("c:\\windows\\"):
        return "os"
    if p.startswith(("c:\\program files\\", "c:\\program files (x86)\\")):
        return "program_files"
    if p.startswith(("c:\\users\\", "c:\\programdata\\")):
        return "user_writable"
    return "unknown"


_EXE = re.compile(r'^\s*"?([A-Za-z]:\\[^"]*?\.exe)', re.I)


def _exe(command):
    m = _EXE.match(command or "")
    return m.group(1).lower() if m else None


def _consent_index(consent):
    """(lowercase exe path -> {kind}), (package family name -> {kind}) for recent use."""
    by_path, by_pkg = {}, {}
    for cap, rows in (consent or {}).items():
        kind = CONSENT_KINDS.get(cap)
        if not kind:
            continue
        for row in rows or []:
            hrs = row.get("hrs")
            if not isinstance(hrs, (int, float)) or hrs > RECENT_HOURS:
                continue
            who = str(row.get("who") or "")
            if row.get("np"):
                by_path.setdefault(who.replace("#", "\\").lower(), set()).add(kind)
            else:
                by_pkg.setdefault(who.split("_", 1)[0].lower(), set()).add(kind)
    return by_path, by_pkg


def _package_name(path):
    m = re.search(r"\\windowsapps\\([^\\_]+)_", (path or "").lower())
    return m.group(1) if m else None


def build(data, boot_id=""):
    """Subjects from one payload. An unusable payload yields nothing, not clean subjects."""
    if not isinstance(data, dict) or not isinstance(data.get("procs"), list):
        return [], {"status": "unavailable", "processes": 0}
    by_path, by_pkg = _consent_index(data.get("consent"))
    auto = {p for p in (_exe(c) for c in data.get("autostart") or []) if p}
    subjects = []
    for p in data["procs"][:MAX_PROCESSES]:
        pid = p.get("pid")
        if not isinstance(pid, int) or pid <= 4:
            continue
        path = p.get("path") or ""
        low = path.lower()
        obs = []
        for kind in sorted(by_path.get(low, set()) | by_pkg.get(_package_name(path) or "", set())):
            obs.append(Observation(kind, "consent-store"))
        if path and is_masquerade(p.get("name"), path_class(path)):
            obs.append(Observation("conceal.masquerade", "identity"))
        if low and low in auto:
            obs.append(Observation("persist.autostart", "autostart"))
        if p.get("ext"):
            obs.append(Observation("egress.external", "tcp"))
        if p.get("window") is False and p.get("session", 0) != 0 and low:
            obs.append(Observation("conceal.no_ui", "window"))
        signature = p.get("sig") if p.get("sig") in ("valid", "invalid", "none", "unknown") else "unknown"
        subjects.append(Subject(
            key=f"win:{boot_id}:{pid}:{p.get('started') or 'unknown-start'}", host="win",
            label=p.get("name") or "", signature=signature, publisher=p.get("signer") or "",
            path_class=path_class(path), age_days=p.get("age") if isinstance(p.get("age"), int) else None,
            has_window=p.get("window") if isinstance(p.get("window"), bool) else None,
            runs_script=(path.replace("/", "\\").rsplit("\\", 1)[-1].lower() in SCRIPT_HOSTS),
            observations=obs))
    return subjects, {"status": "complete", "processes": len(subjects),
                      "consent_rows": sum(len(v or []) for v in (data.get("consent") or {}).values())}
