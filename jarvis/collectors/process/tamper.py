"""Tamper audit: attempts to blind or disarm the machine's own defenses.

Reads Windows' own records (platform/win/tamper.ps1, read-only, unelevated)
and reports what an intruder does to stop being seen before it does anything
else:

  * a Defender exclusion added, so a folder, file type or process is never
    scanned (ATT&CK T1679 Selective Exclusion), named with the process that
    wrote it where Sysmon recorded the registry write;
  * Defender protection switched off or weakened, and tamper protection
    blocking an attempt to do so (T1685 Disable or Modify Tools; ATT&CK split
    the retired T1562 into T1685-T1690);
  * a security product crashing or its service dying, the symptom MITRE's
    analytic for T1687 Exploitation for Defense Impairment looks for;
  * Sysmon stopped, its configuration replaced, or a security service set to
    disabled (T1685);
  * the System or Security event log cleared (T1685.005, formerly T1070.001);
  * an ETW autologger session behind the event logs or Defender switched off
    at boot, which silences logging below every collector (T1685).

Measured on this machine before any rule was written (2026-10-11): 63 Defender
configuration changes in 24 h, every one routine (diagnostics, cloud lookup
timestamps, service start states), so only the keys that weaken protection are
judged. Sysmon logs "Started" at each boot and Security logs 1100 at each
shutdown; neither is reported. Unreadable sources are reported as unknown,
never as clean. Classification only: nothing here changes the machine.
"""

import re

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

PS_TAMPER = load_win_script("tamper.ps1")

# Defender registry values under these keys decide what is never scanned.
EXCLUSION_KEY = re.compile(
    r"\\Windows Defender\\Exclusions\\(Paths|Extensions|Processes|IpAddresses|TemporaryPaths)\\(.+)",
    re.I)
# (key pattern, value that weakens protection). A value is weakening when it
# matches; other writes to the same key (turning protection back on) are not.
WEAKENING = (
    (re.compile(r"\\Real-Time Protection\\(Disable\w+)$", re.I), re.compile(r"^(0x0*1|1)$")),
    (re.compile(r"\\Windows Defender\\(DisableAntiSpyware|DisableAntiVirus)$", re.I),
     re.compile(r"^(0x0*1|1)$")),
    (re.compile(r"\\Spynet\\(SpyNetReporting|SubmitSamplesConsent)$", re.I),
     re.compile(r"^(0x0*0|0)$")),
    (re.compile(r"\\Features\\(TamperProtection)$", re.I), re.compile(r"^(0x0*[04]|0|4)$")),
)
# Defender events that state protection was turned off, and the attempt that
# tamper protection blocked.
DEFENDER_OFF = {5001: "real-time protection was turned off",
                5010: "scanning for spyware and other unwanted software was turned off",
                5012: "scanning for viruses was turned off"}
TAMPER_BLOCKED = 5013
# Display names of the services whose death blinds this machine.
SECURITY_SERVICES = re.compile(
    r"(Sysmon\w*|Windows Event Log|Microsoft Defender[\w ]*|Windows Defender[\w ]*|"
    r"Security Center|JarvisNativeSensor|JarvisSensor)", re.I)
# A crash of one of these is high on its own; another security component's
# single crash is medium, high once it repeats in the window.
CORE_SECURITY = re.compile(r"^(MsMpEng|Sysmon(64)?|JarvisNativeSensor|JarvisSensor)\.exe$", re.I)
EXCEPTIONS = {"0xc0000409": "stack buffer overrun or fail-fast abort: an exploit's corruption "
                            "being caught, or a program aborting itself (low memory does this)",
              "0xc0000005": "access violation", "0xc00000fd": "stack overflow"}


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


def _new_value(msg):
    """(key, value) from a 5007 message's "New value:" line, or ("", "")."""
    m = re.search(r"New value:\s*(.+?)(?:\r?\n|$)", msg or "", re.I)
    if not m:
        return "", ""
    text = m.group(1).strip()
    key, _, value = text.partition(" = ")
    return key.strip(), value.strip()


def _writer(writers, key, when):
    """Image that Sysmon saw writing `key` just before `when`, or ""."""
    tail = key.split("\\Windows Defender\\", 1)[-1].lower()
    for w in aslist((writers or {}).get("events")):
        target = str(w.get("target") or "").lower()
        if tail and tail in target and str(w.get("t") or "") <= when:
            return str(w.get("image") or "")
    return ""


def _source_findings(data):
    """A source that could not be read is unknown, never clean."""
    out = []
    for name, label in (("defender", "Defender operational log"),
                        ("sysmon", "Sysmon operational log"),
                        ("services", "System log service events"),
                        ("system_clear", "System log clear events"),
                        ("app_crashes", "Application log crash events")):
        src = data.get(name)
        if not isinstance(src, dict) or not src.get("ok", False):
            err = (src or {}).get("error") if isinstance(src, dict) else "missing"
            out.append(_finding("visibility", "medium", f"Tamper audit could not read the {label}",
                                f"tampering recorded there is unknown, not absent ({err or 'no answer'})",
                                name))
    sec = data.get("security")
    if isinstance(sec, dict) and not sec.get("ok", False):
        out.append(_finding("visibility", "low", "Tamper audit could not read the Security log",
                            "a cleared Security log (event 1102) cannot be seen without "
                            "Event Log Readers membership", "security"))
    return out


def findings(data):
    """Classify one tamper.ps1 payload. Pure: no I/O."""
    if not isinstance(data, dict):
        return [_finding("visibility", "medium", "Tamper audit unavailable",
                         "powershell.exe returned no data; tampering is unknown, not absent",
                         "interop")]
    out = _source_findings(data)
    writers = data.get("writers")

    for e in aslist((data.get("defender") or {}).get("events")):
        eid, when, msg = int(e.get("id") or 0), str(e.get("t") or ""), str(e.get("msg") or "")
        if eid == 5007:
            key, value = _new_value(msg)
            excl = EXCLUSION_KEY.search(key)
            if excl:
                who = _writer(writers, key, when)
                out.append(_finding(
                    "tamper", "high",
                    f"Defender exclusion added: {excl.group(2)} (T1679)",
                    f"Defender will no longer scan this {excl.group(1).lower().rstrip('s')} "
                    f"(set {when}); "
                    + (f"written by {who}" if who else "the writing process was not recorded")
                    + ". Malware is placed in excluded locations so it is never examined.",
                    key))
                continue
            for pattern, bad in WEAKENING:
                m = pattern.search(key)
                if m and bad.search(value):
                    who = _writer(writers, key, when)
                    out.append(_finding(
                        "tamper", "high", f"Defender protection weakened: {m.group(1)} (T1685)",
                        f"{m.group(1)} set to {value} at {when}; "
                        + (f"written by {who}" if who else "the writing process was not recorded"),
                        key))
                    break
        elif eid in DEFENDER_OFF:
            out.append(_finding("tamper", "high", f"Defender {DEFENDER_OFF[eid]} (T1685)",
                                f"Defender event {eid} at {when}", "Defender"))
        elif eid == TAMPER_BLOCKED:
            out.append(_finding("tamper", "high",
                                "Tamper protection blocked a change to Defender (T1685)",
                                f"something tried to change a protected Defender setting at {when}: "
                                + msg[:300], "Defender"))

    for e in aslist((data.get("sysmon") or {}).get("events")):
        eid, when, msg = int(e.get("id") or 0), str(e.get("t") or ""), str(e.get("msg") or "")
        if eid == 4 and re.search(r"State:\s*Stopped", msg, re.I):
            out.append(_finding("tamper", "high", "Sysmon service stopped (T1685)",
                                f"Sysmon stopped at {when}; process, network and registry "
                                "activity is not recorded while it is down", "Sysmon"))
        elif eid == 16:
            out.append(_finding("tamper", "medium", "Sysmon configuration changed (T1685)",
                                f"Sysmon's rules were replaced at {when}; a replaced configuration "
                                "can stop recording anything chosen. Expected only when JARVIS "
                                "applies its own policy.", "Sysmon"))

    for e in aslist((data.get("services") or {}).get("events")):
        eid, when, msg = int(e.get("id") or 0), str(e.get("t") or ""), str(e.get("msg") or "")
        svc = SECURITY_SERVICES.search(msg)
        if not svc:
            continue
        name = svc.group(1)
        if eid == 7034:
            out.append(_finding("tamper", "high", f"{name} terminated unexpectedly (T1687)",
                                f"the {name} service died at {when}. Crashing or killing a security "
                                "service is how an exploit against it shows; it is a symptom, "
                                "the exploit itself is not observed.", name))
        elif eid == 7040 and re.search(r"to disabled", msg, re.I):
            out.append(_finding("tamper", "high", f"{name} set to disabled (T1685)",
                                f"the start type of {name} was changed to disabled at {when}", name))

    crashes = []
    for e in aslist((data.get("app_crashes") or {}).get("events")):
        msg = str(e.get("msg") or "")
        app = re.search(r"Faulting application name:\s*([^,\r\n]+)", msg, re.I)
        code = re.search(r"Exception code:\s*(0x[0-9a-fA-F]+)", msg)
        crashes.append(((app.group(1).strip() if app else "unknown"),
                        (code.group(1).lower() if code else ""), str(e.get("t") or "")))
    for app in sorted({c[0] for c in crashes}):
        mine = [c for c in crashes if c[0] == app]
        code = mine[0][1]
        meaning = EXCEPTIONS.get(code, "")
        severe = bool(CORE_SECURITY.match(app)) or len(mine) > 1
        out.append(_finding(
            "tamper", "high" if severe else "medium",
            f"Security software crashed: {app} (T1687)",
            f"{len(mine)} crash(es) in 24 h, latest {mine[0][2]}"
            + (f", exception {code}" + (f" ({meaning})" if meaning else "") if code else "")
            + ". A security product crashing is the symptom of an exploit against it; the "
            "exploit itself is not observed.", "Application log"))

    for e in aslist((data.get("system_clear") or {}).get("events")):
        out.append(_finding("tamper", "high", "System event log cleared (T1685)",
                            f"the System log was cleared at {e.get('t')}", "System log"))
    for e in aslist((data.get("security") or {}).get("events")):
        if int(e.get("id") or 0) == 1102:
            out.append(_finding("tamper", "high", "Security event log cleared (T1685)",
                                f"the Security audit log was cleared at {e.get('t')}", "Security log"))

    for a in aslist(data.get("autologgers")):
        name = str(a.get("name") or "?")
        if a.get("exists") and int(a.get("start", -1)) == 0:
            out.append(_finding("tamper", "high", f"ETW session {name} disabled at boot (T1685)",
                                f"{name} has Start=0, so from the next boot the logging it feeds "
                                "is silent below every collector", name))
        disabled = [str(p) for p in aslist(a.get("disabled"))]
        if disabled:
            out.append(_finding("tamper", "high", f"Providers switched off in ETW session {name} (T1685)",
                                f"{len(disabled)} provider(s) set Enabled=0: {', '.join(disabled[:5])}",
                                name))

    if not any(f["severity"] in ("high", "medium") for f in out):
        out.append(_finding("tamper", "ok", "No attempt to blind the defenses recorded",
                            "Defender settings, Sysmon, security services, log clears and ETW "
                            "autologgers were read; nothing weakened them in the window", ""))
    return out


def audit(data=None):
    """`data` replays a payload (the coverage map's probes); None reads Windows."""
    if data is None:
        data = ps_json(PS_TAMPER, timeout=120)
    return findings(data)
