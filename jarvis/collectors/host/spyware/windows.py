"""Windows: capability use (microphone, camera, location), unsigned or oddly signed
autostarts, known monitoring software, and input and audio control devices."""

import datetime
import re

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

from .common import INPUT_VENDORS, STALKERWARE, _finding
from .keyboard import _keyboard_findings

PS_SPY = load_win_script("spyware.ps1")


BAD_SIG = {"NotSigned", "HashMismatch", "NotTrusted", "UnknownError"}


TRUSTED_SIGNERS = re.compile(
    r"Microsoft (Corporation|Windows)|CN=Microsoft|Google LLC|Mozilla Corporation|"
    r"Intel Corporation|NVIDIA|Advanced Micro Devices|Realtek|Logitech|"
    r"Valve Corp|Riot Games|Proton AG|Dropbox|Adobe|Apple Inc|Cisco|"
    r"Discord|Spotify|Oracle|Citrix|VMware|Lenovo|Dell|HP Inc|ASUSTeK",
    re.I,
)


# What each capability actually exposes, which is what should decide how loudly
# it is reported. Windows tracks all of these identically; they are very far
# from equally sensitive.
SURVEILLANCE_CAPS = {
    "microphone", "webcam", "graphicsCaptureProgrammatic",
    "graphicsCaptureWithoutBorder", "userNotificationListener",
    "appDiagnostics", "humanInterfaceDevice", "gazeInput",
    "broadFileSystemAccess",
}


ROUTINE_CAPS = {
    "cellularData", "wifiData", "wiFiDirect", "radios", "bluetooth",
    "bluetoothSync", "musicLibrary", "picturesLibrary", "videosLibrary",
    "documentsLibrary", "usb", "serialCommunication", "sensors.custom",
    "activity", "userDataTasks", "systemAIModels",
}


CAP_TIER = ({c: "surveillance" for c in SURVEILLANCE_CAPS}
            | {c: "routine" for c in ROUTINE_CAPS})


# Windows' internal names do not say what the capability lets an app do.
CAP_LABEL = {
    "graphicsCaptureProgrammatic": "SCREEN CAPTURE (programmatic)",
    "graphicsCaptureWithoutBorder": "SCREEN CAPTURE (no capture border shown)",
    "userNotificationListener": "READS ALL YOUR NOTIFICATIONS",
    "appDiagnostics": "READS OTHER PROCESSES' DIAGNOSTIC INFO",
    "humanInterfaceDevice": "DIRECT HID ACCESS",
    "gazeInput": "EYE TRACKING",
    "broadFileSystemAccess": "YOUR ENTIRE FILE SYSTEM",
    "microphone": "MICROPHONE",
    "webcam": "CAMERA",
    "location": "location",
    "phoneCallHistory": "call history",
    "userAccountInformation": "your account details",
}


# Package families published by Microsoft: the suffix is a hash of the
# publisher, and Windows installs a package only when its signer matches.
# Past use of a capability by Windows' own apps (Snipping Tool) is a record.
MICROSOFT_FAMILY = re.compile(r"_(8wekyb3d8bbwe|cw5n1h2txyewy)(\\|$)", re.I)


def _recent(iso_ts, hours=24):
    """True when an ISO-8601 timestamp is within the last `hours`."""
    if not iso_ts:
        return False
    try:
        t = datetime.datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    if t.tzinfo is None:
        t = t.astimezone()
    delta = datetime.datetime.now(datetime.timezone.utc) - t.astimezone(
        datetime.timezone.utc)
    return datetime.timedelta(0) <= delta <= datetime.timedelta(hours=hours)


def audit_windows(now_iso=None):
    data = ps_json(PS_SPY, timeout=180)
    if data is None:
        return [_finding("access", "medium", "spyware audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. capability ledger ---------------------------------------------
    # Most recent first: "what touched the mic last" is the question being asked.
    caps = sorted(aslist(data.get("caps")),
                  key=lambda c: c.get("start") or "", reverse=True)
    routine = {}
    for c in caps:
        app = c.get("app") or "?"
        cap = c.get("cap") or "?"
        pretty = app.split("\\")[-1] if "\\" in app else app
        when = (c.get("start") or "").replace("T", " ")[:19]
        tier = CAP_TIER.get(cap, "personal")

        # Reading every capability means reading a lot of uninteresting ones.
        # Wi-Fi and cellular data access is how apps check connectivity; listing
        # sixteen of those individually buries the one that used the camera.
        if tier == "routine":
            routine.setdefault(cap, []).append(pretty)
            continue

        if c.get("inUse"):
            out.append(_finding(
                "access", "high" if tier == "surveillance" else "medium",
                f"{CAP_LABEL.get(cap, cap)} IN USE right now",
                f"{pretty} — since {when}", app))
        else:
            if STALKERWARE.search(app):
                sev = "high"
            elif tier == "surveillance" and _recent(c.get("start"), hours=24) \
                    and not MICROSOFT_FAMILY.search(app):
                sev = "medium"
            else:
                sev = "low"
            out.append(_finding(
                "access", sev, f"{CAP_LABEL.get(cap, cap)} used",
                f"{pretty} — last used {when}",
                f"{app}  until {(c.get('stop') or '').replace('T', ' ')[:19]}"))

    for cap, apps in sorted(routine.items()):
        out.append(_finding(
            "access", "low", f"{CAP_LABEL.get(cap, cap)} used",
            f"{len(apps)} app(s): {', '.join(sorted(set(apps))[:6])}"
            + (" …" if len(set(apps)) > 6 else ""),
            "CapabilityAccessManager"))

    if not caps:
        out.append(_finding("access", "low", "no capability history",
                            "no app has recorded use of any tracked capability "
                            "(or the consent store is not readable from here)",
                            "CapabilityAccessManager"))
    else:
        watched = sorted({c.get("cap") for c in caps} & set(SURVEILLANCE_CAPS))
        out.append(_finding(
            "access", "ok", "capability ledger read",
            f"{len(caps)} recorded uses across {len({c.get('cap') for c in caps})} "
            f"capabilities; surveillance-relevant ones present: "
            f"{', '.join(watched) or 'none'}",
            "CapabilityAccessManager"))

    # -- 2. autostart signatures ------------------------------------------
    for s in aslist(data.get("sigs")):
        path, status = s.get("path", ""), s.get("status", "")
        signer = s.get("signer") or ""
        name = path.split("\\")[-1]
        if STALKERWARE.search(path):
            out.append(_finding("spyware", "critical",
                                "autostart matches known monitoring software",
                                name, path))
            continue
        if status in BAD_SIG:
            # Unsigned in Program Files is sloppy vendor practice; unsigned in a
            # directory you can write to without prompting is the shape that
            # matters, because anything on the machine could have put it there.
            in_user_space = re.search(
                r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\", path, re.I)
            out.append(_finding(
                "signing", "critical" if in_user_space else "medium",
                f"autostart binary is unsigned ({status})",
                f"{name} — no verified publisher"
                + (", running from a user-writable directory" if in_user_space else ""),
                path))
        elif status == "Valid" and signer and not TRUSTED_SIGNERS.search(signer):
            cn = re.search(r"CN=([^,]+)", signer)
            out.append(_finding("signing", "low",
                                "autostart signed by an unfamiliar publisher",
                                f"{name} — {cn.group(1) if cn else signer[:60]}", path))

    # -- 3. input / audio control -----------------------------------------
    # Windows creates one consumer-control node per HID collection, so a single
    # keyboard or headset shows up several times. Collapse them, and report the
    # count -- a device with a stuck or oversensitive volume control is by far
    # the most common cause of volume changing on its own.
    hid = aslist(data.get("hid"))
    grouped = {}
    for h in hid:
        key = (h.get("name") or "", h.get("mfr") or "")
        grouped.setdefault(key, []).append(h.get("id", ""))
    for (nm, mfr), ids in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        n = len(ids)
        out.append(_finding(
            "input", "low", "device can send volume/media commands",
            f"{nm}" + (f"  [{mfr}]" if mfr else "")
            + (f"  ×{n} endpoints" if n > 1 else ""),
            "; ".join(ids[:4])))
    if hid:
        out.append(_finding(
            "input", "low", "volume changing on its own",
            f"{len(grouped)} distinct device(s) here can send volume commands — "
            f"unplug them one at a time to rule out a stuck media key before "
            f"suspecting software", "physical-first triage"))

    procs = aslist(data.get("procs"))
    for p in procs:
        blob = f"{p.get('name')} {p.get('path') or ''}"
        if STALKERWARE.search(blob):
            out.append(_finding("spyware", "critical", "monitoring software running",
                                f"{p.get('name')} [pid {p.get('pid')}]",
                                p.get("path") or ""))
        elif INPUT_VENDORS.search(blob):
            out.append(_finding("input", "low", "input/media control software running",
                                f"{p.get('name')} [pid {p.get('pid')}]",
                                p.get("path") or ""))

    for a in aslist(data.get("audio")):
        if a.get("status") not in ("OK", None):
            out.append(_finding("input", "medium", "audio device not healthy",
                                f"{a.get('name')} — {a.get('status')}", ""))

    out.extend(_keyboard_findings(data))
    return out
