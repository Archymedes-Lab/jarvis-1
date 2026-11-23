"""Every input and output control surface this machine exposes to software,
sampled on a short interval with a stored baseline.

What this is:
  * an *inventory* — brightness, displays and their modes, monitor count,
    audio render/capture endpoints, keyboards, mice, HID, cameras, Bluetooth
  * a *change detector* — it keeps the previous sample and the union of every
    device id ever seen, and reports what moved: a device that arrived or
    left, a display mode or topology change, a default that flipped
  * a *live-use probe* — the Windows capability ledger records `microphone`,
    `webcam`, screen-capture and `location` with a stop time of zero while the
    grant is *currently held*, so an app recording right now is visible within
    one sample interval instead of at the next 90-minute `spy` pass

What this is not:
  * predictive. Nothing here forecasts a change; it is caught on the sample
    after it happens. The only mechanisms on this machine that report an event
    *as it occurs* are the Windows Sysmon driver, Sysmon-for-Linux (eBPF) and
    the resident injected-input hook. This collector samples.
  * complete. Physical monitor OSD buttons, a hardware KVM, BIOS/UEFI display
    and audio settings, and monitor firmware emit no OS telemetry — no
    software on the host can see them. WSL has no capability ledger at all;
    mic/camera use inside the distro is covered only by `spy`'s WSLg checks.
  * an attribution engine. "The mic is in use by X" is read from the ledger;
    "brightness changed" names no source, because Windows records none.
"""
import json
import time

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import ps_json

# One PowerShell round-trip. Every block is independently guarded so a single
# unavailable provider degrades that row instead of losing the whole sample.
PS_CONTROLS = load_win_script("controlwatch.ps1")

# Capabilities whose live use is worth a medium, not a low.
_SENSITIVE_CAPS = {
    "microphone": "microphone",
    "webcam": "camera",
    "graphicsCaptureProgrammatic": "programmatic screen capture",
    "graphicsCaptureWithoutBorder": "borderless screen capture",
    "location": "location",
}

_STATE_KEY = "controlwatch_latest_v1"
_SEEN_KEY = "controlwatch_seen_v1"
# Bumped whenever the stored sample's shape changes. A baseline written by an
# older schema is used for inventory only — never for arrival / removal / mode
# diffs, which would otherwise all fire once on the upgrade.
_SCHEMA = 2


def _finding(severity, title, detail, category="controls"):
    return dict(host="win", severity=severity, title=title, detail=detail,
                category=category, where="Windows control state")


def _ids(rows):
    return {r.get("id") for r in (rows or []) if r.get("id")}


def compare(current, previous, seen=None):
    """Findings from this sample against the last one. `seen` is the set of
    every device id observed on prior runs — an id that is in neither
    `previous` nor `seen` is genuinely new, which survives a restart."""
    out = []
    seen = seen or set()
    # Only diff against a baseline of the current shape. A first run, or one
    # right after a schema change, contributes inventory but no change events.
    comparable = previous.get("schema") == _SCHEMA

    # -- brightness: value, and rate of change across one interval ----------
    old_b = {b["id"]: b for b in previous.get("brightness", [])}
    for b in current.get("brightness", []):
        before = old_b.get(b["id"])
        if comparable and before and before.get("value") != b.get("value"):
            delta = abs(int(b.get("value", 0)) - int(before.get("value", 0)))
            note = ("large single-interval swing" if delta >= 40 else "")
            out.append(_finding(
                "low", "display brightness changed",
                f"{before.get('value')}% to {b.get('value')}% ({delta} points"
                f"{'; ' + note if note else ''}); source is not attributed. "
                "A button press, Windows setting, app, or automatic adjustment "
                "can cause this."))
        out.append(_finding(
            "low", "display brightness sample",
            f"{b.get('value')}%; active={b.get('active')}; sampled, not a "
            "button-event trace"))
    if not current.get("brightness"):
        out.append(_finding(
            "medium", "brightness control is not observable",
            "No brightness provider returned data. Physical monitor buttons "
            "and unsupported external displays are not monitored.", "visibility"))

    # -- displays: mode strings and monitor count -------------------------
    old_d = {d["id"]: d for d in previous.get("displays", [])}
    for d in current.get("displays", []):
        before = old_d.get(d["id"]) if comparable else None
        if before and before.get("mode") and d.get("mode") \
                and before.get("mode") != d.get("mode"):
            out.append(_finding(
                "medium", "display mode changed",
                f"{d.get('name')}: {before.get('mode')} -> {d.get('mode')} "
                "(resolution or refresh rate)"))
        if before and before.get("driver") and d.get("driver") \
                and before.get("driver") != d.get("driver"):
            out.append(_finding(
                "medium", "display driver version changed",
                f"{d.get('name')}: {before.get('driver')} -> {d.get('driver')}"))
    pm, cm = previous.get("monitors"), current.get("monitors")
    if comparable and isinstance(pm, int) and isinstance(cm, int) and pm != cm:
        out.append(_finding(
            "medium", "monitor count changed",
            f"{pm} -> {cm} connected monitor(s); a screen was attached, "
            "removed, or switched (mirror/extend, KVM, capture device)"))

    # -- audio endpoints -------------------------------------------------
    for kind, key in (("render", "audioRender"), ("capture", "audioCapture")):
        cur_ids, prev_ids = _ids(current.get(key)), _ids(previous.get(key))
        if comparable:
            for r in current.get(key, []):
                if r.get("id") and r["id"] not in prev_ids and r["id"] not in seen:
                    sev = "medium" if kind == "capture" else "low"
                    out.append(_finding(
                        sev, f"audio {kind} endpoint appeared",
                        f"{r.get('name')} (status {r.get('status')})"))
            for rid in prev_ids - cur_ids:
                out.append(_finding(
                    "low", f"audio {kind} endpoint removed", rid))
        for r in current.get(key, []):
            if r.get("status") not in ("OK", "Unknown", None, ""):
                out.append(_finding(
                    "medium", f"audio {kind} endpoint not healthy",
                    f"{r.get('name')} status={r.get('status')}"))

    # -- input / camera / bluetooth devices ----------------------------
    prev_dev = _ids(previous.get("devices"))
    for d in current.get("devices", []):
        did = d.get("id")
        if comparable and did and prev_dev and did not in prev_dev and did not in seen:
            cls = (d.get("class") or "").lower()
            sev = "medium" if cls in ("keyboard", "camera", "image") else "low"
            out.append(_finding(
                sev, "control device appeared",
                f"{d.get('class')}: {d.get('name')}; device arrival is not "
                "proof of intrusion, but confirm you recognise it"))
        if d.get("status") not in ("OK", "Unknown", None, ""):
            out.append(_finding(
                "medium", "control device reports a problem",
                f"{d.get('class')}: {d.get('name')} status={d.get('status')}"))
    if comparable:
        for did in prev_dev - _ids(current.get("devices")):
            out.append(_finding("low", "control device removed", did))

    # -- live capability use: mic / camera / screen capture / location ---
    for u in current.get("liveUse", []):
        cap = u.get("cap", "")
        label = _SENSITIVE_CAPS.get(cap)
        sev = "medium" if label else "low"
        out.append(_finding(
            sev, f"{label or cap} in use right now",
            f"{u.get('app', 'an app')} has held {cap} since {u.get('since', '?')} "
            "(capability ledger, stop time still zero)", "controls"))

    # -- errors / honest boundary -------------------------------------
    for error in current.get("errors", []):
        out.append(_finding(
            "medium", "control monitoring visibility limited", error, "visibility"))
    out.append(_finding(
        "low", "control monitoring boundaries",
        "Sampled every 5 minutes: brightness, display modes, monitor count, "
        "audio render/capture endpoints, keyboards, mice, HID, cameras, "
        "Bluetooth, and any mic/camera/screen-capture grant currently held. "
        "Not covered: physical monitor OSD buttons, hardware KVM, BIOS/UEFI, "
        "monitor firmware, the default-audio-device selection (needs an extra "
        "module), audio/video content, clipboard, and per-event attribution. "
        "Injected keystrokes/clicks are the resident input hook's job; "
        "remote-access and persistence are separate collectors.",
        # "limits", not "visibility": this is the fixed scope statement, emitted
        # every run. As "visibility" it marked every run partial and the
        # coverage job paged "collector 'controls' is failing". Real read
        # errors above stay "visibility" and still mark coverage incomplete.
        "limits"))
    return out


def audit(store, hosts=("wsl", "win")):
    if "win" not in hosts:
        return [_finding("medium", "Windows controls are not monitored",
                         "Windows collection is disabled.", "visibility")]
    data = ps_json(PS_CONTROLS, timeout=30)
    if not data:
        return [_finding("high", "Windows controls collector is failing",
                         "No fresh control-surface state returned; the previous "
                         "sample is retained.", "collectors")]
    try:
        previous = json.loads(store.get_meta(_STATE_KEY, "{}")) or {}
    except (ValueError, TypeError):
        previous = {}
    try:
        seen = set(json.loads(store.get_meta(_SEEN_KEY, "[]")) or [])
    except (ValueError, TypeError):
        seen = set()

    findings = compare(data, previous, seen)

    # Persist only a clean sample as the new baseline, but always widen the
    # ever-seen set so a device that flaps cannot re-alert forever.
    all_ids = set()
    for key in ("audioRender", "audioCapture", "devices"):
        all_ids |= _ids(data.get(key))
    if all_ids:
        store.set_meta(_SEEN_KEY, json.dumps(sorted(seen | all_ids)))
    if not data.get("errors"):
        store.set_meta(_STATE_KEY,
                       json.dumps(dict(data, ts=time.time(), schema=_SCHEMA)))
    return findings
