"""Microphone, camera and peripheral consent posture, with an owner-declared seal.

The daemon path is read-only: every five minutes it reads the Windows consent
store (user and machine hives), the AppPrivacy policy values, present camera
and Bluetooth devices and the capture endpoint states, keeps the previous
sample, and reports what moved. It never writes.

A *seal* is the owner's declared posture, written through `jarvis privacy
seal`: microphone and camera access set to Deny for Store and desktop apps in
the owner's own hive, with the previous values recorded so `unseal` restores
exactly them. While a seal is declared, anything that opens the surface again
is a high finding: a value that no longer reads Deny, a policy forcing Allow,
or a ledger entry that started after the seal. The collector never says who
changed a value; Windows records no writer here.

What the seal is not: the consent gate is enforced by Windows user-mode
services. Kernel streaming, a driver, or an administrator editing the
registry are not stopped, only seen. Hardware kill switches are stronger.
"""
import json
import time

from jarvis.core import collection
from jarvis.core.paths import load_win_script
from jarvis.platform.windows import ps_json, stdin_text

PS_READ = load_win_script("privacy_seal.ps1")
PS_APPLY = load_win_script("privacy_seal_apply.ps1")

STATE_KEY = "privacyseal_latest_v1"
SEAL_KEY = "privacyseal_declared_v1"
HISTORY_KEY = "privacyseal_history_v1"
HISTORY_KEEP = 50

CAPS = ("microphone", "webcam", "location",
        "graphicsCaptureProgrammatic", "graphicsCaptureWithoutBorder")
SEALABLE = ("microphone", "webcam")
LABEL = {"microphone": "microphone", "webcam": "camera", "location": "location",
         "graphicsCaptureProgrammatic": "programmatic screen capture",
         "graphicsCaptureWithoutBorder": "borderless screen capture"}
POLICY_OF = {"microphone": "LetAppsAccessMicrophone", "webcam": "LetAppsAccessCamera",
             "location": "LetAppsAccessLocation"}
# AppPrivacy policy: 0 user control, 1 force allow, 2 force deny.
POLICY_FORCE_ALLOW = 1
POLICY_FORCE_DENY = 2
LOOPBACK_NAMES = ("stereo mix", "what u hear", "loopback", "wave out mix")
# MMDevices DeviceState low nibble: 1 active, 2 disabled, 4 not present, 8 unplugged.
ENDPOINT_ACTIVE = 1
_MAX_APPS = 128
_MAX_DEVICES = 64
_FILETIME_EPOCH = 116444736000000000


def _finding(severity, title, detail, category="privacy"):
    return {"host": "win", "severity": severity, "title": title,
            "detail": detail, "category": category,
            "where": "Windows privacy settings"}


def _text(value):
    return value is None or (isinstance(value, str) and len(value) <= 64)


def _valid(data):
    if not isinstance(data, dict) or not isinstance(data.get("caps"), dict):
        return False
    if set(data["caps"]) != set(CAPS):
        return False
    for row in data["caps"].values():
        if not isinstance(row, dict) or not isinstance(row.get("apps"), list):
            return False
        for slot in ("user", "machine"):
            hive = row.get(slot)
            if (not isinstance(hive, dict) or not _text(hive.get("global"))
                    or not _text(hive.get("nonpackaged"))):
                return False
        if len(row["apps"]) > _MAX_APPS:
            return False
        for app in row["apps"]:
            if (not isinstance(app, dict) or not isinstance(app.get("name"), str)
                    or not 0 < len(app["name"]) <= 512
                    or app.get("kind") not in ("packaged", "desktop")
                    or app.get("hive") not in ("user", "machine")
                    or not _text(app.get("value"))
                    or not isinstance(app.get("start"), int) or app["start"] < 0
                    or not isinstance(app.get("stop"), int) or app["stop"] < 0):
                return False
    policy = data.get("policy")
    if not isinstance(policy, dict) or any(
            not (value is None or isinstance(value, int) and not isinstance(value, bool))
            for value in policy.values()):
        return False
    if not isinstance(data.get("devices"), list) or len(data["devices"]) > _MAX_DEVICES:
        return False
    if any(not isinstance(d, dict) or not isinstance(d.get("id"), str)
           or not isinstance(d.get("class"), str) or not isinstance(d.get("status"), str)
           for d in data["devices"]):
        return False
    endpoints = data.get("captureEndpoints")
    if not isinstance(endpoints, list) or len(endpoints) > _MAX_DEVICES:
        return False
    if any(not isinstance(e, dict) or not isinstance(e.get("id"), str)
           or not isinstance(e.get("name"), str)
           or not isinstance(e.get("state"), int) or not 0 <= e["state"] <= 15
           for e in endpoints):
        return False
    errors = data.get("errors")
    return (isinstance(errors, list) and len(errors) <= 16
            and all(isinstance(e, str) and len(e) <= 160 for e in errors))


def _filetime_to_unix(value):
    return (value - _FILETIME_EPOCH) / 1e7 if value > _FILETIME_EPOCH else 0.0


def _effective(cap_row, slot="user"):
    hive = cap_row.get(slot) or {}
    return hive.get("global"), hive.get("nonpackaged")


def _is_deny(value):
    return isinstance(value, str) and value.lower() == "deny"


def _is_open(value):
    """A missing value is Allow to Windows; only an explicit Deny closes it."""
    return not _is_deny(value)


def load_seal(store):
    try:
        seal = json.loads(store.get_meta(SEAL_KEY, "") or "null")
    except (ValueError, TypeError):
        return None
    if not isinstance(seal, dict) or not isinstance(seal.get("caps"), dict):
        return None
    return seal


def _record(store, event):
    try:
        history = json.loads(store.get_meta(HISTORY_KEY, "[]")) or []
    except (ValueError, TypeError):
        history = []
    history.append(dict(event, ts=time.time()))
    store.set_meta(HISTORY_KEY, json.dumps(history[-HISTORY_KEEP:]))


def _seal_findings(current, seal, previous):
    findings = []
    declared = float(seal.get("declared") or 0)
    # A finished use is news once; only a grant still held repeats each pass.
    already = {(cap, a["kind"], a["name"], a["start"])
               for cap, row in (previous.get("caps") or {}).items()
               if previous.get("schema") == 1
               for a in row.get("apps", []) if isinstance(a, dict)}
    for cap in sorted(seal["caps"]):
        if cap not in current["caps"]:
            continue
        row = current["caps"][cap]
        label = LABEL.get(cap, cap)
        glob, desktop = _effective(row)
        if _is_open(glob) or _is_open(desktop):
            findings.append(_finding(
                "high", f"privacy seal broken: {label} access re-enabled",
                f"user hive reads global={glob or 'unset'}, desktop apps="
                f"{desktop or 'unset'}; the seal declared Deny. The writer is not "
                "recorded by Windows. Re-apply with: jarvis privacy seal"))
        machine_global, _ = _effective(row, "machine")
        policy_name = POLICY_OF.get(cap)
        policy = current["policy"].get(policy_name) if policy_name else None
        if policy == POLICY_FORCE_ALLOW:
            findings.append(_finding(
                "high", f"privacy seal overridden: policy forces {label} access",
                f"{policy_name}=1 in the machine policy overrides the user Deny; "
                "removing it needs an administrator"))
        elif not _is_deny(machine_global) and machine_global:
            pass  # machine Allow defers to the user value; nothing to add.
        used_after = [app for app in row["apps"]
                      if app["start"] and _filetime_to_unix(app["start"]) > declared
                      and (app["start"] > app["stop"] or
                           (cap, app["kind"], app["name"], app["start"]) not in already)]
        for app in sorted(used_after, key=lambda a: a["start"])[:8]:
            live = " and is still holding it" if app["start"] > app["stop"] else ""
            findings.append(_finding(
                "high", f"{label} used after the privacy seal",
                f"{app['kind']} app {app['name']} started using the {label} at "
                f"{_iso(app['start'])}{live}; the ledger says the gate was passed. "
                "Either the seal was reopened at that time or the app bypasses the "
                "consent gate"))
    return findings


def _iso(filetime):
    unix = _filetime_to_unix(filetime)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(unix)) if unix else "unknown"


def _posture_findings(current, seal):
    findings = []
    sealed = set(seal["caps"]) if seal else set()
    for cap in SEALABLE:
        if cap in sealed:
            continue
        row = current["caps"][cap]
        label = LABEL[cap]
        glob, desktop = _effective(row)
        desktop_apps = sum(1 for a in row["apps"] if a["kind"] == "desktop" and a["start"])
        packaged = sum(1 for a in row["apps"] if a["kind"] == "packaged" and a["start"])
        if _is_open(glob):
            findings.append(_finding(
                "low", f"{label} access is open",
                f"global={glob or 'unset'}, desktop apps={desktop or 'unset'}; "
                f"{desktop_apps} desktop and {packaged} Store app(s) have used it. "
                "Close it reversibly with: jarvis privacy seal"))
        policy_name = POLICY_OF[cap]
        if current["policy"].get(policy_name) == POLICY_FORCE_ALLOW:
            findings.append(_finding(
                "medium", f"policy forces {label} access for every app",
                f"{policy_name}=1 removes the user's ability to deny; unusual "
                "outside managed devices"))
    return findings


def _change_findings(current, previous, seal):
    findings = []
    if previous.get("schema") != 1:
        return findings
    sealed = set(seal["caps"]) if seal else set()
    for cap in CAPS:
        before, after = previous["caps"].get(cap), current["caps"].get(cap)
        if not before or not after:
            continue
        for slot in ("user", "machine"):
            for key in ("global", "nonpackaged"):
                old = (before.get(slot) or {}).get(key)
                new = (after.get(slot) or {}).get(key)
                if old != new and cap not in sealed:
                    findings.append(_finding(
                        "medium", f"{LABEL[cap]} access setting changed",
                        f"{slot} hive {key}: {old or 'unset'} -> {new or 'unset'}; "
                        "not attributed, sampled change"))
        known = {(a["kind"], a["name"]) for a in before["apps"]}
        for app in after["apps"]:
            if (app["kind"], app["name"]) not in known and app["start"]:
                findings.append(_finding(
                    "medium" if cap in SEALABLE else "low",
                    f"new app in the {LABEL[cap]} ledger",
                    f"{app['kind']} app {app['name']} first seen using the "
                    f"{LABEL[cap]} at {_iso(app['start'])}"))
    for name, value in current["policy"].items():
        if previous.get("policy", {}).get(name) != value:
            findings.append(_finding(
                "medium", "app privacy policy changed",
                f"{name}: {previous.get('policy', {}).get(name)} -> {value}; "
                "not attributed"))
    seen = {d["id"] for d in previous.get("devices", [])}
    for device in current["devices"]:
        if device["id"] not in seen and device["class"] in ("Camera", "Image"):
            findings.append(_finding(
                "medium" if sealed else "low", "camera device appeared",
                f"{device['class']} {device.get('name') or device['id']} status "
                f"{device['status']}; a new capture device is not attributed"))
    return findings


def _inventory_finding(current, seal):
    cameras = [d for d in current["devices"] if d["class"] in ("Camera", "Image")]
    active = [e for e in current["captureEndpoints"] if e["state"] == ENDPOINT_ACTIVE]
    loopback = {e["name"] for e in active
                if any(n in e["name"].lower() for n in LOOPBACK_NAMES)}
    sealed = sorted(LABEL.get(c, c) for c in (seal or {}).get("caps", {}))
    state = (f"sealed: {', '.join(sealed)} denied since {_stamp(seal)}" if sealed
             else "no seal declared")
    detail = (f"{state}; {len(cameras)} camera device(s) present, {len(active)} active "
              f"capture endpoint(s)")
    if loopback:
        detail += f", loopback capture endpoint active: {', '.join(sorted(loopback))}"
    detail += ("; five-minute sample of a user-mode consent gate: kernel streaming, "
               "drivers and administrators are not stopped by it")
    return _finding("low", "microphone and camera privacy posture", detail)


def _stamp(seal):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(seal.get("declared") or 0)))


def compare(current, previous, seal):
    findings = []
    if seal:
        findings.extend(_seal_findings(current, seal, previous))
    findings.extend(_posture_findings(current, seal))
    findings.extend(_change_findings(current, previous, seal))
    findings.append(_inventory_finding(current, seal))
    return findings


def audit(store, hosts=("wsl", "win")):
    if "win" not in hosts:
        collection.failed("privacy", "Windows collection disabled")
        return [_finding("medium", "microphone and camera posture is not monitored",
                         "Windows collection is disabled", "visibility")]
    data = ps_json(PS_READ, timeout=45)
    if not _valid(data):
        collection.failed("privacy", "posture probe returned no valid snapshot")
        return [_finding("medium", "privacy posture visibility unavailable",
                         "the consent store returned no complete, valid snapshot; "
                         "previous evidence is retained", "visibility")]
    seal = load_seal(store)
    try:
        previous = json.loads(store.get_meta(STATE_KEY, "{}")) or {}
    except (ValueError, TypeError):
        previous = {}
    findings = compare(data, previous, seal)
    store.set_meta(STATE_KEY, json.dumps(dict(data, schema=1, ts=time.time())))
    if data["errors"]:
        reasons = sorted(set(data["errors"]))[:4]
        collection.failed("privacy", "; ".join(reasons))
        findings.append(_finding(
            "medium", "privacy posture visibility incomplete",
            "; ".join(reasons) + "; the rows that were read are current",
            "visibility"))
        return findings
    collection.succeeded("privacy")
    return findings


# -- owner actions (CLI only; the daemon never calls these) -------------------

class SealError(Exception):
    pass


def snapshot():
    data = ps_json(PS_READ, timeout=45)
    if not _valid(data):
        raise SealError("the consent store returned no valid snapshot")
    return data


def _apply(values):
    for cap, value in values.items():
        if cap not in SEALABLE or value not in ("Allow", "Deny"):
            raise SealError(f"refusing to write {cap}={value}")
    payload = json.dumps({"set": values})
    result = ps_json(stdin_text("jarvisReq") + PS_APPLY, timeout=45, payload=payload)
    if not isinstance(result, dict) or not isinstance(result.get("result"), dict):
        raise SealError("the consent writer returned nothing usable")
    if result.get("errors"):
        raise SealError("; ".join(str(e) for e in result["errors"])[:400])
    for cap, value in values.items():
        got = result["result"].get(cap) or {}
        if got.get("global") != value or got.get("nonpackaged") != value:
            raise SealError(f"{cap} read back as {got}, expected {value}")
    return result["result"]


def seal(store, caps=SEALABLE):
    """Deny the listed capabilities in the owner's hive; record the rollback."""
    caps = tuple(c for c in caps if c in SEALABLE)
    if not caps:
        raise SealError("nothing to seal")
    existing = load_seal(store) or {"caps": {}, "previous": {}}
    before = snapshot()
    previous = dict(existing.get("previous") or {})
    for cap in caps:
        if cap not in previous:
            glob, desktop = _effective(before["caps"][cap])
            previous[cap] = {"global": glob or "", "nonpackaged": desktop or ""}
    written = _apply({cap: "Deny" for cap in caps})
    declared = existing.get("declared") or time.time()
    record = {"declared": declared, "caps": {**existing.get("caps", {}),
                                             **{cap: "Deny" for cap in caps}},
              "previous": previous, "by": "owner cli"}
    store.set_meta(SEAL_KEY, json.dumps(record))
    _record(store, {"event": "seal", "caps": list(caps), "written": written})
    return record


def unseal(store):
    """Restore exactly the values recorded when the seal was declared."""
    existing = load_seal(store)
    if not existing:
        raise SealError("no seal is declared")
    restore = {}
    for cap in existing["caps"]:
        prev = (existing.get("previous") or {}).get(cap) or {}
        # Windows treats a missing value as Allow; restoring Allow explicitly
        # is the same posture and leaves a readable record.
        restore[cap] = "Deny" if _is_deny(prev.get("global")) else "Allow"
    written = _apply(restore)
    store.set_meta(SEAL_KEY, "")
    _record(store, {"event": "unseal", "restored": restore, "written": written})
    return restore


def status(store):
    seal_record = load_seal(store)
    try:
        latest = json.loads(store.get_meta(STATE_KEY, "{}")) or {}
    except (ValueError, TypeError):
        latest = {}
    try:
        history = json.loads(store.get_meta(HISTORY_KEY, "[]")) or []
    except (ValueError, TypeError):
        history = []
    return {"seal": seal_record, "latest": latest, "history": history[-10:]}
