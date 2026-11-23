"""Results from the elevated collector broker (jarvis-elevated-broker.ps1).

The broker is a Windows scheduled task that runs a fixed set of read-only
collector scripts with the user's elevated token, from an administrator-only
folder, and writes each one's normal base64 JSON output next to a status file.
Collectors prefer a fresh broker result and fall back to their unelevated run.

Freshness is judged by the broker's own status timestamp, and a result is only
trusted when the staged script is byte-for-byte (newline-normalised) the one in
this checkout: a stale or modified copy is reported, never silently used.
"""

import base64
import hashlib
import json
import os
import time

from jarvis.core import mechanisms
from jarvis.core.paths import win_script
from jarvis.platform import host

ROOT = host.program_data("Jarvis", "Broker")
BROKER_SCRIPT = "jarvis-elevated-broker.ps1"
# The name staged before the rename. A copy under it is trusted only while it
# is byte-for-byte the pinned pre-rename release (persistence.LEGACY_LAYOUTS),
# until `jarvis broker install` restages the broker under its new name.
LEGACY_BROKER_SCRIPT = "broker-jarvis.ps1"
OUT = os.path.join(ROOT, "out")
# Collectors declare their elevated script in core/mechanisms.py; the rest are
# broker tasks that serve other jobs (Sysmon policy and pressure probes, the
# evidence vault, the input audit trace, the Beep() caller trace).
SCRIPTS = {
    **mechanisms.elevated_scripts(),
    "sysmon_policy": "sysmon_policy.ps1",
    "sysmon_pressure": "sysmon_pressure.ps1",
    "vault": "vault.ps1",
    "inputaudit": "inputaudit.ps1",
    "beeptrace": "beeptrace.ps1",
}
MAX_AGE = 45 * 60          # three missed 15-minute runs


def _norm_hash(path):
    try:
        with open(path, encoding="utf-8-sig", errors="strict", newline="") as fh:
            text = fh.read().replace("\r\n", "\n").rstrip()
    except (OSError, UnicodeError):
        return ""
    return hashlib.sha256(text.encode()).hexdigest()


def installed():
    return any(os.path.exists(os.path.join(ROOT, name))
               for name in (BROKER_SCRIPT, LEGACY_BROKER_SCRIPT))


def _legacy_broker_verified():
    from jarvis.platform.provenance.persistence import LEGACY_LAYOUTS
    _script, _args, pinned = LEGACY_LAYOUTS["jarvis elevated broker"]
    return _norm_hash(os.path.join(ROOT, LEGACY_BROKER_SCRIPT)) == pinned


def status():
    try:
        with open(os.path.join(OUT, "status.json"), encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def drifted():
    """Staged scripts that differ from this checkout (need -Install again)."""
    out = []
    if not os.path.exists(os.path.join(ROOT, BROKER_SCRIPT)) \
            and os.path.exists(os.path.join(ROOT, LEGACY_BROKER_SCRIPT)):
        if not _legacy_broker_verified():
            out.append(LEGACY_BROKER_SCRIPT)
        names = list(SCRIPTS.values())
    else:
        names = [BROKER_SCRIPT] + list(SCRIPTS.values())
    for name in names:
        repo = (os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), name)
                if name == BROKER_SCRIPT else str(win_script(name)))
        if _norm_hash(os.path.join(ROOT, name)) != _norm_hash(repo):
            out.append(name)
    return out


def result(name, now=None):
    """-> (data, "") for a fresh, verified elevated result, else (None, why)."""
    now = time.time() if now is None else now
    if not installed():
        from jarvis.core.mechanisms import NEEDS_ADMIN_SENSOR
        return None, f"{NEEDS_ADMIN_SENSOR}: the elevated broker is not installed in this edition"
    if SCRIPTS[name] in drifted():
        return None, f"the broker's copy of {SCRIPTS[name]} differs from this checkout"
    job = ((status() or {}).get("jobs") or {}).get(name) or {}
    if not job.get("ok"):
        return None, f"the broker's last {name} run failed: {job.get('error') or 'no run recorded'}"
    if now - float(job.get("ts") or 0) > MAX_AGE:
        return None, f"the broker's {name} result is older than {MAX_AGE // 60} minutes"
    try:
        with open(os.path.join(OUT, name + ".b64"), errors="replace") as fh:
            blob = "".join(fh.read().split())
        data = json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
        return None, f"the broker's {name} output is unreadable: {exc}"
    return (data, "") if isinstance(data, dict) else (None, "the broker's output is not an object")
