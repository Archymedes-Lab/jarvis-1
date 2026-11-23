"""The WSL trust boundary, sampled every five minutes from both sides.

Both sides of the boundary run as the same Windows user, and that user is
root inside the distro whenever a Windows process asks (`wsl.exe -u root`,
no prompt). Nothing in the distro can stop that; this collector makes every
way of changing the boundary visible:

* Linux side: `/etc/wsl.conf`, the owner's `.wslconfig`, DrvFs mounts, the
  interop registration and the Docker socket, through the existing bounded
  snapshot, compared with the owner-accepted hash-chained checkpoint that
  `jarvis timeline wsl-boundary --accept` writes. Posture findings (a root
  boot command, a custom kernel) need no checkpoint.
* Windows side: the WSL registration in the registry: each distribution's
  default user, disk path and flags, the WSL service plugins, and the WSL
  policy key, compared with the previous sample.

The collector never writes WSL state. An unreadable source is visibility
loss and keeps the previous evidence; it is never reported as unchanged.
Windows Sysmon rules (techniques.py) are the continuous path for the same
registry keys and for `wsl.exe` launches; this sampler covers the facts no
event carries and the time before the policy is applied.
"""
import json
import os
import time
from pathlib import Path

from jarvis.core import collection
from jarvis.core.execution import wsl_drift
from jarvis.core.paths import load_win_script
from jarvis.platform import host as machine
from jarvis.platform import wsl_boundary
from jarvis.platform.windows import ps_json

PS_READ = load_win_script("wsl_registration.ps1")

STATE_KEY = "wslguard_latest_v1"
CHECKPOINT = Path.home() / ".jarvis" / "wsl-checkpoints.jsonl"
ACCEPT_HINT = "run `jarvis timeline wsl-boundary` and, if the state is yours, add --accept"
MAX_DISTROS = 32
MAX_PLUGINS = 16
MAX_POLICY = 32
MAX_VALUE = 120
ROOT_UID = 0
FLAG_BITS = ((0x1, "interop"), (0x2, "drive mounting"), (0x4, "Windows PATH"))

# (fact, severity, title, detail) for a Linux-side fact whose mere presence
# changes who runs code in the VM. Reported whatever the checkpoint says.
POSTURE = (
    ("wsl_conf.boot.command", "high", "a command runs as root at every WSL boot",
     "wsl.conf [boot] command is set; it runs as root before any service starts"),
    ("wslconfig.wsl2.kernel", "high", "WSL boots a kernel that is not the Microsoft one",
     ".wslconfig [wsl2] kernel points at a custom kernel image for the VM JARVIS runs in"),
    ("wslconfig.wsl2.kernelmodules", "high", "WSL loads custom kernel modules",
     ".wslconfig [wsl2] kernelModules is set; modules run in the kernel JARVIS runs on"),
    ("wslconfig.wsl2.kernelcommandline", "medium", "WSL kernel command line is customised",
     ".wslconfig [wsl2] kernelCommandLine is set"),
)


def _finding(severity, title, detail, category="wsl", host="wsl"):
    return {"host": host, "severity": severity, "title": title,
            "detail": detail[:600], "category": category,
            "where": "WSL boundary"}


def _short(value):
    text = str(value if value is not None else "")
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE] + "…"


# -- Linux side ---------------------------------------------------------------

def load_checkpoints(path=CHECKPOINT):
    """(entries, read_error). Missing is an empty chain; unreadable is an error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()[-wsl_drift.MAX_ENTRIES:]
        return [json.loads(line) for line in lines if line.strip()], None
    except FileNotFoundError:
        return [], None
    except (OSError, ValueError) as exc:
        return [], type(exc).__name__


def wslconfig_path():
    user = os.environ.get("USER") or ""
    users = machine.users_dir()
    if not user or not users:
        return None
    candidate = Path(users) / user / ".wslconfig"
    return str(candidate) if candidate.exists() else None


def linux_findings(snap, entries, read_error):
    """Posture plus drift findings from one boundary snapshot. Pure."""
    out = []
    facts, _unknown = wsl_drift.usable_facts(snap)
    for fact, severity, title, detail in POSTURE:
        if fact in facts:
            out.append(_finding(severity, title, f"{detail}: {_short(facts[fact])!r}",
                                "persistence"))
    if facts.get("wslconfig.wsl2.firewall", "").lower() == "false":
        out.append(_finding("medium", "the Hyper-V firewall for WSL is turned off",
                            ".wslconfig [wsl2] firewall=false; inbound rules no longer "
                            "apply to the VM"))
    if facts.get("wslconfig.wsl2.safemode", "").lower() == "true":
        out.append(_finding("medium", "WSL safe mode is on",
                            ".wslconfig [wsl2] safeMode=true disables networking and "
                            "custom settings; collectors lose their Windows reach"))
    if facts.get("docker.socket"):
        out.append(_finding("low", "the Docker socket makes this user root inside WSL",
                            "any process of this user can start a privileged container "
                            "through the socket; a chosen posture, recorded so it is "
                            "not mistaken for a closed path"))
    if read_error:
        result = {"status": "checkpoint_invalid", "reason": read_error, "findings": []}
    else:
        result = wsl_drift.compare(entries, snap)
    status = result["status"]
    if status == "checkpoint_invalid":
        out.append(_finding("high", "the WSL boundary checkpoint chain is unreadable or broken",
                            f"{result.get('reason')}; an accepted checkpoint cannot be "
                            "trusted until the owner re-accepts it"))
    elif status == "no_baseline":
        out.append(_finding("low", "no accepted WSL boundary checkpoint",
                            "boundary changes cannot be reported until one is accepted; "
                            + ACCEPT_HINT, "visibility"))
    else:
        offline = " while the distro was down" if result.get("offline") else ""
        for f in result["findings"]:
            if f["kind"] == "EVIDENCE_LOST":
                out.append(_finding("low", "a WSL boundary source became unreadable",
                                    f"{f['fact']}: previous evidence retained", "visibility"))
                continue
            severity = "high" if f["critical"] else "medium"
            out.append(_finding(
                severity, f"WSL boundary changed since the accepted checkpoint: {f['fact']}",
                f"{f['change']}{offline}: {_short(f['before'])!r} -> {_short(f['after'])!r}; "
                "re-accept with --accept if this change is yours"))
    unreadable = sorted(k for k, v in snap.get("sources", {}).items()
                        if v.get("status") == "unavailable")
    return out, unreadable


# -- Windows side -------------------------------------------------------------

def _valid(data):
    return (isinstance(data, dict) and isinstance(data.get("distros"), list)
            and isinstance(data.get("errors"), list))


def _distros(data):
    rows = {}
    for row in data.get("distros", [])[:MAX_DISTROS]:
        if not isinstance(row, dict) or not row.get("guid"):
            continue
        rows[str(row["guid"])] = {
            "name": _short(row.get("name") or row["guid"]),
            "defaultUid": _int(row.get("defaultUid")),
            "basePath": _short(row.get("basePath")),
            "flags": _int(row.get("flags")),
        }
    return rows


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _flags(value):
    if value < 0:
        return "unknown"
    names = [name for bit, name in FLAG_BITS if value & bit]
    return f"0x{value:x} ({', '.join(names) or 'none'})"


def _policy(data):
    policy = data.get("policy")
    if not isinstance(policy, dict):
        return {}
    return {str(k)[:64]: _short(v) for k, v in list(policy.items())[:MAX_POLICY]}


def windows_findings(data, previous):
    """Registration posture plus changes since the previous sample. Pure."""
    out = []
    distros = _distros(data)
    plugins = [_short(p) for p in data.get("plugins", [])[:MAX_PLUGINS] if p]
    policy = _policy(data)
    default = _short(data.get("defaultDistribution"))
    for guid, row in distros.items():
        if row["defaultUid"] == ROOT_UID:
            out.append(_finding("high", f"WSL distribution {row['name']} opens as root by default",
                                f"DefaultUid is 0 in the registry for {guid}; every wsl.exe "
                                "launch of it is root without a prompt", host="win"))
    if plugins:
        out.append(_finding("high", "WSL service plugin registered",
                            "a plugin DLL is loaded by the WSL service as SYSTEM at every "
                            f"VM start: {', '.join(plugins)}", "persistence", host="win"))
    before = previous.get("distros") if isinstance(previous.get("distros"), dict) else None
    if before is not None:
        for guid in sorted(set(distros) - set(before)):
            out.append(_finding("medium", f"new WSL distribution registered: {distros[guid]['name']}",
                                f"{guid} at {distros[guid]['basePath']!r}; it has its own root "
                                "and this user's rights on Windows", host="win"))
        for guid in sorted(set(before) - set(distros)):
            out.append(_finding("medium", f"WSL distribution unregistered: {before[guid]['name']}",
                                f"{guid} is no longer registered; its disk is deleted by "
                                "wsl --unregister", host="win"))
        for guid in sorted(set(before) & set(distros)):
            old, new = before[guid], distros[guid]
            if old["defaultUid"] != new["defaultUid"]:
                out.append(_finding("high", f"WSL default user changed for {new['name']}",
                                    f"DefaultUid {old['defaultUid']} -> {new['defaultUid']}",
                                    host="win"))
            if old["basePath"] != new["basePath"]:
                out.append(_finding("high", f"WSL disk location changed for {new['name']}",
                                    f"BasePath {old['basePath']!r} -> {new['basePath']!r}",
                                    host="win"))
            if old["flags"] != new["flags"]:
                out.append(_finding("medium", f"WSL flags changed for {new['name']}",
                                    f"{_flags(old['flags'])} -> {_flags(new['flags'])}",
                                    host="win"))
        if previous.get("default") not in (None, default):
            out.append(_finding("medium", "default WSL distribution changed",
                                f"{previous.get('default')!r} -> {default!r}", host="win"))
        old_plugins = previous.get("plugins") or []
        for name in sorted(set(old_plugins) - set(plugins)):
            out.append(_finding("low", f"WSL service plugin removed: {name}", "no longer "
                                "registered", host="win"))
        old_policy = previous.get("policy") if isinstance(previous.get("policy"), dict) else {}
        for name in sorted(set(old_policy) | set(policy)):
            if old_policy.get(name) != policy.get(name):
                out.append(_finding("medium", f"WSL policy value changed: {name}",
                                    f"{old_policy.get(name)!r} -> {policy.get(name)!r}",
                                    host="win"))
    current = {"distros": distros, "plugins": plugins, "policy": policy, "default": default,
               "version": _short(data.get("wslVersion"))}
    return out, current


# -- the job ------------------------------------------------------------------

def audit(store, hosts=("wsl", "win")):
    findings = []
    # The Linux half is the guest side of a WSL boundary: on a plain Linux
    # server (or native Windows) there is no guest to read.
    if machine.on_wsl():
        snap = wsl_boundary.snapshot(windows_config=wslconfig_path())
        entries, read_error = load_checkpoints()
        linux, unreadable = linux_findings(snap, entries, read_error)
        findings.extend(linux)
        if unreadable:
            collection.failed("wsl", "unreadable: " + ", ".join(unreadable))
            findings.append(_finding("medium", "WSL boundary visibility incomplete",
                                     "unreadable sources: " + ", ".join(unreadable)
                                     + "; the sources that were read are current",
                                     "visibility"))
    if "win" in hosts:
        data = ps_json(PS_READ, timeout=45)
        if not _valid(data):
            collection.failed("wsl", "registration probe returned no valid snapshot")
            findings.append(_finding("medium", "WSL registration visibility unavailable",
                                     "the Windows registry read returned no valid snapshot; "
                                     "previous evidence is retained", "visibility", host="win"))
            return findings
        try:
            previous = json.loads(store.get_meta(STATE_KEY, "{}")) or {}
        except (ValueError, TypeError):
            previous = {}
        windows, current = windows_findings(data, previous)
        findings.extend(windows)
        store.set_meta(STATE_KEY, json.dumps(dict(current, schema=1, ts=time.time())))
        if data["errors"]:
            reasons = sorted(set(str(e) for e in data["errors"]))[:4]
            collection.failed("wsl", "; ".join(reasons))
            findings.append(_finding("medium", "WSL registration visibility incomplete",
                                     "; ".join(reasons) + "; the keys that were read are current",
                                     "visibility", host="win"))
            return findings
    collection.succeeded("wsl")
    return findings
