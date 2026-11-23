"""Authenticode verdicts for Windows files, batched and cached per file.

Inventory findings (autostart entries, services, boot tasks) become low only
when the file they run carries a signature Windows validates. Verifying costs
a PowerShell round trip, so results are cached by (path, size, mtime): a file
that changes is verified again, one that does not costs a stat.
"""

import glob
import hashlib
import json
import os
import re

from jarvis.platform import host
from jarvis.platform.windows import ps_json, stdin_text

_CACHE = {}     # (lower path, size, mtime) -> {"status", "signer"}

# 2026-09-23: the installed unsigned image was extracted byte-for-byte from
# this Windows DriverStore installer with 7-Zip in a read-only, no-network
# namespace. Windows validates the installer via its Microsoft WHCP catalog.
# This is one exact payload proof, not a general trust in Logitech names or
# Program Files. Rehash both files and recheck the installer signature on
# every audit; a changed package or installed image returns to NotSigned.
_LOGI_EXE = r"C:\Program Files\LogiDownloadAssistant\bin\logi_download_assistant.exe"
_LOGI_EXE_SHA256 = "34570a4c5850ac7418288d0c645a823d2e6eb865356501a5c8069439fb0a4cfe"
_LOGI_INSTALLER_SHA256 = "caef22bdc560daffa036b32e584a046c80dd2c86ba6899228f712d7a0cbff90a"
_LOGI_PACKAGE_GLOB = (
    host.windows_dir().replace("\\", "/") + "/System32/DriverStore/FileRepository/"
    "logi_download_assistant_component.inf_amd64_*/"
    "logi_download_assistant-2.0.529-win64.exe")

_ENV = {"%systemroot%": "C:\\Windows", "%windir%": "C:\\Windows",
        "%programfiles%": "C:\\Program Files",
        "%programfiles(x86)%": "C:\\Program Files (x86)"}


def normalize(path):
    """Expand the usual variables and the NT forms services use."""
    p = str(path or "").strip().strip('"')
    for var, value in _ENV.items():
        if p.lower().startswith(var):
            p = value + p[len(var):]
    if p.lower().startswith("\\systemroot\\"):
        p = "C:\\Windows\\" + p[len("\\systemroot\\"):]
    if p.lower().startswith("system32\\"):
        p = "C:\\Windows\\" + p
    if p.startswith("\\??\\"):
        p = p[4:]
    return p


def executable(command):
    """The program a Run key, task or service command line starts."""
    c = str(command or "").strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        return normalize(c[1:end] if end > 0 else c[1:])
    m = re.match(r"(.+?\.(?:exe|dll|sys|com|scr))(?:\s|$)", c, re.I)
    return normalize(m.group(1) if m else c.split(" ")[0])


def _wsl(path):
    if not re.match(r"^[A-Za-z]:\\", path or ""):
        return ""
    return host.local_path(path)


def _key(path):
    try:
        st = os.stat(_wsl(path))
    except (OSError, ValueError):
        return None
    return (path.lower(), st.st_size, int(st.st_mtime))


def _sha256(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _logi_package_verdict(path):
    """Proof for one exact Logitech driver-package payload, or None."""
    if normalize(path).casefold() != _LOGI_EXE.casefold() \
            or _sha256(_wsl(path)) != _LOGI_EXE_SHA256:
        return None
    for installer in glob.glob(_LOGI_PACKAGE_GLOB):
        if _sha256(installer) != _LOGI_INSTALLER_SHA256:
            continue
        win_installer = host.windows_path(installer)
        result = ps_json(
            "$s=Get-AuthenticodeSignature -LiteralPath '"
            + win_installer.replace("'", "''") + "';"
            "@{status=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject}"
            "|ConvertTo-Json -Compress|% {"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_))}",
            timeout=30)
        if not isinstance(result, dict) or result.get("status") != "Valid":
            continue
        signer = str(result.get("signer") or "").casefold()
        if "microsoft windows hardware compatibility publisher" in signer \
                and "o=microsoft corporation" in signer:
            return {"status": "Valid", "source": "package_payload",
                    "signer": "O=Logitech"}
    return None


def verify(paths, timeout=90):
    """{path: {"status": "Valid"|"NotSigned"|...|"Missing"|"Unknown",
    "signer": subject}} for Windows paths. Unreachable files are "Missing";
    a failed query leaves "Unknown", which never counts as verified."""
    out, todo = {}, []
    for raw in dict.fromkeys(normalize(p) for p in paths if p):
        key = _key(raw)
        if key is None:
            out[raw] = {"status": "Missing", "signer": ""}
        elif key in _CACHE:
            out[raw] = _CACHE[key]
        else:
            todo.append((raw, key))
    if todo:
        payload = json.dumps([p for p, _ in todo])
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            + stdin_text("p") +
            "$p=$p|ConvertFrom-Json;"
            "$r=@(foreach($x in $p){$s=Get-AuthenticodeSignature -LiteralPath $x;"
            "@{p=$x;status=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject}});"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
            "(ConvertTo-Json -InputObject $r -Compress -Depth 3)))")
        result = ps_json(script, timeout=timeout, payload=payload)
        rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
        got = {str(r.get("p")): r for r in rows if isinstance(r, dict)}
        for raw, key in todo:
            r = got.get(raw)
            if r is None:
                out[raw] = {"status": "Unknown", "signer": ""}
                continue
            out[raw] = _CACHE[key] = {"status": str(r.get("status") or "Unknown"),
                                      "signer": str(r.get("signer") or "")}
    unsigned = [p for p, v in out.items() if v["status"] == "NotSigned"]
    for path, verdict in _package_verdicts(unsigned).items():
        key = _key(path)
        out[path] = verdict
        if key is not None:
            _CACHE[key] = verdict
    for path in unsigned:
        verdict = _logi_package_verdict(path)
        if verdict:
            out[path] = verdict
    return out


_PACKAGE = re.compile(r"\\WindowsApps\\([^\\]+_[^\\]+__[a-z0-9]+)\\", re.I)


def _package_verdicts(paths, timeout=60):
    """Store- or System-signed package verdicts for files inside
    C:\\Program Files\\WindowsApps, which only the deployment service writes.
    A file there may carry no signature of its own; the package that
    installed it does. Sideloaded (Developer) packages are not accepted."""
    names = {}
    for p in paths:
        m = _PACKAGE.search(p)
        if m:
            names.setdefault(m.group(1), []).append(p)
    if not names:
        return {}
    payload = json.dumps(sorted(names))
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        + stdin_text("want") +
        "$want=$want|ConvertFrom-Json;"
        "$r=@(Get-AppxPackage | ? { $want -contains $_.PackageFullName } | % {"
        "@{full=$_.PackageFullName;name=$_.Name;kind=[string]$_.SignatureKind;"
        "status=[string]$_.Status}});"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json -InputObject $r -Compress)))")
    result = ps_json(script, timeout=timeout, payload=payload)
    rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
    out = {}
    for r in rows:
        if not isinstance(r, dict) or r.get("kind") not in ("Store", "System") \
                or r.get("status") != "Ok":
            continue
        for path in names.get(r.get("full"), ()):
            out[path] = {"status": "Valid",
                         "signer": f"O={r.get('name')} ({r.get('kind')}-signed package)"}
    return out


_LNK = {}   # (path, size, mtime) -> target


def lnk_targets(paths, timeout=60):
    """{shortcut path: target path} for .lnk files, "" when unresolved."""
    out, todo = {}, []
    for raw in dict.fromkeys(normalize(p) for p in paths if p):
        key = _key(raw)
        if key is None:
            out[raw] = ""
        elif key in _LNK:
            out[raw] = _LNK[key]
        else:
            todo.append((raw, key))
    if todo:
        payload = json.dumps([p for p, _ in todo])
        script = (
            "$ErrorActionPreference='SilentlyContinue';$sh=New-Object -ComObject WScript.Shell;"
            + stdin_text("p") +
            "$p=$p|ConvertFrom-Json;"
            "$r=@(foreach($x in $p){@{p=$x;t=[string]$sh.CreateShortcut($x).TargetPath}});"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
            "(ConvertTo-Json -InputObject $r -Compress)))")
        result = ps_json(script, timeout=timeout, payload=payload)
        rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
        got = {str(r.get("p")): str(r.get("t") or "") for r in rows if isinstance(r, dict)}
        for raw, key in todo:
            out[raw] = _LNK[key] = normalize(got.get(raw, ""))
    return out


def publisher(sig):
    """Organisation of a verified signature, or "" when not verified."""
    if not sig or sig.get("status") != "Valid":
        return ""
    m = re.search(r"O=\"?([^,\"]+)", sig.get("signer") or "")
    cn = re.search(r"CN=\"?([^,\"]+)", sig.get("signer") or "")
    return (m or cn).group(1).strip() if (m or cn) else "a verified publisher"
