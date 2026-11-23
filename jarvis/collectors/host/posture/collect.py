"""Reading the posture sample from Windows, unelevated or through one UAC prompt."""

import hashlib
import os
import shutil
import subprocess
import tempfile

from jarvis.core.paths import load_win_script
from jarvis.platform import elevation, host
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

PS_POSTURE = load_win_script("posture.ps1")


def _win_temp():
    r"""%LOCALAPPDATA%\Temp as both a Windows path and a WSL path."""
    out = ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:TEMP})))", timeout=60)
    win = (out or {}).get("t") or r"C:\Windows\Temp"
    p = win.replace("\\", "/")
    wsl = host.local_path(win) if len(p) > 2 and p[1] == ":" else "/tmp"
    return win, wsl


def elevated_data(timeout=300):
    """Re-run the collector through a UAC prompt.

    Several of the most important checks — BitLocker, TPM, Defender's exclusion
    list, optional features — return nothing at all without elevation, and
    "nothing" is indistinguishable from "clean" unless something asks properly.
    There is no way to elevate from inside WSL without a consent prompt, so
    this writes the same script to disk, asks Windows to run it as
    administrator, and reads the result back.

    Returns (data, error). The prompt is user-visible and cancellable; a
    cancelled prompt is an error, not an empty result.
    """
    if not collect_windows.available():
        return None, "the Windows interop bridge is not available"
    # A fresh, randomly named stage (no fixed name another process could
    # pre-write), and the elevated shell runs only a checked copy of the script
    # (platform/elevation.py), never the staged file itself.
    win_tmp, wsl_tmp = _win_temp()
    try:
        stage_wsl = tempfile.mkdtemp(prefix="jarvis-posture-", dir=wsl_tmp)
    except OSError as exc:
        return None, f"could not stage the elevated script: {exc}"
    stage_win = win_tmp + "\\" + os.path.basename(stage_wsl)
    script_wsl = os.path.join(stage_wsl, "posture.ps1")
    out_wsl = os.path.join(stage_wsl, "posture.b64")
    out_win = stage_win + r"\posture.b64"
    try:
        # UTF-8 with BOM so PowerShell reads the file in the right encoding.
        with open(script_wsl, "w", encoding="utf-8-sig") as fh:
            fh.write(PS_POSTURE.replace(
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))",
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)) "
                "| Set-Content -Path " + elevation.literal(out_win) + " -Encoding ascii"))
        with open(script_wsl, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
    except OSError as exc:
        shutil.rmtree(stage_wsl, ignore_errors=True)
        return None, f"could not stage the elevated script: {exc}"

    try:
        return _run_elevated(elevation.launcher(
            elevation.inline_command(stage_win, {"posture.ps1": digest}, "posture.ps1", []), hidden=True),
            out_wsl, timeout)
    finally:
        shutil.rmtree(stage_wsl, ignore_errors=True)


def _run_elevated(launcher, out_wsl, timeout):
    try:
        subprocess.run([*collect_windows.interop_launcher(), collect_windows._PS,
                        "-NoProfile", "-NonInteractive", "-Command", launcher],
                       capture_output=True, timeout=timeout,
                       cwd=host.subprocess_cwd(), **host.spawn_options())
    except subprocess.TimeoutExpired:
        return None, "timed out waiting for the elevation prompt"
    except OSError as exc:
        return None, f"could not launch an elevated shell: {exc}"

    try:
        with open(out_wsl, errors="replace") as fh:
            blob = fh.read().strip().replace("\r", "").replace("\n", "")
    except OSError:
        return None, ("no elevated result was produced — the UAC prompt was "
                      "most likely declined or dismissed")
    if not blob:
        return None, "the elevated run produced an empty result"
    try:
        import base64
        import json as _json
        return _json.loads(base64.b64decode(blob).decode("utf-8", "replace")), ""
    except Exception as exc:
        return None, f"could not decode the elevated result: {exc}"
