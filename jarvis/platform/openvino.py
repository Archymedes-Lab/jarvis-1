"""Bounded WSL-to-Windows bridge for JARVIS OpenVINO GPU inference."""

from __future__ import annotations

import getpass
import json
import math
import os
import subprocess
from pathlib import Path

from jarvis.platform import host

MAX_OUTPUT = 64 * 1024
TIMEOUT_S = 30
WORKER = Path(__file__).resolve().parent / "win" / "openvino_worker.py"


def _python_candidates():
    if host.native_windows():
        base = Path(host.local_appdata("Programs", "Python") or "/nonexistent")
    else:
        base = Path(host.users_dir() or "/nonexistent") / getpass.getuser() \
            / "AppData/Local/Programs/Python"
    found = sorted(base.glob("Python*/python.exe"), reverse=True)
    configured = os.environ.get("JARVIS_OPENVINO_PYTHON", "")
    return ([Path(configured)] if configured else []) + found


def python_binary():
    for path in _python_candidates():
        try:
            if path.is_file():
                return str(path)
        except OSError:
            continue
    return None


def _windows_path(path):
    return host.windows_name(path) or None


def infer(task, values, timeout=TIMEOUT_S):
    """Execute one fixed-shape model and verify it actually ran on GPU."""
    if (not isinstance(values, list) or len(values) > 32
            or any(not isinstance(value, (int, float))
                   or isinstance(value, bool) or not math.isfinite(value)
                   for value in values)):
        return {"ok": False, "error": "invalid_input"}
    python = python_binary()
    worker = _windows_path(WORKER)
    if not python or not worker:
        return {"ok": False, "error": "runtime_unavailable"}
    body = json.dumps({"task": str(task), "values": values},
                      separators=(",", ":"))
    try:
        result = subprocess.run(
            [python, worker], input=body, capture_output=True, text=True,
            errors="replace", timeout=timeout, check=False, cwd="/")
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "error": "execution_failed"}
    stdout = result.stdout or ""
    if len(stdout) > MAX_OUTPUT:
        return {"ok": False, "error": "oversized_output"}
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid_output"}
    devices = payload.get("execution_devices") if isinstance(payload, dict) else None
    gpu = isinstance(devices, list) and any(
        str(device) == "GPU" or str(device).startswith("GPU.")
        for device in devices)
    output = payload.get("output") if isinstance(payload, dict) else None
    valid_output = (isinstance(output, list) and output
                    and all(isinstance(value, (int, float))
                            and not isinstance(value, bool)
                            and math.isfinite(value) for value in output))
    if result.returncode != 0 or payload.get("ok") is not True \
            or not gpu or not valid_output:
        error = payload.get("error") if isinstance(payload, dict) else None
        return {"ok": False, "error": str(error or "inference_failed")[:80]}
    return payload


try:
    from jarvis.core import mlworker as _mlworker_mod
    _mlworker_mod.set_gpu_infer(infer)
except Exception:
    pass
