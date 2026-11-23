"""Constants shared by more than one part of hidden."""

import subprocess

DEFAULT_SWEEP = 65536

PROC = "/proc"


def _finding(severity, title, detail, evidence=""):
    return {"severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "host": ""}


def _run_capture(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _read(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return b"" if binary else ""
