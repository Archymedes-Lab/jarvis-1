"""Reading Sysmon for Linux events out of the journal and parsing them."""

import os
import shutil
import subprocess
from datetime import datetime, timezone

from jarvis.platform.sysmon_records import TRUSTED_MATCH  # noqa: F401  (re-exported for sensorprobe and tests)
from jarvis.platform.sysmon_records import parse as _parse  # noqa: F401  (this package's name for it)

CHANNEL = "journal:sysmon"


def _run(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout, r.returncode
    except (OSError, subprocess.SubprocessError):
        return "", 1


def state():
    """(installed, running)."""
    installed = bool(shutil.which("sysmon")) or os.path.exists("/opt/sysmon/sysmon")
    active_out, _ = _run(["systemctl", "is-active", "sysmon"])
    return installed, active_out.strip() == "active"


def active():
    installed, running = state()
    return installed and running


# Only records journald itself attributes to the root sysmon unit; why: see
# jarvis/platform/sysmon_records.TRUSTED_MATCH (shared with host/restarts.py).


def trusted_text(since_ts, until_ts=None, timeout=40):
    """Trusted sysmon journal text in [since, until]; '' if journalctl failed."""
    args = ["journalctl", *TRUSTED_MATCH, "-o", "cat", "--no-pager", "--since", f"@{int(since_ts)}"]
    if until_ts is not None:
        args += ["--until", f"@{int(until_ts)}"]
    out, rc = _run(args, timeout=timeout)
    return out if rc == 0 else ""


JOURNAL_TIMEOUT_S = 40
SYSLOG = "/var/log/syslog"
# Syslog is read only when journalctl could not answer (its lines carry no
# trusted origin); it is not time-filtered, so only its tail can hold events the
# journal does not. Reading all of it each pass (rsyslog copies reached 9 GB on
# one host) is unbounded; the tail is enough.
SYSLOG_CAP = 8 * 1024 * 1024     # bytes read from the end of syslog, at most


def _syslog(path=SYSLOG, cap=SYSLOG_CAP):
    """(sysmon lines from the last `cap` bytes of syslog, capped?) or (None, False) without one."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - cap))
            data = fh.read(cap)
    except OSError:
        return None, False
    lines = data.decode("utf-8", errors="replace").splitlines()
    if size > cap and lines:
        lines = lines[1:]            # the first line is cut mid-way
    return "\n".join(ln for ln in lines if "sysmon" in ln.lower()), size > cap


def read_since(since_ts, run=subprocess.run, syslog=_syslog):
    """(text, ok, why): the trusted sysmon journal text since `since_ts`; syslog only
    when journalctl failed or is missing.

    ok is False when nothing could be read for that window (journalctl timed out
    or failed and there is no syslog): the caller must not move its cursor past
    it (evidence continuity). why says what happened, or names a capped read."""
    try:
        r = run(["journalctl", *TRUSTED_MATCH, "-o", "cat", "--no-pager", "--since", f"@{int(since_ts)}"],
                capture_output=True, text=True, errors="replace", timeout=JOURNAL_TIMEOUT_S)
        out, rc, failure = r.stdout, r.returncode, f"journalctl failed (exit {r.returncode})"
    except subprocess.TimeoutExpired:
        return None, False, f"journalctl did not answer within {JOURNAL_TIMEOUT_S} s"
    except OSError:
        out, rc, failure = "", None, "journalctl is not available"
    except subprocess.SubprocessError as exc:
        return None, False, f"journalctl could not run ({type(exc).__name__})"
    if rc == 0:
        # A quiet trusted journal is an answer: syslog lines carry no trusted
        # origin, so they are read only when journalctl itself failed.
        return out, True, ""
    text, capped = syslog()
    if text is None:
        return None, False, failure
    return text, True, (f"syslog read limited to its last {SYSLOG_CAP // (1024 * 1024)} MB" if capped else "")


def _raw(since_ts):
    """All sysmon journal text since `since_ts` ("" when nothing could be read)."""
    return read_since(since_ts)[0] or ""



def _clean(v):
    v = (v or "").strip()
    return "" if v in ("-", "<unknown process>", "<unknown>", "") else v


def _base(path):
    path = _clean(path)
    return os.path.basename(path.split()[0]) if path else ""


def _event_utc(e):
    """Journal event time, falling back to the payload time for text records."""
    value = e.get("SystemTime") or e.get("UtcTime") or ""
    try:
        if "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        return (datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                .replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None
