"""Pause a suspicious Linux process instead of killing it.

SIGSTOP freezes a process without ending it: it stops doing whatever it is
doing, but its memory, open files and network connections stay intact for a
dump, and SIGCONT resumes it if the alarm was false. Killing throws all of
that away and cannot be undone, so it is an approval-only action elsewhere.

Matching is deliberately narrow. A process is only a candidate when the same
scan already quarantined the file it was running, so this never freezes a
process on a name match alone.
"""

import os
import signal
import time

from jarvis.platform.linux import signal_zero

from .base import AUTO, Action, register

# Never suspend the tools the monitor and the system depend on.
PROTECTED = {"systemd", "init", "sshd", "bash", "sh", "zsh", "python3",
             "dockerd", "containerd", "systemd-journald", "dbus-daemon"}


def _alive(pid):
    try:
        signal_zero(pid)
        return True
    except OSError:
        return False


def _name(pid):
    try:
        with open(f"/proc/{pid}/comm", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _started(pid):
    """Process start time (jiffies field 22 of /proc/<pid>/stat), for identity."""
    try:
        with open(f"/proc/{pid}/stat", errors="replace") as fh:
            return fh.read().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return ""


@register
class SuspendProcess(Action):
    id = "suspend_process"
    title = "Pause a suspicious process"
    autonomy = AUTO
    reversible = True
    host = "wsl"
    enable_flag = "auto_suspend"

    def match(self, finding, job):
        if (finding or {}).get("host") != "wsl":
            return None
        # A PID on an unrelated finding must never become authority to freeze
        # a process. Only process/runtime detectors can propose this action.
        if (finding or {}).get("category") not in (
                "process", "sysmon-linux", "credential access", "injection",
                "tampering", "intel match", "sample match"):
            return None
        pid = (finding or {}).get("pid")
        if not isinstance(pid, int) or pid <= 1 or not _alive(pid):
            return None
        name = _name(pid)
        if name in PROTECTED:
            return None
        return {"pid": pid, "name": name, "started": _started(pid)}

    def auto_eligible(self, finding, job, target):
        # No current collector carries enough live process identity plus
        # independent corroboration to freeze a process unattended. Keep the
        # reversible action available for explicit approval.
        return False

    def preview(self, target):
        return (f"Pause process {target['pid']} ({target.get('name') or '?'}) "
                f"with SIGSTOP, keeping it intact for inspection. Reversible.")

    def _same(self, target):
        """The pid still points at the same process we matched (not reused)."""
        pid = target["pid"]
        return _alive(pid) and _started(pid) == target.get("started")

    def apply(self, target, case):
        if os.name == "nt":
            # No Linux process exists here, and os.kill would terminate a
            # Windows one rather than pause it.
            return False, {}, "suspending is implemented for Linux processes only"
        if not self._same(target):
            return False, {}, "the process has already exited"
        try:
            os.kill(target["pid"], signal.SIGSTOP)
            return True, {**target, "at": int(time.time())}, f"paused pid {target['pid']}"
        except OSError as exc:
            return False, {}, f"could not pause: {exc.strerror or exc}"

    def undo(self, target, record):
        pid = record.get("pid")
        if os.name == "nt":
            return False, "suspending is implemented for Linux processes only"
        if not _alive(pid):
            return False, "the process is gone"
        if _started(pid) != record.get("started"):
            return False, "that pid now belongs to a different process; not resuming"
        try:
            os.kill(pid, signal.SIGCONT)
            return True, f"resumed pid {pid}"
        except OSError as exc:
            return False, f"could not resume: {exc.strerror or exc}"

    def recover(self, target, record):
        """Determine whether the exact process identity is still paused."""
        identity = record or target
        pid = identity.get("pid") if isinstance(identity, dict) else None
        if not isinstance(pid, int) or not identity.get("started"):
            return "unknown", {}, "missing process identity"
        if not self._same(identity):
            return "not_applied", {}, "the original process no longer exists"
        try:
            with open(f"/proc/{pid}/stat", errors="replace") as fh:
                state = fh.read().rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            return "unknown", {}, "could not read process state"
        if state in ("T", "t"):
            return "applied", {**identity}, f"verified paused pid {pid}"
        return "not_applied", {}, f"pid {pid} is not paused"
