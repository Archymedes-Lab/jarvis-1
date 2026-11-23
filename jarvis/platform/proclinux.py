"""The WSL guest's side of the live process feed (platform/procfeed.py).

Three read-only sources, each cheap enough to run on every 500 ms tick while
someone watches /procs:

  read_linux   one pass over /proc/<pid>/stat: id, parent, name, start time,
               CPU ticks and resident memory (3 ms for ~100 processes,
               measured 2026-10-23).
  exe_path     the executable behind one process, read once when the process
               first appears. The daemon runs unprivileged, so other users'
               processes answer "" (22 of 98 were readable, measured
               2026-10-24); "" means unknown, never "no file".
  StartFollower
               Sysmon for Linux process starts as the journal receives them,
               so a process that lives less than one tick is still seen, and a
               root process started while the map is open still gets its path
               and hash. One `journalctl -f` while watched; ~6.6 starts per
               second here (measured 2026-10-24).

Nothing here signals or changes a process. Paths and hashes go to the daemon's
identity check only; procfeed removes them before a frame reaches a viewer.
"""

import os
import re
import subprocess

SYSMON_IDENTIFIER = "sysmon"
# Records journald attributes to the root sysmon unit; the identifier alone is
# client-set and forgeable (`logger -t sysmon`). Equal to
# collectors.telemetry.sysmon_linux.journal.TRUSTED_MATCH (tests/test_sensorprobe.py).
SYSMON_TRUSTED_MATCH = ("_SYSTEMD_UNIT=sysmon.service", "_UID=0", "-t", SYSMON_IDENTIFIER)
MAX_LINE = 64 << 10
_START = "<EventID>1</EventID>"
_FIELD = re.compile(r"<Data Name=\"(ProcessId|ParentProcessId|Image|Hashes)\">([^<]*)</Data>")
_SHA256 = re.compile(r"SHA256=([0-9A-Fa-f]{64})")


def clock_ticks():
    try:
        return os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError):
        return 100


def boot_time_ms():
    try:
        with open("/proc/stat", encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return int(line.split()[1]) * 1000
    except (OSError, ValueError):
        pass
    return 0


def read_linux(proc="/proc", hz=None, boot_ms=None, page_kb=None):
    """{key: [key, pid, ppid, name, created_ms, cpu_ticks, rss_kb, -1]} from /proc.

    cpu_ticks is cumulative here; diff() turns it into a percentage. A process
    that exits mid-read is simply absent."""
    hz = hz or clock_ticks()
    boot_ms = boot_time_ms() if boot_ms is None else boot_ms
    page_kb = page_kb or os.sysconf("SC_PAGE_SIZE") // 1024
    rows = {}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        try:
            with open(f"{proc}/{entry}/stat", "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        close = raw.rfind(b")")
        if close < 0:
            continue
        name = raw[raw.find(b"(") + 1:close].decode("utf-8", "replace")
        f = raw[close + 2:].split()
        try:
            pid, ppid = int(entry), int(f[1])
            ticks = int(f[11]) + int(f[12])
            created = boot_ms + int(f[19]) * 1000 // hz
            rss_kb = int(f[21]) * page_kb
        except (IndexError, ValueError):
            continue
        key = f"{pid}:{created}"
        rows[key] = [key, pid, ppid, name, created, ticks, rss_kb, -1]
    return rows


def diff(prev, cur, elapsed_s, hz, cpus):
    """(added rows, exited keys, updates [key, cpu, rss]) between two /proc reads.

    Mutates `cur` so each row holds a CPU percentage (of the whole machine,
    like the Windows side) instead of cumulative ticks."""
    added, updated = [], []
    budget = max(elapsed_s, 1e-3) * hz * max(cpus, 1)
    for key, row in cur.items():
        old = prev.get(key)
        ticks = row[5]
        pct = 0.0 if old is None else max(0.0, min(100.0, (ticks - old[8]) * 100.0 / budget))
        row[5] = round(pct, 1)
        row.append(ticks)                       # [8]: raw ticks for the next diff
        if old is None:
            added.append(row[:8])
        elif abs(row[5] - old[5]) >= 0.5 or abs(row[6] - old[6]) > max(1024, old[6] // 50):
            updated.append([key, row[5], row[6]])
        else:
            row[5], row[6] = old[5], old[6]     # keep what the viewer last saw
    exited = [k for k in prev if k not in cur]
    return added, exited, updated


def exe_path(pid, proc="/proc"):
    """The executable of one process, or "" when it cannot be read.

    A replaced or removed file reads "<path> (deleted)" and an anonymous one
    "/memfd:<name> (deleted)"; both are kept as the kernel reports them so the
    identity check can tell them apart."""
    try:
        return os.readlink(f"{proc}/{pid}/exe")
    except OSError:
        return ""


def parse_start(line):
    """One Sysmon for Linux journal line -> {pid, ppid, path, sha256}, or None
    when it is not a process start. Reads nothing else from the record: no
    command line, user or working directory."""
    if _START not in line:
        return None
    fields = dict(_FIELD.findall(line))
    try:
        pid, ppid = int(fields["ProcessId"]), int(fields.get("ParentProcessId") or 0)
    except (KeyError, ValueError):
        return None
    path = fields.get("Image", "").strip()
    sha = _SHA256.search(fields.get("Hashes", ""))
    return {"pid": pid, "ppid": ppid, "path": "" if path == "-" else path,
            "name": os.path.basename(path) if path not in ("", "-") else "?",
            "sha256": sha.group(1).lower() if sha else ""}


class StartFollower:
    """`journalctl -f` over Sysmon for Linux, started and stopped with the feed."""

    def __init__(self, spawn=None):
        self._spawn = spawn or self._journalctl
        self.proc = None

    @staticmethod
    def _journalctl():
        return subprocess.Popen(
            ["journalctl", "-f", "-n", "0", "-o", "cat", *SYSMON_TRUSTED_MATCH, "--no-pager"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def open(self):
        self.proc = self._spawn()

    def starts(self, stop):
        """Yield parsed starts until `stop` is set or the follower ends."""
        for raw in iter(lambda: self.proc.stdout.readline(MAX_LINE), b""):
            if stop.is_set():
                return
            start = parse_start(raw.decode("utf-8", "replace"))
            if start is not None:
                yield start

    def exit_code(self):
        return None if self.proc is None else self.proc.poll()

    def close(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
