"""osquery as an independent second view of processes, listeners and kernel modules.

Argus reads /proc from its own process, through raw syscalls where it matters
(getdents for the process list, openat/read for the socket tables), so a
preloaded libc hook cannot filter Argus's view. osquery is a separate program
that reads through ordinary libc calls (it links glibc dynamically: measured
2026-11-02 with ldd on 5.24.0). The two therefore fail differently:

* a hook inside Argus's own process or runtime hides things from Argus only:
  osquery sees them, Argus does not (high);
* a system-wide hook (/etc/ld.so.preload, a patched libc) fools osquery and
  every ordinary program but not Argus's raw reads: Argus sees them, osquery
  does not (high). When osquery is already installed, this job
asks it three fixed questions and reports where its answer disagrees with
Argus's own view. Disagreement is tamper evidence, not a verdict.

Invariants (tests/test_osquery.py):

* Optional and never installed: runs only an osqueryi found at a fixed path
  (never a PATH lookup) whose resolved file is a regular file owned by root and
  writable by nobody else. Absent osquery is reported once as low, never ok.
* Contained: fixed SQL only, no shell, an empty environment with a private
  temporary HOME removed afterwards, extensions and events off, a timeout and an
  output cap per query. Nothing leaves the machine and nothing is changed.
* Metadata only: process ids, listening TCP port numbers, kernel module names.
  No command lines, paths, users or file contents are read or stored.
* No false disagreement from races: Argus's view is read before and after
  osquery. An item is "missing from Argus" only if it is absent from both reads
  and the kernel still reports it (processes: kill(pid, 0) and not a thread);
  "missing from osquery" only if it is in both Argus reads.
* A failed or malformed osquery answer is reported as unavailable for that
  view, never as agreement.

Measured in a disposable container 2026-11-02 against osquery 5.24.0 with two
real LD_PRELOAD hiding libraries (tests/data notes in assurance.py).

Not covered (assurance.py `osquery_cross_view`): a kernel rootkit that filters
/proc for every reader fools both views (the hidden collector's kill probes and
sysfs checks are the defence there); only port numbers are compared (an
unprivileged osquery lists other accounts' listeners with pid -1, measured
2026-11-02, so the comparison holds without root); listeners
are compared only within Argus's own network namespace, so a container's ports
are out of scope rather than false alarms.
"""

import json
import os
import shutil
import stat
import subprocess
import tempfile

from jarvis.core.finding import finding
from jarvis.platform.linux import signal_zero
from jarvis.platform.procfs import is_thread, read_raw, view_getdents, view_readdir

CANDIDATES = ("/usr/bin/osqueryi", "/opt/osquery/bin/osqueryi", "/usr/local/bin/osqueryi")
FLAGS = ("--json", "--disable_extensions=true", "--disable_events=true")
TIMEOUT_S = 30
MAX_OUTPUT = 4 * 1024 * 1024
WHERE = "osquery (independent view)"

QUERIES = {
    "processes": "SELECT pid FROM processes;",
    # osquery reads every process's network namespace; Argus's /proc/net/tcp is
    # its own. Container listeners would read as hidden from Argus on every
    # Docker host, so rows are scoped to Argus's namespace (net_namespace column).
    "listeners": "SELECT DISTINCT port, net_namespace FROM listening_ports WHERE protocol = 6 AND port > 0;",
    "modules": "SELECT name FROM kernel_modules;",
}
FIELD = {"processes": "pid", "listeners": "port", "modules": "name"}


def _f(severity, title, detail):
    return finding("integrity", severity, title, detail, where=WHERE)


def locate(paths=CANDIDATES, stat_fn=os.stat, realpath=os.path.realpath):
    """The first trusted osqueryi, or None. Follows the deb symlink to osqueryd
    and judges the file it resolves to."""
    for path in paths:
        try:
            st = stat_fn(realpath(path))
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022:
            return path
    return None


def ask(exe, sql, runner=subprocess.run):
    """Rows of one fixed query, or None when osquery failed or answered badly."""
    home = tempfile.mkdtemp(prefix="argus-osquery-")
    try:
        r = runner([exe, *FLAGS, sql], env={"HOME": home}, cwd="/", stdin=subprocess.DEVNULL,
                   capture_output=True, timeout=TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(home, ignore_errors=True)
    out = r.stdout or b""
    if r.returncode != 0 or len(out) > MAX_OUTPUT:
        return None
    try:
        rows = json.loads(out.decode("utf-8", "replace") if isinstance(out, bytes) else out)
    except ValueError:
        return None
    return rows if isinstance(rows, list) and all(isinstance(x, dict) for x in rows) else None


def own_netns(readlink=os.readlink):
    """Argus's network namespace inode as osquery prints it ('4026531840'), or None."""
    try:
        link = readlink("/proc/self/ns/net")
    except OSError:
        return None
    inode = link.rsplit("[", 1)[-1].rstrip("]")
    return inode if inode.isdigit() else None


def values(kind, rows, netns=None):
    """The compared values of one answer, or None when a row is malformed or,
    for listeners, cannot be scoped to Argus's network namespace."""
    out = set()
    if kind == "listeners" and netns is None:
        return None
    for row in rows:
        if kind == "listeners":
            ns = str(row.get("net_namespace", "")).strip()
            if not ns.isdigit():
                return None
            if ns != netns:
                continue
        value = row.get(FIELD[kind])
        if kind == "modules":
            if not isinstance(value, str) or not value:
                return None
            out.add(value)
        else:
            try:
                out.add(int(value))
            except (TypeError, ValueError):
                return None
    return out


# --- Argus's own view --------------------------------------------------------

def own_processes():
    pids = view_readdir()
    raw = view_getdents()
    return pids | (raw or set())


def own_listeners(proc="/proc", reader=read_raw):
    """Listening TCP ports from /proc/net/tcp{,6}, read through raw syscalls so a
    preloaded open() hook cannot remove rows; None when unreadable."""
    ports = set()
    for name in ("tcp", "tcp6"):
        raw = reader(f"{proc}/net/{name}")
        if raw is None:
            if name == "tcp6":
                continue
            return None
        for line in raw.decode("ascii", "replace").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[3] == "0A":  # TCP_LISTEN
                try:
                    ports.add(int(fields[1].rsplit(":", 1)[1], 16))
                except (ValueError, IndexError):
                    return None
    return ports


def own_modules(proc="/proc"):
    try:
        with open(f"{proc}/modules", errors="replace") as fh:
            return {line.split()[0] for line in fh if line.split()}
    except OSError:
        return None


OWN = {"processes": own_processes, "listeners": own_listeners, "modules": own_modules}


def _alive(pid):
    try:
        signal_zero(pid)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return not is_thread(pid)


def compare(kind, before, theirs, after, alive=_alive):
    """(missing_from_argus, missing_from_osquery) after race filtering."""
    ours_any = before | after
    ours_both = before & after
    hidden = theirs - ours_any
    if kind == "processes":
        hidden = {p for p in hidden if alive(p)}
    absent = ours_both - theirs
    if kind == "processes":
        absent = {p for p in absent if alive(p)}
    return hidden, absent


LABEL = {"processes": "process ids", "listeners": "listening TCP ports", "modules": "kernel modules"}


def _show(items):
    items = sorted(items, key=str)
    return ", ".join(map(str, items[:12])) + (f" and {len(items) - 12} more" if len(items) > 12 else "")


def audit(locate_fn=locate, ask_fn=ask, own=None, alive=_alive, netns_fn=own_netns):
    own = own or OWN
    exe = locate_fn()
    if exe is None:
        return [_f("low", "osquery is not installed: no independent second view",
                   "Argus compares its own view of processes, listening ports and kernel modules "
                   "with osquery's when osquery is installed by the operator (Argus never installs "
                   "it). Without it, a hook that filters Argus's own reads is caught only by the "
                   "hidden-process checks.")]
    out, agreed, unavailable = [], [], []
    netns = netns_fn()
    for kind, sql in QUERIES.items():
        before = own[kind]()
        rows = ask_fn(exe, sql)
        after = own[kind]()
        theirs = values(kind, rows, netns) if rows is not None else None
        if before is None or after is None or theirs is None:
            unavailable.append(LABEL[kind])
            continue
        hidden, absent = compare(kind, before, theirs, after, alive)
        if hidden:
            out.append(_f("high", f"{LABEL[kind]} visible to osquery are missing from Argus's own view",
                          f"{_show(hidden)}: osquery saw them, two reads by Argus before and after did "
                          "not, and they still exist. Something may be filtering what Argus's process "
                          "can see (an LD_PRELOAD library or a tampered runtime). Compare with "
                          "`argus hidden` and check /etc/ld.so.preload."))
        if absent:
            out.append(_f("high", f"{LABEL[kind]} seen by Argus are hidden from ordinary programs",
                          f"{_show(absent)}: Argus's raw kernel reads (before and after) found them, "
                          "osquery, which reads through the system C library like most programs, did "
                          "not. A system-wide hiding hook (check /etc/ld.so.preload and the C library) "
                          "or a tampered osquery would explain it."))
        if not hidden and not absent:
            agreed.append(f"{LABEL[kind]} ({len(theirs)})")
    if unavailable:
        out.append(_f("low", "osquery cross-view incomplete",
                      f"No usable answer for {', '.join(unavailable)}; those views were not compared."))
    if agreed:
        out.append(_f("ok", "osquery and Argus agree",
                      "Same set from both readers for " + ", ".join(agreed) + "."))
    return out
