"""Collect processes and their sockets from /proc. Stdlib only, no root needed.

Without root you see full detail for your own processes and names/cmdlines for
everyone else's; sockets owned by other users resolve to the process only if we
can read their fd table.
"""

import os
import re

try:
    import pwd
except ImportError:      # native Windows: no passwd database, and no caller there
    pwd = None

from jarvis.core.util import fingerprint
from jarvis.platform.executable_identity import replaced_identically

PROC = "/proc"
HOST = "wsl"
# At most 2 * 2 * 32 MiB read per process pass.
MAX_REPLACEMENT_CHECKS = 2

# Interpreters whose real identity is the script they were handed, not the binary.
INTERPRETERS = re.compile(
    r"^(python[\d.]*|perl|ruby|node|bash|sh|dash|zsh|ksh|php|lua|Rscript|deno|bun)$"
)
SCRIPT_EXT = re.compile(r"\.(py|sh|pl|rb|js|mjs|cjs|ts|php|lua|R|bash|zsh)$", re.I)


def signal_zero(pid):
    """kill(pid, 0): ask the kernel whether a pid exists. Raises as os.kill does.

    Signal 0 is a question only on POSIX. On Windows the same call is
    os.kill(pid, CTRL_C_EVENT) - it interrupts a console process group instead
    of asking anything - and any other signal number terminates the target.
    There is no Linux pid to ask about there, so the answer is "no such
    process" and nothing is sent.
    """
    if os.name == "nt":
        raise ProcessLookupError(pid)
    os.kill(pid, 0)


def read_file(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return b"" if binary else ""


def _uid_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, AttributeError):
        return str(uid)


def _parse_addr(hexaddr):
    """/proc/net/* encodes addresses as little-endian hex words."""
    host, _, port = hexaddr.rpartition(":")
    port = int(port, 16)
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        ip = ".".join(str(b) for b in raw[::-1])
    elif len(raw) == 16:
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        flat = b"".join(words)
        parts = [f"{flat[i]<<8 | flat[i+1]:x}" for i in range(0, 16, 2)]
        ip = ":".join(parts)
        # Render v4-mapped addresses (::ffff:a.b.c.d) in their familiar form.
        if parts[:6] == ["0", "0", "0", "0", "0", "ffff"]:
            ip = ".".join(str(b) for b in flat[12:16])
    else:
        ip = host
    return ip, port


TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


MAX_SOCKET_TABLE_BYTES = 8 * 1024 * 1024


def socket_table(fresh=False, strict=False):
    """inode -> connection detail, built from all four /proc/net socket tables.

    One authoritative read per interval: shared via jarvis.core.state so
    process, firewall and hidden-socket consumers do not each walk
    /proc/net. Attribution checks can request a fresh view to compare with
    the current fd tables. Strict attribution reads bypass the cache and validate
    required headers, complete rows and a per-table byte budget; errors propagate.
    Best-effort callers retain the mapping-only API and cache fallback.
    """
    if strict:
        return _read_socket_table(strict=True)
    if fresh:
        return _read_socket_table()
    try:
        from jarvis.core import state as _state
        return _state.get_socket_table(_read_socket_table)
    except Exception:
        return _read_socket_table()


def _read_socket_table(strict=False):
    """inode -> connection detail, built from all four /proc/net socket tables."""
    table = {}
    for fname, proto in (("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6")):
        if strict:
            try:
                with open(f"{PROC}/net/{fname}", "rb") as handle:
                    raw = handle.read(MAX_SOCKET_TABLE_BYTES + 1)
            except FileNotFoundError:
                if fname.endswith("6"):
                    continue
                raise
            if len(raw) > MAX_SOCKET_TABLE_BYTES:
                raise ValueError("socket table exceeded the read budget")
            text = raw.decode("ascii")
            header = text.splitlines()[0] if text else ""
            if "local_address" not in header or "inode" not in header:
                raise ValueError("socket table header is missing or malformed")
        else:
            text = read_file(f"{PROC}/net/{fname}")
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                if strict:
                    raise ValueError("socket table row is incomplete")
                continue
            try:
                lip, lport = _parse_addr(f[1])
                rip, rport = _parse_addr(f[2])
                inode = int(f[9])
            except (ValueError, IndexError):
                if strict:
                    raise
                continue
            table[inode] = {
                "proto": proto,
                "local_ip": lip,
                "local_port": lport,
                "remote_ip": rip,
                "remote_port": rport,
                "state": TCP_STATES.get(f[3].upper(), f[3]) if proto.startswith("tcp") else "-",
            }
    return table


def _proc_sockets(pid, table):
    """Map a pid's socket fds back to the connection table."""
    conns = []
    fddir = f"{PROC}/{pid}/fd"
    try:
        fds = os.listdir(fddir)
    except (OSError, PermissionError):
        return conns
    for fd in fds:
        try:
            target = os.readlink(f"{fddir}/{fd}")
        except OSError:
            continue
        if target.startswith("socket:["):
            inode = int(target[8:-1])
            if inode in table:
                conns.append(table[inode])
    return conns


# Flags whose argument is inline code (or a module name), not a script file.
INLINE_FLAGS = {"sh": "c", "bash": "c", "dash": "c", "zsh": "c", "ksh": "c",
                "python": "cm", "perl": "eE", "ruby": "e", "node": "ep", "bun": "e",
                "deno": "", "php": "r", "lua": "e", "Rscript": "e"}
# A temp-directory file in command position inside inline code: run directly,
# sourced, or handed to an interpreter. A redirection target (`>| /tmp/x`) or
# an argument to cat/ls is not executed and does not match.
INLINE_EXEC_TEMP = re.compile(
    r"(?:^|(?<![<>])[;&|]\s*|[({]\s*|\b(?:sh|bash|dash|zsh|source|exec|python3?|perl|node|ruby)\s+"
    r"|(?:^|\s)\.\s+)"
    r"((?:/tmp|/var/tmp|/dev/shm)/[^\s;&|<>'\"]+)")


def _script_target(argv, exe_base):
    """For an interpreter, return the script path it is actually executing.

    Inline code (`bash -c ...`, `python3 -c ...`) is not a script file: before
    2026-10-29 the whole -c string was returned as the "script", so any inline
    command that merely mentioned /tmp (Claude Code's own shell wrapper writes
    `pwd -P >| /tmp/...`) scored as a new binary run from temp, critical. For
    inline code the target is a temp file it executes, or nothing."""
    if not INTERPRETERS.match(exe_base):
        return ""
    family = re.sub(r"[\d.]+$", "", exe_base)
    inline = INLINE_FLAGS.get(family, "")
    args = argv[1:]
    for i, arg in enumerate(args):
        if arg.startswith("--"):
            if arg in ("--eval", "--print", "--command"):
                code = args[i + 1] if i + 1 < len(args) else ""
                m = INLINE_EXEC_TEMP.search(code)
                return m.group(1) if m else ""
            continue
        if arg.startswith("-") and len(arg) > 1:
            if inline and any(ch in inline for ch in arg[1:]):
                code = args[i + 1] if i + 1 < len(args) else ""
                if "m" in arg[1:] and family == "python":
                    return ""                       # a module name, not a file
                m = INLINE_EXEC_TEMP.search(code)
                return m.group(1) if m else ""
            continue
        return arg
    return ""


def collect(with_sockets=True):
    """Return a list of process records for the Linux side."""
    table = socket_table() if with_sockets else {}
    procs = []
    replacement_checks = 0
    self_pid = os.getpid()
    try:
        clock_ticks = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError):
        clock_ticks = 100

    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == self_pid:
            continue
        base = f"{PROC}/{pid}"

        raw = read_file(f"{base}/cmdline", binary=True)
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
        status = read_file(f"{base}/status")
        if not status:
            continue  # process exited mid-scan

        name = ""
        uid = -1
        ppid = 0
        rss_bytes = 0
        for line in status.splitlines():
            if line.startswith("Name:"):
                name = line.split("\t", 1)[-1].strip()
            elif line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("PPid:"):
                ppid = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                try:
                    rss_bytes = int(line.split()[1]) * 1024
                except (ValueError, IndexError):
                    pass

        cpu_seconds = 0.0
        stat_line = read_file(f"{base}/stat")
        try:
            stat_fields = stat_line.rsplit(") ", 1)[1].split()
            cpu_seconds = (int(stat_fields[11]) + int(stat_fields[12])) / clock_ticks
        except (ValueError, IndexError):
            pass

        # Distinguish "no exe" (kernel thread / deleted binary — interesting)
        # from "can't read it" (another user's process — not our business).
        exe, exe_hidden = "", False
        try:
            exe = os.readlink(f"{base}/exe")
        except PermissionError:
            exe_hidden = True
        except OSError:
            pass
        # The executable's file identity, taken with the link: a short-lived
        # process (a udev worker) is often gone before it is assessed, and a
        # later re-read would then fail closed on a process that was fine.
        exe_ident = None
        if exe:
            try:
                st = os.stat(f"{base}/exe")
                exe_ident = (st.st_dev, st.st_ino, st.st_uid, st.st_mode)
            except OSError:
                pass

        replaced_unchanged = False
        if exe.endswith(" (deleted)") and replacement_checks < MAX_REPLACEMENT_CHECKS:
            replacement_checks += 1
            replaced_unchanged = replaced_identically(pid, exe, proc=PROC)

        cmdline = " ".join(argv) if argv else f"[{name}]"
        exe_base = os.path.basename(exe or name)
        script = _script_target(argv, exe_base)

        # A python script's identity is the script, not /usr/bin/python3.
        ident_exe = script if script else exe

        procs.append({
            "host": HOST,
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "exe": exe,
            "exe_hidden": exe_hidden,
            "exe_ident": exe_ident,
            "deleted_replaced_identically": replaced_unchanged,
            "script": script,
            "cmdline": cmdline,
            "user": _uid_name(uid),
            "rss_bytes": rss_bytes,
            "cpu_seconds": cpu_seconds,
            "conns": _proc_sockets(pid, table) if with_sockets else [],
            "fp": fingerprint(HOST, ident_exe or name, cmdline, _uid_name(uid)),
        })

    return procs
