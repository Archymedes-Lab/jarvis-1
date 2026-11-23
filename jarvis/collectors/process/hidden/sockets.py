"""Sockets and listeners with no visible owning process."""

import errno
import os
import time

from jarvis.core import epochs
from jarvis.core.observation import CONFIRMED, INCONCLUSIVE, TRANSIENT
from jarvis.platform.linux import socket_table

from .common import PROC


def _unclaimed_socket_rows():
    """Take one uncached socket/fd view, retaining inode identity for recheck."""
    # The shared five-second socket cache can describe a connection that has
    # already closed before the fd sweep starts. Attribution needs fresh views.
    try:
        table = socket_table(fresh=True, strict=True)
    except (OSError, ValueError, UnicodeError):
        return False, {}, 0
    if not table:
        return True, {}, 0
    claimed = set()
    denied = 0
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            for fd in os.listdir(fddir):
                try:
                    target = os.readlink(f"{fddir}/{fd}")
                except OSError as exc:
                    if exc.errno in (errno.EACCES, errno.EPERM):
                        denied += 1
                    continue
                if target.startswith("socket:["):
                    claimed.add(int(target[8:-1]))
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                denied += 1
            continue

    orphans = {}
    for inode, conn in table.items():
        if inode in claimed or inode == 0:
            continue
        if conn["state"] in ("TIME_WAIT", "CLOSE"):
            continue  # kernel-owned leftovers, no process behind them
        orphans[inode] = conn
    return True, orphans, denied


def orphan_sockets():
    """Return attributed observations and fd-visibility limitations.

    Bounded coherent confirmation (core.observation): exactly one fresh
    re-query. A socket closing between /proc/net and the fd walk has no owner
    to find, so an unowned socket absent from the second view (or replaced by
    a different connection under the same inode) is "transient"; it is still
    returned so the first sighting stays on record, never scored as a
    confirmed discrepancy. A failed second read, or a sleep/resume/clock step
    between the views, is "inconclusive" and keeps the original severity.
    Keep persistent discrepancies visible, including WSL sockets whose owners
    may be outside this distro. This remains a root-only check at the caller.
    """
    before = epochs.sample()
    first_valid, first, first_denied = _unclaimed_socket_rows()
    if not first_valid:
        raise RuntimeError("socket tables unreadable; owner attribution unavailable")
    if not first:
        return [], first_denied
    time.sleep(0.35)
    second_valid, second, second_denied = _unclaimed_socket_rows()
    denied = first_denied + second_denied
    visibility = "limited" if denied else "complete"
    if not second_valid or not epochs.coherent(before, epochs.sample()):
        # A failed second read must not turn a suspicious first view into a
        # clean bill of health. A subsequent collector run can resolve it.
        return [{**conn, "_verification": INCONCLUSIVE, "_fd_visibility": visibility}
                for conn in first.values()], denied
    return ([{**conn, "_verification": CONFIRMED if second.get(inode) == conn else TRANSIENT,
              "_fd_visibility": visibility}
             for inode, conn in first.items()], denied)


def hidden_listeners(limit=10000):
    """Ports the kernel says are taken but /proc/net does not admit to.

    A rootkit that filters /proc/net/tcp still cannot make the kernel hand out a
    port that is genuinely bound. Asking to bind it and being refused with
    EADDRINUSE is only a discrepancy: TIME_WAIT sockets and connections created
    during the sweep can also reserve ports. Retain inode-zero rows and recheck.
    """
    import socket as _s

    visible = _visible_tcp_ports()
    if visible is None:
        raise RuntimeError('TCP socket tables unreadable; hidden listener check unavailable')
    found = []
    for port in range(1, limit + 1):
        if port in visible:
            continue
        sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        try:
            # No SO_REUSEADDR: we want an honest answer about the port.
            sock.bind(("0.0.0.0", port))
        except PermissionError:
            continue  # privileged port and we are not root; inconclusive
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                found.append(port)
            continue
        finally:
            sock.close()
    # Refresh after probing: the scan and socket table are not atomic.
    refreshed = _visible_tcp_ports()
    if refreshed is None:
        raise RuntimeError('TCP socket tables unreadable during listener recheck')
    confirmed = []
    for port in found:
        if port in refreshed:
            continue
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            try:
                sock.bind(('0.0.0.0', port))
            except OSError as exc:
                if exc.errno == errno.EADDRINUSE:
                    confirmed.append(port)
    return confirmed


def _visible_tcp_ports():
    # An inode-keyed dictionary collapses TIME_WAIT rows (all inode 0),
    # manufacturing hidden-port findings. Read every row instead.
    ports = set()
    for name in ('tcp', 'tcp6'):
        try:
            with open(f'{PROC}/net/{name}', errors="replace") as handle:
                for line in list(handle)[1:]:
                    fields = line.split()
                    if len(fields) >= 2:
                        ports.add(int(fields[1].rsplit(':', 1)[1], 16))
        except FileNotFoundError:
            if name == 'tcp6':
                continue
            return None
        except (OSError, ValueError, IndexError):
            return None
    return ports


def _socket_table_safe():
    try:
        return socket_table()
    except Exception:
        return {}
