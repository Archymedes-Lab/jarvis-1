"""Correlating every view into findings."""

import ipaddress
import os
import time

from jarvis.core import epochs
from jarvis.core.observation import TRANSIENT
from jarvis.platform import privilege, topology
from jarvis.platform.linux import signal_zero

from . import ebpf
from .common import DEFAULT_SWEEP, PROC, _finding

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
from .kernel import (
    REPLACED_IDENTICAL,
    bpf_hidden_pins,
    bpf_programs,
    ftrace_hook_list,
    hidden_modules,
    injected_processes,
    io_uring_state,
    proc_overmounts,
)
from .sockets import hidden_listeners, orphan_sockets
from .views import (
    _alive,
    _describe,
    is_thread,
    pid_max,
    view_getdents,
    view_kill_probe,
    view_readdir,
    view_sched_debug,
    view_stat_sweep,
)
from .windows import audit_windows

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def confirmed_ghosts(ghosts, fresh_read, fresh_sig):
    """Pids that answer signals, are not listed in /proc, and are not threads.

    Measured 2026-09-17: a lone critical for a pid that, re-probed, was one of
    ~260 ordinary threads. is_thread() answers False when the status read
    fails, and a thread that exits between the probe and that read fails it.
    So the pid must still answer a signal after the thread test: a vanished
    thread does not, a hidden process does.
    """
    return [pid for pid in ghosts
            if pid in fresh_sig and pid not in fresh_read and not is_thread(pid)
            and _still_alive(pid) and not is_thread(pid)]


def _still_alive(pid):
    """Does `pid` still answer kill(pid, 0)? EPERM counts: it exists."""
    try:
        signal_zero(pid)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def audit_linux(deep=False, db_path=None):
    out = []
    sweep_limit = pid_max() if deep else min(DEFAULT_SWEEP, pid_max())

    readdir = view_readdir()
    getdents = view_getdents()
    swept = view_stat_sweep(sweep_limit)
    signalled = view_kill_probe(sweep_limit)
    sched = view_sched_debug()

    # Anything the sweep can stat but the listing omitted. Re-verify, because a
    # process that simply exited between the two passes looks identical here.
    suspects = sorted(swept - readdir)
    confirmed = []
    if suspects:
        time.sleep(0.35)
        fresh = view_readdir()
        for pid in suspects:
            if _alive(pid) and pid not in fresh and not is_thread(pid):
                confirmed.append(pid)

    for pid in confirmed:
        info = _describe(pid)
        out.append(_finding(
            "critical", "process hidden from /proc listing",
            f"pid {pid} ({info['name']}) resolves by direct stat() but is absent "
            f"from readdir — {info['cmdline'] or info['exe'] or 'no cmdline'}",
            f"uid={info['uid']} ppid={info['ppid']} exe={info['exe'] or '?'}",
        ))

    if getdents is None:
        out.append(_finding("low", "syscall view unavailable",
                            "could not call getdents64 directly on this ABI; "
                            "libc-hook detection was skipped", os.uname().machine))
    else:
        # Sequential views race with process creation. Require the discrepancy
        # to survive fresh views in both directions before raising a finding.
        hooked = sorted(getdents - readdir)
        if hooked:
            fresh_raw = view_getdents()
            fresh_libc = view_readdir()
            hooked = [pid for pid in hooked if fresh_raw is not None
                      and pid in fresh_raw and pid not in fresh_libc]
        for pid in hooked:
            if _alive(pid) and not is_thread(pid):
                info = _describe(pid)
                out.append(_finding(
                    "critical", "process hidden from libc but visible to the kernel",
                    f"pid {pid} ({info['name']}) appears in raw getdents64 output "
                    f"but not through repeated libc listings. This persistent "
                    f"cross-view discrepancy needs investigation; it is not proof of a rootkit.",
                    info["cmdline"] or info["exe"],
                ))

    # -- the signal path vs procfs ----------------------------------------
    # Everything above reaches the kernel through procfs, so one rootkit that
    # filters procfs defeats all of them together. kill(pid, 0) resolves through
    # the pid hash table instead, and a pid that answers a signal while having no
    # /proc entry at all is hidden below the filesystem layer.
    ghosts = sorted(signalled - readdir - swept)
    if ghosts:
        time.sleep(0.35)
        fresh_read, fresh_sig = view_readdir(), view_kill_probe(sweep_limit)
        confirmed = confirmed_ghosts(ghosts, fresh_read, fresh_sig)
        if not confirmed:
            out.append(_finding("ok", "signal view agrees with /proc",
                                f"{len(ghosts)} unlisted pids answered kill(pid, 0); every "
                                f"one re-checked as a thread or had exited", f"1–{sweep_limit}"))
        for pid in confirmed:
            info = _describe(pid)
            out.append(_finding(
                "critical", "pid answers signals but has no /proc entry",
                f"pid {pid} accepts kill(pid, 0) while procfs denies it "
                f"exists — procfs is being filtered below the point every "
                f"other view reads from",
                f"name={info['name'] or '?'} exe={info['exe'] or '?'}"))
    else:
        out.append(_finding("ok", "signal view agrees with /proc",
                            f"{len(signalled)} pids answer kill(pid, 0), all of "
                            f"them present in procfs", f"1–{sweep_limit}"))

    # -- the scheduler's view ---------------------------------------------
    if sched is None:
        out.append(_finding(
            "low", "scheduler view unavailable",
            "/proc/sched_debug is absent — this kernel was built without "
            "CONFIG_SCHED_DEBUG, so the runqueue cross-check was skipped",
            f"{PROC}/sched_debug"))
    else:
        missing = sorted(p for p in sched - readdir if _alive(p) and not is_thread(p))
        for pid in missing:
            info = _describe(pid)
            out.append(_finding(
                "critical", "process on a runqueue but absent from /proc",
                f"pid {pid} ({info['name']}) is scheduled by the kernel yet does "
                f"not appear in the process listing",
                info["cmdline"] or info["exe"] or ""))
        if not missing:
            out.append(_finding("ok", "scheduler view agrees with /proc",
                                f"{len(sched)} scheduled tasks, all visible",
                                f"{PROC}/sched_debug"))

    for path in proc_overmounts():
        out.append(_finding("critical", "/proc entry is bind-mounted over",
                            f"{path} is masked by a mount, hiding that process",
                            "/proc/self/mountinfo"))

    out.extend(bpf_hidden_pins())
    out.extend(io_uring_state())

    # -- hidden listeners --------------------------------------------------
    port_limit = 65535 if deep else 10000
    for port in hidden_listeners(port_limit):
        out.append(_finding(
            "high", "TCP port reservation discrepancy needs investigation",
            f"tcp/{port} refuses a bind with EADDRINUSE, yet nothing in "
            f"/proc/net claims it after a refresh; a race or hidden socket remains possible, not confirmed concealment",
            f"bind probe 1–{port_limit}"))

    # -- kernel modules ----------------------------------------------------
    for mod in hidden_modules():
        out.append(_finding(
            "critical", "kernel module hidden from /proc/modules",
            f"{mod} is live in sysfs but unlisted — the signature of an LKM "
            f"rootkit unlinking itself", f"/sys/module/{mod}"))

    # -- eBPF --------------------------------------------------------------
    progs, holders = bpf_programs()
    for p in progs:
        risky = (p.get("type") or "") in (
            "kprobe", "tracepoint", "raw_tracepoint", "lsm", "fentry", "fexit")
        out.append(_finding(
            "medium" if risky else "low", "eBPF program loaded",
            f"{p['name']} [{p.get('type')}] id={p.get('id')}"
            + (f" pids={[x.get('pid') for x in p['pids']]}" if p.get("pids") else ""),
            "bpftool prog list"))
    # Independent of bpftool, which most machines lack: kallsyms against a baseline.
    try:
        out.extend(ebpf.findings(holders, db_path=db_path))
    except Exception as exc:
        out.append(_finding("medium", "eBPF program inventory unavailable",
                            f"inventory failed: {type(exc).__name__}", "/proc/kallsyms"))
    for h in holders:
        out.append(_finding("low", "process holds eBPF handles",
                            f"{h['name']} [pid {h['pid']}] — {', '.join(h['kinds'])}",
                            f"/proc/{h['pid']}/fd"))

    hooks = ftrace_hook_list()
    by_kind = {k: [f for f, kind in hooks if kind == k] for k in ("ftrace", "bpf", "kernel_bpf")}
    for kind, severity, title, why in (
            ("ftrace", "high", "kernel functions are hooked via ftrace",
             "an ftrace callback, not an eBPF program: the technique ftrace rootkits use"),
            ("bpf", "medium", "kernel functions are traced by eBPF programs",
             "direct calls into eBPF trampolines; see the eBPF programs listed with them"),
            ("kernel_bpf", "low", "kernel HID-BPF dispatcher is attached",
             "the HID subsystem's own BPF hook, present on stock kernels with HID-BPF")):
        names = by_kind[kind]
        if names:
            out.append(_finding(
                severity, title,
                f"{len(names)}: {', '.join(names[:6])}" + ("…" if len(names) > 6 else "") + f" — {why}",
                "/sys/kernel/tracing/enabled_functions"))

    # -- injected / fileless code -----------------------------------------
    for hit in injected_processes():
        worst = max(("fileless" in r[0]) * 2 + ("deleted" in r[0]) for r in hit["reasons"])
        benign = all(r[0] == REPLACED_IDENTICAL for r in hit["reasons"])
        out.append(_finding(
            "low" if benign else "critical" if worst else "high",
            hit["reasons"][0][0],
            f"{hit['name']} [pid {hit['pid']}] — {hit['reasons'][0][1][:80]}",
            hit["cmdline"][:120]))

    if privilege.can_read_other_processes():
        wsl = _on_wsl()
        unowned, denied = orphan_sockets()
        try:
            topo = topology.snapshot() if wsl else None
        except Exception:
            topo = None
        out.extend(_orphan_findings(unowned, denied, wsl, topo))

    out.append(_finding("ok", "cross-view scan complete",
                        f"{len(readdir)} pids via readdir, "
                        f"{len(getdents) if getdents is not None else '—'} via getdents64, "
                        f"{len(swept)} via stat sweep (1–{sweep_limit})",
                        ""))
    for f in out:
        f["host"] = "wsl"
    return out


def _on_wsl():
    try:
        with open("/proc/sys/kernel/osrelease", errors="replace") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


# WSL assigns this address to lo for its DNS tunnel; it is not routable.
WSL_DNS_TUNNEL = "10.255.255.254"


def _local_only_listener(conn):
    """A bound socket with no peer on a loopback address: reachable only from
    this machine. A connection with a peer, or anything on a routable
    address, is not."""
    try:
        local = ipaddress.ip_address(str(conn.get("local_ip") or "").split("%")[0])
        remote = ipaddress.ip_address(str(conn.get("remote_ip") or "").split("%")[0])
    except ValueError:
        return False
    if local.version == 6 and local.ipv4_mapped:
        local = local.ipv4_mapped
    peerless = remote.is_unspecified and str(conn.get("remote_port")) in ("0", "")
    return peerless and (local.is_loopback or str(local) == WSL_DNS_TUNNEL)


def _orphan_finding(conn, wsl, topo=None):
    """Classify exposure and evidence quality without inferring malice or acting."""
    if conn.get("_verification") == TRANSIENT:
        # The first sighting stays on record; one fresh view no longer held
        # it, so it is evidence of a race, not a confirmed discrepancy.
        return _finding(
            "low", "unowned socket closed before confirmation",
            f"{conn.get('proto')} {conn.get('local_ip')}:{conn.get('local_port')} → "
            f"{conn.get('remote_ip')}:{conn.get('remote_port')} ({conn.get('state')}); "
            "no visible process fd claimed it in the first view and a second, valid "
            "view no longer showed it; kept as a first-observation record",
            "/proc/net + two fd sweeps")
    declared = topology.dns_tunnel_listener(conn, topo) if wsl else None
    if declared:
        return _finding(
            "low", "WSL DNS tunnel listener is held outside this distro",
            f"{conn['proto']} {conn['local_ip']}:{conn['local_port']} ({conn['state']}); "
            f"{declared}; confirmed in two views with complete fd visibility; "
            "its owner in the WSL VM is not observable from here",
            "/etc/resolv.conf + /proc/net/fib_trie + two fd sweeps")
    if wsl and _local_only_listener(conn):
        severity, title = "medium", "local listener owner not visible in this distro"
    else:
        try:
            local = ipaddress.ip_address(str(conn.get("local_ip") or "").split("%")[0])
            remote = ipaddress.ip_address(str(conn.get("remote_ip") or "").split("%")[0])
            if local.version == 6 and local.ipv4_mapped:
                local = local.ipv4_mapped
            if remote.version == 6 and remote.ipv4_mapped:
                remote = remote.ipv4_mapped
            peerless = remote.is_unspecified and str(conn.get("remote_port")) in ("0", "")
            if peerless:
                title = "network endpoint with no visible owner"
            elif local.is_loopback and remote.is_loopback:
                title = "local connection with no visible owner"
            else:
                title = "network connection with no visible owner"
        except ValueError:
            title = "socket scope unknown and owner not visible"
        severity = "high"
    verification = conn.get("_verification", "unknown")
    visibility = conn.get("_fd_visibility", "unknown")
    limitations = []
    if verification != "confirmed":
        limitations.append("the second socket-table view was inconclusive")
    if visibility != "complete":
        limitations.append("process fd visibility was limited")
    limitations.append("WSL may have owners outside this distro" if wsl else
                       "a missing visible fd is not proof of a hidden process")
    detail = (f"{conn['proto']} {conn['local_ip']}:{conn['local_port']} → "
              f"{conn['remote_ip']}:{conn['remote_port']} ({conn['state']}); "
              f"no visible process fd claimed this socket; " + "; ".join(limitations))
    return _finding(severity, title, detail, "/proc/net + two fd sweeps")


def _orphan_findings(unowned, denied, wsl, topo=None):
    """Keep scan limitations visible even when no candidate socket remains."""
    out = []
    if denied:
        out.append(_finding(
            "low", "socket owner visibility limited",
            f"{denied} process fd reads were denied across the socket "
            "attribution views; an owner may be unreadable in this distro",
            "/proc/<pid>/fd"))
    out.extend(_orphan_finding(conn, wsl, topo) for conn in unowned)
    return out


def audit(hosts=("wsl", "win"), deep=False, db_path=None):
    out, extra = [], {}
    if db_path:
        # The service passes its store; tests and CLI calls without one never
        # write the protected user's store. A ledger failure never blocks
        # the scan: at worst the next sample opens an extra epoch.
        try:
            epochs.record(db_path)
        except Exception:
            pass
    if "wsl" in hosts:
        out += audit_linux(deep=deep, db_path=db_path)
    if "win" in hosts:
        res = audit_windows()
        if isinstance(res, tuple):
            out += res[0]
            extra = res[1]
        else:
            out += res
    out.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out, extra
