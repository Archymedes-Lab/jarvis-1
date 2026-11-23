"""Kernel-level hiding: modules, eBPF, io_uring and ftrace hooks."""

import os
import re

from jarvis.platform.executable_identity import replaced_identically

from .common import PROC, _finding, _read, _run_capture
from .views import _describe

BPF_HIDE_MAPS = re.compile(r"hidden_(pids?|names?|inodes?|files?|ports?)|"
                           r"(pid|name|inode|port)s?_to_hide|hide_(pid|list|map)",
                           re.I)


def hidden_modules():
    """Modules the kernel has loaded but /proc/modules omits.

    A classic LKM rootkit unlinks itself from the module list, but the sysfs
    directory it created on load usually survives the trick.
    """
    listed = set()
    for line in _read("/proc/modules").splitlines():
        if line.split():
            listed.add(line.split()[0])

    hidden = []
    try:
        for name in os.listdir("/sys/module"):
            # Built-in modules have no initstate; only genuinely loaded ones do.
            state = _read(f"/sys/module/{name}/initstate").strip()
            if state == "live" and name not in listed:
                hidden.append(name)
    except OSError:
        pass
    return hidden


def bpf_programs():
    """Loaded eBPF programs and the processes holding eBPF file descriptors.

    eBPF is now the preferred way to build a Linux rootkit: it loads on any
    modern kernel without matching kernel headers, and it can filter what other
    tools see. Legitimate users exist (systemd, docker, observability agents),
    so this is inventory to review, not an accusation.
    """
    progs, holders = [], []

    out = _run_capture(["bpftool", "--json", "prog", "list"])
    if out:
        try:
            import json as _json
            for p in _json.loads(out):
                progs.append({
                    "id": p.get("id"), "type": p.get("type"),
                    "name": p.get("name") or "(unnamed)",
                    "tag": p.get("tag", ""), "pids": p.get("pids", []),
                })
        except Exception:
            pass

    # Even without bpftool, a process holding a bpf fd is visible in its fd table.
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        kinds = set()
        for fd in fds:
            try:
                target = os.readlink(f"{fddir}/{fd}")
            except OSError:
                continue
            if "bpf-prog" in target or "bpf-map" in target or "bpf_link" in target:
                kinds.add(target.split(":")[-1].strip("[]"))
        if kinds:
            holders.append({"pid": int(entry), "name": _describe(int(entry))["name"],
                            "kinds": sorted(kinds)})
    return progs, holders


def bpf_hidden_pins():
    """Walk /sys/fs/bpf looking for pinned objects that exist to hide things.

    This is the rare check that can do better than 'something is wrong': if a
    map named hidden_pids is present, its contents are the answer.
    """
    out, names = [], []
    root = "/sys/fs/bpf"
    if not os.path.isdir(root):
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        for n in list(dirnames) + list(filenames):
            names.append(os.path.join(dirpath, n))
    for path in names:
        base = os.path.basename(path)
        if BPF_HIDE_MAPS.search(base):
            out.append(_finding(
                "critical", "eBPF object pinned under a concealment name",
                f"{base} — an eBPF map by this name exists to hold the list of "
                f"pids, filenames or ports being hidden from you. Read it with "
                f"`sudo bpftool map dump pinned {path}` to recover what was "
                f"concealed.",
                path))
    if names and not out:
        out.append(_finding("ok", "pinned eBPF objects",
                            f"{len(names)} pinned under /sys/fs/bpf, none named "
                            f"for concealment", root))
    elif not names:
        out.append(_finding("ok", "no pinned eBPF objects",
                            "/sys/fs/bpf is empty", root))
    return out


def io_uring_state():
    """io_uring is the current way to act without making syscalls.

    It can read and write files, open sockets and spawn processes through a
    shared ring buffer, so a tool that watches syscalls sees nothing at all —
    this is the blind spot the 'Curing' proof-of-concept rootkit was written to
    demonstrate. Nothing here is evidence of compromise on its own; it is
    exposure, plus the list of who is currently using it.
    """
    out = []
    disabled = _read(f"{PROC}/sys/kernel/io_uring_disabled").strip()

    users = []
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        for fd in fds:
            try:
                if "io_uring" in os.readlink(f"{fddir}/{fd}"):
                    users.append(int(entry))
                    break
            except OSError:
                continue

    for pid in users:
        info = _describe(pid)
        out.append(_finding(
            "medium", "process is using io_uring",
            f"pid {pid} ({info['name']}) holds an io_uring ring — its file, "
            f"socket and process operations do not appear as syscalls. Legitimate "
            f"for databases, proxies and modern runtimes; confirm you know this one.",
            info["cmdline"] or info["exe"] or ""))

    if disabled == "0":
        out.append(_finding(
            "low", "io_uring is available to every process",
            "io_uring_disabled=0. Setting it to 2 disables io_uring entirely and "
            "closes the syscall-monitoring blind spot, at the cost of breaking "
            "software that genuinely uses it.",
            f"{PROC}/sys/kernel/io_uring_disabled"))
    elif disabled == "2":
        out.append(_finding("ok", "io_uring is disabled kernel-wide",
                            "io_uring_disabled=2 — the syscall-bypass path is shut",
                            f"{PROC}/sys/kernel/io_uring_disabled"))
    elif disabled:
        out.append(_finding("ok", "io_uring is restricted",
                            f"io_uring_disabled={disabled}",
                            f"{PROC}/sys/kernel/io_uring_disabled"))
    if not users:
        out.append(_finding("ok", "no process is using io_uring",
                            "no open io_uring ring in any visible process", ""))
    return out


FTRACE_PATHS = ("/sys/kernel/tracing/enabled_functions",
                "/sys/kernel/debug/tracing/enabled_functions")
# The kernel's own HID-BPF dispatcher: since Linux 6.3 the HID subsystem attaches
# a BPF program to it at boot (fmod_ret), on every stock kernel that has HID-BPF.
KERNEL_BPF_HOOKS = frozenset({"__hid_bpf_tail_call", "hid_bpf_device_event"})


def ftrace_hook_records(text):
    """[(function, kind)] from enabled_functions. A function line may be followed
    by indented continuation lines naming where the call goes; a direct call to a
    bpf_trampoline is an eBPF fentry/fexit/fmod_ret attachment (attributable in
    the eBPF program list), anything else an ftrace_ops callback, the technique
    ftrace rootkits use. kind: "kernel_bpf", "bpf" or "ftrace"."""
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if records and "bpf_trampoline" in line and records[-1][1] == "ftrace":
                func = records[-1][0]
                records[-1] = (func, "kernel_bpf" if func in KERNEL_BPF_HOOKS else "bpf")
            continue
        func = line.split()[0]
        kind = "ftrace"
        if "bpf_trampoline" in line:
            kind = "kernel_bpf" if func in KERNEL_BPF_HOOKS else "bpf"
        records.append((func, kind))
    return records[:40]


def ftrace_hooks():
    """Kernel functions currently hooked via ftrace — how many rootkits patch
    syscalls without touching the syscall table itself."""
    return [f for f, _ in ftrace_hook_list()]


def ftrace_hook_list():
    for path in FTRACE_PATHS:
        body = _read(path)
        if body.strip():
            return ftrace_hook_records(body)
    return []


REPLACED_IDENTICAL = "executable replaced on disk by an identical copy"
MAX_REPLACEMENT_CHECKS = 2


def _replaced_identically(pid, mapped):
    """A deleted main executable whose original bytes (still readable through
    /proc/<pid>/exe) equal the file now at the same path: an in-place
    reinstall such as `sysmon -i` or a package re-copy, so the running code
    does have an honest file behind it. Anything unreadable or different
    stays a deleted mapping."""
    return replaced_identically(pid, mapped, proc=PROC)


def injected_processes():
    """Processes running code with no honest file behind it.

    Three shapes worth catching:
      LD_PRELOAD in a live environment  -- userland hooking of that process
      an executable mapping marked (deleted) -- the file was unlinked after load
      a memfd: executable mapping -- fileless execution, never touched the disk
    """
    hits = []
    replacement_checks = 0
    replacement_results = {}
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        reasons = []

        environ = _read(f"{PROC}/{pid}/environ", binary=True)
        if b"LD_PRELOAD=" in environ:
            val = ""
            for part in environ.split(b"\x00"):
                if part.startswith(b"LD_PRELOAD="):
                    val = part.decode("utf-8", "replace")[11:]
            if val:
                reasons.append(("LD_PRELOAD set", val))

        maps = _read(f"{PROC}/{pid}/maps")
        replaced = False
        for line in maps.splitlines():
            if len(line.split()) < 6:
                continue
            perms, path = line.split()[1], line.split(None, 5)[5]
            if "x" not in perms:
                continue
            if path.endswith("(deleted)"):
                key = (pid, path)
                if key not in replacement_results:
                    if replacement_checks < MAX_REPLACEMENT_CHECKS:
                        replacement_checks += 1
                        replacement_results[key] = _replaced_identically(pid, path)
                    else:
                        replacement_results[key] = False
                if replacement_results[key]:
                    if not replaced:
                        replaced = True
                        reasons.append((REPLACED_IDENTICAL, path))
                    continue
                reasons.append(("executable mapping was deleted from disk", path))
                break
            if path.startswith("/memfd:"):
                reasons.append(("fileless executable mapping (memfd)", path))
                break

        if reasons:
            info = _describe(pid)
            hits.append({"pid": pid, "name": info["name"],
                         "cmdline": info["cmdline"] or info["exe"],
                         "reasons": reasons})
    return hits


def proc_overmounts():
    """A bind-mount over /proc/<pid> makes a process unreadable without any
    code injection at all."""
    hits = []
    try:
        with open("/proc/self/mountinfo", errors="replace") as fh:
            for line in fh:
                f = line.split()
                if len(f) > 4 and re.match(r"^/proc/\d+", f[4]):
                    hits.append(f[4])
    except OSError:
        pass
    return hits
