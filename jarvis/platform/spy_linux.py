"""Read-only Linux evidence for spyware reasoning: capture devices, image state, egress.

Reads only /proc and /sys metadata for processes the caller may inspect. No
command lines, environment values, file contents or full paths are kept: a
descriptor is reduced to a device class, an image to a path class. A process
that cannot be read stays unknown; it is never treated as clean.
"""

import ipaddress
import os

from jarvis.core.reasoning.vocab import (
    LINUX_KERNEL_THREAD_PREFIXES,
    Observation,
    Subject,
    is_masquerade,
)

MAX_PROCESSES = 4096
MAX_FDS = 512
MAX_SOCKETS = 65536
SOURCE = "proc"


def _read(path, limit=8192):
    with open(path, "rb") as fh:
        return fh.read(limit).decode("utf-8", "replace")


def _boot(proc):
    try:
        return _read(f"{proc}/sys/kernel/random/boot_id").strip()
    except OSError:
        return ""


def _key_bits(hexmap):
    """Set of bit numbers from a sysfs capability bitmap ("a b c", MSB word first)."""
    bits, words = set(), hexmap.split()
    for index, word in enumerate(reversed(words)):
        try:
            value = int(word, 16)
        except ValueError:
            return None
        for bit in range(64):
            if value >> bit & 1:
                bits.add(index * 64 + bit)
    return bits


def keyboard_event(number, sysfs="/sys"):
    """True/False when the input event device advertises letter keys; None unknown."""
    try:
        bits = _key_bits(_read(f"{sysfs}/class/input/event{number}/device/capabilities/key"))
    except OSError:
        return None
    if bits is None:
        return None
    return 30 in bits            # KEY_A


def path_class(exe):
    if not exe:
        return "unknown"
    exe = exe.split(" (deleted)")[0]
    if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")):
        return "temp"
    if exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib", "/snap/")):
        return "os"
    if exe.startswith("/opt/"):
        return "program_files"
    if exe.startswith(("/home/", "/root/", "/mnt/")):
        return "user_writable"
    return "unknown"


def _external_inodes(proc):
    """Socket inodes with an established connection to a public address."""
    inodes = set()
    for name, v6 in (("tcp", False), ("tcp6", True)):
        try:
            rows = _read(f"{proc}/net/{name}", limit=4 * 1024 * 1024).splitlines()[1:MAX_SOCKETS]
        except OSError:
            continue
        for line in rows:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "01":
                continue
            try:
                host = parts[2].rsplit(":", 1)[0]
                raw = bytes.fromhex(host)
                if v6:
                    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
                    ip = ipaddress.IPv6Address(raw)
                else:
                    ip = ipaddress.IPv4Address(raw[::-1])
            except ValueError:
                continue
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped
            if ip.is_global:
                inodes.add(parts[9])
    return inodes


def _fd_facts(base, external):
    kinds, egress, seen = set(), False, 0
    try:
        names = os.listdir(f"{base}/fd")
    except OSError:
        return None
    for name in names[:MAX_FDS]:
        try:
            target = os.readlink(f"{base}/fd/{name}")
        except OSError:
            continue
        seen += 1
        if target.startswith("/dev/input/event"):
            kinds.add(("input", target[len("/dev/input/event"):]))
        elif target.startswith("/dev/video"):
            kinds.add(("video", ""))
        elif target.startswith("/dev/snd/pcmC") and target.endswith("c"):
            kinds.add(("audio", ""))
        elif target == "/dev/uinput":
            kinds.add(("uinput", ""))
        elif target.startswith("socket:[") and target[8:-1] in external:
            egress = True
    return kinds, egress


def subjects(proc="/proc", sysfs="/sys", limit=MAX_PROCESSES):
    """One Subject per readable process instance, plus coverage counters."""
    boot = _boot(proc)
    external = _external_inodes(proc)
    out, unreadable = [], 0
    try:
        pids = sorted(int(p) for p in os.listdir(proc) if p.isdigit())
    except OSError:
        return [], {"processes": 0, "unreadable": 0, "status": "unavailable"}
    for pid in pids[:limit]:
        base = f"{proc}/{pid}"
        try:
            stat = _read(f"{base}/stat")
            comm = _read(f"{base}/comm").strip()
            fields = stat[stat.rfind(")") + 2:].split()
            start, ppid = fields[19], int(fields[1])
            pidns = os.readlink(f"{base}/ns/pid")
        except (OSError, ValueError, IndexError):
            continue
        if ppid == 2 or pid == 2:
            continue                    # kernel threads have no image or descriptors
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            exe = None
        facts = _fd_facts(base, external)
        obs = []
        if exe is None and facts is None:
            unreadable += 1
            # Unreadable is unknown, never clean: record it as an incomplete source.
            obs.append(Observation("cap.keyboard.evdev", "proc:unreadable", complete=False))
        if exe and (exe.endswith(" (deleted)") or exe.startswith("/memfd:")):
            obs.append(Observation("conceal.deleted_image", SOURCE))
        klass = path_class(exe)
        # A kernel-thread name on a process that has a real image, or a system-service name
        # running from a user-writable location, is a disguise; real kernel threads have no exe.
        if exe and (comm.startswith(LINUX_KERNEL_THREAD_PREFIXES)
                    or is_masquerade(comm, klass, windows=False)):
            obs.append(Observation("conceal.masquerade", SOURCE))
        if facts is not None:
            kinds, egress = facts
            for kind, detail in kinds:
                if kind == "input" and keyboard_event(detail, sysfs) is False:
                    continue            # pointer-only device
                obs.append(Observation({"input": "cap.keyboard.evdev", "video": "cap.video.camera",
                                        "audio": "cap.audio.mic",
                                        "uinput": "cap.input.injection"}[kind], SOURCE))
            if egress:
                obs.append(Observation("egress.external", SOURCE))
        out.append(Subject(
            key=f"linux:{boot}:{pidns}:{pid}:{start}", host="wsl", label=comm,
            signature="unknown", path_class=klass, observations=obs))
    return out, {"processes": len(out), "unreadable": unreadable,
                 "status": "partial" if unreadable else "complete"}
