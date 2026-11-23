"""Linux keyboard readers and hidden staging (spyware research 2026-10-29,
~/.cache/argus-research/spyware/SYNTHESIS.md gaps 4 and 6).

    readers   processes holding a keyboard event device (/dev/input/eventN that
              reports letter keys), a raw HID device (/dev/hidraw*) or the input
              injector (/dev/uinput). Spyware on Linux reads keystrokes straight
              from evdev; nothing else on the system records who opened it.
              A process is judged by its image, never by its name (a name is
              what the attacker picks): the compositors, login manager and
              hotkey daemons that need the keyboard are quiet when their image
              is a root-owned file a package installed in a system directory;
              any other packaged program is low, a known keylogger package or
              an image from a writable place or a deleted file is high, and a
              process whose image cannot be read is said to be unverified.
    staging   hidden entries where stolen data is staged on Linux (QLNX keeps
              credentials in /var/log/.ICE-unix): any dot-entry directly in
              /var/log, unexpected ones in /run, and hidden executables in
              /dev/shm, /tmp and /var/tmp.

Invariants (tests/test_keyreaders.py holds each):
    I1  an image that cannot be read is unverified, never cleared
    I2  identity from the image (package, owner, location, not deleted), never
        from the process name
    I3  privacy: only which process holds a device is recorded, never input;
        staging checks read at most 4 magic bytes
    I4  bounded: processes, descriptors, directory entries and listed names
"""

import os
import re
import stat

from jarvis.core.finding import finding as _finding
from jarvis.platform.spy_linux import keyboard_event

MAX_PROCESSES = 4096
MAX_FDS = 1024
MAX_ENTRIES = 2000
MAX_LISTED = 6
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/")
# Programs that read the keyboard by design, when their image proves it.
EXPECTED = {"systemd-logind", "Xorg", "X", "Xwayland", "gnome-shell", "kwin_wayland", "kwin_x11", "weston",
            "sway", "Hyprland", "mutter", "gdm-wayland-session", "acpid", "thd", "triggerhappy", "gpm",
            "keyd", "kanata", "input-remapper-service", "plasmashell", "wireplumber", "upowerd"}
# Packaged keyloggers: a package does not make them benign.
KEYLOGGERS = re.compile(r"^(logkeys|lkl|uberkey|keysniffer|keylogger|pykeylogger|xkeylogger|evkeylogger)$", re.I)

STAGING = {
    "/var/log": ("any", ()),
    "/run": ("any", (".containerenv", ".toolboxenv", ".initrd-tmp")),
    "/dev/shm": ("exec", ()),
    "/tmp": ("exec", ()),
    "/var/tmp": ("exec", ()),
}


def _root_only(path):
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & 0o022


def _package_owner(path):
    import shutil

    from jarvis.core.util import dpkg_owns, package_manager
    manager = package_manager()
    if not shutil.which("rpm" if manager == "rpm" else "dpkg"):
        return None
    return dpkg_owns(path, manager)


def holders(proc="/proc", sysfs="/sys"):
    """{(pid, comm, exe or None): set of device kinds}, and how many processes
    could not have their descriptors read."""
    out, blind = {}, 0
    try:
        pids = sorted(int(p) for p in os.listdir(proc) if p.isdigit())[:MAX_PROCESSES]
    except OSError:
        return {}, -1
    for pid in pids:
        base = f"{proc}/{pid}"
        try:
            fds = os.listdir(f"{base}/fd")
        except OSError:
            blind += 1
            continue
        kinds = set()
        for fd in fds[:MAX_FDS]:
            try:
                target = os.readlink(f"{base}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("/dev/input/event"):
                if keyboard_event(target[len("/dev/input/event"):], sysfs) is not False:
                    kinds.add("keyboard")
            elif target.startswith("/dev/hidraw"):
                kinds.add("raw HID")
            elif target == "/dev/uinput":
                kinds.add("input injection")
        if not kinds:
            continue
        try:
            with open(f"{base}/comm", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            comm = "?"
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            exe = None
        out[(pid, comm, exe)] = kinds
    return out, blind


def judge(comm, exe, owner=_package_owner):
    """(severity, why). severity "" means expected and verified: not reported."""
    if exe is None:
        return "medium", "its executable could not be read (needs CAP_SYS_PTRACE), so it is unverified"
    if exe.endswith(" (deleted)") or exe.startswith("/memfd:"):
        return "high", "it runs from a deleted or in-memory file"
    name = os.path.basename(exe)
    if KEYLOGGERS.match(name) or KEYLOGGERS.match(comm):
        return "high", f"{name} is a keylogger"
    if not exe.startswith(SYSTEM_DIRS) or not _root_only(exe):
        return "high", f"it runs from {os.path.dirname(exe) or exe}, a place a non-root account can write"
    owned = owner(exe)
    if owned is False:
        return "high", "no package installed its executable"
    if owned is None:
        return "medium", "its executable could not be matched to a package (no package tool)"
    if comm in EXPECTED or name in EXPECTED:
        return "", ""
    return "low", f"{name} is a packaged program; confirm it should read input"


def reader_findings(proc="/proc", sysfs="/sys", owner=_package_owner):
    held, blind = holders(proc, sysfs)
    out, problems = [], []
    if blind < 0:
        return out, ["/proc could not be listed"]
    by_exe = {}
    for (pid, comm, exe), kinds in held.items():
        sev, why = judge(comm, exe, owner)
        if not sev:
            continue
        key = (exe or f"pid {pid}", comm)
        entry = by_exe.setdefault(key, {"sev": sev, "why": why, "pids": [], "kinds": set()})
        entry["pids"].append(pid)
        entry["kinds"] |= kinds
    order = {"high": 0, "medium": 1, "low": 2}
    for (exe, comm), e in sorted(by_exe.items(), key=lambda kv: order[kv[1]["sev"]]):
        what = " and ".join(sorted(e["kinds"]))
        pids = ", ".join(str(p) for p in e["pids"][:MAX_LISTED])
        out.append(_finding("spyware", e["sev"], f"{comm} reads the {what}",
                            f"pid {pids}: {e['why']}. Reading /dev/input or hidraw directly sees every key "
                            "typed on this machine.", exe))
    if blind:
        problems.append(f"{blind} process(es) whose open devices could not be read (needs CAP_SYS_PTRACE)")
    return out, problems


def _is_executable(path):
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return False
        if st.st_mode & 0o111:
            return True
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"          # I3: four bytes, never content
    except OSError:
        return False


def staging_findings(root="/"):
    out, problems = [], []
    for d, (mode, allowed) in STAGING.items():
        path = os.path.join(root, d.lstrip("/")) if root != "/" else d
        try:
            names = sorted(os.listdir(path))[:MAX_ENTRIES]
        except FileNotFoundError:
            continue
        except OSError as exc:
            problems.append(f"{d}: {exc.strerror or exc}")
            continue
        for n in names:
            if not n.startswith(".") or n in (".", "..") or n in allowed:
                continue
            p = os.path.join(path, n)
            if mode == "exec":
                if _is_executable(p):
                    out.append(_finding("spyware", "high", f"hidden executable in {d}: {n}",
                                        "a hidden program in a world-writable directory is how implants are "
                                        "staged and run", p))
                continue
            is_dir = os.path.isdir(p) and not os.path.islink(p)
            out.append(_finding("spyware", "high" if (is_dir or _is_executable(p)) else "medium",
                                f"hidden {'folder' if is_dir else 'file'} in {d}: {n}",
                                f"nothing on a stock system keeps a hidden entry in {d}; spyware stages stolen "
                                "data there (QLNX: /var/log/.ICE-unix)", p))
    return out, problems


def audit(store=None, hosts=None, proc="/proc", sysfs="/sys", root="/", owner=_package_owner):
    out, problems = reader_findings(proc, sysfs, owner)
    s, p = staging_findings(root)
    out += s
    problems += p
    if problems:
        out.append(_finding("visibility", "low", "keyboard readers or staging not fully observed",
                            "; ".join(problems)[:1500], "keyreaders"))
    return out
