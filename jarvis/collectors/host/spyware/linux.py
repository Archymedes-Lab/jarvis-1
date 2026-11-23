"""WSL side: WSLg wires a Linux process straight into a display and audio server.

This is the part of the machine that has no consent ledger at all. WSLg gives
every process in the distro an X11 display, a Wayland socket and a PulseAudio
server, and X11 in particular has no isolation between clients: any process
that can open the display can screenshot the entire desktop and read the
keyboard, with no prompt and nothing recorded anywhere. Windows asks before an
app uses the microphone; nothing asks here.
"""

import os
import re

_SOCKET_FD = re.compile(r"^socket:\[(\d+)\]$")


def _unix_socket_map():
    """inode -> unix socket path, from /proc/net/unix."""
    out = {}
    try:
        with open("/proc/net/unix", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 8 and parts[6].isdigit():
                    out[int(parts[6])] = parts[7]
    except (OSError, ValueError, StopIteration):
        pass
    return out


# Which server a socket path belongs to, and what connecting to it grants.
DISPLAY_SOCKETS = (
    (re.compile(r"/tmp/\.X11-unix/X\d+"), "X11 display",
     "X11 has no isolation between clients: any connected process can capture "
     "the whole screen and read every keystroke sent to any window"),
    (re.compile(r"wayland-\d+"), "Wayland display",
     "Wayland isolates clients from each other, so this is normal for a GUI app"),
    (re.compile(r"PulseServer|/pulse/native"), "PulseAudio server",
     "a connected client can record from the microphone"),
)


def audit_linux():
    """Who inside WSL is wired into the display and audio servers."""
    out = []

    def _f(sev, title, detail, where=""):
        return {"category": "access", "severity": sev, "title": title,
                "detail": detail, "where": where, "host": "wsl"}

    if not os.path.isdir("/mnt/wslg"):
        return [_f("ok", "no WSLg display stack",
                   "this distro has no GUI, audio or screen-capture surface", "")]

    inodes = _unix_socket_map()
    clients = {}          # (kind, note) -> [ "name [pid]" ]
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/comm", errors="replace") as fh:
                name = fh.read().strip()
        except OSError:
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        seen = set()
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            m = _SOCKET_FD.match(target)
            if not m:
                continue
            path = inodes.get(int(m.group(1)), "")
            if not path:
                continue
            for pattern, kind, note in DISPLAY_SOCKETS:
                if pattern.search(path) and kind not in seen:
                    seen.add(kind)
                    clients.setdefault((kind, note), []).append(f"{name} [{pid}]")

    for (kind, note), procs in sorted(clients.items()):
        sev = "medium" if kind.startswith("X11") else "low"
        out.append(_f(sev, f"connected to the {kind}",
                      f"{len(procs)} process(es): {', '.join(sorted(set(procs))[:8])}"
                      + (" …" if len(set(procs)) > 8 else "")
                      + f" — {note}",
                      kind))
    if not clients:
        out.append(_f("ok", "nothing inside WSL is connected to a display or audio server",
                      "WSLg is present but no process holds an X11, Wayland or "
                      "PulseAudio connection", "/mnt/wslg"))

    # X11 exposure is a property of the display being reachable at all, not of
    # anyone currently using it.
    if os.path.exists("/tmp/.X11-unix/X0"):
        out.append(_f(
            "low", "an X11 display is reachable from every process in this distro",
            "Any process here can connect to :0 and, because X11 grants every "
            "client access to every other client's input and to the framebuffer, "
            "screenshot the desktop and log keystrokes without a prompt and "
            "without leaving a record. Windows' capability ledger does not cover "
            "this. Prefer Wayland-native apps; unset DISPLAY for anything that "
            "does not need a GUI.",
            "/tmp/.X11-unix/X0"))

    snd = [d for d in (os.listdir("/dev/snd") if os.path.isdir("/dev/snd") else [])
           if d.startswith(("pcm", "control"))]
    if snd:
        out.append(_f("low", "ALSA capture devices present in WSL",
                      f"{', '.join(sorted(snd)[:6])}", "/dev/snd"))

    cams = [d for d in os.listdir("/dev") if d.startswith("video")] \
        if os.path.isdir("/dev") else []
    if cams:
        out.append(_f("medium", "camera device present in WSL",
                      f"{', '.join(sorted(cams))} — a process here can read the "
                      f"camera directly, outside Windows' capability ledger", "/dev"))

    return out
