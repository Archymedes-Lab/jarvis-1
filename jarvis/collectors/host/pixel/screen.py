"""Can anything read your screen, and is the screen protected from it?

A screen is the one surface that shows every secret the machine handles —
passwords as they are typed, one-time codes, decrypted documents. Reading it
needs no exploit: Windows hands any process the Desktop Duplication and
Graphics Capture APIs, X11 lets any client that can open the display copy the
whole desktop, and remote-access tools stream it by design.

This module reports posture rather than only presence: not just "a capture
tool is running", but whether the paths that read a screen are closed, and
whether the ones that must stay open are at least protected.
"""

import os
import re

from jarvis.core.finding import win_finding as finding
from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

# Remote-access and capture products, by executable name. Presence is a
# prompt to confirm the session is yours, never a verdict on its own.
REMOTE_TOOLS = {
    "teamviewer": "TeamViewer", "anydesk": "AnyDesk",
    "rustdesk": "RustDesk", "screenconnect": "ScreenConnect",
    "connectwisecontrol": "ConnectWise Control", "vncserver": "VNC server",
    "winvnc": "VNC server", "tvnserver": "TightVNC",
    "dwagent": "DWService", "supremo": "Supremo", "ammyy": "Ammyy Admin",
    "aeroadmin": "AeroAdmin", "gotomypc": "GoToMyPC",
    "logmein": "LogMeIn", "splashtop": "Splashtop",
    "chromoting": "Chrome Remote Desktop", "remoting_host": "Chrome Remote Desktop",
    "quickassist": "Windows Quick Assist",
}

CAPTURE_TOOLS = {
    "obs64": "OBS Studio", "obs32": "OBS Studio", "sharex": "ShareX",
    "snagit32": "Snagit", "snagiteditor": "Snagit", "camtasia": "Camtasia",
    "bandicam": "Bandicam", "fraps": "Fraps", "screenrec": "ScreenRec",
    "loom": "Loom", "flameshot": "Flameshot", "greenshot": "Greenshot",
}

# Ports that carry a live screen off the machine.
SCREEN_PORTS = {
    3389: "RDP", 5900: "VNC", 5901: "VNC", 5938: "TeamViewer",
    6568: "ScreenConnect", 7070: "AnyDesk",
}

PS_SCREEN = load_win_script("pixel_screen.ps1")


def rules_windows(data):
    """Turn one PowerShell payload into findings. Pure, so it is testable."""
    if not data:
        return [finding("screen", "low", "Windows screen posture unavailable",
                        "the Windows bridge did not return data; screen "
                        "capture exposure on the Windows side is unknown", "")]
    out = []

    denied = data.get("rdpDenied")
    protection = data.get("captureProtection")
    if denied == 0:
        detail = ("Remote Desktop is accepting connections, so the session "
                  "can be streamed to anything that authenticates.")
        if protection == 1:
            out.append(finding(
                "screen", "medium", "Remote Desktop is enabled, with capture "
                "protection on",
                detail + " Screen-capture protection is enabled, so the "
                "session is at least hidden from other capture APIs.",
                "Terminal Server\\fDenyTSConnections"))
        else:
            out.append(finding(
                "screen", "high", "Remote Desktop is enabled without capture "
                "protection",
                detail + " fEnableScreenCaptureProtection is not set, so a "
                "local process can also record the same session. Disable RDP "
                "if it is not needed, or set the policy.",
                "Terminal Server\\fDenyTSConnections"))
        if data.get("rdpNla") == 0:
            out.append(finding(
                "screen", "high", "Remote Desktop accepts connections without "
                "Network Level Authentication",
                "NLA off means the logon screen is rendered before the caller "
                "proves who they are, which widens both the attack surface and "
                "what an unauthenticated peer sees.",
                "WinStations\\RDP-Tcp\\UserAuthentication"))
    elif denied == 1:
        out.append(finding("screen", "ok", "Remote Desktop is disabled",
                           "fDenyTSConnections is set; no RDP session can be "
                           "opened against this machine", ""))

    ports = set(aslist(data.get("listeners")))
    for port, name in sorted(SCREEN_PORTS.items()):
        if port in ports:
            out.append(finding(
                "screen", "high", "a screen-sharing port is listening",
                "%s is accepting connections on port %d — anything that "
                "reaches this port and authenticates can watch the desktop"
                % (name, port), "TCP/%d" % port))

    running = {}
    for proc in aslist(data.get("procs")):
        if not isinstance(proc, dict):
            continue
        low = (proc.get("name") or "").lower()
        for key, label in list(REMOTE_TOOLS.items()) + list(CAPTURE_TOOLS.items()):
            if key in low:
                running.setdefault(label, proc.get("path") or proc.get("name"))
    for label, where in sorted(running.items()):
        remote = label in REMOTE_TOOLS.values()
        out.append(finding(
            "screen", "medium" if remote else "low",
            "%s is running" % label,
            ("remote-access software can stream this screen to another "
             "machine — confirm the session is yours"
             if remote else
             "screen-recording software is running; confirm you started it"),
            where or ""))

    for pkg in aslist(data.get("capturePkgs")):
        if not isinstance(pkg, dict):
            continue
        caps = aslist(pkg.get("caps"))
        borderless = any("WithoutBorder" in str(c) for c in caps)
        # Windows installs a package only when its signer matches the
        # declared publisher, so an Ok package published by Microsoft is
        # Windows' own capture (shell, Snipping Tool, Teams), not a stranger.
        windows_own = (re.search(r"(^|,\s*)O=Microsoft Corporation(,|$)",
                                 str(pkg.get("publisher") or ""))
                       and pkg.get("status") == "Ok")
        out.append(finding(
            "screen", "medium" if borderless and not windows_own else "low",
            "an app may capture the screen%s"
            % (" without showing the capture border" if borderless else ""),
            "%s declares %s. %s"
            % (pkg.get("name", "?"), ", ".join(str(c) for c in caps),
               ("Published by Microsoft (verified package): Windows' own "
                "capture feature." if windows_own and borderless else
                "Nothing on screen will indicate that recording is happening.")
               if borderless else
               "Windows shows a capture border while it records."),
            pkg.get("name", "")))

    # This summary is about live egress of the screen only. An installed app
    # that *may* capture is a different question and must not suppress it.
    streaming = ports & set(SCREEN_PORTS) or \
        any(label in REMOTE_TOOLS.values() for label in running)
    if not streaming:
        out.append(finding("screen", "ok", "no screen is being streamed off "
                           "this machine",
                           "no screen-sharing port is listening and no remote-"
                           "access tool is running", ""))
    return out


def rules_linux(env=None, x11_socket="/tmp/.X11-unix/X0"):
    """Desktop-read exposure on the Linux side.

    X11 has no isolation between clients: any process that can open the
    display can read every window and every keystroke. Wayland does not grant
    that by default, which is the whole difference here.
    """
    env = os.environ if env is None else env
    out = []
    session = (env.get("XDG_SESSION_TYPE") or "").lower()
    wayland = env.get("WAYLAND_DISPLAY")
    display = env.get("DISPLAY")

    if session == "wayland" or (wayland and not display):
        out.append(finding(
            "screen", "ok", "the Linux session is Wayland",
            "a Wayland client cannot read other windows or the whole screen "
            "without going through the portal, which prompts", "", host="wsl"))
    elif display or os.path.exists(x11_socket):
        out.append(finding(
            "screen", "medium", "the Linux display is X11",
            "X11 gives every client that can open DISPLAY=%s the ability to "
            "read the whole screen and every keystroke, with no prompt and no "
            "record. Prefer a Wayland session for anything sensitive."
            % (display or ":0"), display or x11_socket, host="wsl"))
    else:
        out.append(finding(
            "screen", "ok", "no graphical display on the Linux side",
            "there is no X11 or Wayland session here, so there is no desktop "
            "to capture", "", host="wsl"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out.extend(rules_linux())
    if "win" in hosts:
        out.extend(rules_windows(ps_json(PS_SCREEN)))
    return out
