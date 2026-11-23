"""The spyware audit across both hosts."""

from .linux import audit_linux
from .windows import audit_windows


def audit(now_iso=None, hosts=("wsl", "win")):
    """Run the spyware audit for the requested hosts.

    Split per host deliberately: the WSL display/audio checks need no PowerShell,
    so a broken interop bridge must not take them down with it.
    """
    out = []
    if "win" in hosts:
        out.extend(audit_windows(now_iso))
    if "wsl" in hosts:
        out.extend(audit_linux())
    return out
