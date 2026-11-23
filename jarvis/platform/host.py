"""Which machine is this, and which execution domains can be observed from it.

JARVIS grew up inside WSL: Python in the Linux guest, the Windows host reached
through interop and the /mnt/c mount. That is one topology of three:

    wsl      Linux guest of a Windows host; both domains observable
    windows  native Windows Python; there is no Linux domain on this machine
    linux    Linux with no Windows host behind it

Any other operating system (macOS today) is "unsupported": it has neither
domain, so nothing Linux- or Windows-only is scheduled there, and the daemon
refuses to start (unsupported_reason) instead of running half blind. It used
to fall through to "linux" because /proc was simply unreadable.

Everything that used to assume the first asks here instead: which domains
exist, how a Windows path is named from this process, where the per-user and
machine-wide Windows state lives. Collectors keep their `hosts` tuple and their
"wsl"/"win" finding labels - those are part of every finding's identity and of
the stored history, so the Linux domain keeps the label "wsl" on plain Linux.

A domain that does not exist here is not selected, so it produces neither a
finding nor a failure: absent is "not applicable", never "healthy" and never
"blind". Nothing here grants credit for a domain that was not observed.
"""

import os
import re
import subprocess
import sys

LINUX = "wsl"       # label of the Linux execution domain in findings
WINDOWS = "win"     # label of the Windows execution domain in findings

_DRIVE = re.compile(r"^[A-Za-z]:([\\/]|$)")
_MOUNT = re.compile(r"^/mnt/([A-Za-z])(/|$)")


# A server-edition install inside WSL can be told to watch only the Linux guest,
# like a plain server: no Windows domain, no PowerShell over interop (an
# independent second monitor beside the workstation one). Root-owned and
# writable by root alone, and it can only narrow "wsl" to "linux".
KIND_OVERRIDE = "/etc/jarvis/host-kind"


def _override(path=KIND_OVERRIDE):
    try:
        st = os.stat(path)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return ""
        with open(path, encoding="ascii", errors="replace") as fh:
            return fh.read().strip().lower()
    except OSError:
        return ""


def _detect(os_name=None, osrelease=None, override=None, platform=None):
    if (os.name if os_name is None else os_name) == "nt":
        return "windows"
    if not (sys.platform if platform is None else platform).startswith("linux"):
        return "unsupported"
    if osrelease is None:
        try:
            with open("/proc/sys/kernel/osrelease", errors="replace") as fh:
                osrelease = fh.read()
        except OSError:
            osrelease = ""
    kind = "wsl" if "microsoft" in osrelease.lower() else "linux"
    if kind == "wsl" and (_override() if override is None else override) == "linux":
        return "linux"
    return kind


KIND = _detect()


def kind():
    return KIND


def unsupported_reason(kind_=None):
    """Why this daemon must not run here, or "" when the host is supported."""
    if (KIND if kind_ is None else kind_) == "unsupported":
        return (f"ARGUS-INSTINCT does not support {sys.platform} yet: only Linux, WSL and Windows are "
                "observable. Nothing was started.")
    return ""


def native_windows():
    return KIND == "windows"


def on_wsl():
    return KIND == "wsl"


def has_linux():
    return KIND in ("wsl", "linux")


def has_windows():
    return KIND in ("wsl", "windows")


def domains():
    """The finding-host labels observable from this process, Linux first."""
    return tuple(label for label, present in ((LINUX, has_linux()),
                                              (WINDOWS, has_windows())) if present)


def select(hosts):
    """`hosts` narrowed to the domains that exist here, order preserved."""
    present = domains()
    return tuple(h for h in hosts if h in present)


def local_label():
    """Label for findings about JARVIS's own process, files and service."""
    return WINDOWS if KIND == "windows" else LINUX


def is_windows_path(path):
    return isinstance(path, str) and bool(_DRIVE.match(path))


def local_path(win_path):
    """A Windows path as this process must name it, or "" when it cannot.

    `C:\\Users\\x` is `/mnt/c/Users/x` from the WSL guest and itself on
    Windows. On plain Linux no Windows filesystem exists, so nothing maps.
    """
    if not is_windows_path(win_path):
        return ""
    if KIND == "windows":
        return win_path
    if KIND != "wsl":
        return ""
    return "/mnt/" + win_path[0].lower() + win_path[2:].replace("\\", "/")


def windows_path(path):
    """The Windows name of a path this process can open, or "" when it has none.

    The inverse of local_path() for drive mounts. A path inside the Linux
    guest has a UNC name only wslpath knows; callers that need it ask wslpath.
    """
    path = str(path)
    if is_windows_path(path):
        return path.replace("/", "\\")
    if KIND == "windows":
        return os.path.abspath(path)
    m = _MOUNT.match(path)
    if KIND == "wsl" and m:
        return m.group(1).upper() + ":\\" + path[m.end():].replace("/", "\\")
    return ""


def windows_name(path):
    """windows_path(), asking wslpath for a path inside the Linux guest."""
    known = windows_path(path)
    if known or KIND != "wsl":
        return known
    try:
        out = subprocess.run(["wslpath", "-w", str(path)], capture_output=True, text=True,
                             errors="replace", timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _env_dir(name, fallback):
    value = os.environ.get(name) or fallback
    return value if is_windows_path(value) else fallback


def system_drive():
    """`C:` - the drive Windows is installed on, when that can be known."""
    if KIND == "windows":
        drive = os.environ.get("SystemDrive") or ""
        if re.fullmatch(r"[A-Za-z]:", drive):
            return drive.upper()
    return "C:"


def windows_root():
    """Local name of the Windows system drive's root ("" on plain Linux)."""
    if KIND == "windows":
        return system_drive() + "\\"
    return local_path(system_drive())


def windows_dir():
    """Local name of %SystemRoot%."""
    if KIND == "windows":
        return _env_dir("SystemRoot", system_drive() + "\\Windows")
    return local_path("C:\\Windows")


def program_data(*parts):
    """Local name of a path under %ProgramData% (machine-wide JARVIS state)."""
    if KIND == "windows":
        base = _env_dir("ProgramData", system_drive() + "\\ProgramData")
    else:
        base = local_path("C:\\ProgramData")
    return _join(base, parts)


# Profile folders that are never a person's.
_NOT_PEOPLE = {"all users", "default", "default user", "public", "defaultapppool",
               "wdagutilityaccount"}


def windows_user():
    """The Windows account whose profile holds JARVIS's per-user state.

    In WSL: an explicit JARVIS_WINDOWS_USER or WSL_USER; else the Linux account
    name when a Windows profile of that name exists (the usual WSL setup); else
    the only real profile on the machine. Otherwise "" (unknown): callers then
    read nothing rather than another person's profile."""
    if KIND == "windows":
        return os.environ.get("USERNAME") or ""
    explicit = os.environ.get("JARVIS_WINDOWS_USER") or os.environ.get("WSL_USER")
    if explicit:
        return explicit
    users = users_dir()
    if not users or not os.path.isdir(users):
        return ""
    try:
        import pwd
        login = pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        login = ""
    if login and os.path.isdir(os.path.join(users, login, "AppData", "Local")):
        return login
    try:
        people = [n for n in os.listdir(users)
                  if n.lower() not in _NOT_PEOPLE
                  and os.path.isdir(os.path.join(users, n, "AppData", "Local"))]
    except OSError:
        return ""
    return people[0] if len(people) == 1 else ""


def users_dir():
    """Local name of the directory holding the Windows user profiles."""
    return local_path(system_drive() + "\\Users")


def local_appdata(*parts):
    """Local name of a path under the Windows user's %LOCALAPPDATA%."""
    if KIND == "windows":
        home = _env_dir("USERPROFILE", "")
        base = _env_dir("LOCALAPPDATA", home + "\\AppData\\Local" if home else "")
    else:
        base = local_path("C:\\Users\\%s\\AppData\\Local" % windows_user())
    return _join(base, parts)


def _join(base, parts):
    if not base:
        return ""
    sep = "\\" if KIND == "windows" else "/"
    return sep.join([base.rstrip("\\/"), *parts]) if parts else base


def powershell_candidates():
    """Where powershell.exe lives when PATH cannot help."""
    if KIND == "windows":
        root = windows_dir()
        files = _env_dir("ProgramFiles", system_drive() + "\\Program Files")
        return [root + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                files + "\\PowerShell\\7\\pwsh.exe"]
    if KIND == "wsl":
        return ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
                "/mnt/c/Program Files/PowerShell/7/pwsh.exe"]
    return []


def subprocess_cwd():
    """A working directory every child can start in.

    From WSL "/" avoids the UNC-path warning Windows programs print when
    started in a Linux directory. On Windows it is the system directory, never
    a directory an unprivileged process can plant a DLL or script in.
    """
    return windows_dir() if KIND == "windows" else "/"


def spawn_options():
    """subprocess keyword arguments every child of the daemon is started with.

    A Windows service-like process has no console, and each console child
    would otherwise open a visible window of its own.
    """
    if KIND == "windows":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}
