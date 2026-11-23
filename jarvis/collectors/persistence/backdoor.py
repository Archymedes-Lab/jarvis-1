"""Backdoors: the ways back in that survive a reboot and a password change.

A backdoor is not malware. It is usually a line in a config file, a key in a
file the owner never reads, or an account that looks like it belongs. Nothing
here is a signature match — every check reads a mechanism that grants access
and asks whether what it grants is what you intended.

The vectors are the ones current research keeps naming: SSH authorised keys and
sshd_config, systemd *user* services (which need no root at all), XDG autostart
entries, appended shell profiles, sudoers NOPASSWD grants, setuid binaries no
package owns, and second UID-0 accounts.

Most findings here need a human to confirm, because the tool cannot know which
SSH key is yours. So each one shows the actual evidence — the key comment, the
sudoers line, the appended command — rather than only naming the file.
"""

import glob
import os
import re
import stat
import subprocess

try:
    import pwd
except ImportError:      # native Windows: no passwd database, and no caller there
    pwd = None
from jarvis.collectors.persistence import startup_state
from jarvis.core.finding import file_finding
from jarvis.core.finding import finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.core.util import dpkg_owns
from jarvis.platform.windows import aslist, ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"remote access": 0, "privilege": 1, "persistence": 2,
             "accounts": 3}

# Commands that fetch and run, or open a shell to somewhere. In a profile or a
# cron entry these are how a foothold re-establishes itself on every login.
PAYLOAD_RE = re.compile(
    r"(curl|wget)\s[^|;&]*\|\s*(ba|z|d|k)?sh"          # download and pipe
    r"|nc\s+(-[a-z]*e|.*-e\s)"                          # netcat with -e
    r"|bash\s+-i\s*>&\s*/dev/tcp"                       # bash reverse shell
    r"|/dev/tcp/\d"                                     # raw tcp redirect
    r"|python3?\s+-c\s+.{0,40}(socket|pty)"             # python reverse shell
    r"|base64\s+-d\s*\|\s*(ba)?sh"                      # decode and run
    r"|socat\s+.*exec"
    r"|\bncat\b.*--exec",
    re.I)


def _read(path, limit=200000):
    try:
        with open(path, errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


_dpkg_owns = dpkg_owns

# jarvis's own units, installed by install.sh. A monitor that reports itself as
# a backdoor trains you to skim the section where a real one would appear.
_SELF_UNITS = ("jarvis.service", "jarvis-selfcheck.service",
               "jarvis-selfcheck.timer")


def _is_self(unit_name, execs):
    """True for jarvis's own systemd units — matched on name AND command.

    Both have to agree. Matching on the filename alone would let anything
    named jarvis.service through, which is a cheap way to hide in the one
    place this audit has been told not to look.
    """
    if unit_name not in _SELF_UNITS:
        return False
    if not execs:
        return unit_name.endswith(".timer")     # timers carry no Exec line
    return all(re.search(r"-m\s+jarvis\b", e) for e in execs)


def _home_dirs():
    out = []
    try:
        for p in pwd.getpwall():
            if p.pw_dir and os.path.isdir(p.pw_dir) and (
                    p.pw_uid >= 1000 or p.pw_uid == 0):
                out.append((p.pw_name, p.pw_dir, p.pw_uid))
    except Exception:
        pass
    return out


# ── SSH ───────────────────────────────────────────────────────────────────

def check_ssh():
    out = []
    for user, home, _uid in _home_dirs():
        ak = os.path.join(home, ".ssh", "authorized_keys")
        body = _read(ak)
        if not body.strip():
            continue
        keys = [l.strip() for l in body.splitlines()
                if l.strip() and not l.startswith("#")]
        for k in keys:
            parts = k.split()
            comment = parts[2] if len(parts) > 2 else "(no comment)"
            fp = parts[1][:24] + "…" if len(parts) > 1 else "?"
            forced = "command=" in k or "no-pty" in k
            out.append(_finding(
                "remote access", "high",
                f"SSH key authorised for {user}: {comment}",
                f"anyone holding the matching private key can log in as {user} "
                f"without a password"
                + (" — this entry also forces a command" if forced else "")
                + f"  [{fp}]", ak))
        # A key file writable by others is a way to add a key later.
        try:
            mode = os.stat(ak).st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                out.append(_finding(
                    "remote access", "critical",
                    f"authorized_keys for {user} is writable by others",
                    f"mode {oct(mode & 0o777)} — anyone on this system can "
                    f"add their own key", ak))
        except OSError:
            pass

    cfg = _read("/etc/ssh/sshd_config")
    extra = ""
    for inc in glob.glob("/etc/ssh/sshd_config.d/*.conf"):
        extra += "\n" + _read(inc)
    full = cfg + extra
    risky = {
        "permitrootlogin": (re.compile(r"^\s*PermitRootLogin\s+(yes|without-password|prohibit-password)",
                                       re.I | re.M),
                            "high", "root can log in over SSH"),
        "authorizedkeyscommand": (re.compile(r"^\s*AuthorizedKeysCommand\s+(\S+)", re.I | re.M),
                                  "high",
                                  "authorised keys come from a command's output — "
                                  "whoever controls that program controls who may log in"),
        "permittunnel": (re.compile(r"^\s*PermitTunnel\s+(yes|point-to-point|ethernet)", re.I | re.M),
                         "medium", "SSH may build a network tunnel into this host"),
        "gatewayports": (re.compile(r"^\s*GatewayPorts\s+(yes|clientspecified)", re.I | re.M),
                         "medium", "forwarded ports are reachable from off-host"),
        "permitemptypasswords": (re.compile(r"^\s*PermitEmptyPasswords\s+yes", re.I | re.M),
                                 "critical", "accounts with empty passwords may log in"),
    }
    for _name, (rx, sev, why) in risky.items():
        m = rx.search(full)
        if m:
            out.append(_finding(
                "remote access", sev,
                f"sshd_config: {m.group(0).strip()}", why, "/etc/ssh/sshd_config"))
    return out


# ── privilege ─────────────────────────────────────────────────────────────

# Binaries that turn a fixed sudo grant into a shell or an arbitrary write
# (GTFOBins-style): any of these in a grant keeps it reportable.
SUDO_ESCAPES = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "fish", "su", "sudo", "env", "nice",
    "python", "python3", "perl", "ruby", "node", "lua", "php", "awk", "gawk",
    "vi", "vim", "nano", "emacs", "less", "more", "man", "find", "tar", "zip",
    "cp", "mv", "tee", "dd", "chmod", "chown", "install", "rsync", "sed",
    "git", "docker", "crontab", "journalctl", "script", "xargs", "time",
})
# systemctl verbs that act on a named unit without a pager or unit editing.
SYSTEMCTL_SAFE = frozenset({"restart", "start", "stop", "try-restart",
                            "reload", "reset-failed", "is-active"})


def _fixed_sudo_command(cmd):
    """One command in a NOPASSWD list that cannot become a root shell: an
    absolute root-owned binary nobody else can write, explicit arguments with
    no wildcard (none at all would allow any), and no escape-capable tool."""
    parts = cmd.split()
    if len(parts) < 2 or not parts[0].startswith("/") or re.search(r"[*?\[\]]", cmd):
        return False
    binary = parts[0]
    if os.path.basename(binary) in SUDO_ESCAPES:
        return False
    if os.path.basename(binary) == "systemctl" and (
            parts[1] not in SYSTEMCTL_SAFE or len(parts) != 3):
        return False
    try:
        for path in (binary, os.path.dirname(binary)):
            st = os.stat(path)
            if st.st_uid != 0 or st.st_mode & 0o022:
                return False
    except OSError:
        return False
    return True


INTERPRETERS = re.compile(r"^(python[\d.]*|node|bun|deno|perl|ruby|bash|sh|dash|zsh)$")


def _user_writable(path):
    """True when a non-root account can change `path` or any directory above
    it. Unreadable paths prove nothing and return False."""
    path = os.path.abspath(path)
    while True:
        try:
            st = os.stat(path)
        except OSError:
            return False
        if st.st_uid != 0 or st.st_mode & 0o022:
            return True
        parent = os.path.dirname(path)
        if parent == path:
            return False
        path = parent


def _unit_code_paths(props):
    """Files and directories whose contents decide what a unit executes."""
    argv = re.search(r"argv\[\]=([^;]*)", props.get("ExecStart", ""))
    args = argv.group(1).split() if argv else []
    paths = [a for a in args if a.startswith("/")]
    if args and INTERPRETERS.match(os.path.basename(args[0])) and "-I" not in args[1:]:
        # Without isolation an interpreter imports from its working directory.
        paths.append(props.get("WorkingDirectory") or "/")
    return paths


def check_service_code():
    """A root or capability-holding unit that runs code a user can edit hands
    that user the unit's privilege on its next (re)start."""
    out = []
    units = sorted(os.path.basename(p) for p in glob.glob("/etc/systemd/system/*.service")
                   if not os.path.islink(p))
    for unit in units:
        try:
            text = subprocess.run(
                ["systemctl", "show", unit, "--no-pager", "-p",
                 "User,AmbientCapabilities,ExecStart,WorkingDirectory"],
                capture_output=True, text=True, errors="replace", timeout=10,
                check=False).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        props = dict(l.split("=", 1) for l in text.splitlines() if "=" in l)
        caps = props.get("AmbientCapabilities", "").strip()
        if props.get("User", "") not in ("", "root") and not caps:
            continue
        writable = [p for p in _unit_code_paths(props) if _user_writable(p)]
        if writable:
            power = f"capabilities {caps}" if caps else "root"
            out.append(_finding(
                "privilege", "high",
                f"privileged service runs user-editable code: {unit}",
                f"runs with {power} but {', '.join(writable[:3])} can be changed "
                f"by a non-root account, which then gets that privilege on the "
                f"next restart", f"/etc/systemd/system/{unit}"))
    return out


def _sudo_lines(text):
    """Logical sudoers lines: backslash continuations joined."""
    return re.sub(r"\\\s*\n\s*", " ", text).splitlines()


def restricted_sudo(line):
    """Number of commands in a NOPASSWD rule when every one is a fixed,
    non-escaping command (see _fixed_sudo_command); None otherwise."""
    commands = [c.strip() for c in re.split(r"NOPASSWD\s*:", line, flags=re.I)[-1].split(",")]
    return len(commands) if commands and all(_fixed_sudo_command(c) for c in commands) else None


def check_privilege():
    out = []
    files = ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*"))
    for f in files:
        for line in _sudo_lines(_read(f)):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "NOPASSWD" in line.upper():
                count = restricted_sudo(line)
                if count:
                    out.append(_finding(
                        "privilege", "low", f"passwordless sudo: {line[:90]}",
                        f"restricted to {count} fixed command(s): root-owned "
                        f"binaries nobody else can write, explicit arguments, no "
                        f"shell-escape tool. Inventory; a change is reported.", f))
                    continue
                sev = "high" if re.search(r"ALL\s*$", line) else "medium"
                out.append(_finding(
                    "privilege", sev, f"passwordless sudo: {line[:90]}",
                    "this grant does not re-prompt, so anything running as "
                    "that user can become root silently", f))

    # setuid binaries no package owns
    roots = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
             "/usr/local/sbin", "/opt", "/home", "/tmp", "/var/tmp")
    checked = 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if checked > 40000:
                break
            if dirpath.count("/") - root.count("/") > 3:
                dirnames[:] = []
            for fn in filenames:
                checked += 1
                full = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                    continue
                if _dpkg_owns(full):
                    continue
                which = "setuid" if st.st_mode & stat.S_ISUID else "setgid"
                out.append(_finding(
                    "privilege", "critical",
                    f"{which} binary no package owns: {fn}",
                    f"runs as {'root' if st.st_uid == 0 else 'uid ' + str(st.st_uid)} "
                    f"regardless of who executes it — a classic way to keep root "
                    f"after losing it", full))
    return out


# ── accounts ──────────────────────────────────────────────────────────────

def check_accounts():
    out = []
    try:
        entries = list(pwd.getpwall())
    except Exception:
        return out
    for p in entries:
        if p.pw_uid == 0 and p.pw_name != "root":
            out.append(_finding(
                "accounts", "critical",
                f"second account with uid 0: {p.pw_name}",
                "a uid-0 account is root under another name", "/etc/passwd"))
    shadow = _read("/etc/shadow")
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1] == "":
            out.append(_finding(
                "accounts", "critical",
                f"account '{parts[0]}' has an empty password",
                "it can be logged into with no credential at all", "/etc/shadow"))
    return out


# ── persistence ───────────────────────────────────────────────────────────

PROFILE_FILES = (".bashrc", ".bash_profile", ".profile", ".zshrc",
                 ".zprofile", ".bash_login", ".bash_logout")


def check_persistence():
    out = []
    # shell profiles
    targets = ["/etc/profile"] + sorted(glob.glob("/etc/profile.d/*.sh"))
    for user, home, _uid in _home_dirs():
        targets += [os.path.join(home, f) for f in PROFILE_FILES]
    for f in targets:
        body = _read(f)
        if not body:
            continue
        for i, line in enumerate(body.splitlines(), 1):
            if PAYLOAD_RE.search(line):
                out.append(file_finding(
                    "persistence", "critical",
                    f"shell profile runs a payload: {os.path.basename(f)}:{i}",
                    "A fetch/execute or reverse-shell indicator appears in startup code; source and arguments are withheld.",
                    f))

    # systemd user services need no root and are easy to miss
    for user, home, _uid in _home_dirs():
        d = os.path.join(home, ".config", "systemd", "user")
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith((".service", ".timer")):
                continue
            full = os.path.join(d, fn)
            # A masked unit is a link to /dev/null that systemd refuses to
            # start; it is the removal of persistence, not an instance of it.
            if os.path.realpath(full) == os.devnull:
                continue
            body = _read(full)
            execs = re.findall(r"^\s*Exec\w*\s*=\s*(.+)$", body, re.M)
            # Do not report ourselves. jarvis's own units are installed by
            # install.sh and are the reason this audit runs at all; flagging
            # them as persistence teaches you to skim past this section, which
            # is exactly how a real unit slips through.
            if _is_self(fn, execs):
                continue
            out.append(file_finding(
                "persistence", "high",
                f"systemd user unit for {user}: {fn}",
                "User units start at login and need no root; source and arguments are withheld.", full))

    # XDG autostart
    xdg = ["/etc/xdg/autostart"]
    for user, home, _uid in _home_dirs():
        xdg.append(os.path.join(home, ".config", "autostart"))
    for d in xdg:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".desktop"):
                continue
            full = os.path.join(d, fn)
            if _dpkg_owns(full):
                continue
            out.append(file_finding(
                "persistence", "medium",
                f"autostart entry no package owns: {fn}",
                "An unowned desktop startup entry is present; source and arguments are withheld.", full))

    # cron
    cron_files = sorted(glob.glob("/etc/cron.d/*")) + ["/etc/crontab"]
    cron_files += sorted(glob.glob("/var/spool/cron/crontabs/*"))
    for f in cron_files:
        body = _read(f)
        if not body:
            continue
        owned = _dpkg_owns(f)
        for i, line in enumerate(body.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if PAYLOAD_RE.search(line):
                out.append(file_finding(
                    "persistence", "critical",
                    f"cron entry runs a payload: {os.path.basename(f)}:{i}",
                    "A fetch/execute or reverse-shell indicator appears in cron code; source and arguments are withheld.", f))
            elif not owned and f.startswith("/etc/cron.d/"):
                out.append(file_finding(
                    "persistence", "medium",
                    f"cron file no package owns: {os.path.basename(f)}",
                    "An unowned system cron entry is present; source and arguments are withheld.", f))
    # Fresh metadata-only state supplements the legacy keyword signatures.
    already_reported = {f.get("where") for f in out}
    out.extend(f for f in startup_state.audit(_home_dirs())
               if f.get("where") not in already_reported)
    return out


# ── Windows ───────────────────────────────────────────────────────────────

PS_BACKDOOR = load_win_script("backdoor.ps1")


def _hidden_account_severity(h):
    """A hidden administrator or remote-desktop user is the classic backdoor.
    A hidden standard account can still sign in with its password but holds
    neither right. Unknown membership stays high."""
    if h.get("exists") is False:
        return "low", "no local account has this name"
    if h.get("exists") and h.get("enabled") is False:
        return "low", "the account is disabled"
    if h.get("admin") is False and h.get("rdp") is False and h.get("enabled"):
        return "medium", ("a standard account, not an administrator or "
                          "Remote Desktop user, that can still sign in with "
                          "its password")
    return "high", ""


def check_windows():
    d = ps_json(PS_BACKDOOR, timeout=180)
    if not d:
        return []
    out = []
    for ak in aslist(d.get("authkeys")):
        for line in (ak.get("body") or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            comment = parts[2] if len(parts) > 2 else "(no comment)"
            out.append(_finding(
                "remote access", "high",
                f"Windows SSH key authorised: {comment}",
                "grants passwordless SSH into this machine",
                ak.get("path", ""), "win"))
    for i in aslist(d.get("ifeo")):
        out.append(_finding(
            "remote access", "critical",
            f"accessibility backdoor on {i.get('exe')}",
            f"debugger = {i.get('debugger')} — this yields a SYSTEM shell from "
            f"the logon screen with no credential",
            "IFEO", "win"))
    for h in aslist(d.get("hidden")):
        if h.get("val") == 0:
            sev, why = _hidden_account_severity(h)
            out.append(_finding(
                "accounts", sev,
                f"account hidden from the sign-in screen: {h.get('name')}",
                "SpecialAccounts\\UserList hides it from view but not from use"
                + (f" — {why}" if why else ""),
                "Winlogon", "win"))
    if str(d.get("sshsvc")).lower() in ("running", "4"):
        out.append(_finding(
            "remote access", "medium", "the Windows OpenSSH server is running",
            "inbound SSH is listening on this machine", "sshd", "win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        for fn in (check_ssh, check_privilege, check_service_code, check_accounts,
                   check_persistence):
            try:
                out += fn()
            except Exception as exc:
                out.append(_finding("persistence", "medium",
                                    f"{fn.__name__} failed", str(exc)))
    if "win" in hosts:
        try:
            out += check_windows()
        except Exception as exc:
            out.append(_finding("remote access", "medium",
                                "windows backdoor audit failed", str(exc), "", "win"))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
