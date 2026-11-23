"""Audit the ways something can take or keep control of the machine.

Process monitoring answers "what is running right now". This module answers the
harder question: "what has arranged to run later, what can drive this machine
from outside, and has anything turned off the defenses?"

Three categories:
  persistence -- autostart hooks that survive reboot (tasks, services, cron,
                 registry Run keys, shell rc files, authorized_keys)
  remote      -- anything that grants interactive control from elsewhere
                 (RDP, WinRM, SSH, VNC/TeamViewer/AnyDesk-class agents)
  defense     -- the state of the controls themselves (Defender, tamper
                 protection, firewall, audit logging), because an attacker's
                 first move is usually to disable them
"""

import glob
import hashlib
import os
import re
import subprocess

try:
    import pwd
except ImportError:      # native Windows: no passwd database, and no caller there
    pwd = None
from jarvis.collectors.signatures import REMOTE_AGENTS
from jarvis.core.paths import load_win_script
from jarvis.core.util import package_manager, short
from jarvis.platform import broker, host
from jarvis.platform import host as machine
from jarvis.platform.provenance import persistence as managed_persistence
from jarvis.platform.windows import aslist, ps_json

from .backdoor import _sudo_lines, restricted_sudo
from .trusted_tasks import verified_maintenance_task

# PowerShell's -EncodedCommand, as a real flag rather than any string containing
# "enc" (Proton's "ms-encodedlaunch:" URI matched a looser pattern).
OBFUSCATED = re.compile(
    r"(?:^|[\s\"'])[-/]e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}|"
    r"FromBase64String|"
    r"powershell[^\n]*\s[-/]w(?:indowstyle)?\s+hidden",
    re.I,
)


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True,
                           errors="replace")
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": ""}


# ---------------------------------------------------------------------------
# Linux / WSL side
# ---------------------------------------------------------------------------

PACKAGED_UNIT_DIRS = ("/usr/lib/systemd/system/", "/lib/systemd/system/")
UNIT_LOAD_PATH = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")

SHELL_RC = ["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
            "~/.bash_login", "~/.config/autostart"]


def audit_linux():
    out = []

    # -- persistence: cron -------------------------------------------------
    crontab = _run(["crontab", "-l"])
    for line in crontab.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(_finding("persistence", "medium", "user cron job",
                                short(line, 100), "crontab -l"))

    stock_cron = []
    for path in glob.glob("/etc/cron.d/*") + ["/etc/crontab"]:
        if unchanged_package_file(path):
            # Shipped by a package and byte-identical to what it shipped: the
            # distribution's schedule, summarised once below. An edited or
            # unowned file keeps one finding per entry.
            stock_cron.append(path)
            continue
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("SHELL") \
                            and not line.startswith("PATH") and not line.startswith("MAILTO"):
                        out.append(_finding("persistence", "low", "system cron entry",
                                            short(line, 100), path))
        except OSError:
            pass
    if stock_cron:
        out.append(_finding("persistence", "ok", "system cron files are as their packages shipped them",
                            ", ".join(sorted(os.path.basename(p) for p in stock_cron)),
                            "/etc/cron.d"))

    # -- persistence: systemd ---------------------------------------------
    units = _run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager",
                  "--no-legend"])
    enabled = [line.split()[0] for line in units.splitlines() if line.split()]
    enabled = [u for u in enabled if not u.startswith(("systemd-", "dbus", "getty", "network",
                                                       "ssh.socket", "cron"))]
    packaged = packaged_units(enabled)
    for unit in enabled:
        if unit not in packaged:
            out.append(_finding("persistence", "low", "enabled systemd unit", unit,
                                "systemctl"))
    if packaged:
        out.append(_finding("persistence", "ok", f"{len(packaged)} enabled units come from installed packages",
                            ", ".join(sorted(packaged)[:40]) + (" ..." if len(packaged) > 40 else ""),
                            "systemctl"))

    for pattern in ("/etc/systemd/system/*.service", os.path.expanduser(
            "~/.config/systemd/user/*.service")):
        for path in glob.glob(pattern):
            target = os.path.realpath(path)
            if target == os.devnull:
                # `systemctl mask` links a unit to /dev/null so nothing can
                # start it: a disabled unit, not a service.
                out.append(_finding("persistence", "low", "masked systemd unit",
                                    os.path.basename(path), path))
                continue
            if os.path.islink(path) and target.startswith(PACKAGED_UNIT_DIRS):
                # `systemctl enable` writes aliases like syslog.service ->
                # rsyslog.service. The unit itself belongs to a package; a link
                # to anywhere else stays a custom service below.
                out.append(_finding("persistence", "ok", "systemd alias to a packaged unit",
                                    f"{os.path.basename(path)} -> {target}", path))
                continue
            proof = _verified_unit(path)
            finding = _finding("persistence", "low" if proof else "medium",
                               "custom systemd service", os.path.basename(path)
                               + (f" — verified: {proof}" if proof else ""), path)
            out.append(finding)

    # -- persistence: shell startup + rc hooks -----------------------------
    for rc in SHELL_RC:
        path = os.path.expanduser(rc)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    s = line.strip()
                    if re.search(r"(curl|wget)\s+[^|]*\|\s*(ba)?sh|nc\s+-e|"
                                 r"base64\s+-d|/dev/tcp/", s):
                        out.append(_finding("persistence", "critical",
                                            "shell rc runs remote code",
                                            short(s, 100), f"{path}:{n}"))
        except OSError:
            pass

    # -- persistence: preload hijack ---------------------------------------
    if os.path.exists("/etc/ld.so.preload"):
        try:
            with open("/etc/ld.so.preload", errors="replace") as fh:
                body = fh.read().strip()
        except OSError:
            body = "<unreadable>"
        if body:
            out.append(_finding("persistence", "critical",
                                "global library preload set", body,
                                "/etc/ld.so.preload"))

    # On a plain server the backdoor audit owns SSH keys (one finding per key,
    # with its options) and the firewall exposure audit owns listeners (weighed
    # by declared services and the firewall). Repeating them here only doubled
    # every finding (ARGUS-SERVER.md W2).
    server = machine.kind() == "linux"

    # -- remote: SSH trust -------------------------------------------------
    key_files = [] if server else (
        glob.glob(os.path.expanduser("~/.ssh/authorized_keys"))
        + glob.glob("/home/*/.ssh/authorized_keys") + glob.glob("/root/.ssh/authorized_keys"))
    for path in key_files:
        try:
            with open(path, errors="replace") as fh:
                keys = [l for l in fh if l.strip() and not l.startswith("#")]
        except OSError:
            continue
        for k in keys:
            comment = k.strip().split()[-1] if len(k.split()) > 2 else "(no comment)"
            out.append(_finding("remote", "high", "SSH key can log in as this user",
                                comment, path))

    # -- remote: listening services ---------------------------------------
    ss = _run(["ss", "-tulnp"])
    for line in ss.splitlines()[1:]:
        f = line.split()
        if len(f) < 5:
            continue
        local = f[4]
        if local.startswith(("0.0.0.0", "*", "[::]", ":::")):
            proc = f[6] if len(f) > 6 else ""
            agent = REMOTE_AGENTS.search(line)
            if server and not agent:
                continue
            sev = "high" if agent else "medium"
            out.append(_finding("remote", sev, "listening on all interfaces",
                                f"{local} {short(proc, 60)}", "ss -tulnp"))

    # -- privilege: sudoers drop-ins --------------------------------------
    for path in glob.glob("/etc/sudoers.d/*"):
        try:
            with open(path, errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        rules = [line.strip() for line in _sudo_lines(body)
                 if "NOPASSWD" in line.upper() and not line.strip().startswith("#")]
        if not rules:
            continue
        # Every rule limited to fixed, root-owned, non-escaping commands
        # cannot become a root shell; any other NOPASSWD rule can.
        restricted = all(restricted_sudo(rule) for rule in rules)
        out.append(_finding("defense", "low" if restricted else "high",
                            "restricted passwordless sudo rule" if restricted
                            else "passwordless sudo rule",
                            short(" ".join(rules), 90), path))

    # -- defense: WSL is not the security boundary -------------------------
    if host.on_wsl() and os.path.exists("/mnt/c/Windows"):
        out.append(_finding("defense", "low", "Windows drive mounted in WSL",
                            "processes in WSL can read and write the Windows "
                            "filesystem at /mnt/c", "/mnt/c"))

    for f in out:
        f["host"] = "wsl"
    return out


# ---------------------------------------------------------------------------
# Windows side
# ---------------------------------------------------------------------------

PS_CONTROL = load_win_script("control.ps1")




def _task_action_text(task):
    return " ; ".join(
        " ".join(filter(None, (a.get("execute"), a.get("arguments"))))
        for a in aslist(task.get("actions")) if isinstance(a, dict)
    )


def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def packaged_units(units, run=None):
    """The subset of `units` whose unit file a package owns. Two subprocess
    calls however many units: one systemctl show, one dpkg -S / rpm -qf. Unknown
    (no package manager, a failed query) owns nothing, so it never hides a unit."""
    run = run or _run
    manager = package_manager()
    if not units or not manager:
        return set()
    # The unit file systemd would load, from its load path in order (templates
    # included); `systemctl show` aborts the whole batch on one template name.
    paths = {}
    for unit in units:
        for d in UNIT_LOAD_PATH:
            candidate = os.path.join(d, unit)
            if os.path.lexists(candidate):
                real = os.path.realpath(candidate)
                if real != os.devnull:
                    paths[real] = unit
                break
    if not paths:
        return set()
    owned = set()
    # Snap mounts are written by snapd, not shipped by a package: recognised by
    # what they mount, a squashfs under /var/lib/snapd/snaps.
    for path, unit in paths.items():
        if unit.startswith("snap-") and unit.endswith(".mount") and _mounts_a_snap(path):
            owned.add(path)
    if manager == "dpkg":
        # dpkg may have recorded the pre-usrmerge spelling (/lib for /usr/lib).
        spellings = {}
        for path in paths:
            spellings[path] = path
            if path.startswith("/usr/lib/"):
                spellings[path[4:]] = path
        for line in run(["dpkg", "-S", *sorted(spellings)]).splitlines():
            if ": " in line:
                recorded = line.split(": ", 1)[1].strip()
                if recorded in spellings:
                    owned.add(spellings[recorded])
    else:
        for path, line in zip(sorted(paths), run(["rpm", "-qf", *sorted(paths)]).splitlines()):
            if line and "not owned" not in line:
                owned.add(path)
    return {paths[p] for p in paths if p in owned}


def _mounts_a_snap(path):
    try:
        with open(path, errors="replace") as fh:
            return any(line.strip().startswith("What=/var/lib/snapd/snaps/") and line.strip().endswith(".snap")
                       for line in fh)
    except OSError:
        return False


def unchanged_package_file(path, run=None):
    """True when a package owns `path` and it is byte-identical to what the
    package shipped (dpkg conffile md5, or an empty `rpm -Vf`). Anything not
    proven stays False, so the caller reports the file's contents."""
    run = run or _run
    manager = package_manager()
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    if manager == "dpkg":
        owner = run(["dpkg", "-S", path]).split(":", 1)[0].strip()
        if not owner or " " in owner:
            return False
        conffiles = run(["dpkg-query", "-W", "-f", "${Conffiles}\n", owner])
        for line in conffiles.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == path:
                return hashlib.md5(data, usedforsecurity=False).hexdigest() == parts[1]
        return False
    if manager == "rpm":
        owner = run(["rpm", "-qf", path]).strip()
        return bool(owner) and "not owned" not in owner and run(["rpm", "-V", "-f", path]).strip() == ""
    return False


def _unit_show(name, user=False):
    cmd = ["systemctl"] + (["--user"] if user else []) + [
        "show", name, "--no-pager", "-p", "ExecStart,User"]
    props = dict(line.split("=", 1) for line in _run(cmd).splitlines() if "=" in line)
    argv = re.search(r"argv\[\]=([^;]*)", props.get("ExecStart", ""))
    return (argv.group(1).split() if argv else []), props.get("User", "")


def _root_only(path):
    """Owned by root and writable by nobody else, following links."""
    try:
        st = os.stat(os.path.realpath(path))
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & 0o022


def _verified_unit(path):
    """Why a custom unit is known, or "" when it is not proven.

    Three units exist here by design and each is checked on its content,
    never its name: Microsoft's Sysmon for Linux (its /opt copy must be
    byte-identical to the dpkg-owned binary, and dpkg must verify that),
    JARVIS's self-check (identical to the repository template), and JARVIS
    itself (it must run JARVIS, as the checkout owner)."""
    from jarvis.core.paths import SOURCE_ROOT
    name = os.path.basename(path)
    try:
        if name == "sysmon.service" and path.startswith("/etc/systemd/system/"):
            argv, _user = _unit_show(name)
            if argv and argv[0] == "/opt/sysmon/sysmon" \
                    and _sha256(argv[0]) == _sha256("/usr/bin/sysmon") \
                    and "/usr/bin/sysmon" not in _run(["dpkg", "-V", "sysmonforlinux"]) \
                    and "sysmonforlinux" in _run(["dpkg", "-S", "/usr/bin/sysmon"]):
                return "Sysmon for Linux, identical to the dpkg-verified /usr/bin/sysmon"
        if name == "jarvis-selfcheck.service":
            with open(SOURCE_ROOT / "systemd" / name, errors="replace") as fh:
                template = fh.read().replace("@REPO_ROOT@", str(SOURCE_ROOT))
            with open(path, errors="replace") as fh:
                if fh.read() == template:
                    return "identical to JARVIS's reviewed unit template"
        if name == "jarvis.service" and path.startswith("/etc/systemd/system/"):
            argv, user = _unit_show(name)
            owner = pwd.getpwuid(os.stat(SOURCE_ROOT).st_uid).pw_name
            runs_jarvis = argv[1:5] == ["-I", "/opt/jarvis/current/jarvis-release.py",
                                        "serve", "--port"] or argv[1:4] == ["-m", "jarvis", "serve"]
            if argv[:1] == ["/usr/bin/python3"] and runs_jarvis and user == owner:
                return f"runs JARVIS as {owner}"
            # The server edition: the sealed /opt/jarvis/app launcher, as the
            # dedicated jarvis account, by a root-owned interpreter nobody else
            # can write (the launcher drops its capabilities otherwise).
            # The packaged edition ships the launcher compiled (.pyc, no source).
            for launcher in ("/opt/jarvis/app/jarvis-release.py", "/opt/jarvis/app/jarvis-release.pyc"):
                if (argv[1:5] == ["-I", launcher, "serve", "--port"]
                        and user == "jarvis" and argv and _root_only(argv[0])
                        and _root_only(launcher)):
                    return "runs the sealed JARVIS server release as the jarvis account"
            # The native edition (release/launcher.py compiled, no Python at all):
            # the root-owned binary itself, as the jarvis account.
            if (argv[:1] == ["/opt/jarvis/bin/jarvis-server"] and argv[1:3] == ["serve", "--port"]
                    and user == "jarvis" and _root_only(argv[0])):
                return "runs the sealed native JARVIS server binary as the jarvis account"
    except (OSError, KeyError, ValueError, AttributeError):
        return ""
    return ""


def audit_windows():
    data = ps_json(PS_CONTROL)
    if data is None:
        return [_finding("defense", "medium", "Windows audit unavailable",
                         "powershell.exe did not return data; some checks need an "
                         "elevated shell", "interop")]
    out = []

    for t in aslist(data.get("tasks")):
        action = _task_action_text(t)
        trusted, trust_detail = verified_maintenance_task(t, data)
        if trusted:
            out.append(_finding("persistence", "low", "verified scheduled task",
                                f"{t.get('name')} — {trust_detail}",
                                (t.get("path") or "") + str(t.get("name"))))
            continue
        sev = "high" if REMOTE_AGENTS.search(action + (t.get("name") or "")) else "low"
        if OBFUSCATED.search(action):
            sev = "critical"
        # A declared JARVIS-managed task that fails verification is either
        # modified or an impostor using the name: critical either way. The
        # reason leads the detail: after the command line it was cut at 90
        # characters and never read (2026-10-30).
        detail = f"{t.get('name')} → {short(action, 90)}"
        if (t.get("name") or "").casefold() in managed_persistence.CRITICAL_ON_MISMATCH:
            sev = "critical"
            detail = f"{t.get('name')}: verification failed: {trust_detail} — runs {short(action, 90)}"
        finding = _finding("persistence", sev, "scheduled task", detail,
                           (t.get("path") or "") + str(t.get("name")))
        finding["response_target"] = {"kind": "task", "name": t.get("name") or "",
                                      "path": t.get("path") or "\\"}
        acts = [a for a in aslist(t.get("actions")) if isinstance(a, dict)]
        if len(acts) == 1:
            # untruncated; a COM-handler task runs its registered DLL
            finding["program"] = str(acts[0].get("execute") or acts[0].get("handler") or "")
        out.append(finding)

    for k in aslist(data.get("runkeys")):
        val = k.get("value") or ""
        sev = "high" if REMOTE_AGENTS.search(val) else "medium"
        if OBFUSCATED.search(val) or re.search(r"\\temp\\|\\downloads\\", val, re.I):
            sev = "critical"
        finding = _finding("persistence", sev, "autostart registry entry",
                           f"{k.get('name')} = {short(val, 90)}", k.get("key", ""))
        finding["response_target"] = {"kind": "runkey", "name": k.get("name") or "",
                                      "key": k.get("key") or "", "value": val}
        out.append(finding)

    for s in aslist(data.get("startup")):
        out.append(_finding("persistence", "medium", "startup folder item",
                            s.get("name", ""), s.get("path", "")))

    for s in aslist(data.get("services")):
        path = s.get("path") or ""
        sev = "high" if REMOTE_AGENTS.search(path + (s.get("disp") or "")) else "low"
        if re.search(r"\\temp\\|\\users\\public\\|\\appdata\\", path, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "auto-start service",
                            f"{s.get('disp') or s.get('name')} [{s.get('state')}] "
                            f"{short(path, 80)}", s.get("name", "")))

    for w in aslist(data.get("wmi")):
        pair = f"{w.get('filter')} {w.get('consumer')}"
        # Windows ships one of these out of the box; the rest deserve alarm.
        stock = "SCM Event Log" in pair
        out.append(_finding("persistence", "low" if stock else "critical",
                            "WMI event subscription"
                            + (" (Windows built-in)" if stock else ""),
                            f"{short(str(w.get('filter')), 60)} → "
                            f"{short(str(w.get('consumer')), 60)}",
                            "root\\subscription"))

    remote = data.get("remote") or {}
    if remote.get("rdpEnabled"):
        out.append(_finding("remote", "high", "Remote Desktop is enabled",
                            "inbound RDP can drive this machine interactively",
                            "Terminal Server\\fDenyTSConnections"))
    if (remote.get("winrm") or "") == "Running":
        out.append(_finding("remote", "high", "WinRM service running",
                            "accepts remote PowerShell", "Service: WinRM"))
    if (remote.get("sshd") or "") == "Running":
        out.append(_finding("remote", "high", "OpenSSH server running",
                            "accepts inbound SSH", "Service: sshd"))
    me = (data.get("currentUser") or "").casefold().rsplit("\\", 1)[-1]
    for line in aslist(remote.get("sessions")):
        if isinstance(line, str) and line.strip() and "USERNAME" not in line:
            # `query user`: [>]USERNAME SESSIONNAME ID STATE ... Your own
            # console session is the machine being used; anything else
            # (another account, an RDP session) keeps its severity.
            cols = line.lstrip(" >").split()
            own = (len(cols) >= 2 and me and cols[0].casefold() == me
                   and cols[1].casefold() == "console")
            out.append(_finding("remote", "low" if own else "medium", "logon session",
                                short(line.strip(), 90), "query user"))

    d = data.get("defender") or {}
    if d.get("present"):
        if d.get("realtime") is False:
            out.append(_finding("defense", "critical",
                                "Defender real-time protection is OFF",
                                "live scanning disabled", "Get-MpComputerStatus"))
        if d.get("tamperProtection") is False:
            out.append(_finding("defense", "high", "Tamper Protection is OFF",
                                "Defender settings can be changed by software",
                                "Get-MpComputerStatus"))
        if d.get("antivirus") is False:
            out.append(_finding("defense", "critical", "Defender antivirus disabled",
                                "", "Get-MpComputerStatus"))
        age = d.get("sigAgeDays")
        if isinstance(age, int) and age > 7:
            out.append(_finding("defense", "medium", "Defender signatures stale",
                                f"{age} days old", "Get-MpComputerStatus"))
        denied = False
        # The elevated broker's posture run reads the real exclusion lists; an
        # unelevated Get-MpPreference only returns "N/A: must be an administrator".
        elevated, _why = broker.result("posture")
        pref = (elevated or {}).get("mppref") or {}
        if elevated and pref:
            d = dict(d, exclusionPaths=pref.get("ExclusionPath"),
                     exclusionProcs=pref.get("ExclusionProcess"))
        for kind, key in (("path", "exclusionPaths"), ("process", "exclusionProcs")):
            for p in aslist(d.get(key)):
                if not p:
                    continue
                if str(p).startswith("N/A"):
                    denied = True  # non-admin shell: value is a refusal, not a path
                    continue
                out.append(_finding("defense", "high",
                                    f"Defender scan exclusion ({kind})",
                                    str(p), "Get-MpPreference"))
        if denied:
            out.append(_finding("defense", "medium", "Defender exclusions not readable",
                                "run this audit from an elevated PowerShell to see "
                                "which paths are excluded from scanning",
                                "Get-MpPreference"))
    else:
        out.append(_finding("defense", "medium", "Defender status unreadable",
                            "run the audit from an elevated shell for defense checks",
                            "Get-MpComputerStatus"))

    for fw in aslist(data.get("firewall")):
        if fw.get("enabled") in (False, 0, "False"):
            out.append(_finding("defense", "critical",
                                f"firewall disabled on {fw.get('name')} profile",
                                "inbound traffic unfiltered", "Get-NetFirewallProfile"))

    for r in aslist(data.get("fwrules")):
        out.append(_finding("remote", "low", "inbound firewall allow rule",
                            short(str(r.get("DisplayName")), 80),
                            str(r.get("Profile"))))

    for a in aslist(data.get("admins")):
        out.append(_finding("defense", "low", "local administrator", str(a),
                            "Administrators group"))

    if data.get("uac") == 0:
        out.append(_finding("defense", "critical", "UAC is disabled",
                            "elevation prompts are off", "EnableLUA"))

    for f in out:
        f["host"] = "win"
    return out


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"defense": 0, "remote": 1, "persistence": 2}


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += audit_linux()
    if "win" in hosts:
        out += audit_windows()
    # Group by category first so each section prints once, worst item at the top.
    out.sort(key=lambda f: (CAT_ORDER.get(f["category"], 9),
                            SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out
