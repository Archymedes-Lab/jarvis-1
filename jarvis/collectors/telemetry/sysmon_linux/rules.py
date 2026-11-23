"""Linux-shaped detection rules over parsed Sysmon events."""

import ipaddress
import os
import re
import subprocess

try:
    import pwd
except ImportError:      # native Windows: no passwd database, and no caller there
    pwd = None
from jarvis.collectors.telemetry import community, techniques
from jarvis.core import egress as egress_baseline
from jarvis.core import sigma, vet, warninglist
from jarvis.core.finding import finding as _finding
from jarvis.core.util import now

from .harness import _payload
from .journal import CHANNEL, _base, _clean, _event_utc

WORLD_WRITABLE = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/var/lib/php/")


# Unambiguous web servers only. node/java/python host servers too but also host
# most other things, so a shell under those is not on its own a signal.
WEB_PARENTS = ("nginx", "httpd", "apache2", "php-fpm", "php-cgi", "php",
               "caddy", "lighttpd", "tomcat", "gunicorn", "uwsgi")


SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "busybox")


RECON_BINS = {"whoami", "id", "uname", "hostname", "hostnamectl", "ifconfig",
              "netstat", "arp", "route", "w", "who", "last", "lastlog",
              "crontab", "lsmod", "nmap", "showmount", "rpcinfo"}


REVSHELL_BINS = {"nc", "ncat", "netcat", "socat", "telnet"}


# Only locations that are actually read: system paths anchored at /, and
# per-user paths inside a real account's home. The same names under /tmp are
# never loaded by systemd, cron or a login shell (JARVIS's own test suite
# writes them there on every deploy).
SYSTEM_PERSIST = re.compile(
    r"^(/etc/cron|/var/spool/cron|/etc/systemd/system/|/etc/systemd/user/|"
    r"/etc/init\.d/|/etc/ld\.so\.preload$|/etc/sudoers|/etc/profile\.d/|"
    r"/etc/rc\.local$)")
HOME_PERSIST = re.compile(
    r"^(?P<home>/.+?)/(\.ssh/authorized_keys|\.config/systemd/user/.+|"
    r"\.bashrc|\.bash_profile|\.profile)$")


def _account_homes():
    try:
        return {os.path.normpath(p.pw_dir) for p in pwd.getpwall() if p.pw_dir}
    except Exception:
        return set()


def persistence_location(path):
    """True when `path` is somewhere a login, systemd or cron will read."""
    path = os.path.normpath(path or "")
    if SYSTEM_PERSIST.search(path):
        return True
    m = HOME_PERSIST.match(path)
    return bool(m) and m.group("home") in _account_homes()


# snapd rewrites its own revision-pinned units under /etc/systemd/system on
# every refresh, through an atomic temp file whose name ends in `~`. The
# directory is a genuine persistence location, so the exemption is scoped to
# snapd touching a `snap-*` / `snap.*` unit name and nothing else — a unit
# with any other name, or any other writer, still surfaces.
SNAP_UNIT = re.compile(
    r"/etc/systemd/system/snap[-.][^/]+\.(mount|service|timer|socket|slice)"
    r"(\.[A-Za-z0-9_]+~)?$")


# The numbered-generation ladder a log rotator leaves behind: `dmesg.0`,
# `syslog.7.gz`, `apt/history.log.3.xz`. savelog/logrotate hand the previous
# generation to a compressor, which deletes the source once it is packed.
ROTATED_LOG = re.compile(r"^/var/log/.+\.\d+(\.(gz|xz|bz2|zst|Z))?$")


LOG_ROTATORS = {"gzip", "bzip2", "xz", "zstd", "lzma", "compress",
                "savelog", "logrotate"}


# What makes this dangerous is fetched content reaching an interpreter, not the
# mere presence of curl. The old second alternative was `sh -c .* (curl|...)`,
# where `.*` matched a fetch used for anything at all -- an ordinary
# `bash -c '... curl -s https://api/health ...'` tripped it every time. Each
# alternative below now requires the download and the execution to be joined.
DOWNLOAD_RUN = re.compile(
    # fetch piped straight into an interpreter
    r"(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b|"
    # fetch inside a substitution that is then evaluated
    r"\b(eval|exec|source)\b[^\n]{0,30}\$\(\s*(curl|wget|fetch)\b|"
    # base64 payload decoded into a shell
    r"base64\s+(-d|--decode)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b|"
    # a shell reaching for a raw TCP socket
    r"\b(ba)?sh\b\s+-c\b[^\n]*/dev/tcp/|"
    # python one-liner opening a socket or exec'ing fetched code
    r"python[0-9.]*\s+-c\s+[^\n]{0,80}\b(socket|exec)\b",
    re.I)


# Package-manager layouts under a world-writable root. A JS or Python project
# checked out in /tmp runs binaries out of its own dependency tree constantly;
# that is a dev habit, not a dropper. Still reported -- node_modules is a fine
# place to hide a payload -- but one severity lower, so the genuinely odd case
# of an unparented binary in /tmp stays visible above the noise.
DEV_PKG_PATH = re.compile(
    r"/(node_modules|site-packages|\.venv|venv|\.pnpm|\.cargo|vendor|"
    r"go-build\d+/b\d+)/")


DEV_PARENTS = ("node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "tsx",
               "python", "python3", "pip", "pip3", "cargo", "go", "make")


# Container and build tooling legitimately runs a lot of enumeration commands.
BUILD_PARENTS = {"runc", "containerd", "containerd-shim", "dockerd",
                 "docker", "buildkitd", "bun", "node", "npm", "yarn",
                 "make", "cmake", "cargo", "go", "bazel", "ansible-playbook"}

LOG_DELETE_TITLE = "a log or history file was deleted"


EGRESS_TITLE = egress_baseline.TITLE


EXPECTED_EGRESS = {
    "firefox", "chrome", "chromium", "curl", "wget", "apt", "apt-get", "http",
    "https", "snap", "snapd", "packagekitd", "systemd", "systemd-resolved",
    "NetworkManager", "dockerd", "containerd", "git", "git-remote-http", "gh",
    "ssh", "sshd", "code", "node", "python3", "bun", "npm", "pip", "pip3", "uv",
}


LOG_DELETE_SUFFIX = " — indicator removal"


PERSIST_WRITE_TITLE = "write to a persistence or trust location"


RAW_ACCESS_TITLE = "raw device read"  # retain existing alert identity


RAW_UNRESOLVED_TITLE = "Sysmon raw-access event has an unresolved device"


RAW_LEGACY_SUFFIX = " for raw access — disk imaging or filesystem-bypass read"


ROTATION_PARENT = re.compile(r"(^|[/\s])(savelog|logrotate)(\s|$)")


# A heredoc whose delimiter is quoted (<<'EOF', <<"EOF", <<\EOF) is written
# verbatim: no expansion, no substitution, nothing runs. Measured 2026-09-17:
# `cat > approvals.test.ts <<'EOF'` with test source mentioning `curl | sh`
# raised "download-and-run". Unquoted heredocs are left in place — `$(curl …)`
# inside one does execute.
#
# Verbatim is not inert when a shell or interpreter reads it: `bash <<'E'`,
# `cat <<'E' | sh` or `python3 - <<'E'` run the body. Such a heredoc stays in
# the command line (the leaked source made this bypass easy to find).
_HEREDOC_READER = re.compile(
    r"(?:^|[\s/;&|(`])(?:(?:ba|da|z|k|c|tc|fi|a)?sh|busybox|python[\d.]*|perl[\d.]*|ruby|node|nodejs|deno|bun"
    r"|php[\d.]*|lua[\d.]*|tclsh|expect|pwsh|source|eval|exec|su|ssh|at|batch|crontab)(?=$|[\s;&|)`])")


def _without_quoted_heredocs(cmd):
    out, pos = [], 0
    for m in re.finditer(r"<<-?\s*(?:'([^']+)'|\"([^\"]+)\"|\\(\w+))[^\n]*\n", cmd or ""):
        if m.start() < pos:
            continue
        # The command that owns the heredoc: back to the last separator, and the
        # rest of its line (`cat <<'E' | sh` pipes the body into a shell).
        seg = max(cmd.rfind(c, 0, m.start()) for c in ";&|(`\n") + 1
        if _HEREDOC_READER.search(cmd[seg:m.start()]) or _HEREDOC_READER.search(m.group(0)):
            continue                        # a shell or interpreter reads the body: it runs
        tag = m.group(1) or m.group(2) or m.group(3)
        end = re.compile(r"^\s*" + re.escape(tag) + r"\s*$", re.M).search(cmd, m.end())
        out.append(cmd[pos:m.end()])
        pos = end.end() if end else len(cmd)
    out.append((cmd or "")[pos:])
    return "".join(out)


_DMESG_WINDOWS = {}     # boot id -> [(start, end)] of dmesg.service runs


def _dmesg_windows():
    """(start, end) epoch pairs of this boot's dmesg.service runs, read once
    per boot from systemd's journal. Ubuntu's unit runs `savelog -c 5` on
    /var/log/dmesg, which removes the oldest generation."""
    try:
        with open("/proc/sys/kernel/random/boot_id", errors="replace") as fh:
            boot = fh.read().strip()
    except OSError:
        return []
    if boot in _DMESG_WINDOWS:
        return _DMESG_WINDOWS[boot]
    try:
        text = subprocess.run(
            ["journalctl", "-u", "dmesg.service", "-b", "-o", "short-unix", "--no-pager"],
            capture_output=True, text=True, errors="replace", timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    windows, start = [], None
    for line in text.splitlines():
        try:
            stamp = float(line.split(" ", 1)[0])
        except ValueError:
            continue
        if "Starting dmesg.service" in line or ("Started dmesg.service" in line and start is None):
            start = stamp if start is None else start
        elif "dmesg.service: Deactivated" in line and start is not None:
            windows.append((start, stamp))
            start = None
    if start is not None:
        windows.append((start, start + 120))
    if not windows:
        windows = _dmesg_unit_window()
    _DMESG_WINDOWS.clear()
    _DMESG_WINDOWS[boot] = windows
    return windows


def _dmesg_unit_window():
    """This boot's dmesg.service run from systemd's own unit timestamps.

    The journal lines above rotate away within the hour when Sysmon is busy
    (measured 2026-09-23: oldest entry ~40 min old), which turned every later
    read of a legitimate rotation into "indicator removal". systemd keeps the
    last run's activation and deactivation times for the whole boot."""
    try:
        text = subprocess.run(
            ["systemctl", "show", "dmesg.service", "--timestamp=unix",
             "-p", "InactiveExitTimestamp", "-p", "InactiveEnterTimestamp"],
            capture_output=True, text=True, errors="replace", timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    stamps = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        try:
            stamps[key] = float(value.lstrip("@"))
        except ValueError:
            continue
    start, end = stamps.get("InactiveExitTimestamp"), stamps.get("InactiveEnterTimestamp")
    if start and end and 0 <= end - start <= 600:
        return [(start, end)]
    return []


def _dmesg_rotation(path, when):
    """An unparented rm of a rotated /var/log/dmesg generation, inside a run
    of dmesg.service in this boot (measured 2026-09-23: deletion 6s after the
    unit started, 9s before it ended).

    `when` is one event time or several readings of it. Sysmon's ingestion
    time (TimeCreated) lags while it drains its boot backlog, and dmesg.service
    runs in exactly that backlog (2026-09-24: the 17:13:51-17:13:59 run still
    left `rm deleted /var/log//dmesg.4.gz` high); the kernel-side UtcTime is
    accurate at boot but drifts after standby. Either reading inside the run
    window is enough; the window itself is not widened."""
    times = [t for t in (when if isinstance(when, (tuple, list)) else (when,))
             if isinstance(t, (int, float))]
    if not times or not re.match(r"^/var/log/dmesg\.\d+(\.gz)?$", path):
        return False
    return any(start - 5 <= t <= end + 5
               for start, end in _dmesg_windows() for t in times)


def _event_times(e):
    """The event's ingestion time and its kernel-side time, when present."""
    return tuple(t for t in (_event_utc({"SystemTime": e.get("SystemTime")}),
                             _event_utc({"UtcTime": e.get("UtcTime")}))
                 if t is not None)


def _expected_log_maintenance(actor, target, parent_cmdline="", when=None):
    """True only for a logging daemon or the rotation tooling acting on files
    it owns.

    Two exact shapes, nothing wider — broadly trusting anything that touches
    /var/log would be an easy indicator-removal blind spot:

      * journald unlinking one of its own archived journal segments, and
      * a compressor (invoked by savelog/logrotate) removing the previous
        numbered generation of a log once it has been packed — e.g. `gzip`
        deleting `/var/log/dmesg.0`.

    A bare `rm /var/log/auth.log`, or a compressor deleting a name that is not
    a numbered generation, still surfaces as indicator removal.
    """
    path = os.path.normpath(target or "")
    if (actor == "systemd-journald"
            and path.startswith("/var/log/journal/")
            and path.endswith((".journal", ".journal~"))):
        return True
    if actor == "rm":
        # savelog deletes the oldest generation with a plain `rm -f`; Ubuntu's
        # dmesg.service runs `savelog -c 5 /var/log/dmesg` at every boot.
        # Measured: `rm deleted /var/log/dmesg.4.gz` raised a high each WSL
        # start. Only rm's own process record naming savelog or logrotate as
        # its parent exempts it; an rm Sysmon cannot parent stays high.
        # The run window alone is not enough: an rm with a visible parent that
        # is not savelog/logrotate (a shell, a script) is not the unit's rm.
        parent = parent_cmdline or ""
        if (ROTATED_LOG.match(path) and _dmesg_rotation(path, when)
                and (not parent or ROTATION_PARENT.search(parent))):
            return True
        return bool(ROTATED_LOG.match(path)) and bool(ROTATION_PARENT.search(parent_cmdline or ""))
    return actor in LOG_ROTATORS and bool(ROTATED_LOG.match(path))


def _expected_persistence(actor, target):
    """True only for snapd rewriting one of its own revision-pinned units.

    snapd regenerates `/etc/systemd/system/snap-<name>-<rev>.mount` (and the
    matching temp file ending in `~`) on every snap install or refresh. No
    other writer, and no other unit name, is exempt.
    """
    return actor == "snapd" and bool(
        SNAP_UNIT.search(os.path.normpath(target or "")))


def _is_public_ip(ip):
    """Globally routable, judged after unmapping IPv4-mapped IPv6. Sysmon
    writes the unspecified address as `0:0:0:0:0:0:0:0` and Docker peers as
    `0:0:0:0:0:ffff:ac12:5` (172.18.0.5); prefix matching called both public."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip("[]").split("%")[0])
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global


def _is_jarvis(e):
    """jarvis shells out to ps/ss/ip/journalctl constantly — do not report
    its own activity as reconnaissance or unexplained egress."""
    blob = (str(e.get("ParentCommandLine", "")) + " "
            + str(e.get("CommandLine", "")) + " "
            + str(e.get("ParentImage", ""))).lower()
    return "jarvis" in blob or "-m jarvis" in blob


def _rules(events, store=None, community_rules=None):
    out = []
    recon, egress = {}, {}
    technique_hits, discovery_seen = {}, []
    dns_names, dests = set(), set()
    # A PID can be reused. Only a matching Sysmon ProcessGuid can supply the
    # command line for an event that doesn't contain one of its own.
    processes = {e["ProcessGuid"]: e for e in events
                 if e.get("id") == 1 and _clean(e.get("ProcessGuid"))
                 and e["ProcessGuid"] != "{00000000-0000-0000-0000-000000000000}"}

    for e in events:
        eid = e.get("id")
        img = _clean(e.get("Image") or e.get("SourceImage"))
        cmd = _clean(e.get("CommandLine"))
        # The command the operator actually ran, with any agent-harness wrapper
        # stripped — this is what the content rules should judge.
        pcmd = _payload(cmd)
        parent = _clean(e.get("ParentImage"))
        base, pbase = _base(img), _base(parent)
        mine = _is_jarvis(e)

        if eid == 1:
            # Only the executable's own path counts — a world-writable path in
            # an argument (runc/containerd pass plenty) is not execution from
            # there.
            if img and img.startswith(WORLD_WRITABLE):
                # A binary sitting inside a checked-out dependency tree
                # (node_modules, site-packages, …) that a project under /tmp
                # runs against itself is a dev habit, not a dropper — whether
                # or not Sysmon managed to resolve the parent this time. HIGH is
                # for an executable in a world-writable dir that is *not*
                # transparently part of a package tree.
                dev = bool(DEV_PKG_PATH.search(img)) and (
                    pbase in DEV_PARENTS or not pbase)
                out.append(_finding(
                    "sysmon-linux", "medium" if dev else "high",
                    "process executed from a world-writable directory",
                    f"{img}  «{cmd[:120]}»  parent {pbase or '?'}"
                    + ("  — dependency-tree binary run by its own package "
                       "manager, which is normal for a project under /tmp"
                       if dev else ""), CHANNEL))
            if DOWNLOAD_RUN.search(_without_quoted_heredocs(pcmd)):
                out.append(_finding(
                    "sysmon-linux", "high", "download-and-run in a command line",
                    f"{pbase or base}: {pcmd[:160]}", CHANNEL))
            if pbase in WEB_PARENTS and base in SHELLS:
                out.append(_finding(
                    "sysmon-linux", "critical",
                    f"the web server ({pbase}) spawned a shell",
                    f"{img}  «{cmd[:140]}» — the classic post-exploitation "
                    f"step after a web shell or an RCE", CHANNEL))
            if base in REVSHELL_BINS and re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b|"
                                                   r"-e\b|/dev/tcp", pcmd):
                out.append(_finding(
                    "sysmon-linux", "high",
                    f"{base} invoked with a connect-back argument",
                    pcmd[:160], CHANNEL))
            if base in RECON_BINS and not mine:
                recon.setdefault(pbase or "?", set()).add(base)
            # A shell's command line is judged as the operator typed it, with
            # the harness wrapper and quoted heredocs (file contents) removed.
            tcmd = _without_quoted_heredocs(pcmd) if base in techniques.SHELLS else cmd
            for rule, span in techniques.match(img, tcmd, techniques.LINUX, parent):
                hit = technique_hits.setdefault(rule, [0, span, base])
                hit[0] += 1
            if not mine and pbase not in BUILD_PARENTS:
                guid = _clean(e.get("ParentProcessGuid"))
                if guid and guid != "{00000000-0000-0000-0000-000000000000}":
                    when = next(iter(_event_times(e)), None)
                    for tid in techniques.discovery(img, cmd, techniques.LINUX):
                        discovery_seen.append((guid, pbase or "?", when, tid, base))

        elif eid == 3:
            dst = e.get("DestinationIp") or ""
            host = e.get("DestinationHostname") or ""
            port = e.get("DestinationPort") or "?"
            if host:
                dns_names.add(host.lower())
            if dst:
                dests.add(dst)
            # Event 3 names the connecting process in Image and carries no
            # parent, so the list is checked against `base`. It was checked
            # against the (always empty) parent, which turned every public
            # connection from node, curl or gh into its own medium finding —
            # 209 of them in three days.
            if _is_public_ip(dst) and not mine and base not in EXPECTED_EGRESS:
                egress.setdefault(base or "", {}).setdefault(f"{dst}:{port}", host)

        elif eid == 10:
            tgt = e.get("TargetImage") or ""
            ga = (e.get("GrantedAccess") or "").lower()
            if "ptrace" in ga or "/proc/" in tgt or tgt:
                out.append(_finding(
                    "sysmon-linux", "high",
                    "a process read another process's memory",
                    f"{base or '?'} → {_base(tgt) or tgt or '?'} "
                    f"(access {ga or '?'}) — the Linux shape of credential "
                    f"dumping and injection", CHANNEL))

        elif eid == 11:
            tgt = e.get("TargetFilename") or ""
            if persistence_location(tgt) and not _expected_persistence(base, tgt):
                out.append(_finding(
                    "sysmon-linux", "high", PERSIST_WRITE_TITLE,
                    f"{base or '?'} created/modified {tgt}", CHANNEL))

        elif eid in (23, 26):
            tgt = e.get("TargetFilename") or ""
            creator = processes.get(e.get("ProcessGuid"), {})
            if ((tgt.startswith("/var/log/") or "/.bash_history" in tgt)
                    and not _expected_log_maintenance(
                        base, tgt, _clean(creator.get("ParentCommandLine")),
                        _event_times(e))):
                out.append(_finding(
                    "sysmon-linux", "high", LOG_DELETE_TITLE,
                    f"{base or '?'} deleted {tgt}{LOG_DELETE_SUFFIX}", CHANNEL))

        elif eid == 9:
            device = _clean(e.get("Device"))
            proc = processes.get(e.get("ProcessGuid"), {})
            context = _clean(proc.get("CommandLine")) if proc.get("Image") == img else ""
            # Linux Event 9 originates in processFileOpen (Sysmon 1.5.2),
            # which tests S_IFBLK but doesn't establish a read or disk imaging.
            # Missing/relative device names are retained as an uncertainty,
            # never silently trusted or promoted to a confirmed disk read.
            resolved = device.startswith("/") and device != "/"
            out.append(_finding(
                "sysmon-linux", "high" if resolved else "medium",
                RAW_ACCESS_TITLE if resolved else RAW_UNRESOLVED_TITLE,
                f"{img or '?'}: Sysmon Event 9 reports device {device or '<missing>'!r}; "
                + ("block-device open requires investigation; read/write direction "
                   "and disk imaging are not established"
                   if resolved else "target is unresolved; raw disk access is not established")
                + f"; PID {e.get('ProcessId') or '?'}; event time {e.get('UtcTime') or '?'}"
                + (f"; command {context[:180]}" if context else ""),
                CHANNEL))

    # One finding per program, not per address: the question is whether this
    # program should talk to the internet at all.
    for base, peers in sorted(egress.items()):
        sample = ", ".join(f"{d}" + (f" ({h})" if h and h != "-" else "")
                           for d, h in list(peers.items())[:4])
        verdict = egress_baseline.decision(store, "wsl", base) if (store is not None and base) else ""
        if base and verdict == egress_baseline.EXPECTED:
            continue            # you confirmed this program reaches the internet
        if base and verdict == egress_baseline.UNEXPECTED:
            out.append(_finding(
                "sysmon-linux", "high", f"{EGRESS_TITLE} {base}",
                f"{len(peers)} public destination(s): {sample} — you marked this "
                f"program as not expected to reach the internet", CHANNEL))
        elif base:
            out.append(_finding(
                "sysmon-linux", "medium", f"{EGRESS_TITLE} {base}",
                f"{len(peers)} public destination(s): {sample} — confirm this "
                f"program is expected to reach the internet", CHANNEL))
        else:
            out.append(_finding(
                "sysmon-linux", "low", f"{EGRESS_TITLE} an unresolved process",
                f"{len(peers)} public destination(s): {sample} — Sysmon could not "
                f"name the process, so this is a visibility gap, not a detection",
                CHANNEL))

    for rule, (count, span, base) in technique_hits.items():
        f = _finding(
            "sysmon-linux", rule.severity, techniques.finding_title(rule),
            f"{base}" + (f", {count} times" if count > 1 else "")
            + (f": {span}" if span else " (command line withheld: it may carry a secret)")
            + " — the action is what is reported; whether it was authorised is for "
              "you to confirm", CHANNEL)
        f["techniques"] = list(rule.tids)
        if rule.origin:
            f["origin"] = "rulepack"     # content, not authority: never acted on unasked
        out.append(f)
    for parent, tids, commands in techniques.bursts(discovery_seen):
        f = _finding("sysmon-linux", "medium", techniques.burst_title(parent),
                     techniques.burst_detail(tids, commands), CHANNEL)
        f["techniques"] = sorted(tids)
        out.append(f)

    for pbase, bins in recon.items():
        # An unresolved parent means unattributable — and that bucket is
        # dominated by short-lived system and monitoring processes.
        if pbase and pbase != "?" and pbase not in BUILD_PARENTS and len(bins) >= 5:
            out.append(_finding(
                "sysmon-linux", "medium",
                f"host reconnaissance burst under {pbase}",
                f"{', '.join(sorted(bins))} from one parent in a short window — "
                f"enumeration a sampling monitor would never have caught",
                CHANNEL))

    # Community rules (Sigma), judged per install; after the built-in rules,
    # never instead of them. On for the machine, off for a replay unless asked
    # (a replay exercises the built-in table). A replay learns nothing.
    if community_rules is None:
        community_rules = store is not None
    if community_rules:
        out += community.findings(
            sigma.LINUX_PROC, [e for e in events if e.get("id") == 1],
            lambda e: (_clean(e.get("Image")), _clean(e.get("ParentImage")), _clean(e.get("UtcTime")),
                       _clean(e.get("CommandLine"))),
            lambda severity, title, detail, image: _finding("sysmon-linux", severity, title, detail,
                                                            image or CHANNEL),
            store=store, now=now())

    if store is not None and (dns_names or dests):
        out += _correlate(store, dns_names, dests)
    return out


def _correlate(store, dns_names, dests):
    """Check observed names/IPs against the indicator corpus."""
    out = []
    values = list(dns_names) + list(dests)
    if not values:
        return out
    qmarks = ",".join("?" * len(values))
    try:
        rows = store.db.execute(
            f"SELECT value, kind, malware, source, confidence FROM indicators "
            f"WHERE status='active' AND (norm IN ({qmarks}) OR value IN ({qmarks}))",
            values + values).fetchall()
    except Exception:
        return out
    for r in rows:
        # The same gates the Windows matcher uses: vetting, popularity, and
        # the indicator's own confidence. This matched exactly, unvetted, and
        # made every hit critical — a writeup's brand name included.
        value = r["value"]
        severity = "critical" if r["confidence"] == "high" else "medium"
        if r["kind"] == "domain":
            if not vet.vet_domain(value)[0]:
                continue
            worth = warninglist.judge_domain(store, value.lower(), value.lower(), r["source"])
            if worth == "none":
                continue
            if worth == "weak":
                severity = "low"
        elif r["kind"] == "ipv4" and not vet.vet_ipv4(value)[0]:
            continue
        out.append(_finding(
            "sysmon-linux", severity,
            f"a process contacted a known-bad indicator: {value}",
            f"{r['kind']} — {r['malware'] or 'flagged'} (via {r['source']})",
            "threat-intel"))
    return out
