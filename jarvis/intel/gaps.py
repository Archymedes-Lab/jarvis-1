"""Detection coverage against current intelligence: what is nothing here checking?

Technique IDs cannot be "found" on a host, so instead they are compared against
what jarvis's own collectors check, turning current intel into a gap list for
the tool itself. coverage.py asks whether jarvis is running; gaps() asks
whether it is looking at the right things.
"""

from jarvis.collectors.telemetry import auditd, sysmon_linux, techniques
from jarvis.core.finding import finding as _finding

# Which jarvis audit covers which ATT&CK technique. Parent technique ids cover
# their sub-techniques unless a sub-technique is listed on its own.
COVERAGE = {
    "T1014":     "hidden / evasion — rootkit detection",
    "T1542":     "preos — measured-boot replay against a pinned baseline",
    "T1055":     "hidden — process injection artefacts",
    "T1027":     "detect — obfuscated/encoded command lines",
    "T1036":     "detect — masquerading (name vs executable)",
    "T1053":     "control — scheduled tasks and cron",
    "T1543":     "control — service and systemd unit creation",
    "T1547":     "control / startup — boot and logon autostart",
    "T1546":     "asep — event-triggered execution; sysmon — WMI event filters, consumers and bindings",
    "T1559":     "sysmon — named pipes of known remote-execution and credential-dump tools",
    "T1574":     "asep — hijacked execution flow",
    "T1564":     "evasion — hidden files, streams and artefacts",
    "T1070":     "evasion — indicator removal and log tampering",
    "T1679":     "evasion / tamper — Defender exclusions added, with the writing process",
    "T1687":     "evasion / tamper — security product crashes and dying security services",
    "T1056":     "spy — input capture",
    "T1113":     "spy — screen capture",
    "T1123":     "spy — audio capture",
    "T1125":     "spy — video capture",
    "T1021":     "firewall — remote services and inbound access",
    "T1071":     "monitor — application layer C2 egress",
    "T1059":     "detect — command and scripting interpreter",
    "T1105":     "detect — ingress tool transfer (download-and-run)",
    "T1204":     "intrusion — user execution artefacts",
    "T1219":     "control — remote access software",
    "T1218":     "detect / asep — signed binary proxy execution",
    "T1620":     "hidden — in-memory / reflective loading",
    "T1082":     "scan — system information discovery",
    # Closed by the modules added alongside the intel engine.
    "T1556":     "implant / backdoor — PAM stack and auth configuration",
    "T1553":     "implant — root certificate trust store",
    "T1557":     "netwatch — gateway MAC and DNS changes",
    "T1090":     "firewall / implant — proxy, tunnelling, PAC and portproxy",
    "T1548":     "backdoor — sudo, setuid and elevation grants",
    "T1098":     "backdoor / posture — account and group inventory",
    "T1136":     "backdoor — new and hidden accounts",
    "T1078":     "backdoor / posture — account inventory",
    "T1133":     "backdoor / firewall — external remote services",
    "T1518":     "posture — installed defenses and their state",
    "T1600":     "implant — cryptographic trust weakening",
    "T1595":     "netwatch — wireless association history",
    # Added with the bruteforce collector and by wiring existing modules to the
    # techniques they already answer.
    "T1110":     "bruteforce — failed-auth spikes and account lockouts",
    "T1552":     "secrets — plaintext credentials on disk (files, history, config)",
    "T1539":     "intrusion — browser session and cookie theft artefacts",
    "T1555.003": "intrusion — non-browser processes naming browser credential "
                 "stores on a command line",
    "T1003.001": "sysmon — LSASS process-access events (Windows, needs Sysmon)",
    "T1040":     "sniffing — promiscuous NICs, raw sockets, capture drivers/tools",
    "T1197":     "intrusion — BITS transfer jobs outside the known updaters",
    "T1505.003": "webshell — dispatcher-shaped scripts in web document roots",
    "T1112":     "asep / control / posture — autostart and security-relevant "
                 "registry surface",
    # Added with the toolchain collector: the developer trust surface, where
    # execution comes from a config file rather than from a service or a key.
    "T1176":     "toolchain / intrusion — software extensions",
    "T1176.001": "intrusion — browser extension artefacts",
    "T1176.002": "toolchain — IDE/editor extension inventory, version drift and "
                 "post-install modification",
    "T1195.001": "toolchain — package registry and index redirection "
                 "(~/.npmrc, pip.conf)",
    "T1546.016": "toolchain — executable .pth lines that run on every Python "
                 "interpreter start",
    "T1059.006": "toolchain / sysmon_linux — Python execution, including "
                 "site-triggered startup code",
}

# Removed 2026-10-04 (COVERAGE-PLAN.md, phase 2): T1497 (sandbox evasion) and
# T1571 (non-standard port) were listed against `hidden` and `firewall`, but
# neither collector has a rule a probe could make fire. They read blind now.

# Techniques recognised from single process-creation events by the shared rule
# table. Listed here so the gap report stops calling them unchecked; whether
# each rule still fires is the coverage map's job (service/attackmap.py).
COVERAGE.update({
    "T1490": "sysmon — shadow-copy and recovery destruction commands",
    "T1006": "sysmon_linux — raw block-device opens",
    "T1003": "sysmon — LSASS memory access and credential-dump commands",
})
for _tid in sorted(techniques.technique_ids()):
    COVERAGE.setdefault(_tid, "sysmon / sysmon_linux — process-creation technique rules")

# Proven by a probe against an existing collector (service/attackmap.py). A
# test keeps this in step with the probes, so the gap report and the coverage
# map cannot disagree about what is looked for.
COVERAGE.update({
    "T1068": "evasion / sysmon — exploitable kernel drivers; system services starting a shell",
    "T1102": "evasion — dead-drop and tunnel hosts in the DNS cache",
    "T1185": "internet — browsers started with a remote-debugging port",
    "T1187": "sysmon — outbound file-share connections to public addresses",
    "T1195": "toolchain — package registry and index redirection",
    "T1200": "preos — option ROM code not in the measured-boot baseline",
    "T1568": "sysmon — bursts of lookups for names that do not exist",
    "T1689": "netwatch — Wi-Fi encryption weakened on a known network",
    "T1205": "sniffing — an unexpected process holding a raw packet socket",
    "T1091": "sysmon — a program started from a removable drive",
    "T1025": "sysmon — a copy command reading from a removable drive",
    "T1052": "sysmon — a copy command writing to a removable drive",
    "T1571": "sysmon — a script host connecting out to a public address on an unusual port",
    "T1674": "input — events Windows marks as injected by software rather than typed",
    "T1495": "preos — firmware code measured differently with no version change",
})

# Ids ATT&CK retired by splitting them. Writeups keep citing the old id for
# years; it is covered when a successor is, and is never mapped by itself.
SUPERSEDED = {"T1562": ("T1685", "T1686", "T1688", "T1689", "T1690")}

# Ids MITRE revoked and folded into one successor (the v7 restructuring and
# later). The catalogue feed drops revoked objects, but a catalogue loaded
# before that filter existed, and writeups citing the old id for years, both
# keep them alive; a gap is judged under the successor, never the dead id.
REVOKED = {
    "T1043": "T1571", "T1064": "T1059", "T1086": "T1059.001", "T1085": "T1218.011",
    "T1060": "T1547.001", "T1023": "T1547.009", "T1050": "T1543.003",
    "T1031": "T1543.003", "T1035": "T1569.002", "T1077": "T1021.002",
    "T1076": "T1021.001", "T1193": "T1566.001", "T1192": "T1566.002",
    "T1173": "T1559.002", "T1175": "T1021.003", "T1038": "T1574.001",
    "T1138": "T1546.009", "T1063": "T1518.001", "T1158": "T1564.001",
    "T1093": "T1055.011", "T1116": "T1553.002", "T1067": "T1542.001",
    "T1088": "T1548.002", "T1045": "T1027.002", "T1073": "T1574.001",
    "T1081": "T1552.001", "T1214": "T1552.002", "T1004": "T1547.004",
    "T1015": "T1546.008", "T1084": "T1546.003",
}

# Platforms this host has (Docker runs inside WSL). A technique MITRE scopes only to cloud, SaaS,
# network devices, ESXi or mobile cannot be a gap in a laptop's monitoring.
HOST_PLATFORMS = {"Windows", "Linux", "Containers"}


def _successors(parent):
    mapped = [t for t in SUPERSEDED.get(parent, ()) if t in COVERAGE]
    return f"superseded by {', '.join(mapped)}, which are mapped" if mapped else None

# Techniques worth naming explicitly as uncovered when intel raises them, with
# the reason they are hard rather than merely missing.
KNOWN_BLIND = {
    "T1555": "credential stores beyond browsers — Windows Credential Manager "
             "and OS keyrings are not read",
    # Narrowed by the toolchain collector, not closed: registry redirection,
    # editor-extension drift and repo-supplied agent/MCP/git hooks are checked,
    # but the contents of an installed package are still taken on trust.
    "T1195": "supply chain compromise — package *sources* and developer-tool "
             "configuration are audited by `toolchain`, but installed package "
             "contents are not verified against their publisher",
    "T1554": "compromised host binary — no integrity baseline for system files",
    "T1505": "server software component — no web/server module auditing",
    "T1567": "exfiltration to web service — egress is seen but not classified",
    "T1611": "containers / sysmon_linux — privileged, host-namespace, host-mount and Docker-socket containers; nsenter and privileged `docker run` command lines",
    "T1610": "containers / sysmon_linux — container creation events and privileged or unconfined `docker run` command lines",
    "T1609": "containers / sysmon_linux — `docker exec` activity from daemon events and command lines, escape-shaped commands reported high",
    "T1003": "credential dumping beyond LSASS memory (SAM, LSA secrets, NTDS, "
             "DCSync) — sysmon covers LSASS access; the rest needs "
             "registry/file/replication auditing",
}


# Tactics whose techniques are defined by runtime behaviour rather than by
# anything left on disk. A monitor that samples state on an interval cannot
# see them at all — that is the sampling blind spot coverage.py already
# reports, not a missing collector. Listing them as work to do would bury the
# gaps that could actually be closed.
BEHAVIOURAL_TACTICS = {
    "discovery", "collection", "execution", "impact", "exfiltration",
    "lateral-movement", "privilege-escalation", "reconnaissance",
    "resource-development", "initial-access",
}

_INTERCEPT = None


def _intercept_active():
    """(active, name) — is a syscall-interception layer recording on this box?

    auditd or Sysmon for Linux (eBPF). When one is, the behavioural bucket is
    covered rather than merely unobservable. Probed once per process.
    """
    global _INTERCEPT
    if _INTERCEPT is None:
        _INTERCEPT = (False, "")
        for mod, label in ((auditd, "auditd"), (sysmon_linux, "Sysmon for Linux")):
            try:
                if mod.active():
                    _INTERCEPT = (True, label)
                    break
            except Exception:
                continue
    return _INTERCEPT


def gaps(store, min_docs=1):
    """Techniques current intel is talking about, against what jarvis checks.

    Three outcomes, and the distinction is the whole point of the report:

      * covered      — a collector already looks for this
      * closeable    — leaves host artefacts, nothing looks for them yet
      * behavioural  — needs syscall interception; no collector here can help

    Only the middle group is a work queue.
    """
    rows = store.db.execute(
        "SELECT norm, doc_count, context, source_url FROM indicators "
        "WHERE kind='attack' AND status='active' AND doc_count>=? "
        "ORDER BY doc_count DESC", (min_docs,)).fetchall()

    cat, platforms = {}, {}
    for r in store.db.execute("SELECT tid,name,tactics,platforms FROM attack_techniques"):
        cat[r["tid"]] = (r["name"], r["tactics"])
        platforms[r["tid"]] = {p.strip() for p in (r["platforms"] or "").split(",") if p.strip()}

    covered, closeable, behavioural, inapplicable = [], [], [], []
    for r in rows:
        cited, n = r["norm"], r["doc_count"]
        successor = REVOKED.get(cited) or REVOKED.get(cited.split(".")[0])
        tid = successor or cited
        retired = f"retired id {cited}, now {tid}: " if successor else ""
        parent = tid.split(".")[0]
        where = COVERAGE.get(tid) or COVERAGE.get(parent) or _successors(parent)
        if where:
            covered.append((cited, n, retired + where))
            continue
        name, tactics = cat.get(tid) or cat.get(parent) or ("", "")
        why = retired + (KNOWN_BLIND.get(tid) or KNOWN_BLIND.get(parent)
                         or "no collector checks this")
        if not name:
            behavioural.append((cited, n, "deprecated or unrecognised "
                                          "technique id", ""))
            continue
        scoped = platforms.get(tid) or platforms.get(parent) or set()
        if scoped and not scoped & HOST_PLATFORMS:
            inapplicable.append((cited, n, ", ".join(sorted(scoped)), name))
            continue
        tset = {t for t in (tactics or "").split(",") if t}
        if tset and tset <= BEHAVIOURAL_TACTICS:
            intercept_on, intercept_name = _intercept_active()
            if intercept_on:
                covered.append((tid, n,
                                f"{intercept_name} — syscall interception active"))
            else:
                behavioural.append((tid, n, "runtime behaviour — needs syscall "
                                            "interception (auditd/Sysmon)", name))
        else:
            closeable.append((tid, n, why, name))

    out = []
    for tid, n, why, name in closeable:
        # Weight by how many separate writeups raised it: a technique three
        # independent teams wrote about this year is a better use of an
        # afternoon than one mentioned once.
        sev = "high" if n >= 5 else "medium" if n >= 2 else "low"
        out.append(_finding(
            "coverage gap", sev, f"{tid} {name}".strip(),
            f"{why} — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "this is a detection coverage gap, not observed activity on this host"))
    for tid, n, why, name in behavioural:
        out.append(_finding(
            "not observable", "low", f"{tid} {name}".strip(),
            f"{why} — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "this is a visibility limitation, not observed activity on this host"))
    for tid, n, scoped, name in inapplicable:
        out.append(_finding(
            "not applicable", "low", f"{tid} {name}".strip(),
            f"MITRE scopes this technique to {scoped}, which this host does not "
            f"run — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "not a gap in this machine's monitoring"))
    return out, covered, closeable
