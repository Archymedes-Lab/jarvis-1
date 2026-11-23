"""The mechanism registry: one declaration per collector, one per primitive.

Every scheduled collector used to have its contract spread over eight tables in
six modules (schedule, scheduler lanes, reliability tiers and timeouts,
governor deferral, score areas, dependency roots, ...). They drifted: on
2026-10-23 the `storage` collector was scheduled but sat in neither the scored
nor the deliberately-unscored list. Here each collector is declared once, as a
frozen record, and the old tables are views derived from it
(schedule.ALL_JOBS, scheduler.FAST/BULK/ISOLATED, governor.GOVERNED_JOBS,
score.AREAS/UNSCORED, reliability tiers, timeouts and DEPENDENCIES).
tests/test_mechanisms.py proves each view equals the table it replaced, value
for value and order for order, so moving the facts here changed no behaviour.

PRIMITIVES is the other half: the catalogue of mechanism kinds JARVIS is built
from (collector, lane, lease, receipt, cursor, journal, stream, gate, ...),
each with its contract, its invariants, the modules that implement it and the
tests that hold it. docs/architecture/MECHANISMS.md is the readable form;
`python -m jarvis.verify` and the Argus build gate run conformance() so a
mechanism that breaks its contract cannot ship.

Pure data and pure checks: no imports from JARVIS, so every layer may read it.
"""

from dataclasses import dataclass, field
from pathlib import Path

LANES = ("fast", "frequent", "main", "bulk")
DOMAINS = ("both", "windows", "linux")
CRITICALITY = ("critical", "high", "medium", "low")
# Protection areas in display order. Order is behaviour: score.compute walks
# them in this order and the dashboard lists them so.
AREAS = ("Active threats", "OS hardening", "Persistence & access", "Data & privacy",
         "Network", "Developer toolchain", "Monitoring")
# When a root dies every collector naming it fails for the same reason, and the
# root is reported once instead of paging for each dependent.
DEPENDENCY_ROOTS = ("windows-bridge", "native-sensor", "scheduler")
# Duty-cycle ceiling per serial lane: the share of wall time its jobs may take
# at steady state, leaving the rest to catch up after a restart or a standby.
LANE_DUTY_LIMIT = 0.8
# The frequent lane (2026-11-03): every evidence collector on a cadence of
# FREQUENT_MAX_INTERVAL or less gets a serial worker of its own, so the post-boot
# sweep of multi-minute audits on the main lane cannot age it past STALE (2x its
# cadence). Measured that morning: one main pass took 1331 s after a boot and 20
# collectors went stale for 16 min with no error. Its jobs may launch PowerShell;
# platform/interop_gate.py bounds concurrent launches daemon-wide, so a lane
# count never raises interop concurrency. Each run is bounded by
# FREQUENT_TIMEOUT_MAX so one slow job cannot hold the lane for long.
FREQUENT_MAX_INTERVAL = 300
FREQUENT_TIMEOUT_MAX = 60.0


@dataclass(frozen=True)
class Collector:
    """The whole contract of one scheduled collector.

    area/area_rank: the score area and the position inside it. Position is
    behaviour, not cosmetics: within an area an earlier collector wins a
    finding both report (hidden before deep_hidden). area None means
    deliberately unscored, and `unscored` must say why.
    tier/criticality/timeout: the reliability plane's budgets (tier 0 is the
    continuous native streams, 4 the daily hunts).
    governed: the resource governor may defer it under pressure. Never true
    for tier 0 or the fast lane: protection and ingestion always run.
    isolated: runs in a deadline-bounded child process.
    evidence: False only for jobs that describe JARVIS's own reporting
    (coverage, report); they sit outside the freshness invariant.
    cost_s: measured wall seconds per run on this machine, when known; the
    lane duty-cycle check sums cost_s / interval.
    command: the CLI command that audits the same ground by hand, named in
    reports so a finding is directly actionable (`jarvis <command>`).
    health/health_limit_s: "required" means the service is not healthy while
    this collector's evidence is older than the limit; "optional" reports its
    freshness in /api/health without making it a dependency.
    elevated: the broker script that runs this collector's elevated half, if any.
    admin_sensor: "unavailable" when this collector produces nothing without the
    administrator sensor (the native sensor, the elevated broker), "limited" when
    it still checks what an unprivileged account can see. Without the sensor the
    daemon reports such a job as blind with NEEDS_ADMIN_SENSOR, never as
    complete coverage (platform/admin_sensor.py). Derived from the collector code:
    each of these calls broker.result or reads the sensor's spool.
    servers: False for workstation features (a news globe, a local model) that a
    plain Linux server neither has nor wants; there they are not applicable.
    requires: names from REQUIREMENTS that the host must satisfy for this
    collector to have anything to observe (platform/facts.py measures them).
    A requirement names the thing observed (a package database, a boot chain
    of its own, a container engine), never the sensor: an absent audit sensor
    is a visibility gap the collector must still report, not a reason to skip
    it. Unmet means "not applicable on this host" with the reason, never
    failing and never healthy (docs/architecture/AGNOSTIC-DEPLOYMENT.md).
    boot_scoped: its evidence describes state a reboot activates or resets
    (startup entries, services, drivers, boot chain, live processes, firewall),
    so a result taken before the current boot does not describe this machine
    now. The scheduler counts such a result as at least one cadence late, and
    boot readiness waits for a post-boot result (scheduler.boot_readiness).
    """
    name: str
    interval: int
    label: str
    area: str | None
    area_rank: int
    tier: int
    criticality: str
    timeout: float
    lane: str = "main"
    domain: str = "both"
    governed: bool = False
    isolated: bool = False
    evidence: bool = True
    depends_on: tuple = ()
    unscored: str = ""
    cost_s: float | None = None
    command: str = ""
    health: str = ""
    health_limit_s: int = 0
    elevated: str = ""
    admin_sensor: str = ""
    servers: bool = True
    boot_scoped: bool = False
    requires: tuple = ()


# Host requirements a collector may declare (Collector.requires). Each is
# (what it means, predicate over platform/facts.py facts). A predicate returns
# False when the fact is unknown: unknown is unmet, so the collector is listed
# not applicable with the reason, never run blind and never counted healthy.
REQUIREMENTS = {
    "package-db": ("a dpkg or rpm package database to verify against",
                   lambda f: bool({"dpkg", "rpm"} & set(f.get("package_dbs") or ()))),
    "systemd": ("systemd as the init system",
                lambda f: f.get("init") == "systemd"),
    "own-kernel": ("a boot chain and kernel of its own (not a container)",
                   lambda f: f.get("os") == "linux" and f.get("container") is None and f.get("kernel") is not None),
    "container-engine": ("a container engine (Docker or Podman) installed",
                         lambda f: bool(f.get("container_engines"))),
    "oval-source": ("a distribution with published OVAL security data (Ubuntu or Debian)",
                    lambda f: f.get("distro") in ("ubuntu", "debian")),
}


def unmet(collector, facts):
    """Reasons `collector` has nothing to observe on a host with `facts` ([] = applicable)."""
    out = []
    for name in collector.requires:
        meaning, test = REQUIREMENTS[name]
        try:
            ok = bool(test(facts))
        except (TypeError, AttributeError):
            ok = False
        if not ok:
            out.append(f"needs {meaning}")
    return out


def _c(name, interval, label, area, rank, tier, crit, timeout, **kw):
    return Collector(name, interval, label, area, rank, tier, crit, float(timeout), **kw)


AT, OS, PA, DP, NW, DT, MO = AREAS
_KNOWLEDGE = "knowledge-base upkeep or analysis of JARVIS's own coverage, not this machine's state"

# Declaration order is behaviour: it is schedule.ALL_JOBS order, and on a cold
# start the scheduler breaks ties in this order, so the fast watchdogs come
# before the long Windows audits.
COLLECTORS = (
    _c("scan", 60, "Processes & network", AT, 11, 1, "high", 30,
       command="scan", health="required", health_limit_s=180,
       lane="fast", depends_on=("scheduler",), cost_s=2.2),
    # A standalone fast copy of coverage's Windows-bridge check: available()
    # only stats a socket, so it pages within a minute of interop dying. Its
    # finding is an outage and mails whatever alert_min_severity says.
    _c("bridge", 45, "Windows bridge reachability", MO, 1, 1, "high", 30,
       command="coverage", health="required", health_limit_s=135,
       lane="fast", domain="windows", depends_on=("scheduler",)),
    _c("input_hook", 45, "Input monitor watchdog", AT, 10, 1, "high", 30,
       admin_sensor="limited",
       command="inputwatch",
       lane="fast", domain="windows", depends_on=("windows-bridge",)),
    # Drains the native Windows sensor's spool into the event log: local file
    # reads only, no PowerShell, and ahead of sysmon, which reads its output.
    _c("native", 60, "Native sensor ingestion", MO, 3, 0, "critical", 45,
       admin_sensor="unavailable",
       command="timeline status", health="required", health_limit_s=180,
       lane="fast", domain="windows", isolated=True, depends_on=("native-sensor",), cost_s=1.5),
    # The other half of mutual supervision: jarvis-selfcheck.timer restarts
    # this daemon, this re-arms that timer when it stops.
    _c("watchdogs", 120, "Watchdog mutual supervision", MO, 2, 2, "high", 60,
       command="selfcheck",
       lane="fast", cost_s=0.2),
    _c("resources", 300, "Resource pressure", None, 0, 2, "medium", 60,
       command="status", health="optional", health_limit_s=900,
       unscored="performance and resource pressure, not evidence of compromise", lane="frequent", cost_s=16.5),
    _c("internet", 120, "Internet apps & incoming traffic", NW, 0, 2, "medium", 60,
       admin_sensor="limited",
       command="netwatch", health="optional", health_limit_s=300, elevated="internetwatch.ps1",
       domain="windows", lane="frequent", cost_s=5.4),
    _c("controls", 300, "Brightness & control devices", None, 0, 2, "medium", 60,
       command="control",
       domain="windows", unscored="device state, not evidence of compromise", lane="frequent", cost_s=6.6),
    _c("audio", 300, "Audio endpoints & routes", None, 0, 2, "medium", 60,
       command="audio",
       domain="windows", unscored="device state, not evidence of compromise", lane="frequent", cost_s=10.2),
    # One registry read plus a PnP listing, about 2 s: consent store posture,
    # AppPrivacy policy and capture devices, checked against the owner's seal.
    _c("privacy", 300, "Microphone & camera privacy seal", DP, 5, 2, "medium", 60,
       command="privacy audit",
       domain="windows", cost_s=3.2, lane="frequent"),
    # Both sides of the WSL boundary: config and mounts from Linux, the
    # registration from the Windows registry (about 1 s), drift against the
    # owner-accepted checkpoint and the previous sample.
    _c("wsl", 300, "WSL trust boundary", OS, 4, 2, "medium", 60, cost_s=5.5,
       # Its Windows half (distros, .wslconfig, policy) exists wherever Windows
       # does; on a plain Linux server there is no WSL boundary (2026-10-24).
       command="timeline wsl-boundary", domain="windows", lane="frequent"),
    # Headroom on the only disk: system drive free, WSL image overhang,
    # page-file policy, ballast; one PowerShell read plus bounded cache walks.
    _c("storage", 1800, "Disk headroom & WSL image", None, 0, 3, "medium", 180,
       command="status",
       unscored="disk headroom is availability, like resources; not evidence of compromise"),
    # Replays the TPM measured-boot logs and one bounded event-log query, about
    # 3 s. Boots are rare; a baseline drift persists.
    _c("preos", 1800, "Pre-OS boot integrity", None, 0, 3, "medium", 180,
       command="preos",
       domain="windows", cost_s=3.0,
       unscored="measured-boot drift is reported, not yet scored (owner decision pending)", boot_scoped=True),
    # Reads the elevated broker's copy of the HP Sure Start audit log (the
    # broker refreshes it every 15 min); local file reads only.
    _c("fwaudit", 1800, "HP firmware audit log", None, 0, 3, "medium", 60,
       admin_sensor="unavailable",
       command="status", elevated="hp_firmware_audit.ps1",
       domain="windows", cost_s=0.1,
       unscored="firmware audit records are reported, not yet scored (unsoaked; owner decision pending)"),
    _c("deep_hidden", 86400, "Deep process cross-view scan", AT, 5, 4, "low", 300,
       command="hidden --deep", boot_scoped=True),
    _c("hidden", 300, "Hidden processes", AT, 4, 2, "high", 60, cost_s=24.0,
       command="hidden", boot_scoped=True, lane="frequent"),
    # osquery, when the operator installed it, as a second reader of processes,
    # listeners and kernel modules; disagreement with Argus's own view is tamper
    # evidence. Never installs osquery.
    _c("osquery", 3600, "Independent view (osquery)", None, 0, 3, "medium", 120,
       command="hidden", domain="linux",
       unscored="optional second view; source-tested against recorded answers, never run on a host with osquery"),
    _c("firewall", 2400, "Firewall & inbound", OS, 1, 3, "high", 240,
       command="firewall",
       depends_on=("windows-bridge",), cost_s=18.0, boot_scoped=True),
    _c("control", 1800, "Control surfaces", PA, 0, 3, "high", 180,
       admin_sensor="limited",
       command="control",
       depends_on=("windows-bridge",), cost_s=16.0, boot_scoped=True),
    # One registry/environment read, about 1 s: CLR profiler, startup-hook,
    # AppDomainManager and runtime-ETW settings, and the AMSI providers.
    _c("dotnet", 1800, ".NET runtime hijack points", PA, 6, 3, "medium", 180,
       command="dotnet",
       domain="windows", cost_s=1.0, boot_scoped=True),
    _c("asep", 3600, "Autostart points", PA, 1, 3, "high", 300,
       command="asep",
       domain="windows", depends_on=("windows-bridge",), boot_scoped=True),
    _c("spy", 5400, "Spyware & capabilities", DP, 1, 3, "medium", 300,
       command="spy",
       governed=True, depends_on=("windows-bridge",), cost_s=22.0, boot_scoped=True),
    _c("pixel", 3600, "Screen capture & tracking pixels", DP, 2, 3, "medium", 300,
       command="pixel",
       governed=True),
    _c("identity", 900, "Who is acting on this machine", PA, 4, 3, "medium", 90,
       command="impersonation"),
    _c("intrusion", 5400, "Intrusion artifacts", AT, 7, 3, "high", 300,
       command="intrusion",
       domain="windows", governed=True, depends_on=("windows-bridge",), cost_s=106.0),
    _c("evasion", 1200, "Evasion & kernel integrity", AT, 6, 3, "high", 120,
       command="evasion",
       domain="windows", depends_on=("windows-bridge",), boot_scoped=True),
    _c("coverage", 600, "Self-audit & blind spots", MO, 0, 3, "high", 60,
       command="coverage",
       evidence=False, cost_s=0.5),
    _c("boot", 21600, "Startup analysis", PA, 2, 4, "medium", 300, domain="windows",
       command="boot", boot_scoped=True),
    # Local and cheap: compare what intel knows against what is on the box.
    _c("hunt", 1800, "Threat-intel indicator hunt", AT, 0, 3, "medium", 180,
       command="hunt",
       governed=True, cost_s=0.5),
    _c("gaps", 21600, "Detection coverage vs current intel", None, 0, 4, "low", 300,
       command="gaps",
       governed=True, cost_s=0.5, unscored=_KNOWLEDGE),
    # Networked and metered. One topic per run, so the corpus rotates itself;
    # the daily budget guard in intel.py is what bounds spend.
    _c("intel", 18000, "Threat-intelligence refresh", None, 0, 4, "low", 300,
       command="intel",
       governed=True, unscored=_KNOWLEDGE),
    # Runs after the equally frequent intel refresh in declaration-order ties,
    # so a report can describe the newest research rather than the prior wave.
    _c("report", 300, "Daily advisory & change digests", None, 0, 2, "medium", 60,
       command="alert",
       evidence=False, unscored="the email cadence, a record of findings counted elsewhere"),
    # Free, unauthenticated and high volume; each feed has its own cadence and
    # this job asks which are due. Network, no PowerShell: bulk lane.
    _c("feeds", 3600, "Bulk indicator feeds", None, 0, 3, "medium", 300,
       command="feeds",
       lane="bulk", governed=True, cost_s=90.0, unscored=_KNOWLEDGE),
    _c("implant", 3600, "Interception & boundary bypass", OS, 2, 3, "high", 300,
       command="implant",
       depends_on=("windows-bridge",), cost_s=15.0, boot_scoped=True),
    # Short interval on purpose: the value is a continuous record, and a drop
    # between two samples cannot be investigated.
    # Windows-only by nature: Wi-Fi state and the Windows network logs, read
    # through PowerShell. On a server it has nothing to observe (2026-10-24).
    _c("netwatch", 300, "Network & wireless state", NW, 1, 1, "high", 45,
       command="netwatch", domain="windows",
       depends_on=("scheduler",), cost_s=11.5, lane="frequent"),
    _c("posture", 7200, "Windows security posture", OS, 0, 3, "high", 300,
       admin_sensor="limited",
       command="posture", elevated="posture.ps1",
       domain="windows", governed=True, depends_on=("windows-bridge",), cost_s=14.0, boot_scoped=True),
    _c("backdoor", 3600, "Backdoors & access grants", PA, 3, 3, "high", 300,
       command="backdoor",
       depends_on=("windows-bridge",), boot_scoped=True),
    # The developer trust surface: MCP servers, agent hooks, editor extensions,
    # git hooks, .pth files. Local only, but it walks $HOME.
    _c("toolchain", 3600, "Developer toolchain trust", DT, 0, 3, "medium", 300,
       command="toolchain",
       governed=True, cost_s=17.0),
    # Reads only the alert ledger and snapshot timestamps.
    _c("ledger", 1800, "Unresolved & recurring alerts", None, 0, 3, "medium", 180,
       command="outstanding",
       unscored="a record of past alerts, already counted where they came from"),
    # The helper does the watching; this drains its output and runs the
    # injected-event audit. input_hook keeps the helper alive.
    _c("input", 300, "Synthetic input", AT, 9, 2, "high", 60,
       admin_sensor="limited",
       command="inputwatch",
       domain="windows", depends_on=("windows-bridge",), lane="frequent", cost_s=0.7),
    # Walks every readable process's address space; expensive, so rare.
    _c("memscan", 7200, "Memory & instruction level", AT, 3, 3, "medium", 300,
       admin_sensor="limited",
       command="memscan", elevated="memscan.ps1",
       domain="windows", governed=True, cost_s=90.0, boot_scoped=True),
    # Walks the home directory; secrets do not appear by the minute.
    _c("secrets", 43200, "Plaintext credentials", DP, 0, 4, "low", 300,
       command="secrets", health="optional", health_limit_s=90000,
       governed=True, cost_s=60.0),
    # Counts failed-auth records in the OS logs: one PowerShell call and a read.
    _c("bruteforce", 3600, "Brute force & auth failures", PA, 5, 3, "medium", 300,
       command="bruteforce",
       depends_on=("windows-bridge",)),
    _c("sniffing", 1800, "Packet capture", DP, 3, 3, "medium", 180,
       command="sniffing"),
    _c("webshell", 21600, "Web shells", AT, 8, 4, "low", 300, governed=True,
       command="webshell"),
    # File bytes in the places dropped files land (temp folders, downloads, web
    # roots, startup folders) against compiled community content rules. Reads
    # only; bounded per pass; unchanged files are not read again.
    _c("content", 3600, "File content rules", None, 0, 3, "low", 120,
       command="content", domain="linux", lane="bulk", governed=True, isolated=True,
       unscored="content-rule findings are reported, not yet scored (unsoaked)"),
    # Is the Linux syscall-interception layer present and recording?
    _c("auditd", 7200, "Syscall interception posture", OS, 3, 3, "medium", 300,
       command="auditd",
       domain="linux", boot_scoped=True),
    # eBPF syscall interception on Linux, read incrementally like sysmon.
    # Tier 0 by contract but on the main lane: recorded as found 2026-10-23.
    _c("sysmon_linux", 600, "Sysmon for Linux (eBPF)", AT, 2, 0, "critical", 45,
       command="sysmon-linux",
       domain="linux"),
    # Positive control for it: one harmless labelled process start per run, looked
    # for in the trusted journal. Proves the sensor sees, not just that a job ran.
    _c("sensorprobe", 900, "Process sensor positive control", None, 0, 3, "high", 60,
       command="sysmon-linux", domain="linux", cost_s=0.3,
       unscored="a self-test of the process sensor; scored after it has soaked on real hosts"),
    # The interception layer: frequent, because its value is catching things
    # that start and exit between sampling passes. Incremental, 1.5 s.
    _c("sysmon", 600, "Sysmon telemetry", AT, 1, 0, "critical", 45,
       admin_sensor="unavailable",
       command="sysmon", health="required", health_limit_s=1500,
       domain="windows", depends_on=("windows-bridge", "native-sensor"), cost_s=1.5),
    # What PowerShell actually ran (event 4104), for commands that start no
    # process. Reads only what Windows already logs; never turns logging on.
    # The log is a small ring, so the cadence is short.
    _c("psscript", 120, "PowerShell script blocks", None, 0, 2, "medium", 60,
       command="sysmon", domain="windows", depends_on=("windows-bridge",), cost_s=3.0,
       lane="frequent",
       unscored="script-block findings are reported, not yet scored (unsoaked; reads only "
                "when Windows script-block logging is already on)"),
    # What Windows Security blocked (attack surface reduction, controlled folder
    # access), explained; says so when the blocked program is part of Argus.
    # Reads the Defender log only; never unblocks or excludes anything.
    _c("winblocks", 600, "Windows Security blocks", None, 0, 3, "medium", 60,
       command="status", domain="windows", depends_on=("windows-bridge",), cost_s=3.0,
       unscored="blocked-action findings are reported, not yet scored (unsoaked)"),
    # Linux system integrity: PAM, sessions, sudo, loader, udev, APT, motd and
    # module config by per-install baseline, plus invariants (PAM programs,
    # global LD_PRELOAD, dangerous file capabilities, logs cut in place).
    _c("linuxguard", 900, "Linux system integrity", None, 0, 3, "high", 60,
       command="backdoor", domain="linux", cost_s=1.5,
       unscored="system-integrity findings are reported, not yet scored (unsoaked)"),
    # ATT&CK coverage, validated by probing the real detectors.
    _c("attackmap", 21600, "ATT&CK coverage map", None, 0, 4, "low", 300,
       command="attack",
       governed=True, unscored=_KNOWLEDGE),
    # The synthetic validation suite against the real detectors. Local only.
    _c("arena", 3600, "Adversarial self-validation", MO, 4, 3, "medium", 300, governed=True,
       command="arena suite"),
    # One registry read when location is off, one locator call with consent.
    _c("geo", 900, "Device location & geofencing", DP, 4, 3, "medium", 90,
       command="geo status",
       domain="windows", governed=True),
    # Context for /world: unscored, deferrable, and the same requests whoever
    # and wherever the owner is.
    _c("world", 900, "World conflict reports", None, 0, 3, "medium", 90,
       command="geo world",
       lane="bulk", governed=True, servers=False,
       unscored="news about conflicts elsewhere says nothing about this machine"),
    # `docker inspect` per container, read-only.
    _c("containers", 900, "Container privilege and exposure inventory", None, 0, 3, "medium", 90,
       command="containers", requires=("container-engine",),
       domain="linux", unscored="inventory pending its own scoring decision", boot_scoped=True),
    # Linux servers (ARGUS-SERVER.md, 2026-10-24). Unscored until soaked on a
    # real internet-facing server: their thresholds are unmeasured there.
    # Reads the packet sensor's spool (a separate CAP_NET_RAW unit); cheap.
    _c("netflow", 60, "Incoming packets (header-only)", None, 0, 2, "medium", 30,
       command="netflow", domain="linux", cost_s=0.2,
       unscored="source-tested only; detection thresholds not yet tuned on real internet traffic", lane="frequent"),
    # sshd "Accepted" records behind a journal cursor.
    _c("logins", 300, "SSH logins", None, 0, 2, "medium", 60,
       command="logins", domain="linux", cost_s=0.5,
       unscored="source-tested only; new-network and new-key learning not yet soaked", lane="frequent"),
    # Effective sshd policy, every account's authorised keys and host keys
    # (learned, then drift), and the tunnels sshd and ssh clients hold open now.
    _c("sshwatch", 300, "SSH server, keys and tunnels", None, 0, 2, "medium", 60,
       command="sshwatch", domain="linux", cost_s=0.1,
       unscored="source-tested only; never run against a real internet-facing sshd", lane="frequent"),
    # The daily checks operators most want automated (Exa research 2026-10-28):
    # failed units, TLS certificate expiry, kernel OOM kills, unclean reboots.
    # What WSL (or any systemd host) runs against the owner-approved manifest:
    # owners from cgroups, drift per owner (owner request 2026-10-31).
    _c("wslmanifest", 300, "WSL process manifest", None, 0, 2, "medium", 60,
       command="wslmanifest", domain="linux", cost_s=0.3,
       unscored="new; reports drift only after the owner approves a manifest, not yet soaked", lane="frequent"),
    # Restart autopsy (2026-11-04): every stop of this daemon is attributed to
    # an actor and its reason cross-examined (systemd, Sysmon lineage, the
    # restarters' own logs); an unidentified stop is a high tamper finding.
    _c("restarts", 300, "Daemon stop attribution", None, 0, 1, "high", 60,
       command="restarts", domain="linux", cost_s=4.0,
       unscored="new; restarter signatures source-tested and replayed on 23 real stops, not yet soaked", lane="frequent"),
    _c("opshealth", 900, "Server operations health", None, 0, 3, "medium", 90,
       command="opshealth", domain="linux", cost_s=0.6, requires=("systemd",),
       unscored="operational health, not machine safety; thresholds not yet soaked on real servers"),
    # Boot-chain persistence (GRUB, grub.d, initramfs hooks, dracut modules,
    # kernel and initramfs images) and kernel attack surface (Exa threat
    # research 2026-10-29). Stat signatures for images keep a run cheap.
    _c("bootchain", 1800, "Boot chain & kernel attack surface", None, 0, 3, "medium", 90,
       command="bootchain", domain="linux", cost_s=0.1, boot_scoped=True, requires=("own-kernel",),
       unscored="source-tested only; package-update attribution not yet soaked on real servers"),
    # Processes reading the keyboard, raw HID or uinput, judged by their image;
    # hidden staging in /var/log, /run, /dev/shm and /tmp (spyware research 2026-10-29).
    _c("keyreaders", 900, "Keyboard readers & hidden staging", None, 0, 3, "medium", 60,
       command="keyreaders", domain="linux", cost_s=0.1, boot_scoped=True, requires=("own-kernel",),
       unscored="source-tested only; expected-reader list not yet soaked on desktops and servers"),
    # Friday Defender reviews of the codebases appcode found, with the owner's
    # consent (`jarvis defender enable`). Each pass collects finished reviews and
    # starts at most one detached review; deferrable, so only when idle.
    _c("friday_defender", 3600, "Friday Defender code reviews", None, 0, 3, "medium", 60,
       command="defender status", lane="bulk", governed=True, cost_s=0.3,
       unscored="advisory model findings, capped at medium; not a measured state of this machine"),
    # dpkg --verify / rpm -V over the packages intruders replace; IO-heavy, so
    # daily, deferrable and in the bulk lane.
    _c("pkgverify", 86400, "Package file integrity", None, 0, 4, "medium", 300,
       command="pkgverify", domain="linux", lane="bulk", governed=True, requires=("package-db",),
       unscored="source-tested only; a rewritten package database defeats it"),
    # ARGUS-SERVER.md W10: one bounded GET to the owner's dead-man service, so a
    # silent host or daemon pages someone. Fast lane: the ping proves it runs.
    _c("heartbeat", 60, "Off-box heartbeat", None, 0, 1, "medium", 30,
       command="alert", lane="fast", cost_s=0.3,
       unscored="delivery of liveness to an outside service, not a state of this machine"),
    # ARGUS-SERVER.md W11: fixable CVEs, pending updates, pending reboots.
    _c("patches", 3600, "Security fixes not installed", None, 0, 3, "medium", 180,
       command="status", domain="linux", governed=True, cost_s=8.0, requires=("package-db",),
       unscored="source-tested; scored after it has run on a real server"),
    # Outdated software on every package manager (apt, snap, Homebrew, winget,
    # Chocolatey), important first; with auto_update opted in, hands user-scope
    # items to the bounded updater (response/updater.py). Listing measured
    # 2026-11-02 at ~75 s (winget 2 x 24 s, Chocolatey 25 s, Homebrew 19 s).
    # Main lane: the winget and Chocolatey listings run through PowerShell, and
    # the bulk lane never crosses into Windows (tests/test_bulk_lane.py).
    _c("updates", 21600, "Outdated software", None, 0, 4, "medium", 300,
       command="update plan", governed=True, cost_s=75.0,
       unscored="source-tested; scored after its listings are measured across machines"),
    # Daily download of the release's own OVAL security data. Debian 12 parses at
    # ~85 MB above baseline and returns to +6 MB once freed (measured 2026-10-25).
    # Isolated (2026-10-29): parsing a large dump inside the daemon stalled it
    # entirely on a busy host; a child process gets a deadline it can be killed at.
    _c("distrovuln", 86400, "Distribution security data", None, 0, 4, "medium", 300,
       command="status", domain="linux", lane="bulk", governed=True, isolated=True,
       cost_s=25.0, unscored=_KNOWLEDGE, requires=("oval-source",)),
    # ARGUS-SERVER.md W12: every codebase on the server, its dependencies
    # against OSV, risky code, credentials, writable code and web-root leaks.
    # One bounded audit (200 000 files; 180 s for walk, rules and tools, so a
    # slow 1-vCPU host still ends inside the 300 s timeout), daily, deferrable.
    _c("appcode", 86400, "Application code vulnerabilities", None, 0, 4, "medium", 300,
       command="appcode", domain="linux", lane="bulk", governed=True,
       unscored="source-tested; heuristic code rules not yet soaked on real server codebases"),
    # Daily download of the public OSV dumps for the ecosystems appcode found,
    # streamed to disk and filtered to the inventory (npm 219 MB, 2026-10-28).
    # Isolated (2026-10-29): the npm dump is 219 MB and ~220 000 files; parsed
    # in-process it ran 1031 s on a busy WSL host and froze the whole Argus
    # daemon, dashboard included, with its 300 s timeout unenforceable.
    _c("osv", 86400, "Dependency advisories (OSV)", None, 0, 4, "medium", 300,
       command="appcode", domain="linux", lane="bulk", governed=True, isolated=True,
       unscored=_KNOWLEDGE),
    # One loopback GET (or one bridge round trip), never a generation. Its
    # command, `ask model status`, runs the same ping through the assistant.
    _c("model", 1800, "Local model availability", None, 0, 3, "medium", 180,
       command="ask model status",
       governed=True, servers=False,
       unscored="availability of the local model, not machine safety"),
    # Copies the event history into the independent Rust store and re-verifies
    # it, O(store), about 20 s at its 128 MiB budget.
    _c("rust_mirror", 1200, "Independent evidence mirror", MO, 5, 3, "medium", 120,
       command="status",
       lane="bulk", governed=True, cost_s=20.0),
    # Whole-chain verification of the event history: O(history), 75 s at
    # 1.5 GiB, so it has its own daily bulk slot.
    _c("history_verify", 86400, "Event history verification", MO, 8, 4, "low", 300,
       command="timeline status",
       lane="bulk", governed=True, cost_s=75.0),
    # Owner retention policy (2026-11-04): after 30 days, keep only the suspicious
    # events of older history segments (collectors/telemetry/history_retention.py).
    _c("retention", 1800, "Event history retention", MO, 10, 3, "low", 180,
       command="timeline status",
       lane="bulk", governed=True, cost_s=60.0),
    # The in-tree verification ladder over the installed code, under 1 s CPU.
    _c("verify", 86400, "Code verification (properties and models)", MO, 9, 4, "low", 300,
       command="status",
       lane="bulk", governed=True, cost_s=1.0),
    # Stages sealed history for the broker's vault, verifies it, checks the
    # running Sysmon rules and timestamps chain heads. DrvFS hashing: bulk.
    _c("evidence", 900, "Evidence vault & anchors", MO, 6, 3, "medium", 90,
       admin_sensor="unavailable",
       command="broker status",
       lane="bulk", cost_s=217.0),
    # Planted canary bait: journal verification, decoy fingerprints, off-box
    # callback hits. Cheap and local, frequent so a trip surfaces quickly.
    _c("canary", 300, "Canary tokens & tripwires", MO, 7, 2, "medium", 60,
       command="canary status", lane="frequent", cost_s=0.1),
    # Tamper evidence that holds when the source is public (DETECTION-CONTENT.md):
    # Python startup hooks, Argus's own code against RELEASE.json, its units,
    # its state directory's writers and the signed rule-pack channel. Hashes
    # the release tree, about 1.2 s cold and 0.1 s warm (measured 2026-10-30).
    _c("selfguard", 1800, "Argus self-protection & tamper evidence", None, 0, 3, "high", 120,
       command="status", domain="linux", cost_s=1.2,
       unscored="source-tested and measured once read-only on one host; not yet soaked"),
)

BY_NAME = {c.name: c for c in COLLECTORS}


# --- derived views (the tables other modules used to own) ---------------------

def schedule_table():
    """name -> (interval, label), in declaration order: schedule.ALL_JOBS."""
    return {c.name: (c.interval, c.label) for c in COLLECTORS}


NEEDS_ADMIN_SENSOR = "Needs administrator sensor"


def admin_sensor_jobs():
    """{job: "unavailable" | "limited"} for the collectors that need the administrator sensor."""
    return {c.name: c.admin_sensor for c in COLLECTORS if c.admin_sensor}


def names(**match):
    """Collector names whose fields equal every keyword, in declaration order."""
    return tuple(c.name for c in COLLECTORS
                 if all(getattr(c, k) == v for k, v in match.items()))


def score_areas():
    """((area, (job, ...)), ...) in display order and in-area precedence."""
    return tuple((area, tuple(c.name for c in sorted(
        (c for c in COLLECTORS if c.area == area), key=lambda c: c.area_rank)))
        for area in AREAS)


def boot_scoped():
    """Collectors whose pre-boot evidence is not evidence about this boot."""
    return tuple(c.name for c in COLLECTORS if c.boot_scoped)


def dependencies():
    """root -> dependent collectors, for every declared root."""
    return {root: tuple(c.name for c in COLLECTORS if root in c.depends_on)
            for root in DEPENDENCY_ROOTS}


# Health sources that are not scheduled collectors. The opt-in browser sensor
# (veil) posts through its own route, so its freshness is judged the same way.
EXTRA_HEALTH_SOURCES = {"veil": 90}


def commands():
    """job -> the CLI command that audits the same ground: JOB_COMMANDS."""
    return {c.name: c.command for c in COLLECTORS}


def elevated_scripts():
    """job -> its elevated broker script, for collectors that have one."""
    return {c.name: c.elevated for c in COLLECTORS if c.elevated}


def health_sources(windows=True):
    """(required, optional), each name -> freshness limit in seconds.

    The one rulebook /api/health and the dashboard both judge from. A
    Windows-domain requirement applies only where the scheduler observes
    Windows; optional sources are always reported, never a dependency."""
    required = {c.name: c.health_limit_s for c in COLLECTORS if c.health == "required"
                and (windows or c.domain != "windows")}
    optional = {c.name: c.health_limit_s for c in COLLECTORS if c.health == "optional"}
    return required, {**optional, **EXTRA_HEALTH_SOURCES}


# --- the mechanism catalogue ---------------------------------------------------

@dataclass(frozen=True)
class Primitive:
    """One kind of mechanism: what it promises and where that promise is held."""
    name: str
    contract: str
    invariants: tuple
    implemented_by: tuple          # module paths relative to the repo root
    verified_by: tuple             # test modules relative to the repo root
    failure: str                   # what a failure looks like from outside
    instances: tuple = field(default=())


PRIMITIVES = (
    Primitive(
        "collector",
        "A bounded audit of one ground: run_job(name) returns findings in the common shape and "
        "an observation status (complete, partial, unavailable) recorded with a receipt.",
        ("declared exactly once in COLLECTORS, with a runner in service/jobs.RUNNERS",
         "a failure to observe is a visibility finding or partial status, never an empty clean result",
         "scored, or unscored with a written reason",
         "timeout below its interval, so a hang is caught before dependents go stale"),
        ("jarvis/core/mechanisms.py", "jarvis/service/jobs.py", "jarvis/core/collection.py"),
        ("tests/test_mechanisms.py", "tests/test_score.py"),
        "the coverage view shows it failing or stale; score counts it blind"),
    Primitive(
        "lane",
        "A serial worker: fast (sub-second liveness), frequent (five-minute collectors), main "
        "(long PowerShell audits), bulk (DrvFS and network). One job at a time per lane; "
        "PowerShell launches from every lane share the interop admission gate.",
        ("fast-lane jobs are never governed and finish in seconds",
         "each lane's measured duty cycle stays under LANE_DUTY_LIMIT",
         "starving jobs (past the hard deadline) are served first",
         "an evidence collector on a cadence of 300 s or less runs in the frequent lane, "
         "never behind the main lane's post-boot sweep"),
        ("jarvis/service/scheduler.py",),
        ("tests/test_mechanisms.py", "tests/test_lane_fairness.py", "tests/test_bulk_lane.py",
         "tests/test_frequent_lane.py"),
        "lane age grows; protection health reports the lane stalled"),
    Primitive(
        "freshness budget",
        "Evidence age against the declared interval: FRESH to 100%, LATE to 130%, DEGRADED to 200%, "
        "then STALE.",
        ("no collector is STALE with nothing trying to recover it",
         "an unknown age is STALE: no result is no result",
         "a failed rerun never rewrites the last good snapshot as unsafe"),
        ("jarvis/service/reliability.py",),
        ("tests/test_reliability.py",),
        "the collector reads stale and coverage pages"),
    Primitive(
        "clock",
        "Two clocks with separate jobs: the monotonic clock measures durations, waits, "
        "timeouts and liveness; the wall clock stamps evidence that other processes compare.",
        ("every wait, timeout and age is measured on time.monotonic()",
         "a wall-clock step (the WSL clock fight steps ~9 s) never ends a wait early or "
         "declares a stall",
         "standby is not a stall: lane ages use the monotonic clock"),
        ("jarvis/service/scheduler.py", "jarvis/platform/procfeed.py"),
        ("tests/test_mechanisms.py", "tests/test_daemon_resilience.py"),
        "a wait gives up early or a healthy collector reads stalled after a clock step"),
    Primitive(
        "lease",
        "A worker's claim on one run that expires on its own, so a dead worker is detected by "
        "expiry rather than inferred minutes later.",
        ("a lease always expires", "one active lease per collector"),
        ("jarvis/service/reliability.py",),
        ("tests/test_reliability.py",),
        "an expired lease is recorded as a failed run"),
    Primitive(
        "hold and retry",
        "A transient failure inside the freshness budget keeps the last good result and retries "
        "after RETRY_S, at most HOLD_MAX times, then is recorded.",
        ("bounded: retries end and escalate", "the held result is labelled as held, not fresh"),
        ("jarvis/service/scheduler.py", "jarvis/service/reliability.py"),
        ("tests/test_daemon_resilience.py",),
        "after HOLD_MAX the failure is recorded and visible"),
    Primitive(
        "governor deferral",
        "Under CPU, memory, disk or battery pressure only governed collectors may wait.",
        ("tier 0 and fast-lane collectors are never governed",
         "deferral is recorded, never silent"),
        ("jarvis/core/governor.py",),
        ("tests/test_mechanisms.py",),
        "deferred jobs are listed in protection health"),
    Primitive(
        "observation receipt",
        "Every run writes a receipt with its coverage status beside its findings, so a clean "
        "report and no report never look the same.",
        ("partial or unavailable coverage is carried into the error and the score",),
        ("jarvis/core/store.py", "jarvis/core/collection.py"),
        ("tests/test_collection.py", "tests/test_observation.py"),
        "collector coverage incomplete"),
    Primitive(
        "cursor",
        "An incremental reader's resume point (record id, sequence) with gap detection: cleared "
        "logs start a new generation, overwritten ranges are recorded as gaps.",
        ("a cursor never moves past unread evidence", "every gap is recorded with its range"),
        ("jarvis/collectors/telemetry/sysmon.py", "jarvis/platform/native/ingest.py"),
        ("tests/test_sysmon_windows.py", "tests/test_native.py"),
        "a gap finding with the exact missing range"),
    Primitive(
        "hash-chained journal",
        "Append-only records each carrying the previous record's hash; verify() names the first "
        "broken link.",
        ("append fails loudly; a caller that needs the record denies on failure",
         "records hold metadata and digests, never secret values"),
        ("jarvis/core/eventlog.py", "jarvis/core/canary.py", "jarvis/argus/journal.py"),
        ("tests/test_continuity.py",),
        "verify() returns the index and reason of the break"),
    Primitive(
        "sealed release",
        "Root-owned code under /opt/jarvis/releases run with python3 -I; switched atomically with "
        "the previous release kept for rollback.",
        ("the running daemon never executes user-writable code",
         "a release is accepted only on a live readback against a written baseline"),
        ("scripts/deploy_root_runtime.py", "jarvis/platform/provenance/release.py"),
        ("tests/test_release_controller.py", "tests/test_verify_models.py"),
        "the release refuses to switch, or rolls back"),
    Primitive(
        "stream",
        "A read-only, bounded push channel (Server-Sent Events) from one shared cached state.",
        ("read-only: no route back into the daemon",
         "bounded: MAX_STREAMS, MAX_LIFETIME_S, one shared rebuild per period",
         "blindness is never quiet: a failed or stale state is sent as such"),
        ("jarvis/web/stream.py", "jarvis/web/procview.py"),
        ("tests/test_stream.py", "tests/test_procfeed.py", "tests/test_procs_page.py"),
        "the client shows unknown, never clean"),
    Primitive(
        "helper",
        "A long-lived Windows-side process started from the daemon (input hook, process feed) "
        "with a heartbeat and one instance at a time.",
        ("single instance, except a handoff: a successor runs beside it for at most "
         "procfeed.HANDOFF_S and takes over on its first report",
         "heartbeat age decides liveness",
         "runs only with the least privilege it needs",
         "its compiled code is a reviewed script (collectors/process/assemblies.OWN_SCRIPTS)",
         "demand-driven helpers stop when their last consumer leaves"),
        ("jarvis/collectors/host/inputwatch/helper.py", "jarvis/platform/procfeed.py",
         "jarvis/platform/win/procfeed.ps1"),
        ("tests/test_inputwatch.py", "tests/test_procfeed.py"),
        "the watchdog reports it deaf and restarts it within bounds"),
    Primitive(
        "gate",
        "A deterministic decision before a consequential act (fix approval, Argus agent calls): "
        "fail closed, human authority bound to the exact act.",
        ("any failure denies", "approval is single use, expiring and bound to one digest",
         "no allow without a durable journal record"),
        ("jarvis/argus/policy.py", "jarvis/argus/monitor.py", "jarvis/response/selffix.py"),
        ("tests/test_argus_monitor.py", "tests/test_selffix.py"),
        "a deny with its reasons in the journal"),
    Primitive(
        "advisory",
        "Jev and local models: typed judgments that may rank or add friction.",
        ("never authorises, applies, suppresses or allows",
         "missing or uncertain output falls back to the deterministic path"),
        ("jarvis/response/jev.py",),
        ("tests/test_jev.py",),
        "unavailable is reported, and the safe path runs"),
    Primitive(
        "verification property",
        "An executable claim checked over generated cases or an exhaustive model, run by "
        "python -m jarvis.verify, the daily verify job and the Argus build gate.",
        ("a failing property fails the build", "cases are replayable by seed and index"),
        ("jarvis/verify/properties.py", "jarvis/verify/report.py"),
        ("tests/test_verify_props.py",),
        "the build stops and names the property"),
)


def tier_band(interval):
    """The reliability tier a collector of this cadence belongs to (tiers 0-1,
    the continuous streams and liveness checks, are chosen explicitly)."""
    return 2 if interval <= 300 else 3 if interval <= 7200 else 4


def timeout_cap(interval):
    """The longest run budget for this cadence: a tenth of it, between 60 s
    and 300 s, so a hang is caught before dependents go stale. Shorter is
    allowed (a timeout then fails loudly, never silently)."""
    return min(300.0, max(60.0, interval / 10))


def conformance(root=None, files=True):
    """Every way the declarations break their own contract, as readable strings.

    Pure over the declarations, plus (files=True) that each primitive's code and
    tests exist under `root`, the repo or release tree; default: the tree this
    module sits in. Paths under jarvis/ resolve against the package's real
    directory, so a renamed package (Argus ships it as argus/) still checks.
    An empty list is the only passing result.
    """
    out = []
    seen = set()
    for c in COLLECTORS:
        where = f"collector {c.name}"
        if c.name in seen:
            out.append(f"{where}: declared twice")
        seen.add(c.name)
        if c.lane not in LANES:
            out.append(f"{where}: unknown lane {c.lane!r}")
        if c.domain not in DOMAINS:
            out.append(f"{where}: unknown domain {c.domain!r}")
        if c.criticality not in CRITICALITY:
            out.append(f"{where}: unknown criticality {c.criticality!r}")
        if not 0 <= c.tier <= 4:
            out.append(f"{where}: tier {c.tier} outside 0-4")
        if c.interval <= 0 or not c.label:
            out.append(f"{where}: needs a positive interval and a label")
        if c.timeout >= c.interval and c.lane != "fast":
            out.append(f"{where}: timeout {c.timeout}s not below interval {c.interval}s")
        # Budgets are declared, not derived, so these bands keep a new
        # declaration consistent with the rest (Jev flagged drift at 0.73).
        if c.tier >= 2 and c.tier != tier_band(c.interval):
            out.append(f"{where}: tier {c.tier} outside the band for {c.interval}s "
                       f"(expected {tier_band(c.interval)})")
        if c.tier <= 1 and c.interval > 600:
            out.append(f"{where}: tiers 0-1 are continuous or liveness, at most 600s")
        if (c.tier == 0) != (c.criticality == "critical"):
            out.append(f"{where}: critical means tier 0 and tier 0 means critical")
        if c.timeout > timeout_cap(c.interval):
            out.append(f"{where}: timeout {c.timeout}s over the cap {timeout_cap(c.interval)}s")
        if c.area is None and not c.unscored:
            out.append(f"{where}: unscored without a reason")
        if c.area is not None and c.area not in AREAS:
            out.append(f"{where}: unknown area {c.area!r}")
        if c.area is not None and c.unscored:
            out.append(f"{where}: scored and also given an unscored reason")
        if c.governed and (c.tier == 0 or c.lane == "fast"):
            out.append(f"{where}: tier 0 and fast-lane collectors must never be governed")
        if c.isolated and c.lane in ("main", "frequent"):
            out.append(f"{where}: isolation is defined for the fast and bulk lanes only")
        if c.lane == "frequent":
            if c.governed:
                out.append(f"{where}: frequent-lane collectors must never be governed")
            if c.interval > FREQUENT_MAX_INTERVAL:
                out.append(f"{where}: the frequent lane holds cadences of at most "
                           f"{FREQUENT_MAX_INTERVAL}s, not {c.interval}s")
            if c.timeout > FREQUENT_TIMEOUT_MAX:
                out.append(f"{where}: a frequent-lane timeout of {c.timeout}s is over "
                           f"{FREQUENT_TIMEOUT_MAX}s")
            if c.cost_s is None:
                out.append(f"{where}: a frequent-lane collector needs a measured cost_s")
        elif (c.lane == "main" and c.evidence and c.interval <= FREQUENT_MAX_INTERVAL):
            out.append(f"{where}: a {c.interval}s evidence collector on the main lane waits "
                       f"behind the post-boot backlog; declare lane=\"frequent\"")
        if not c.command:
            out.append(f"{where}: needs the CLI command that audits the same ground")
        if c.health not in ("", "required", "optional"):
            out.append(f"{where}: unknown health role {c.health!r}")
        elif c.health and c.health_limit_s < c.interval:
            out.append(f"{where}: health limit {c.health_limit_s}s is shorter than its "
                       f"interval {c.interval}s, so it would always read stale")
        elif not c.health and c.health_limit_s:
            out.append(f"{where}: a health limit without a health role")
        for dep in c.depends_on:
            if dep not in DEPENDENCY_ROOTS:
                out.append(f"{where}: unknown dependency root {dep!r}")
    for area in AREAS:
        ranks = [c.area_rank for c in COLLECTORS if c.area == area]
        if sorted(ranks) != list(range(len(ranks))):
            out.append(f"area {area}: ranks {sorted(ranks)} are not 0..{len(ranks) - 1}")
    for lane in LANES:
        duty = sum(c.cost_s / c.interval for c in COLLECTORS
                   if c.lane == lane and c.cost_s is not None)
        if duty > LANE_DUTY_LIMIT:
            out.append(f"lane {lane}: measured duty {duty:.2f} over {LANE_DUTY_LIMIT}")
    package = Path(__file__).resolve().parents[1]
    base = Path(root) if root is not None else package.parent
    if root is not None:
        package = base / package.name

    def located(rel):
        head, _, rest = rel.partition("/")
        return package / rest if head == "jarvis" else base / rel

    if files:
        for c in COLLECTORS:
            if c.elevated and not located(f"jarvis/platform/win/{c.elevated}").exists():
                out.append(f"collector {c.name}: elevated script {c.elevated} missing")
    clash = set(EXTRA_HEALTH_SOURCES) & set(BY_NAME)
    if clash:
        out.append(f"extra health sources {sorted(clash)} are also collectors")
    names_seen = set()
    for p in PRIMITIVES:
        if p.name in names_seen:
            out.append(f"primitive {p.name}: declared twice")
        names_seen.add(p.name)
        if not (p.contract and p.invariants and p.implemented_by and p.verified_by and p.failure):
            out.append(f"primitive {p.name}: contract, invariants, implementation, "
                       "tests and failure are all required")
        if not files:
            continue
        for rel in p.implemented_by:
            if not located(rel).exists():
                out.append(f"primitive {p.name}: implementation {rel} missing")
        for rel in p.verified_by:
            if not located(rel).exists():
                out.append(f"primitive {p.name}: test {rel} missing")
    return out
