"""Firewall posture and inbound connections — who can reach in, and who did.

Outbound egress is covered by the process scanner. This module looks the other
way down the wire:

  * the firewall's actual state, per profile, including whether logging is on
  * every inbound Allow rule, with attention to the dangerous shapes: any
    program, any remote address, or a rule pointing at a user-writable path
  * connections that were initiated *from outside* — distinguished from your own
    outbound traffic by whether the local port is one you are listening on
  * remote logons and file-share sessions, which is what an actual intrusion
    looks like after the connection succeeds
"""

import os
import re

from jarvis.collectors.network import exposure
from jarvis.collectors.signatures import REMOTE_AGENTS
from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.core.util import classify_ip
from jarvis.platform import firewall_state
from jarvis.platform import host as machine
from jarvis.platform.linux import read_file, socket_table
from jarvis.platform.windows import aslist, ps_json

USER_WRITABLE = re.compile(r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|"
                           r"\\programdata\\", re.I)

# Rule groups that hand out interactive control or file access. These are worth
# surfacing even though Windows ships them, because whether they are *on* is a
# decision, not a default.
NOTABLE_GROUPS = re.compile(
    r"remote desktop|remote assistance|remote event|remote service|"
    r"remote volume|remote scheduled|windows remote management|winrm|"
    r"file and printer sharing|netlogon|windows management instrumentation",
    re.I,
)


# Rules the Host Network Service generates for container / WSL NAT networking.
# They are genuinely broad — the DNS one is any program, any address, port 53 —
# but they are machine-generated per virtual switch, carry that switch's GUID in
# the name, and HNS recreates them on the next container start. Reporting them
# as something to go and remove sends you after a rule that grows back, so they
# are named for what they are and rated for the fact that they exist rather than
# as a finding you can act on.
HOST_NETWORKING = re.compile(
    r"^(HNS Container Networking|vEthernet|WSL|Hyper-V)\b.*"
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    re.I,
)


# ---------------------------------------------------------------------------
# Linux side: who is listening, and who connected in
# ---------------------------------------------------------------------------

def _sample(ips, n=3):
    ips = sorted(ips)
    return ", ".join(ips[:n]) + (f" and {len(ips) - n} more" if len(ips) > n else "")


def audit_server(table=None, declared=None, declared_src="", declared_problems=(),
                 snapshot=None, snapshot_problem="", load=True):
    """The Linux firewall audit on a plain server (ARGUS-SERVER.md W2).

    Expected service traffic is not a finding: inbound connections to a
    declared port from a declared source are the server doing its job.
    Everything else is aggregated per port, never one finding per connection.
    """
    if load:
        declared, declared_src, declared_problems = exposure.load_declared()
        snapshot, snapshot_problem = exposure.load_netstate()
    table = socket_table() if table is None else table
    out = []
    listeners = exposure.exposed_listeners(table)
    # No file, or a file with every line still commented out (as the installer
    # writes it): the owner has not said what this server serves yet.
    undeclared_mode = not declared

    # Inbound connections, grouped by local port.
    peers = {}
    for conn in table.values():
        if conn.get("state") != "ESTABLISHED" or (conn.get("local_port"), "tcp") not in listeners:
            continue
        scope = classify_ip(conn.get("remote_ip", ""))
        if scope in ("loopback", "invalid", "unspecified"):
            continue
        if exposure.is_declared(declared, conn["local_port"], "tcp", conn.get("remote_ip")):
            continue
        bucket = peers.setdefault(conn["local_port"], {"public": set(), "private": set()})
        bucket["public" if scope == "public" else "private"].add(conn["remote_ip"])
    for port, b in sorted(peers.items()):
        if b["public"]:
            sev = "medium" if undeclared_mode else "high"
            out.append(_finding("inbound", sev, f"internet clients on undeclared port {port}/tcp",
                                f"{len(b['public'])} public address(es): {_sample(b['public'])}",
                                f"port {port}/tcp", host="wsl"))
        if b["private"]:
            out.append(_finding("inbound", "medium" if not undeclared_mode else "low",
                                f"private-network clients on undeclared port {port}/tcp",
                                f"{len(b['private'])} address(es): {_sample(b['private'])}",
                                f"port {port}/tcp", host="wsl"))

    # Listeners beyond loopback that nobody declared, weighed by the firewall.
    fresh = snapshot is not None and not snapshot_problem
    lo, hi = exposure.ephemeral_range()
    for (port, proto), addrs in sorted(listeners.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        if exposure.is_declared(declared, port, proto):
            continue
        verdict, source = exposure.reachability(snapshot, port, proto) if fresh else (exposure.UNKNOWN, "")
        sev = {exposure.OPEN: "high", exposure.RESTRICTED: "medium",
               exposure.UNKNOWN: "medium", exposure.FILTERED: "low"}[verdict]
        if undeclared_mode and sev == "high":
            sev = "medium"
        note = ""
        if proto == "udp" and lo <= port <= hi and sev != "low":
            # Usually a client's reply socket, but a backdoor can sit here too:
            # kept visible, at low.
            sev, note = "low", "; in the ephemeral port range, likely a client socket"
        why = {exposure.OPEN: f"the firewall lets it in ({source})",
               exposure.RESTRICTED: f"the firewall admits some sources ({source})",
               exposure.FILTERED: f"the firewall blocks new inbound connections ({source})",
               exposure.UNKNOWN: "whether the firewall lets it in is not known"
                                 + (f" ({source})" if source else
                                    f" ({snapshot_problem})" if snapshot_problem else "")}[verdict]
        out.append(_finding("exposure", sev, f"undeclared service listening on {port}/{proto}",
                            f"bound to {', '.join(addrs[:4])}; {why}{note}",
                            f"port {port}/{proto}", host="wsl"))

    # What the owner has (not) said, and whether the firewall was seen at all.
    if undeclared_mode:
        listed = ", ".join(f"{p}/{pr}" for p, pr in sorted(listeners)) or "none"
        out.append(_finding("posture", "medium", "exposed services are not declared",
                            "Argus cannot tell the server's own traffic from an intrusion until "
                            f"{exposure.DECLARED_PATHS[0]} lists the ports it serves "
                            f"(listening beyond loopback now: {listed})",
                            exposure.DECLARED_PATHS[0], host="wsl"))
    elif declared_problems:
        out.append(_finding("posture", "medium", "declared services file has unreadable lines",
                            "; ".join(list(declared_problems)[:5]), declared_src, host="wsl"))
    if not fresh and not os.path.isdir(exposure.NET_DIR):
        # The firewall reader is part of the opt-in network sensor: unknown
        # posture, stated, but not a collector failure.
        out.append(_finding("configuration", "medium", "firewall rules are not read",
                            "the argus-netstate unit is opt-in (install.sh --net-sensor); until it "
                            "runs, whether the firewall lets these ports in is unknown",
                            exposure.NET_DIR, host="wsl"))
    elif not fresh:
        out.append(_finding("visibility", "medium", "firewall rules not observed",
                            snapshot_problem or "no firewall snapshot", exposure.NET_DIR, host="wsl"))
    else:
        nft = snapshot.get("nft") or {}
        if nft.get("ok"):
            policies = exposure.nft_input_policies(nft.get("ruleset"))
            if not policies:
                any_open = any(f["severity"] == "high" and f["category"] == "exposure" for f in out)
                out.append(_finding("posture", "high" if any_open else "medium",
                                    "no inbound packet filtering",
                                    "the netfilter ruleset has no input chain: every listening port "
                                    "is reachable from every network this server is on",
                                    "nft list ruleset", host="wsl"))
        elif not any((snapshot.get(k) or {}).get("ok") for k in ("ufw", "firewalld")):
            out.append(_finding("visibility", "medium", "firewall rules not observed",
                                "nft: " + str(nft.get("error") or "unreadable")
                                + "; ufw and firewalld unreadable too", "argus-netstate", host="wsl"))
    return out


def audit_linux():
    if machine.kind() == "linux":
        return audit_server()
    out = []
    table = socket_table()

    listening = {c["local_port"] for c in table.values() if c["state"] == "LISTEN"}
    for conn in table.values():
        if conn["state"] != "ESTABLISHED":
            continue
        # An established connection on a port we listen on came from outside.
        if conn["local_port"] in listening:
            scope = classify_ip(conn["remote_ip"])
            if scope in ("loopback",):
                continue
            sev = "critical" if scope == "public" else "medium"
            out.append(_finding(
                "inbound", sev, "inbound connection from outside",
                f"{conn['remote_ip']}:{conn['remote_port']} → local port "
                f"{conn['local_port']} ({scope})",
                "/proc/net", host="wsl"))

    # WSL's own firewall state is mostly advisory — Windows filters the NAT — but
    # a local rule set that blocks nothing is still worth stating plainly.
    nft = read_file("/proc/net/nf_conntrack")
    if not read_file("/proc/net/ip_tables_names").strip() and not nft:
        out.append(_finding("posture", "low", "no netfilter rules loaded in WSL",
                            "the Windows host firewall is what actually protects "
                            "this machine's network edge", "/proc/net", host="wsl"))
    return out


# ---------------------------------------------------------------------------
# Windows side
# ---------------------------------------------------------------------------

PS_FW = load_win_script("firewall.ps1")


def audit_windows(data=None):
    """`data` is a payload already collected: the coverage map's probes pass a
    synthetic one so they exercise these rules rather than a copy of them."""
    if data is None:
        data = ps_json(PS_FW, timeout=240)
    if data is None:
        return [_finding("posture", "medium", "firewall audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- posture -----------------------------------------------------------
    for p in aslist(data.get("profiles")):
        nm = p.get("name")
        if not p.get("enabled"):
            out.append(_finding("posture", "critical",
                                f"firewall OFF on the {nm} profile",
                                "inbound traffic is unfiltered on this network type",
                                "Get-NetFirewallProfile"))
        if (p.get("inbound") or "").lower() == "allow":
            out.append(_finding("posture", "critical",
                                f"{nm} profile allows inbound by default",
                                "anything not explicitly blocked can reach this machine",
                                "DefaultInboundAction"))
        if not p.get("logBlocked"):
            out.append(_finding("posture", "low",
                                f"{nm} profile does not log blocked connections",
                                "turning this on gives you a record of what got "
                                "turned away", p.get("logFile") or ""))

    # -- inbound allow rules ----------------------------------------------
    rules = aslist(data.get("rules"))
    inbound_rules_ignored = firewall_state.rule_inactive()
    for r in rules:
        app = r.get("app") or ""
        remote = r.get("remote") or "Any"
        name = r.get("name") or "?"
        group = r.get("group") or ""

        # A grouped rule shipped with Windows or with a feature you turned on.
        # Reporting every one of those buries the rules something *added*, so
        # stock groups are skipped unless the group itself grants remote control
        # or the program sits somewhere anyone could have replaced it.
        if (group and not NOTABLE_GROUPS.search(group)
                and not USER_WRITABLE.search(app) and r.get("exists") is not False):
            continue

        risky = []

        if app and app != "Any" and r.get("exists") is False:
            risky.append("program no longer installed — orphaned rule")
        if app in ("", "Any", None) and not group:
            risky.append("any program")
        if remote in ("Any", "*", ""):
            risky.append("any remote address")
        if USER_WRITABLE.search(app):
            risky.append("program in a user-writable directory")
        if NOTABLE_GROUPS.search(group):
            risky.append(f"grants remote access ({group})")

        # A firewall hole opened for a remote-control agent is the single most
        # consequential rule shape here: it means something can be driven from
        # outside, by design.
        agent = REMOTE_AGENTS.search(f"{name} {app}")
        if agent:
            risky.append("REMOTE-CONTROL AGENT")

        if not risky:
            continue
        infra = HOST_NETWORKING.search(name)
        if agent:
            sev = "critical"
        elif infra:
            # Broad by construction and regenerated by HNS; knowing it is open
            # matters, being told to delete it every 15 minutes does not.
            sev = "medium"
            risky.append("auto-generated by Host Network Service — "
                         "recreated if removed")
        elif ("program in a user-writable directory" in risky or len(risky) > 1):
            sev = "high"
        else:
            sev = "medium"
        # With every profile ignoring allow rules ("block all incoming
        # connections"), the rule admits nothing now. A remote-access agent's
        # rule stays critical: the agent is installed and one toggle away.
        inactive = sev != "critical" and inbound_rules_ignored
        out.append(_finding(
            "rules", "low" if inactive else sev, "permissive inbound rule",
            f"{name} — {', '.join(risky)}"
            + (f" [{r.get('port')}]" if r.get("port") else "")
            + (" — inactive: every firewall profile blocks all incoming "
               "connections, allow rules included" if inactive else ""),
            app or r.get("group") or ""))

    out.append(_finding("rules", "ok", "inbound allow rules",
                        f"{len(rules)} enabled", "Get-NetFirewallRule"))

    # -- inbound connections ----------------------------------------------
    conns = aslist(data.get("conns"))
    procs = {p.get("pid"): p for p in aslist(data.get("procs"))}
    listening = {c.get("lport") for c in conns if c.get("state") == "Listen"}

    for c in conns:
        if c.get("state") != "Established":
            continue
        if c.get("lport") not in listening:
            continue  # our own outbound socket, not someone reaching in
        rip = c.get("rip") or ""
        scope = classify_ip(rip)
        if scope in ("loopback", "unspecified", "invalid"):
            continue
        who = procs.get(c.get("pid"), {})
        sev = "critical" if scope == "public" else "medium"
        out.append(_finding(
            "inbound", sev, "inbound connection from outside",
            f"{rip}:{c.get('rport')} → local port {c.get('lport')} ({scope}) "
            f"served by {who.get('name') or f'pid {c.get('pid')}'}",
            (who.get("path") or "") + (f"  since {c.get('created')}"
                                       if c.get("created") else "")))

    # -- who actually logged in remotely ----------------------------------
    logons = aslist(data.get("logons"))
    for l in logons:
        kind = "RDP" if str(l.get("type")) == "10" else "network"
        scope = classify_ip(l.get("ip") or "")
        sev = "critical" if scope == "public" else "high"
        out.append(_finding("access", sev, f"remote {kind} logon succeeded",
                            f"{l.get('user')} from {l.get('ip')} ({scope})",
                            l.get("time") or ""))

    failed = aslist(data.get("failed"))
    if failed:
        by_ip = {}
        for f in failed:
            by_ip.setdefault(f.get("ip"), []).append(f)
        for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:10]:
            scope = classify_ip(ip or "")
            sev = "high" if len(items) >= 10 or scope == "public" else "medium"
            out.append(_finding("access", sev, "failed logon attempts",
                                f"{len(items)} failures from {ip} ({scope}), "
                                f"latest user tried: {items[0].get('user')}",
                                items[0].get("time") or ""))

    if not data.get("secReadable"):
        out.append(_finding("access", "medium", "security log not readable",
                            "remote-logon history needs an elevated PowerShell — "
                            "an empty result here does not mean nobody logged in",
                            "Security event log"))

    for s in aslist(data.get("smb")):
        out.append(_finding("access", "high", "active file-share session",
                            f"{s.get('client')} as {s.get('user')} "
                            f"({s.get('numOpen')} files open)", "Get-SmbSession"))

    # Event 7045's message is one run-on string once newlines are stripped, so
    # each field has to be bounded by the label that follows it. The same
    # service reinstalls on every update, so collapse repeats into a count.
    installs = {}
    for s in aslist(data.get("newsvc")):
        msg = s.get("msg") or ""
        name = re.search(r"Service Name:\s*(.*?)\s*Service File Name:", msg)
        file = re.search(r"Service File Name:\s*(.*?)\s*Service Type:", msg)
        key = (name.group(1) if name else msg[:60]).strip()
        entry = installs.setdefault(key, {"n": 0, "file": "", "last": ""})
        entry["n"] += 1
        entry["file"] = entry["file"] or (file.group(1).strip() if file else "")
        entry["last"] = max(entry["last"], s.get("time") or "")

    for name, e in sorted(installs.items(), key=lambda kv: kv[1]["last"], reverse=True):
        sev = "high" if USER_WRITABLE.search(e["file"]) else "medium"
        times = f" ×{e['n']}" if e["n"] > 1 else ""
        finding = _finding("posture", sev, "service installed recently",
                           f"{name}{times} — {e['file'][:90] or 'path unknown'}",
                           e["last"].replace("T", " ")[:19])
        finding["program"] = e["file"]      # untruncated, for verification
        out.append(finding)

    return out


CAT_ORDER = {"inbound": 0, "access": 1, "posture": 2, "rules": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += audit_linux()
    if "win" in hosts:
        out += audit_windows()
    out.sort(key=lambda f: (CAT_ORDER.get(f["category"], 9),
                            SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out
