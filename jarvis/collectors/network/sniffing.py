"""Packet capture on this host — the local half of T1040 Network Sniffing.

An attacker who wants to read traffic they are not a party to has to do one of
a few visible things: put an interface in promiscuous mode, open an
AF_PACKET / raw socket, or load a capture driver. None of that is traffic
analysis — it is all local state, so a sampling monitor can see it.

  Linux    IFF_PROMISC on an interface, and any process holding a packet
           socket. Bridges and container veth pairs run promiscuous by design,
           so those are noted, not alarmed; a physical NIC in promiscuous mode
           with no capture tool to explain it is the finding.

  Windows  the Npcap / WinPcap driver being present at all (it is not there on
           a stock machine), plus any running capture tool — Wireshark,
           dumpcap, tshark, windump, NetworkMiner, Fiddler, mitmproxy.

It cannot see a capture that a driver-level implant does entirely in kernel
without a userland socket, and it says as much.
"""

import glob
import os
import re
import subprocess

from jarvis.core.finding import finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import aslist, ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

IFF_PROMISC = 0x100
CAPTURE_TOOLS = ("tcpdump", "tshark", "dumpcap", "wireshark", "windump",
                 "netsniff-ng", "ettercap", "bettercap", "mitmproxy",
                 "mitmdump", "ngrep", "tcpflow", "netcat-capture")
# Interface name prefixes that are promiscuous as part of normal operation.
BENIGN_IFACE = ("br-", "docker", "veth", "virbr", "vnet", "lxc", "cni",
                "flannel", "cali", "tap", "tun", "kube")


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── Linux ───────────────────────────────────────────────────────────────────

def _capture_procs_linux():
    procs = []
    for p in glob.glob("/proc/[0-9]*"):
        try:
            with open(f"{p}/comm", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm in CAPTURE_TOOLS:
            procs.append((os.path.basename(p), comm))
    return procs


def _packet_sockets(proc="/proc", max_pids=65536):
    """(pid, name) of each process holding an AF_PACKET socket."""
    return packet_socket_scan(proc, max_pids)[0]


def packet_socket_scan(proc="/proc", max_pids=65536):
    """(holders, unattributed): (pid, name) pairs, and how many packet sockets
    no readable process accounts for (their holder is unknown, never absent).

    Read natively: /proc/net/packet lists every packet socket's inode, and the
    holders come from /proc/<pid>/fd with this process's own CAP_SYS_PTRACE.
    `ss -p` was used before, but programs this daemon launches do not inherit
    its capabilities, so on a server ss could not name a root-owned holder and
    a root implant was never listed (found 2026-10-29). ss stays the fallback
    when /proc/net/packet cannot be read."""
    try:
        with open(f"{proc}/net/packet", errors="replace") as fh:
            rows = fh.read(4 * 1024 * 1024).splitlines()[1:]
    except OSError:
        return _packet_sockets_ss(), 0
    inodes = {parts[-1] for parts in (r.split() for r in rows) if parts and parts[-1].isdigit()}
    if not inodes:
        return [], 0
    holders, found = [], set()
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()][:max_pids]
    except OSError:
        return _packet_sockets_ss(), 0
    for pid in pids:
        try:
            fds = os.listdir(f"{proc}/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{proc}/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                found.add(target[8:-1])
                if not holders or holders[-1][0] != pid:
                    try:
                        with open(f"{proc}/{pid}/comm", errors="replace") as fh:
                            name = fh.read().strip()
                    except OSError:
                        name = "?"
                    holders.append((pid, name))
    return holders, len(inodes - found)


def _packet_sockets_ss():
    """Processes holding an AF_PACKET socket, via `ss` (fallback)."""
    try:
        r = subprocess.run(["ss", "-0", "-p", "-a", "-H"],
                           capture_output=True, text=True,
                           errors="replace", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    holders = []
    for line in r.stdout.splitlines():
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if m:
            holders.append((m.group(2), m.group(1)))
    return holders


# Daemons that hold packet sockets by design (DHCP, link management, mDNS).
# A name is what the attacker chooses (BPFdoor runs under a fixed fake daemon
# name), so a name alone never exempts: the image must be a root-owned file a
# package installed, in a system directory, and not deleted.
PACKET_DAEMONS = ("systemd-networkd", "NetworkManager", "dhclient", "dhcpcd",
                  "wpa_supplicant", "avahi-daemon")
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/")
# Microsoft's Sysmon for Linux holds a packet socket for its network events. It
# runs from /opt/sysmon, outside the system directories, so it is proven the
# way the control audit proves its unit: a byte-identical copy of the
# package-verified /usr/bin/sysmon (2026-10-29: reported high before this).
SYSMON = ("/opt/sysmon/sysmon", "/usr/bin/sysmon")
SENSOR_LAUNCHERS = ("/opt/jarvis/app/jarvis-release.py", "/opt/jarvis/app/jarvis-release.pyc",
                    "/opt/jarvis/current/jarvis-release.py")


def _root_only(path):
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & 0o022


def _sha256(path):
    """Hex digest of a file, or None when it cannot be read."""
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def packet_holder_identity(pid, name, proc="/proc", owner=None):
    """"verified" (an expected holder, proven by its image), "unverified" (its
    image cannot be read: unknown, never exempt) or "unexpected"."""
    if owner is None:
        from jarvis.core.util import dpkg_owns as owner
    try:
        exe = os.readlink(f"{proc}/{pid}/exe")
    except OSError:
        return "unverified"
    if exe.endswith(" (deleted)") or exe.startswith("/memfd:"):
        return "unexpected"
    if exe == SYSMON[0]:
        copy, packaged = _sha256(SYSMON[0]), _sha256(SYSMON[1])
        if copy is None or packaged is None:
            return "unverified"
        return "verified" if copy == packaged and owner(SYSMON[1]) else "unexpected"
    # Matched on the image's file name: the process name is truncated to 15
    # characters (systemd-networkd shows as "systemd-network", found in the
    # 2026-10-29 VM run) and is the attacker's to choose anyway.
    if os.path.basename(exe) in PACKET_DAEMONS:
        if exe.startswith(SYSTEM_DIRS) and _root_only(exe) and owner(exe):
            return "verified"
        return "unexpected"
    # This monitor's own packet sensor: the sealed launcher, run by a root-owned
    # interpreter, with the netsensor command.
    try:
        with open(f"{proc}/{pid}/cmdline", "rb") as fh:
            argv = [a.decode("utf-8", "replace") for a in fh.read(4096).split(b"\0") if a]
    except OSError:
        return "unverified"
    if (len(argv) >= 4 and argv[1] == "-I" and argv[2] in SENSOR_LAUNCHERS and argv[3] == "netsensor"
            and _root_only(exe) and _root_only(argv[2])):
        return "verified"
    return "unexpected"


def _promisc_ifaces():
    out = []
    for path in glob.glob("/sys/class/net/*/flags"):
        iface = path.split("/")[-2]
        try:
            flags = int(open(path, errors="replace").read().strip(), 16)
        except (OSError, ValueError):
            continue
        if flags & IFF_PROMISC:
            out.append(iface)
    return out


def _linux(tools=None, sockets=None, promisc=None, identity=None):
    """Findings for the Linux side. The arguments replace what is read from this
    machine, so the coverage map can show the rules fire; the rules are the same."""
    out = []
    tools = _capture_procs_linux() if tools is None else tools
    identity = identity or packet_holder_identity
    held, unverified, unattributed = [], [], 0
    if sockets is None:
        sockets, unattributed = packet_socket_scan()
    for pid, name in sockets:
        who = identity(pid, name)
        if who == "unexpected":
            held.append((pid, name))
        elif who == "unverified":
            unverified.append((pid, name))
    sockets = held
    promisc = _promisc_ifaces() if promisc is None else promisc
    phys_promisc = [i for i in promisc
                    if not any(i.startswith(b) for b in BENIGN_IFACE)
                    and i != "lo"]

    for pid, comm in tools:
        out.append(_finding(
            "sniffing", "high", f"a packet-capture tool is running: {comm}",
            f"pid {pid}. Confirm this is a capture you started",
            f"/proc/{pid}"))

    for pid, name in sockets:
        if any(t[0] == pid for t in tools):
            continue
        out.append(_finding(
            "sniffing", "high",
            f"{name} (pid {pid}) is holding a raw packet socket",
            "an AF_PACKET socket reads frames off the wire directly — normal "
            "for a sniffer, unexpected for anything else", f"/proc/{pid}"))

    for pid, name in unverified:
        out.append(_finding(
            "sniffing", "medium",
            f"{name} (pid {pid}) holds a raw packet socket; its identity is not verified",
            "its executable could not be read (needs CAP_SYS_PTRACE), so it is neither cleared "
            "nor accused by name: an implant can take any daemon's name", f"/proc/{pid}"))

    if unattributed:
        out.append(_finding(
            "visibility", "medium",
            f"{unattributed} raw packet socket(s) held by a process that could not be read",
            "the socket exists (/proc/net/packet) but no readable process accounts for it, so its "
            "holder is unknown, not absent (reading other accounts' descriptors needs CAP_SYS_PTRACE)",
            "/proc/net/packet"))

    for iface in phys_promisc:
        explained = bool(tools or sockets)
        out.append(_finding(
            "sniffing", "medium" if explained else "high",
            f"{iface} is in promiscuous mode",
            ("a capture tool above explains it" if explained else
             "no capture process on this host explains a physical NIC "
             "reading every frame on the segment"), f"/sys/class/net/{iface}"))

    benign_promisc = [i for i in promisc if i not in phys_promisc and i != "lo"]
    if not out:
        note = (f"; {', '.join(benign_promisc)} promiscuous by design (bridge/"
                f"container)" if benign_promisc else "")
        out.append(_finding(
            "sniffing", "ok", "no packet capture on the Linux side",
            f"no capture tool, no unexplained raw socket, no physical NIC in "
            f"promiscuous mode{note}", "ip link / ss"))
    return out


# ── Windows ─────────────────────────────────────────────────────────────────

_WIN_PS = load_win_script("sniffing.ps1")


def _windows():
    if not collect_windows.available():
        return []
    d = ps_json(_WIN_PS, timeout=120)
    if not d:
        return []
    out = []
    for drv in aslist(d.get("drivers")):
        name = (drv or {}).get("name", "?")
        status = (drv or {}).get("status", "?")
        if name == "pktmon":
            continue  # built-in, only interesting when actively tracing
        out.append(_finding(
            "sniffing", "medium" if status != "Running" else "high",
            f"a packet-capture driver is installed: {name} ({status})",
            "Npcap/WinPcap is not present on a stock machine — something "
            "installed it to capture traffic. Fine if that was you",
            "services", host="win"))
    for t in aslist(d.get("tools")):
        out.append(_finding(
            "sniffing", "high",
            f"a capture tool is running: {(t or {}).get('name', '?')}",
            f"pid {(t or {}).get('id', '?')} — confirm this capture is yours",
            "processes", host="win"))
    for name in aslist(d.get("promisc")):
        out.append(_finding(
            "sniffing", "high", f"adapter {name} is in promiscuous mode",
            "an adapter reading every frame on the segment", "netadapter",
            host="win"))
    if not out:
        out.append(_finding(
            "sniffing", "ok", "no packet capture on the Windows side",
            "no Npcap/WinPcap driver, no capture tool running, no adapter in "
            "promiscuous mode", "services / processes", host="win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += _linux()
    if "win" in hosts:
        out += _windows()
    return sort_findings(out)
