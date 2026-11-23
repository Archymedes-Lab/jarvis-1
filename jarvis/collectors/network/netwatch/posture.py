"""Wireless posture: what the machine's own Wi-Fi configuration exposes.

The timeline in record.py watches the network change underneath the laptop.
This module judges the laptop's side, read every half hour:

  hotspot on           The PC is sharing its connection over Wi-Fi (Mobile
                       Hotspot or a hosted network). Often deliberate; a
                       compromised host can use it to bridge or expose itself.
  routes around a VPN  With a VPN up, non-local routes through the physical
                       gateway send that traffic outside the tunnel. A rogue
                       DHCP server can push them (TunnelVision,
                       CVE-2024-3661) while the VPN still shows connected.
  open auto-join       A saved open network set to connect automatically: an
                       evil twin or KARMA access point with that name gets the
                       laptop's traffic without any prompt.
  unpatched Wi-Fi RCE  Builds before the June 2024 cumulative update carry
                       CVE-2024-30078, code execution by anyone in radio range.
  driver               Inventory, so a Wi-Fi driver/firmware advisory can be
                       checked against what is installed.

Severities were weighed with a Jev advisory review (2026-09-24) and set here
deterministically. See docs/research/WIFI-MALWARE.md.
"""

import time

from jarvis.core.finding import win_finding as _finding

# June 11, 2024 cumulative updates (KB5039211: 19044/19045.4529; KB5039212:
# 22621/22631.3737) fixed CVE-2024-30078. Builds absent here are reported as
# unknown rather than guessed.
CVE_2024_30078_FIXED = {19044: 4529, 19045: 4529, 22621: 3737, 22631: 3737}
# 24H2 reached general availability in October 2024 at 26100.1742, after the fix.
FIXED_FROM_24H2 = (26100, 1742)
UNSUPPORTED_BEFORE = 19044   # Windows 10 releases that no longer receive fixes

DRIVER_OLD_S = 3 * 365 * 86400
POSTURE_STALE_S = 2 * 3600


def _int(value, default=-1):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def build_status(build, ubr):
    """'fixed', 'vulnerable' or 'unknown' for CVE-2024-30078."""
    build, ubr = _int(build), _int(ubr)
    if build < 0 or ubr < 0:
        return "unknown"
    if build in CVE_2024_30078_FIXED:
        return "fixed" if ubr >= CVE_2024_30078_FIXED[build] else "vulnerable"
    if build > FIXED_FROM_24H2[0] or (build == FIXED_FROM_24H2[0] and ubr >= FIXED_FROM_24H2[1]):
        return "fixed"
    if build < UNSUPPORTED_BEFORE:
        return "vulnerable"
    return "unknown"


def hotspot_on(p):
    hosted = str(p.get("hosted") or "").strip().lower()
    direct_up = any(str(a.get("status") or "").lower() == "up" for a in p.get("direct") or [])
    return hosted == "started" or str(p.get("icssvc") or "").lower() == "running" or direct_up


def bypass_routes(p):
    """Non-local, non-default routes on interfaces that are not a VPN."""
    vpn = {str(v.get("iface") or "") for v in p.get("vpn") or []}
    out = []
    for r in p.get("routes") or []:
        iface = str(r.get("iface") or "")
        prefix = str(r.get("prefix") or "")
        if (not prefix or prefix == "0.0.0.0/0" or iface in vpn
                or str(r.get("protocol") or "").lower() == "local"
                or iface.lower().startswith(("loopback", "vethernet"))):
            continue
        out.append(f"{prefix} via {r.get('nexthop') or '?'} on {iface}")
    return out


def findings(p, now=None):
    """Findings from one posture reading. Pure: `p` is the stored dict."""
    if not isinstance(p, dict) or not p.get("at"):
        return []
    now = time.time() if now is None else now
    if now - float(p["at"]) > POSTURE_STALE_S:
        return []
    out = []

    if hotspot_on(p):
        out.append(_finding(
            "network", "low", "this PC is sharing its connection as a Wi-Fi hotspot",
            "Mobile Hotspot or a hosted network is active. Fine if you turned it "
            "on; otherwise something on this PC is offering a network to others.",
            "Mobile Hotspot"))

    routes = bypass_routes(p)
    vpn_up = [str(v.get("name") or v.get("iface") or "VPN") for v in p.get("vpn") or []]
    if routes and vpn_up:
        out.append(_finding(
            "network", "high", "traffic can bypass the VPN",
            f"{', '.join(vpn_up[:2])} is connected, but {len(routes)} route(s) send "
            f"traffic through the physical network instead: {'; '.join(routes[:4])}. "
            "A rogue DHCP server pushing classless static routes (TunnelVision, "
            "CVE-2024-3661) produces exactly this while the VPN still shows connected.",
            "route table"))
    elif routes:
        out.append(_finding(
            "network", "low", "the network pushed extra routes",
            f"{'; '.join(routes[:4])}. Harmless without a VPN, but these routes would "
            "carry traffic around a VPN once it connects (TunnelVision, CVE-2024-3661).",
            "route table"))

    open_auto = [str(x) for x in p.get("open_auto") or []]
    if open_auto:
        n = len(open_auto)
        out.append(_finding(
            "network", "medium",
            f"{n} saved open Wi-Fi network{'s' if n != 1 else ''} join automatically",
            f"{', '.join(open_auto[:5])}{'…' if n > 5 else ''}: unencrypted and set to "
            "connect without asking, so an evil twin or KARMA access point using the "
            "name receives this laptop's traffic. Set them to connect manually or "
            "forget them (Settings > Network & internet > Wi-Fi > Manage known networks).",
            "saved Wi-Fi profiles"))

    b = p.get("build") or {}
    status = build_status(b.get("build"), b.get("ubr"))
    label = f"{b.get('product') or 'Windows'} {b.get('display') or ''} build {b.get('build')}.{b.get('ubr')}".replace("  ", " ")
    if status == "vulnerable":
        out.append(_finding(
            "network", "high", "Windows lacks the fix for a no-click Wi-Fi attack",
            f"{label} predates the June 2024 cumulative update for CVE-2024-30078: "
            "anyone within radio range can run code through the Wi-Fi driver without "
            "the laptop joining their network. Install the latest Windows update.",
            "Windows Update"))
    elif status == "fixed":
        out.append(_finding(
            "network", "ok", "Windows includes the Wi-Fi driver RCE fix",
            f"{label} is at or past the June 2024 fix for CVE-2024-30078.",
            "Windows Update"))
    else:
        out.append(_finding(
            "network", "low", "Wi-Fi driver RCE patch level not determined",
            f"{label} is not in JARVIS's table for CVE-2024-30078; check that Windows "
            "Update is current.", "Windows Update"))

    d = p.get("driver") or {}
    if d.get("version"):
        detail = (f"{d.get('desc') or 'Wi-Fi adapter'}: driver {d.get('version')} "
                  f"({d.get('provider') or '?'}, {d.get('date') or 'undated'})")
        old = False
        try:
            from datetime import datetime
            old = now - datetime.fromisoformat(str(d.get("date"))[:10]).timestamp() > DRIVER_OLD_S
        except (TypeError, ValueError):
            pass
        out.append(_finding(
            "network", "low" if old else "ok",
            "the Wi-Fi driver is over three years old" if old else "Wi-Fi driver inventoried",
            detail + (". Wi-Fi chip flaws (Broadpwn, FragAttacks) are fixed in drivers "
                      "and firmware; check the vendor for an update." if old else "."),
            d.get("desc") or "Wi-Fi adapter"))
    return out
