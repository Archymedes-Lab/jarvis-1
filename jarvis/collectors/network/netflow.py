"""Incoming packets, judged: the `netflow` job (ARGUS-SERVER.md W5).

Reads the one-minute windows the separate packet sensor (argus-netsensor,
platform/netsensor/capture.py) writes, in order, behind a cursor, and judges
them against the declared services and what actually listens.

Continuity is part of the evidence (I7): a missing sequence number is a gap, a
new boot id a sensor restart, an old newest window a stale sensor, and kernel
drops or rate-limited packets reduced visibility. None of them is silence.

Internet background scanning never stops on a public server. Findings are
therefore aggregated over the last hour per source network (/24, /48) and keyed
by what was probed, not by who, so a new scanner does not page and a scanner
that finds an open undeclared service does.
"""

import ipaddress
import json
import os
import time

from jarvis.collectors.network import exposure
from jarvis.core.finding import win_finding as _finding
from jarvis.platform.linux import socket_table
from jarvis.platform.netsensor import spool

CURSOR_META = "netflow_cursor_v1"         # {"start", "boot", "seq"}
HOUR_META = "netflow_hour_v1"             # rolling per-window summaries
BASE_META = "netflow_syn_baseline_v1"     # per-port EWMA of SYNs per minute
MAX_WINDOWS_PER_RUN = 180
HOUR_S = 3600
STALE_S = 180
SCAN_PORTS = 20             # distinct closed/undeclared ports from one source in a window
PROBE_SOURCES = 5           # sources reaching one undeclared open port in the hour
FLOOD_MIN_PER_MIN = 500
FLOOD_FACTOR = 10.0
EWMA_ALPHA = 0.05
ICMP_FLOOD_PER_MIN = 200
UDP_SCAN_PORTS = 20
DNS_SUSPECT_PER_MIN = 30
DROP_SHARE = 0.01
REACHED_PER_PORT = 64       # sources kept per undeclared port per window (bounds stored state)


def network_of(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    plen = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))


def _load(store, key, default):
    try:
        value = json.loads(store.get_meta(key, "") or "null")
    except (ValueError, TypeError):
        value = None
    return default if value is None else value


def read_new(store, spool_dir=spool.SPOOL_DIR, limit=MAX_WINDOWS_PER_RUN):
    """(windows, continuity events, unreadable count). Advances the cursor."""
    cursor = _load(store, CURSOR_META, {})
    files = spool.list_windows(spool_dir)
    after = [f for f in files if (f[0], f[1], f[2]) > (cursor.get("start", -1), cursor.get("boot", ""),
                                                         cursor.get("seq", -1))]
    events, windows, unreadable = [], [], 0
    if len(after) > limit:
        events.append(("backlog", len(after) - limit))
        after = after[-limit:]
    prev_boot, prev_seq = cursor.get("boot"), cursor.get("seq")
    for start, boot, seq, path in after:
        if prev_boot is not None:
            if boot != prev_boot:
                events.append(("restart", start))
            elif seq != prev_seq + 1:
                events.append(("gap", seq - prev_seq - 1))
        try:
            w = spool.read_json(path)
        except (OSError, ValueError):
            unreadable += 1
            w = None
        if isinstance(w, dict):
            windows.append(w)
        prev_boot, prev_seq = boot, seq
        store.set_meta(CURSOR_META, json.dumps({"start": start, "boot": boot, "seq": seq}))
    return windows, events, unreadable


def summarize(w, listeners, declared):
    """The parts of one window the hour keeps: per-source port counts against
    closed/undeclared ports, undeclared open ports reached, rates."""
    open_undeclared_t = {p for (p, pr) in listeners if pr == "tcp" and not exposure.is_declared(declared, p, "tcp")}
    listening_t = {p for (p, pr) in listeners if pr == "tcp"}
    listening_u = {p for (p, pr) in listeners if pr == "udp"}
    scans, udp_scans, reached, icmp_heavy = {}, {}, {}, {}
    for src, s in (w.get("sources") or {}).items():
        if not isinstance(s, dict):
            continue
        tports = [p for p in s.get("tports") or [] if isinstance(p, int)]
        closed = [p for p in tports if p not in listening_t or not exposure.is_declared(declared, p, "tcp", src)]
        if len(closed) >= SCAN_PORTS:
            net = network_of(src)
            scans[net] = max(scans.get(net, 0), len(closed))
        uports = [p for p in s.get("uports") or [] if isinstance(p, int) and p not in listening_u]
        if len(uports) >= UDP_SCAN_PORTS:
            net = network_of(src)
            udp_scans[net] = max(udp_scans.get(net, 0), len(uports))
        for p in tports:
            if p in open_undeclared_t:
                srcs = reached.setdefault(str(p), [])
                if len(srcs) < REACHED_PER_PORT:
                    srcs.append(src)
        if (s.get("icmp") or 0) >= ICMP_FLOOD_PER_MIN:
            icmp_heavy[network_of(src)] = s["icmp"]
    stats = w.get("stats") or {}
    return {"start": w.get("start"), "end": w.get("end"),
            "syn": {k: v for k, v in (w.get("syn") or {}).items() if isinstance(v, int)},
            "scans": scans, "udp_scans": udp_scans, "reached": reached, "icmp": icmp_heavy,
            "dns": w.get("dns") or {}, "seen": stats.get("seen", 0),
            "kernel_packets": stats.get("kernel_packets", 0), "kernel_drops": stats.get("kernel_drops", 0),
            "over_rate": stats.get("over_rate", 0),
            "capped": stats.get("source_cap", 0) + stats.get("port_cap", 0)}


def _floods(store, summaries):
    """[(port, per_minute, baseline)] where SYNs ran far above the port's own
    baseline; updates the baseline with every window seen."""
    base = _load(store, BASE_META, {})
    floods = []
    for s in summaries:
        for port, n in s["syn"].items():
            mean = base.get(port)
            if mean is not None and n >= FLOOD_MIN_PER_MIN and n >= FLOOD_FACTOR * max(mean, 1.0):
                floods.append((int(port), n, mean))
                continue            # a flood minute does not teach the baseline
            base[port] = n if mean is None else (1 - EWMA_ALPHA) * mean + EWMA_ALPHA * n
        for port in list(base):
            if port not in s["syn"]:
                base[port] *= (1 - EWMA_ALPHA)
                if base[port] < 0.01:
                    del base[port]
    if len(base) > 2048:
        base = dict(sorted(base.items(), key=lambda kv: -kv[1])[:2048])
    store.set_meta(BASE_META, json.dumps(base))
    return floods


def judge(summaries, hour, events, unreadable, newest_end, now, floods=(), installed=True):
    out = []
    if not installed:
        # An opt-in the owner has not taken is configuration, not a failing
        # collector: stated once, without marking coverage incomplete.
        return [_finding("configuration", "low", "incoming packet sensor is not enabled",
                         "inbound packets are not observed; the argus-netsensor unit is opt-in "
                         "(install.sh --net-sensor)", exposure.NET_DIR, host="wsl")]
    # Continuity.
    if newest_end is None:
        out.append(_finding("visibility", "medium", "packet sensor has written nothing",
                            "no window in the spool; is argus-netsensor running?", exposure.NET_DIR, host="wsl"))
    elif now - newest_end > STALE_S:
        out.append(_finding("visibility", "medium", "packet sensor has stopped reporting",
                            f"newest window ended {int((now - newest_end) // 60)} min ago",
                            exposure.NET_DIR, host="wsl"))
    gaps = sum(n for kind, n in events if kind == "gap")
    if gaps:
        out.append(_finding("visibility", "medium", "packet sensor windows are missing",
                            f"{gaps} window(s) skipped in sequence: those minutes were not observed",
                            exposure.NET_DIR, host="wsl"))
    backlog = sum(n for kind, n in events if kind == "backlog")
    if backlog:
        out.append(_finding("visibility", "medium", "packet windows were skipped unread",
                            f"{backlog} older window(s) beyond the per-run limit", exposure.NET_DIR, host="wsl"))
    if unreadable:
        out.append(_finding("visibility", "medium", "packet windows unreadable",
                            f"{unreadable} window file(s) could not be parsed", exposure.NET_DIR, host="wsl"))
    restarts = sum(1 for kind, _ in events if kind == "restart")
    if restarts:
        out.append(_finding("collectors", "low", "packet sensor restarted",
                            f"{restarts} restart(s) since the last run", exposure.NET_DIR, host="wsl"))
    packets = sum(h["kernel_packets"] for h in hour)
    drops = sum(h["kernel_drops"] for h in hour)
    over = sum(h["over_rate"] for h in hour)
    capped = sum(h["capped"] for h in hour)
    if packets and drops / max(packets + drops, 1) > DROP_SHARE:
        out.append(_finding("visibility", "medium", "packet sensor is dropping packets",
                            f"kernel dropped {drops} of {packets + drops} matching packets in the last hour",
                            exposure.NET_DIR, host="wsl"))
    if over or capped:
        out.append(_finding("visibility", "low", "packet sensor sampled under load",
                            f"{over} packet(s) over the rate limit and {capped} beyond per-window caps "
                            "in the last hour were counted, not analysed", exposure.NET_DIR, host="wsl"))

    # Detections over the hour.
    scans = {}
    for h in hour:
        for net, n in h["scans"].items():
            scans[net] = max(scans.get(net, 0), n)
    if scans:
        top = sorted(scans.items(), key=lambda kv: -kv[1])[:5]
        out.append(_finding("inbound", "medium", "port scans against this server",
                            f"{len(scans)} source network(s) in the last hour, e.g. "
                            + ", ".join(f"{net} ({n} ports)" for net, n in top),
                            "inbound packets", host="wsl"))
    udp = {}
    for h in hour:
        for net, n in h["udp_scans"].items():
            udp[net] = max(udp.get(net, 0), n)
    if udp:
        top = sorted(udp.items(), key=lambda kv: -kv[1])[:5]
        out.append(_finding("inbound", "medium", "UDP port probing against this server",
                            f"{len(udp)} source network(s) in the last hour, e.g. "
                            + ", ".join(f"{net} ({n} ports)" for net, n in top),
                            "inbound packets", host="wsl"))
    reached = {}
    for h in hour:
        for port, srcs in h["reached"].items():
            reached.setdefault(port, set()).update(srcs)
    for port, srcs in sorted(reached.items(), key=lambda kv: int(kv[0])):
        nets = {network_of(s) for s in srcs}
        sev = "high" if len(srcs) >= PROBE_SOURCES or nets & set(scans) else "medium"
        out.append(_finding("inbound", sev, f"undeclared open port {port}/tcp is being found",
                            f"{len(srcs)} source(s) from {len(nets)} network(s) opened connections to it in "
                            "the last hour" + (", including networks that scanned this server"
                                               if nets & set(scans) else ""),
                            f"port {port}/tcp", host="wsl"))
    for port, n, mean in floods:
        out.append(_finding("inbound", "high", f"SYN flood on port {port}/tcp",
                            f"{n} new connection attempts in one minute against a baseline of {mean:.0f}",
                            f"port {port}/tcp", host="wsl"))
    icmp = {}
    for h in hour:
        for net, n in h["icmp"].items():
            icmp[net] = max(icmp.get(net, 0), n)
    if icmp:
        net, n = max(icmp.items(), key=lambda kv: kv[1])
        out.append(_finding("inbound", "medium", "ICMP flood against this server",
                            f"{len(icmp)} network(s) sent at least {ICMP_FLOOD_PER_MIN} ICMP packets in a "
                            f"minute; most: {net} ({n})", "inbound packets", host="wsl"))
    suspect = max((max(h["dns"].get("long_names", 0), h["dns"].get("high_entropy", 0)) for h in hour), default=0)
    if suspect >= DNS_SUSPECT_PER_MIN:
        out.append(_finding("network", "medium", "DNS traffic shaped like tunnelling",
                            f"up to {suspect} DNS messages a minute with very long or random-looking names "
                            "(features only; names are not recorded)", "inbound packets", host="wsl"))
    return out


def audit(store, hosts=None, now=None, spool_dir=None, table=None, declared=None, load=True):
    now = time.time() if now is None else now
    spool_dir = spool.SPOOL_DIR if spool_dir is None else spool_dir
    if not os.path.isdir(spool_dir):
        return judge([], [], [], 0, None, now, installed=False)
    if load:
        declared = exposure.load_declared()[0]
    listeners = exposure.exposed_listeners(socket_table() if table is None else table)
    windows, events, unreadable = read_new(store, spool_dir)
    summaries = [summarize(w, listeners, declared) for w in windows]
    hour = [h for h in _load(store, HOUR_META, []) if isinstance(h, dict)
            and now - float(h.get("end") or 0) <= HOUR_S] + summaries
    store.set_meta(HOUR_META, json.dumps(hour[-int(HOUR_S / 60) - 5:]))
    floods = _floods(store, summaries)
    files = spool.list_windows(spool_dir)
    newest_end = None
    if files:
        newest_end = files[-1][0] + 60
    return judge(summaries, hour, events, unreadable, newest_end, now, floods=floods)
