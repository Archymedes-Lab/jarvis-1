"""The packet sensor: `argus netsensor` (ARGUS-SERVER.md W5).

Run by `argus-netsensor.service` as `argus-net` with CAP_NET_RAW only. It opens
one AF_PACKET socket with the filter in bpf.py, then drops every capability:
an open socket keeps working, and nothing else in the process can open another.

It aggregates what the kernel hands it into one-minute windows and writes each
window to the spool. A window holds counts, never packets:

    syn      {dport: n}                      new TCP connection attempts
    udp      {dport: n}
    icmp     {"v4:8": n, ...}                type, per family
    sources  {src: {"syn": n, "udp": n, "icmp": n, "tports": [...], "uports": [...]}}
    dns      response feature counts (long names, high-entropy labels); no names
    stats    packets seen, parsed, over the rate limit, kernel drops, caps hit

Everything is bounded: at most MAX_SOURCES sources and MAX_PORTS_PER_SOURCE
ports per source per window (the overflow is counted), at most MAX_PPS packets
parsed per second (the rest are counted, not parsed), and the spool keeps a
day of windows.
"""

import ctypes
import ipaddress
import math
import os
import secrets
import signal
import socket
import struct
import sys
import time

from jarvis.platform.netsensor import bpf, spool

WINDOW_S = 60
MAX_SOURCES = 4096
MAX_PORTS_PER_SOURCE = 256
MAX_PPS = int(os.environ.get("ARGUS_NETSENSOR_MAX_PPS", "5000"))
KEEP_WINDOWS = 24 * 60
RCVBUF = 4 * 1024 * 1024
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_STATISTICS = 6
LONG_QNAME = 100            # characters in a DNS question name
ENTROPY_LABEL_MIN = 24      # a label at least this long ...
ENTROPY_BITS = 3.8          # ... with at least this Shannon entropy per character


def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def dns_features(msg):
    """(is_response, qname_len, longest_label_len, longest_label_entropy) from
    a DNS message prefix, or None. Labels are read and discarded here."""
    if len(msg) < 13:
        return None
    flags, qd = struct.unpack("!H", msg[2:4])[0], struct.unpack("!H", msg[4:6])[0]
    if qd < 1:
        return None
    i, labels, total = 12, [], 0
    while i < len(msg):
        ln = msg[i]
        if ln == 0 or ln & 0xc0:
            break
        label = msg[i + 1:i + 1 + ln]
        if len(label) < ln:
            break                       # truncated by the filter: use what we have
        labels.append(label.decode("ascii", "replace"))
        total += ln + 1
        i += ln + 1
    if not labels:
        return None
    longest = max(labels, key=len)
    return bool(flags & 0x8000), total, len(longest), entropy(longest.lower())


def parse(data, protocol):
    """(src, kind, dport, extra) for a filtered, truncated packet, or None.
    kind is "syn", "udp", "icmp"; extra is the ICMP key or DNS features."""
    try:
        if protocol == bpf.ETH_P_IP:
            if len(data) < 20:
                return None
            ihl = (data[0] & 0x0f) * 4
            proto = data[9]
            src = str(ipaddress.IPv4Address(data[12:16]))
            l4 = data[ihl:]
            fam = "v4"
        elif protocol == bpf.ETH_P_IPV6:
            if len(data) < 40:
                return None
            proto = data[6]
            src = str(ipaddress.IPv6Address(data[8:24]))
            l4 = data[40:]
            fam = "v6"
        else:
            return None
        if proto == 6 and len(l4) >= 4:
            return src, "syn", struct.unpack("!H", l4[2:4])[0], None
        if proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack("!HH", l4[0:4])
            extra = dns_features(l4[8:]) if 53 in (sport, dport) else None
            return src, "udp", dport, extra
        if proto in (1, 58) and len(l4) >= 1:
            return src, "icmp", None, f"{fam}:{l4[0]}"
    except (ValueError, struct.error):
        return None
    return None


class Window:
    """One minute of counts, hard-capped."""

    def __init__(self, start):
        self.start = start
        self.syn, self.udp, self.icmp = {}, {}, {}
        self.sources = {}
        self.dns = {"responses": 0, "queries": 0, "long_names": 0, "high_entropy": 0, "max_label": 0}
        self.stats = {"seen": 0, "parsed": 0, "unparsed": 0, "over_rate": 0, "source_cap": 0,
                      "port_cap": 0, "kernel_packets": 0, "kernel_drops": 0}

    def add(self, src, kind, dport, extra):
        self.stats["parsed"] += 1
        if kind == "icmp":
            self.icmp[extra] = self.icmp.get(extra, 0) + 1
        else:
            table = self.syn if kind == "syn" else self.udp
            table[dport] = table.get(dport, 0) + 1
            if kind == "udp" and extra:
                resp, qlen, llen, ent = extra
                self.dns["responses" if resp else "queries"] += 1
                self.dns["long_names"] += qlen >= LONG_QNAME
                self.dns["high_entropy"] += llen >= ENTROPY_LABEL_MIN and ent >= ENTROPY_BITS
                self.dns["max_label"] = max(self.dns["max_label"], llen)
        s = self.sources.get(src)
        if s is None:
            if len(self.sources) >= MAX_SOURCES:
                self.stats["source_cap"] += 1
                return
            s = self.sources[src] = {"syn": 0, "udp": 0, "icmp": 0, "tports": set(), "uports": set()}
        s[kind] += 1
        if kind != "icmp":
            ports = s["tports" if kind == "syn" else "uports"]
            if dport not in ports:
                if len(ports) >= MAX_PORTS_PER_SOURCE:
                    self.stats["port_cap"] += 1
                else:
                    ports.add(dport)

    def to_json(self, boot, seq, end, partial=False):
        return {"version": 1, "boot": boot, "seq": seq, "start": self.start, "end": end,
                "partial": partial,
                "syn": {str(k): v for k, v in self.syn.items()},
                "udp": {str(k): v for k, v in self.udp.items()},
                "icmp": self.icmp, "dns": self.dns, "stats": self.stats,
                "sources": {ip: {"syn": s["syn"], "udp": s["udp"], "icmp": s["icmp"],
                                 "tports": sorted(s["tports"]), "uports": sorted(s["uports"])}
                            for ip, s in self.sources.items()}}


class RateLimit:
    """At most `rate` tokens per second, burst of one second."""

    def __init__(self, rate, clock=time.monotonic):
        self.rate, self.clock = rate, clock
        self.tokens, self.at = float(rate), clock()

    def allow(self):
        now = self.clock()
        self.tokens = min(self.rate, self.tokens + (now - self.at) * self.rate)
        self.at = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


def kernel_stats(sock):
    """(packets, drops) since the last call; reading resets the kernel's counters."""
    try:
        raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        return struct.unpack("II", raw)
    except OSError:
        return 0, 0


def drop_all_capabilities():
    """Clear every capability set of this process (the socket stays usable)."""
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(47, 4, 0, 0, 0)                      # PR_CAP_AMBIENT_CLEAR_ALL
    if libc.capset(ctypes.byref(Header(0x20080522, 0)), (Data * 2)()) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")


def open_socket():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    try:
        lo = socket.if_nametoindex("lo")
    except OSError:
        lo = 1
    bpf.attach(sock, bpf.program(lo))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    sock.settimeout(1.0)
    kernel_stats(sock)          # discard counts from before the filter was attached
    return sock


def run(spool_dir=spool.SPOOL_DIR, sock=None, clock=time.time, stop=None, max_windows=None):
    """Capture until stopped. `sock`, `clock`, `stop` and `max_windows` exist
    for tests; production passes none of them."""
    windows = os.path.join(spool_dir, spool.WINDOW_DIR)
    os.makedirs(windows, exist_ok=True)
    if sock is None:
        sock = open_socket()
        drop_all_capabilities()
    boot, seq = secrets.token_hex(4), 0
    limit = RateLimit(MAX_PPS)
    stopping = {"now": False}
    if stop is None:
        def _stop(*_a):
            stopping["now"] = True
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        stop = lambda: stopping["now"]          # noqa: E731
    now = clock()
    win = Window(int(now // WINDOW_S * WINDOW_S))
    written = 0

    def flush(end, partial=False):
        nonlocal seq, written
        packets, drops = kernel_stats(sock)
        win.stats["kernel_packets"] += packets
        win.stats["kernel_drops"] += drops
        spool.write_json(os.path.join(windows, spool.window_name(win.start, boot, seq)),
                         win.to_json(boot, seq, end, partial))
        seq += 1
        written += 1
        if seq % 60 == 0:
            spool.prune(spool_dir, keep=KEEP_WINDOWS)

    while not stop():
        try:
            data, addr = sock.recvfrom(bpf.DNS_SNAP)
        except socket.timeout:
            data = None
        except InterruptedError:
            continue
        now = clock()
        if now >= win.start + WINDOW_S:
            flush(win.start + WINDOW_S)
            if max_windows is not None and written >= max_windows:
                return written
            win = Window(int(now // WINDOW_S * WINDOW_S))
        if data is None:
            continue
        win.stats["seen"] += 1
        if not limit.allow():
            win.stats["over_rate"] += 1
            continue
        got = parse(data, addr[1] if isinstance(addr, tuple) and len(addr) > 1 else 0)
        if got is None:
            win.stats["unparsed"] += 1
            continue
        win.add(*got)
    flush(clock(), partial=True)
    return written


def main():
    print(f"netsensor: capturing new inbound connections into {spool.SPOOL_DIR} "
          f"(headers only, {WINDOW_S}-s windows, at most {MAX_PPS} packets/s parsed)",
          file=sys.stderr, flush=True)
    run()
    return 0
