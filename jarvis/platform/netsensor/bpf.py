"""The kernel-side filter of the packet sensor, as classic BPF.

Attached to an AF_PACKET SOCK_DGRAM socket, so offset 0 is the network header
on every link type (Ethernet, WireGuard, tun). It keeps only:

    inbound to this host (PACKET_HOST), not on loopback
    TCP with SYN and without ACK            -> new connection attempts
    ICMP and ICMPv6
    UDP

and returns at most the headers: IPv4 header + 20 bytes of TCP or + 8 of
UDP/ICMP (computed from the real header length), fixed lengths for IPv6, and a
DNS-sized prefix only for UDP port 53. The kernel truncates to that length, so
packet payloads never reach user space (ARGUS-SERVER.md I5). Non-first IPv4
fragments carry no ports and are dropped.

`interpret()` runs the same instructions over a byte string in Python, so the
tests check the bytecode the kernel receives, not a re-implementation of it.
"""

import ctypes
import struct

# Classic BPF opcodes (linux/filter.h).
LD, LDX, ALU, JMP, RET, MISC = 0x00, 0x01, 0x04, 0x05, 0x06, 0x07
W, H, B = 0x00, 0x08, 0x10
IMM, ABS, IND, MSH = 0x00, 0x20, 0x40, 0xa0
ADD, AND = 0x00, 0x50
JA, JEQ, JSET = 0x00, 0x10, 0x40
K, X_SRC, A_SRC = 0x00, 0x08, 0x10
TAX, TXA = 0x00, 0x80

SKF_AD_OFF = -0x1000
SKF_AD_PROTOCOL = 0
SKF_AD_PKTTYPE = 4
SKF_AD_IFINDEX = 8
PACKET_HOST = 0
ETH_P_IP, ETH_P_IPV6 = 0x0800, 0x86DD

TCP_SNAP_EXTRA = 20         # TCP header without options: ports and flags
SMALL_SNAP_EXTRA = 8        # UDP header, ICMP header
DNS_SNAP = 320              # IP + UDP + DNS header + a bounded question
V6_TCP_SNAP = 40 + 20
V6_SMALL_SNAP = 40 + 8


def _u32(k):
    return k & 0xffffffff


def assemble(lines):
    """[(code, jt_label, jf_label, k)] with string labels, or a label name on
    its own, -> [(code, jt, jf, k)] with relative jumps."""
    labels, ops = {}, []
    for item in lines:
        if isinstance(item, str):
            labels[item] = len(ops)
        else:
            ops.append(item)
    out = []
    def rel(target, i):
        if target is None:
            return 0
        off = labels[target] - i - 1
        if not 0 <= off <= 255:
            raise ValueError(f"jump to {target} out of range at {i}")
        return off

    for i, (code, jt, jf, k) in enumerate(ops):
        if code == JMP | JA and isinstance(k, str):
            k = labels[k] - i - 1
        out.append((code, rel(jt, i), rel(jf, i), _u32(k)))
    return out


def program(lo_ifindex=1):
    """The filter, assembled. `lo_ifindex` is loopback's interface index."""
    ld_abs_w, ld_abs_h, ld_abs_b = LD | W | ABS, LD | H | ABS, LD | B | ABS
    ld_ind_b, ld_ind_h = LD | B | IND, LD | H | IND
    jeq, jset = JMP | JEQ | K, JMP | JSET | K
    ret_k, ret_a = RET | K, RET | A_SRC
    return assemble([
        (ld_abs_w, None, None, SKF_AD_OFF + SKF_AD_PKTTYPE),
        (jeq, "host", "drop", PACKET_HOST),
        "host",
        (ld_abs_w, None, None, SKF_AD_OFF + SKF_AD_IFINDEX),
        (jeq, "drop", "notlo", lo_ifindex),
        "notlo",
        (ld_abs_w, None, None, SKF_AD_OFF + SKF_AD_PROTOCOL),
        (jeq, "v4", "notv4", ETH_P_IP),
        "notv4",
        (jeq, "v6", "drop", ETH_P_IPV6),

        "v4",
        (ld_abs_h, None, None, 6),
        (jset, "drop", "v4first", 0x1fff),          # non-first fragment
        "v4first",
        (LDX | B | MSH, None, None, 0),             # X = IPv4 header length
        (ld_abs_b, None, None, 9),
        (jeq, "v4tcp", "v4n1", 6),
        "v4n1",
        (jeq, "v4udp", "v4n2", 17),
        "v4n2",
        (jeq, "v4small", "drop", 1),
        "v4tcp",
        (ld_ind_b, None, None, 13),
        (ALU | AND | K, None, None, 0x12),          # SYN | ACK
        (jeq, "v4syn", "drop", 0x02),
        "v4syn",
        (MISC | TXA, None, None, 0),
        (ALU | ADD | K, None, None, TCP_SNAP_EXTRA),
        (ret_a, None, None, 0),
        "v4udp",
        (ld_ind_h, None, None, 0),
        (jeq, "dns", "v4udp2", 53),
        "v4udp2",
        (ld_ind_h, None, None, 2),
        (jeq, "dns", "v4small", 53),
        "v4small",
        (MISC | TXA, None, None, 0),
        (ALU | ADD | K, None, None, SMALL_SNAP_EXTRA),
        (ret_a, None, None, 0),

        "v6",
        (ld_abs_b, None, None, 6),
        (jeq, "v6tcp", "v6n1", 6),
        "v6n1",
        (jeq, "v6udp", "v6n2", 17),
        "v6n2",
        (jeq, "v6small", "drop", 58),
        "v6tcp",
        (ld_abs_b, None, None, 40 + 13),
        (ALU | AND | K, None, None, 0x12),
        (jeq, "v6syn", "drop", 0x02),
        "v6syn",
        (ret_k, None, None, V6_TCP_SNAP),
        "v6udp",
        (ld_abs_h, None, None, 40),
        (jeq, "dns", "v6udp2", 53),
        "v6udp2",
        (ld_abs_h, None, None, 42),
        (jeq, "dns", "v6small", 53),
        "v6small",
        (ret_k, None, None, V6_SMALL_SNAP),

        "dns",
        (ret_k, None, None, DNS_SNAP),
        "drop",
        (ret_k, None, None, 0),
    ])


def interpret(prog, packet, pkttype=PACKET_HOST, protocol=ETH_P_IP, ifindex=2):
    """Run `prog` over `packet` as the kernel would: the number of bytes kept
    (0 = dropped). An out-of-bounds load drops the packet, as in the kernel."""
    a = x = 0
    pc = 0
    n = len(packet)
    anc = {SKF_AD_PROTOCOL: protocol, SKF_AD_PKTTYPE: pkttype, SKF_AD_IFINDEX: ifindex}

    def load(off, size):
        if off >= _u32(SKF_AD_OFF):
            return anc[off - _u32(SKF_AD_OFF)]
        if off < 0 or off + size > n:
            return None
        return int.from_bytes(packet[off:off + size], "big")

    for _ in range(4096):
        code, jt, jf, k = prog[pc]
        pc += 1
        cls = code & 0x07
        if cls == LD:
            size = {W: 4, H: 2, B: 1}[code & 0x18]
            mode = code & 0xe0
            off = k if mode == ABS else (x + k) & 0xffffffff if mode == IND else None
            if mode == IMM:
                a = k
                continue
            v = load(off, size)
            if v is None:
                return 0
            a = v
        elif cls == LDX:
            if code & 0xe0 == MSH:
                v = load(k, 1)
                if v is None:
                    return 0
                x = 4 * (v & 0x0f)
            else:
                x = k
        elif cls == ALU:
            op, src = code & 0xf0, x if code & X_SRC else k
            a = (a + src) & 0xffffffff if op == ADD else a & src if op == AND else None
            if a is None:
                raise ValueError(f"unsupported ALU op {code:#x}")
        elif cls == JMP:
            op = code & 0xf0
            if op == JA:
                pc += k
            elif op == JEQ:
                pc += jt if a == k else jf
            elif op == JSET:
                pc += jt if a & k else jf
            else:
                raise ValueError(f"unsupported jump {code:#x}")
        elif cls == RET:
            v = a if code & A_SRC else k
            return min(v, n)
        elif cls == MISC:
            if code & 0xf8 == TXA:
                a = x
            else:
                x = a
    raise RuntimeError("filter did not terminate")


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


SO_ATTACH_FILTER = 26


def attach(sock, prog):
    """Attach `prog` to `sock`. The ctypes buffers live only for the call:
    the kernel copies the program."""
    arr = (_SockFilter * len(prog))(*[_SockFilter(*op) for op in prog])
    fprog = _SockFprog(len(prog), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
    import socket
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(memoryview(fprog)))  # type: ignore[arg-type]
    return len(prog)


def ipv4(proto, payload, src="185.220.101.5", dst="198.51.100.7", frag=0, ihl=5):
    """A test IPv4 packet (no checksum: the filter does not read it)."""
    import ipaddress
    head = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(payload), 0, frag, 64, proto, 0,
                       ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    return head + b"\x00" * (4 * ihl - 20) + payload


def tcp(dport, flags, sport=40000):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0)


def udp(dport, body=b"", sport=40000):
    return struct.pack("!HHHH", sport, dport, 8 + len(body), 0) + body
