"""What a Linux server is meant to expose, and what its firewall lets in.

Two inputs the rest of the network audit judges against (ARGUS-SERVER.md W2):

  declared services  /etc/argus/services.conf (or ~/.jarvis/services.conf): the
                     ports this server exists to serve, one per line,

                         22/tcp                       # ssh, from anywhere
                         443/tcp
                         5432/tcp 10.0.0.0/8          # postgres, private only

                     Traffic to a declared port from a declared source is the
                     server doing its job, not a finding. Declaring a port
                     lowers severity for that port and protocol only.

  firewall view      the snapshot the separate `argus-netstate` unit writes
                     (nft -j list ruleset, ufw status, firewall-cmd --list-all).
                     The daemon itself holds no CAP_NET_ADMIN.

Reachability is evaluated conservatively: a port is "filtered" only when every
rule up to the verdict is understood. A rule this module cannot read that could
accept the packet makes the answer "unknown", never "filtered" (I1).
"""

import ipaddress
import json
import os
import time

DECLARED_PATHS = ("/etc/argus/services.conf", os.path.expanduser("~/.jarvis/services.conf"))
NET_DIR = os.environ.get("JARVIS_NET_DIR", "/var/lib/argus-net")
NETSTATE_FILE = "netstate.json"
NETSTATE_MAX_AGE_S = 15 * 60      # the oneshot runs every 5 minutes
NETSTATE_MAX_BYTES = 4 * 1024 * 1024
MAX_DECLARED = 512
JUMP_DEPTH = 8

OPEN, FILTERED, RESTRICTED, UNKNOWN = "open", "filtered", "restricted", "unknown"
PROTOS = ("tcp", "udp")


# -- declared services --------------------------------------------------------

def parse_declared(text):
    """({(port, proto): [networks]}, [problems]). An empty network list means
    "from anywhere"."""
    out, problems = {}, []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        port, _, proto = parts[0].partition("/")
        proto = (proto or "tcp").lower()
        try:
            p = int(port)
            if not 0 < p < 65536 or proto not in PROTOS:
                raise ValueError
            nets = [ipaddress.ip_network(x, strict=False) for x in parts[1:]]
        except ValueError:
            problems.append(f"line {n}: {raw.strip()[:80]!r}")
            continue
        out.setdefault((p, proto), []).extend(nets)
        if len(out) >= MAX_DECLARED:
            problems.append(f"more than {MAX_DECLARED} declared services; the rest ignored")
            break
    return out, problems


def load_declared(paths=DECLARED_PATHS):
    """(declared, source path, problems); declared is None when no file exists:
    the owner has not said what this server should expose."""
    for path in paths:
        try:
            with open(path, errors="replace") as fh:
                text = fh.read(256 * 1024)
        except FileNotFoundError:
            continue
        except OSError as exc:
            return None, path, [f"unreadable: {exc.strerror or exc}"]
        declared, problems = parse_declared(text)
        return declared, path, problems
    return None, "", []


def is_declared(declared, port, proto, remote_ip=None):
    """True when (port, proto) is declared and, if it names networks, the
    remote address is inside one of them."""
    if not declared:
        return False
    nets = declared.get((port, _base_proto(proto)))
    if nets is None:
        return False
    if not nets or remote_ip is None:
        return True
    try:
        addr = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in nets)


def _base_proto(proto):
    return "udp" if str(proto).startswith("udp") else "tcp"


# -- listeners ----------------------------------------------------------------

# Client sockets that bind a fixed port to receive replies: not services.
CLIENT_PORTS = {(68, "udp"): "DHCP client", (546, "udp"): "DHCPv6 client"}


def ephemeral_range(path="/proc/sys/net/ipv4/ip_local_port_range"):
    """(low, high) ports the kernel hands to outgoing sockets."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lo, hi = (int(x) for x in fh.read().split()[:2])
            return lo, hi
    except (OSError, ValueError):
        return 32768, 60999


def exposed_listeners(table):
    """{(port, proto): sorted bind addresses} for sockets that accept from
    beyond loopback: TCP LISTEN and bound unconnected UDP."""
    out = {}
    for conn in (table or {}).values():
        proto = _base_proto(conn.get("proto", ""))
        if proto == "tcp" and conn.get("state") != "LISTEN":
            continue
        if proto == "udp" and conn.get("remote_port") not in (0, None):
            continue
        ip = conn.get("local_ip") or ""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or (conn.get("local_port"), proto) in CLIENT_PORTS:
            continue
        out.setdefault((conn.get("local_port"), proto), set()).add(ip)
    return {k: sorted(v) for k, v in out.items()}


# -- firewall snapshot ---------------------------------------------------------

def load_netstate(net_dir=NET_DIR, now=None):
    """(snapshot, problem). problem is "" when a fresh snapshot was read."""
    now = time.time() if now is None else now
    path = os.path.join(net_dir, NETSTATE_FILE)
    try:
        st = os.stat(path)
        if st.st_size > NETSTATE_MAX_BYTES:
            return None, f"{path} is larger than {NETSTATE_MAX_BYTES} bytes"
        with open(path, errors="replace") as fh:
            snap = json.load(fh)
    except FileNotFoundError:
        return None, "the argus-netstate unit is not installed or has not run"
    except (OSError, ValueError) as exc:
        return None, f"{path} unreadable: {exc}"
    if not isinstance(snap, dict):
        return None, f"{path} is not a snapshot"
    age = now - float(snap.get("ts") or 0)
    if age > NETSTATE_MAX_AGE_S:
        return snap, f"the firewall snapshot is {int(age // 60)} min old (argus-netstate stopped?)"
    return snap, ""


# -- nftables evaluation ------------------------------------------------------

def _chains(ruleset):
    """({(family, table, chain): chain}, {(family, table, chain): [rule exprs]})."""
    chains, rules = {}, {}
    for item in (ruleset or {}).get("nftables", []) if isinstance(ruleset, dict) else []:
        if not isinstance(item, dict):
            continue
        if "chain" in item and isinstance(item["chain"], dict):
            c = item["chain"]
            chains[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "rule" in item and isinstance(item["rule"], dict):
            r = item["rule"]
            rules.setdefault((r.get("family"), r.get("table"), r.get("chain")), []).append(
                r.get("expr") or [])
    return chains, rules


def _port_matches(right, port):
    """True / False when `right` (an nft JSON value) does or does not contain
    port; None when it is something this evaluator does not read."""
    if isinstance(right, int):
        return right == port
    if isinstance(right, dict):
        if "set" in right:
            hits = [_port_matches(x, port) for x in right["set"]]
            if any(h is True for h in hits):
                return True
            return None if any(h is None for h in hits) else False
        if "range" in right and isinstance(right["range"], list) and len(right["range"]) == 2:
            lo, hi = right["range"]
            if isinstance(lo, int) and isinstance(hi, int):
                return lo <= port <= hi
        return None
    if isinstance(right, list):
        return _port_matches({"set": right}, port)
    return None


def _unsure(applies):
    """A match this evaluator cannot read: a rule already known not to apply
    stays so; otherwise whether it applies is unknown."""
    return False if applies is False else None


def _rule_for(expr, port, proto):
    """Classify one rule for a packet to (port, proto) arriving from outside on
    a non-loopback interface, as a new connection.

    Returns (applies, verdict, restricted): applies True/False/None (None =
    cannot tell), verdict "accept"/"drop"/"jump:<chain>"/"" and restricted True
    when the rule narrows sources."""
    applies, restricted, verdict = True, False, ""
    for e in expr:
        if not isinstance(e, dict):
            applies = _unsure(applies)
            continue
        if "match" in e:
            m = e["match"] if isinstance(e["match"], dict) else {}
            left, right, op = m.get("left") or {}, m.get("right"), m.get("op", "==")
            neg = op == "!="
            if "payload" in left:
                pl = left["payload"] or {}
                field, lproto = pl.get("field"), pl.get("protocol")
                if field == "dport":
                    if lproto in PROTOS and lproto != proto:
                        hit = False
                    elif lproto in ("th",) or lproto == proto:
                        hit = _port_matches(right, port)
                    else:
                        hit = None
                    if hit is None:
                        applies = _unsure(applies)
                    elif hit == neg:
                        applies = False
                elif field == "saddr":
                    restricted = True
                elif field in ("sport", "daddr"):
                    applies = _unsure(applies)
                else:
                    applies = _unsure(applies)
            elif "meta" in left:
                key = (left["meta"] or {}).get("key")
                if key in ("iifname", "iif") and right in ("lo",) and not neg:
                    applies = False             # loopback only; never from outside
                elif key == "l4proto":
                    vals = right if isinstance(right, list) else (right.get("set") if isinstance(right, dict) else [right])
                    if isinstance(vals, list) and all(isinstance(v, str) for v in vals):
                        if (proto in vals) == neg:
                            applies = False
                    else:
                        applies = _unsure(applies)
                elif key in ("nfproto",):
                    pass
                else:
                    applies = _unsure(applies)
            elif "ct" in left:
                key = (left["ct"] or {}).get("key")
                vals = right if isinstance(right, list) else (right.get("set") if isinstance(right, dict) else [right])
                if key == "state" and isinstance(vals, list):
                    new_hits = "new" in vals or not ({"established", "related", "invalid"} & set(vals))
                    if neg:
                        new_hits = "new" not in vals
                    if not new_hits:
                        applies = False         # established/related: not a new inbound connection
                else:
                    applies = _unsure(applies)
            else:
                applies = _unsure(applies)
        elif "accept" in e:
            verdict = "accept"
        elif "drop" in e or "reject" in e:
            verdict = "drop"
        elif "jump" in e or "goto" in e:
            target = (e.get("jump") or e.get("goto") or {}).get("target", "")
            verdict = ("goto:" if "goto" in e else "jump:") + str(target)
        elif "return" in e:
            verdict = "return"
        elif "xt" in e:
            applies = _unsure(applies)      # an iptables-nft extension match
        # counter, log, limit, mangle, notrack ... carry no verdict
    return applies, verdict, restricted


def _walk(chains, rules, key, port, proto, depth=0):
    """Verdict of one chain for the packet: OPEN, FILTERED, RESTRICTED,
    UNKNOWN or None (fell through without a verdict)."""
    if depth > JUMP_DEPTH:
        return UNKNOWN
    uncertain, restricted_seen = False, False
    for expr in rules.get(key, []):
        applies, verdict, restricted = _rule_for(expr, port, proto)
        if applies is False or not verdict:
            continue
        if verdict.startswith(("jump:", "goto:")):
            target = (key[0], key[1], verdict.split(":", 1)[1])
            if target not in chains:
                uncertain = True
                continue
            sub = _walk(chains, rules, target, port, proto, depth + 1)
            if sub is None:
                if verdict.startswith("goto:"):
                    return None
                continue
            if applies is None:
                uncertain = True
                continue
            if sub == OPEN and restricted:
                return RESTRICTED
            return sub
        if verdict == "return":
            if applies is None:
                uncertain = True
                continue
            return None
        if applies is None:
            # Could match: an accept we cannot read may open the port, a drop
            # we cannot read may close it. Either way the outcome is unknown.
            uncertain = True
            continue
        if verdict == "accept":
            if restricted:
                restricted_seen = True
                continue        # some sources only; later rules decide the rest
            return UNKNOWN if uncertain else OPEN
        if verdict == "drop":
            if restricted:
                continue
            return UNKNOWN if uncertain else (RESTRICTED if restricted_seen else FILTERED)
    if uncertain:
        return UNKNOWN
    return RESTRICTED if restricted_seen else None


def nft_reachability(ruleset, port, proto):
    """Whether a new inbound connection to (port, proto) passes every base
    input chain in the ruleset: OPEN, FILTERED, RESTRICTED or UNKNOWN."""
    chains, rules = _chains(ruleset)
    base = [k for k, c in chains.items()
            if c.get("hook") == "input" and c.get("type", "filter") == "filter"
            and c.get("family") in ("inet", "ip", "ip6")]
    if not base:
        return OPEN         # no input hook: netfilter filters nothing inbound
    results = []
    for key in base:
        verdict = _walk(chains, rules, key, port, proto)
        if verdict is None:
            policy = (chains[key].get("policy") or "accept").lower()
            verdict = OPEN if policy == "accept" else FILTERED
        results.append(verdict)
    if FILTERED in results:
        return FILTERED     # every chain must accept; one drop closes it
    if UNKNOWN in results:
        return UNKNOWN
    if RESTRICTED in results:
        return RESTRICTED
    return OPEN


def nft_input_policies(ruleset):
    """[(family table/chain, policy)] for base input filter chains."""
    chains, _ = _chains(ruleset)
    return sorted((f"{k[0]} {k[1]}/{k[2]}", (c.get("policy") or "accept").lower())
                  for k, c in chains.items()
                  if c.get("hook") == "input" and c.get("family") in ("inet", "ip", "ip6"))


# -- ufw / firewalld text (fallback when nft is unreadable) --------------------

FIREWALLD_SERVICES = {
    "ssh": [(22, "tcp")], "http": [(80, "tcp")], "https": [(443, "tcp")],
    "dns": [(53, "tcp"), (53, "udp")], "smtp": [(25, "tcp")], "smtps": [(465, "tcp")],
    "submission": [(587, "tcp")], "imaps": [(993, "tcp")], "pop3s": [(995, "tcp")],
    "mysql": [(3306, "tcp")], "postgresql": [(5432, "tcp")], "redis": [(6379, "tcp")],
    "cockpit": [(9090, "tcp")], "dhcpv6-client": [(546, "udp")], "ntp": [(123, "udp")],
    "openvpn": [(1194, "udp")], "wireguard": [(51820, "udp")],
}


def parse_ufw(text):
    """{"active": bool|None, "default_in": str, "allow": {(port, proto): restricted}}."""
    out = {"active": None, "default_in": "", "allow": {}}
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("Status:"):
            out["active"] = s.split(":", 1)[1].strip() == "active"
        elif s.startswith("Default:"):
            for part in s.split(":", 1)[1].split(","):
                if "(incoming)" in part:
                    out["default_in"] = part.split("(")[0].strip()
        else:
            cols = s.split()
            if len(cols) >= 3 and "ALLOW" in cols:
                port, _, proto = cols[0].partition("/")
                if port.isdigit():
                    src = " ".join(cols[cols.index("ALLOW") + 2:]) if "IN" in cols else " ".join(cols[cols.index("ALLOW") + 1:])
                    restricted = not src.startswith("Anywhere")
                    for pr in ([proto] if proto in PROTOS else list(PROTOS)):
                        out["allow"][(int(port), pr)] = restricted
    return out


def parse_firewalld(text):
    """{"target": str, "allow": {(port, proto): False}, "sources": bool}."""
    out = {"target": "", "allow": {}, "sources": False}
    for line in (text or "").splitlines():
        key, _, val = line.strip().partition(":")
        val = val.strip()
        if key == "target":
            out["target"] = val
        elif key == "services":
            for name in val.split():
                for pp in FIREWALLD_SERVICES.get(name, []):
                    out["allow"][pp] = False
        elif key == "ports":
            for item in val.split():
                port, _, proto = item.partition("/")
                if port.isdigit() and proto in PROTOS:
                    out["allow"][(int(port), proto)] = False
        elif key == "sources" and val:
            out["sources"] = True
    return out


def reachability(snapshot, port, proto):
    """(verdict, source) for a new inbound connection to (port, proto) from
    the netstate snapshot; UNKNOWN when nothing could be read."""
    if not isinstance(snapshot, dict):
        return UNKNOWN, ""
    nft = snapshot.get("nft")
    if isinstance(nft, dict) and nft.get("ok") and isinstance(nft.get("ruleset"), dict):
        return nft_reachability(nft["ruleset"], port, proto), "nftables"
    ufw = snapshot.get("ufw")
    if isinstance(ufw, dict) and ufw.get("ok"):
        u = parse_ufw(ufw.get("text"))
        if u["active"] is False:
            return OPEN, "ufw (inactive)"
        if u["active"]:
            if (port, proto) in u["allow"]:
                return (RESTRICTED if u["allow"][(port, proto)] else OPEN), "ufw"
            return (FILTERED if u["default_in"] in ("deny", "reject") else OPEN), "ufw"
    fwd = snapshot.get("firewalld")
    if isinstance(fwd, dict) and fwd.get("ok"):
        f = parse_firewalld(fwd.get("text"))
        if (port, proto) in f["allow"]:
            return OPEN, "firewalld"
        if f["target"] in ("default", "%%REJECT%%", "DROP", "REJECT"):
            return FILTERED, "firewalld"
        return UNKNOWN, "firewalld"
    return UNKNOWN, ""
