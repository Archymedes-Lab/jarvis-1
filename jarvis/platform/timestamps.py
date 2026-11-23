"""OpenTimestamps anchoring: prove a digest existed, without revealing it.

Only a 32-byte SHA-256 digest leaves the machine. Public calendar servers
aggregate submitted digests into a Merkle tree whose root is committed to a
Bitcoin transaction, so once a proof is upgraded, nobody (including an
administrator of this machine) can later produce a different history that
matches it. The proofs are standard `.ots` files: `ots verify <file>` from the
official client checks them independently of JARVIS.

Only the fixed calendar origins below are contacted, through a direct HTTPS
opener that ignores proxy settings and refuses redirects. URLs recorded inside
a proof are never followed unless they are on this allowlist: proof files sit
where anything running as the user could edit them.
"""

import hashlib
import json
import urllib.error
import urllib.request

CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
)
MIN_CALENDARS = 2
# Calendars name their own canonical servers in pending attestations; only
# these are asked for upgrades.
UPGRADE_CALENDARS = (
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
    "https://btc.calendar.catallaxy.com",
)
# Block-header source for checking a Bitcoin attestation. It is trusted only
# to report the chain honestly; an attacker on this machine cannot alter it.
EXPLORER = "https://blockstream.info/api"
TIMEOUT_S = 15
MAX_RESPONSE = 64 * 1024

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAJOR_VERSION = 1
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN = bytes.fromhex("0588960d73d71901")
OP_SHA256, OP_APPEND, OP_PREPEND = 0x08, 0xF0, 0xF1
_UNARY = {0x08: lambda m: hashlib.sha256(m).digest(),
          0x02: lambda m: hashlib.sha1(m).digest()}
_BINARY = {OP_APPEND: lambda m, a: m + a, OP_PREPEND: lambda m, a: a + m}
MAX_DEPTH = 256
MAX_MSG = 4096
MAX_VARBYTES = 8192


class ProofError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("redirects are refused")


def _fetch(url, data=None, accept="application/vnd.opentimestamps.v1"):
    """(status, body) for one bounded request; (None, b"") on failure."""
    req = urllib.request.Request(url, data=data, headers={
        "Accept": accept, "User-Agent": "jarvis-evidence/1"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            body = resp.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                return None, b""
            return resp.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError, ValueError):
        return None, b""


# -- serialization -----------------------------------------------------------

def _varuint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _varbytes(data):
    return _varuint(len(data)) + data


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def byte(self):
        if self.pos >= len(self.data):
            raise ProofError("truncated proof")
        self.pos += 1
        return self.data[self.pos - 1]

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ProofError("truncated proof")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def varuint(self):
        value = shift = 0
        while True:
            byte = self.byte()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise ProofError("varuint too long")

    def varbytes(self):
        n = self.varuint()
        if n > MAX_VARBYTES:
            raise ProofError("field too long")
        return self.take(n)


def _node(msg):
    return {"msg": msg, "att": [], "ops": []}


def _parse(reader, msg, depth=0):
    if depth > MAX_DEPTH or len(msg) > MAX_MSG:
        raise ProofError("proof too deep or message too long")
    node = _node(msg)

    def item(tag):
        if tag == 0x00:
            node["att"].append((reader.take(8), reader.varbytes()))
        elif tag in _BINARY:
            arg = reader.varbytes()
            node["ops"].append((bytes([tag]) + _varbytes(arg),
                                _parse(reader, _BINARY[tag](msg, arg), depth + 1)))
        elif tag in _UNARY:
            node["ops"].append((bytes([tag]), _parse(reader, _UNARY[tag](msg), depth + 1)))
        else:
            raise ProofError(f"unsupported operation 0x{tag:02x}")

    tag = reader.byte()
    while tag == 0xFF:
        item(reader.byte())
        tag = reader.byte()
    item(tag)
    return node


def _serialize(node):
    items = [b"\x00" + tag + _varbytes(payload) for tag, payload in node["att"]]
    items += [op + _serialize(child) for op, child in node["ops"]]
    if not items:
        raise ProofError("empty timestamp")
    return b"".join(b"\xff" + item for item in items[:-1]) + items[-1]


def parse_timestamp(data, msg):
    reader = _Reader(data)
    node = _parse(reader, msg)
    if reader.pos != len(data):
        raise ProofError("trailing bytes after timestamp")
    return node


def serialize_file(digest, node):
    return MAGIC + _varuint(MAJOR_VERSION) + bytes([OP_SHA256]) + digest + _serialize(node)


def parse_file(data):
    """-> (digest, timestamp tree) of a detached SHA-256 `.ots` proof."""
    reader = _Reader(data)
    if reader.take(len(MAGIC)) != MAGIC:
        raise ProofError("not an OpenTimestamps proof")
    if reader.varuint() != MAJOR_VERSION:
        raise ProofError("unsupported proof version")
    if reader.byte() != OP_SHA256:
        raise ProofError("proof is not over a SHA-256 digest")
    digest = reader.take(32)
    node = _parse(reader, digest)
    if reader.pos != len(data):
        raise ProofError("trailing bytes after proof")
    return digest, node


def _walk(node):
    yield node
    for _op, child in node["ops"]:
        yield from _walk(child)


def _merge(into, other):
    for att in other["att"]:
        if att not in into["att"]:
            into["att"].append(att)
    for op, child in other["ops"]:
        existing = next((c for o, c in into["ops"] if o == op), None)
        if existing is None:
            into["ops"].append((op, child))
        else:
            _merge(existing, child)


def _pending_url(payload):
    try:
        return _Reader(payload).varbytes().decode("ascii")
    except (ProofError, UnicodeDecodeError):
        return ""


def attestations(node):
    """[(kind, detail, message)] for every attestation in a proof tree."""
    out = []
    for n in _walk(node):
        for tag, payload in n["att"]:
            if tag == PENDING:
                out.append(("pending", _pending_url(payload), n["msg"]))
            elif tag == BITCOIN:
                try:
                    out.append(("bitcoin", _Reader(payload).varuint(), n["msg"]))
                except ProofError:
                    out.append(("unknown", tag.hex(), n["msg"]))
            else:
                out.append(("unknown", tag.hex(), n["msg"]))
    return out


# -- network -----------------------------------------------------------------

def submit(digest, calendars=CALENDARS, fetch=None):
    """Submit a digest; -> (.ots bytes, calendars that accepted it).

    Raises ProofError unless at least MIN_CALENDARS independent calendars
    returned a well-formed commitment for exactly this digest.
    """
    fetch = fetch or _fetch
    if len(digest) != 32:
        raise ProofError("digest must be 32 bytes")
    root, accepted = _node(digest), []
    for calendar in calendars:
        status, body = fetch(calendar + "/digest", data=digest)
        if status != 200 or not body:
            continue
        try:
            _merge(root, parse_timestamp(body, digest))
        except ProofError:
            continue
        accepted.append(calendar)
    if len(accepted) < MIN_CALENDARS:
        raise ProofError(f"only {len(accepted)} calendar(s) accepted the digest")
    return serialize_file(digest, root), accepted


def upgrade(data, fetch=None):
    """Ask allowlisted calendars for completed Bitcoin proofs.

    -> (.ots bytes, changed). Pending attestations stay beside any upgrade.
    """
    fetch = fetch or _fetch
    digest, root = parse_file(data)
    changed = False
    for node in list(_walk(root)):
        for tag, payload in list(node["att"]):
            url = _pending_url(payload) if tag == PENDING else ""
            if url.rstrip("/") not in UPGRADE_CALENDARS:
                continue
            status, body = fetch(url.rstrip("/") + "/timestamp/" + node["msg"].hex())
            if status != 200 or not body:
                continue
            try:
                _merge(node, parse_timestamp(body, node["msg"]))
                changed = True
            except ProofError:
                continue
    return (serialize_file(digest, root) if changed else data), changed


def verify_bitcoin(height, msg, fetch=None):
    """True when block `height`'s Merkle root equals the attested message,
    False when it differs, None when the explorer could not be asked."""
    fetch = fetch or _fetch
    status, block_hash = fetch(f"{EXPLORER}/block-height/{int(height)}", accept="text/plain")
    if status != 200:
        return None
    block_hash = block_hash.decode("ascii", "replace").strip()
    if len(block_hash) != 64 or any(c not in "0123456789abcdef" for c in block_hash):
        return None
    status, body = fetch(f"{EXPLORER}/block/{block_hash}", accept="application/json")
    if status != 200:
        return None
    try:
        merkle = json.loads(body)["merkle_root"]
        return bytes.fromhex(merkle)[::-1] == msg
    except (ValueError, KeyError, TypeError):
        return None
