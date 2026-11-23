"""Signed execution identities: who launched a process tree, known in advance.

An identity is a small canonical-JSON record signed with an Ed25519 key that
only the capability-holding JARVIS daemon can read (root-owned 0400, read
through CAP_DAC_READ_SEARCH; see EVIDENCE-FABRIC.md for why a same-user
attacker cannot read it). It binds

  * who: an actor (jarvis, claude, codex, test_suite, user) and whether that
    actor was observed by the daemon or declared by the requester;
  * which process: pid, kernel start time (clock ticks since boot), boot id
    and executable path. The daemon observes them through kernel peer
    credentials; the request never supplies them;
  * for how long: an expiry on CLOCK_BOOTTIME, which wall-clock jumps and
    standby cannot stretch, together with the boot id.

`lookup(pid, start)` answers for one process and `attribute(pid)` walks its
live ancestry. Both return None unless the signature, binding, boot and
expiry all verify, and the process still runs the same executable (execve
keeps the pid and start time, so the executable path is rechecked). None
means "no provenance", never "benign" (P2, P3).
"""

import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

VERSION = 1
ACTORS = ("jarvis", "claude", "codex", "test_suite", "user")
# Actors a requester may declare over the socket. "jarvis" is only ever
# issued by the daemon for itself.
DECLARABLE = ("claude", "codex", "test_suite", "user")

KEY_DIR = Path("/etc/jarvis/provenance")
PRIVATE_KEY = KEY_DIR / "ed25519.key"
PUBLIC_KEY = KEY_DIR / "ed25519.pub"
STATE_DIR = Path(os.path.expanduser("~/.jarvis/provenance"))
LEDGER = STATE_DIR / "ledger.jsonl"

MAX_TTL_S = 24 * 3600
MAX_ROW_BYTES = 4096
LEDGER_ROTATE_BYTES = 4 << 20        # one rotated generation is kept
MAX_ANCESTRY = 64
MAX_TEXT = 120
MAX_CAPABILITIES = 16


class ProvenanceError(RuntimeError):
    pass


# -- process facts (Linux /proc) ---------------------------------------------

def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def boottime_s():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def proc_stat(pid):
    """(ppid, start ticks) of a live process, or None.

    The command name can hold spaces and parentheses, so fields are split
    after the last ')'."""
    try:
        with open(f"/proc/{int(pid)}/stat", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except (OSError, ValueError):
        return None
    tail = raw.rpartition(")")[2].split()
    try:
        # tail[0] is state (field 3); ppid is field 4, starttime field 22.
        return int(tail[1]), int(tail[19])
    except (IndexError, ValueError):
        return None


def proc_exe(pid):
    try:
        return os.readlink(f"/proc/{int(pid)}/exe")
    except (OSError, ValueError):
        return ""


def file_sha256(path, limit=512 << 20):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            read = 0
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                read += len(chunk)
                if read > limit:
                    return ""
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# -- canonical form and keys --------------------------------------------------

def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _clean_text(value, limit=MAX_TEXT):
    text = "".join(c for c in str(value or "") if c.isprintable())
    return text[:limit]


def load_private_key(path=PRIVATE_KEY):
    """The signing key, or None when this process cannot read it (normal
    for everything but the capability-holding daemon)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        raw = Path(path).read_bytes()
        if len(raw) != 32:
            return None
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        return None


def load_public_key(path=PUBLIC_KEY):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw = bytes.fromhex(Path(path).read_text(encoding="ascii").strip())
        if len(raw) != 32:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def key_id(public_key):
    from cryptography.hazmat.primitives import serialization
    raw = public_key.public_bytes(serialization.Encoding.Raw,
                                  serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair(key_dir, owner=0):
    """Create the signing key pair if absent (root, at deploy). Returns the
    key id. The private key is 0400 and the public key 0444, both owned by
    `owner` (root in production)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key_dir = Path(key_dir)
    private, public = key_dir / PRIVATE_KEY.name, key_dir / PUBLIC_KEY.name
    key_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chown(key_dir, owner, owner)
    os.chmod(key_dir, 0o755)
    if not private.exists():
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw,
                                serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        os.chown(private, owner, owner)
        pub_hex = key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw).hex()
        tmp = public.with_suffix(".new")
        tmp.write_text(pub_hex + "\n", encoding="ascii")
        os.chown(tmp, owner, owner)
        os.chmod(tmp, 0o444)
        os.replace(tmp, public)
    return key_id(load_public_key(public))


# -- records --------------------------------------------------------------------

def make_identity(*, actor, basis, pid, start, exe, uid, release_id, ttl_s,
                  session="", workspace="", capabilities=(), purpose="",
                  parent=None, parent_identity=None, boot=None, now=None, boot_now=None):
    """An unsigned identity record, validated and bounded."""
    if actor not in ACTORS:
        raise ProvenanceError(f"unknown actor {actor!r}")
    if basis not in ("observed", "declared"):
        raise ProvenanceError("basis must be observed or declared")
    ttl_s = int(ttl_s)
    if not 0 < ttl_s <= MAX_TTL_S:
        raise ProvenanceError(f"ttl must be 1..{MAX_TTL_S} seconds")
    caps = sorted({_clean_text(c, 40) for c in capabilities if _clean_text(c, 40)})
    if len(caps) > MAX_CAPABILITIES:
        raise ProvenanceError("too many capabilities")
    now = int(time.time() if now is None else now)
    boot_now = boottime_s() if boot_now is None else boot_now
    return {
        "v": VERSION,
        "id": secrets.token_hex(16),
        "actor": actor,
        "actor_basis": basis,
        "session": _clean_text(session, 64),
        "workspace": _clean_text(workspace, 256),
        "capabilities": caps,
        # Declared, not enforced: capsules do not yet restrict network or
        # filesystem access (EVIDENCE-FABRIC.md, status).
        "capabilities_enforced": False,
        "purpose": _clean_text(purpose),
        "binding": {"pid": int(pid), "start": int(start), "exe": str(exe)[:512],
                    "uid": int(uid), "boot_id": boot if boot is not None else boot_id()},
        "parent": parent,
        "parent_identity": parent_identity,
        "release_id": release_id or "",
        "issued_at": now,
        "expires_at": now + ttl_s,
        "issued_boot_s": round(boot_now, 3),
        "expires_boot_s": round(boot_now + ttl_s, 3),
        "nonce": secrets.token_hex(8),
    }


def sign(record, private_key):
    return {"identity": record, "key": key_id(private_key.public_key()),
            "sig": private_key.sign(canonical(record)).hex()}


def verify_row(row, public_key):
    """The identity record of a signed row, or None. Pure: no process checks."""
    if public_key is None or not isinstance(row, dict):
        return None
    record, sig = row.get("identity"), row.get("sig")
    if not isinstance(record, dict) or not isinstance(sig, str):
        return None
    try:
        public_key.verify(bytes.fromhex(sig), canonical(record))
    except Exception:
        return None
    if record.get("v") != VERSION or record.get("actor") not in ACTORS:
        return None
    binding = record.get("binding")
    if not isinstance(binding, dict):
        return None
    return record


def live_problem(record, *, boot=None, boot_now=None, stat=None, exe=None):
    """Why a verified record does not describe the live process now, or ""."""
    binding = record["binding"]
    if binding.get("boot_id") != (boot_id() if boot is None else boot):
        return "different boot"
    boot_now = boottime_s() if boot_now is None else boot_now
    if boot_now >= float(record.get("expires_boot_s", 0)):
        return "expired"
    stat = proc_stat(binding["pid"]) if stat is None else stat
    if not stat or stat[1] != binding.get("start"):
        return "process gone or pid reused"
    exe = proc_exe(binding["pid"]) if exe is None else exe
    if exe != binding.get("exe"):
        return "process now runs a different executable"
    return ""


@dataclass(frozen=True)
class Provenance:
    """A verified identity for a live process (attribution, not permission)."""
    identity_id: str
    actor: str
    actor_basis: str
    session: str
    release_id: str
    pid: int
    start: int
    chain: tuple = field(default=())     # pids from the queried process up to the root
    capabilities: tuple = field(default=())
    capabilities_enforced: bool = False
    expires_at: int = 0

    def as_dict(self):
        return {"identity_id": self.identity_id, "actor": self.actor,
                "actor_basis": self.actor_basis, "session": self.session,
                "release_id": self.release_id, "pid": self.pid, "start": self.start,
                "chain": list(self.chain), "capabilities": list(self.capabilities),
                "capabilities_enforced": self.capabilities_enforced,
                "expires_at": self.expires_at, "advisory": "attribution only",
                # A declared actor can be self-assigned by any process of the
                # user: a grouping key, never a reason to lower a finding.
                "mitigates_findings": False}


# -- ledger ---------------------------------------------------------------------

_append_lock = threading.Lock()


def _still_live_lines(path, budget):
    """Rows of `path` whose identity still binds a live, unexpired process:
    the daemon's own first, then newest first, within `budget` bytes.

    Carried into each new generation so that a flood of requests (anything
    of the same user may ask) cannot rotate genuine identities out of the
    ledger. Signatures are checked on read, not here."""
    boot, now, rows = boot_id(), boottime_s(), []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for order, line in enumerate(fh):
                if len(line) > MAX_ROW_BYTES:
                    continue
                try:
                    record = json.loads(line)["identity"]
                    b = record["binding"]
                    if (b["boot_id"] != boot or now >= float(record["expires_boot_s"])
                            or (proc_stat(b["pid"]) or (0, None))[1] != b["start"]):
                        continue
                except (ValueError, KeyError, TypeError):
                    continue
                rows.append((record.get("actor") != "jarvis", -order, line))
    except OSError:
        return []
    kept, used = [], 0
    for _own_last, _newest, line in sorted(rows):
        if used + len(line) > budget:
            continue
        kept.append(line)
        used += len(line)
    return kept


def append(row, ledger=LEDGER):
    """Append one signed row. Rotates at LEDGER_ROTATE_BYTES, keeping one
    older generation and carrying identities that are still live, so disk
    use stays under twice that budget (P7) and flooding cannot evict them."""
    line = json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
    if len(line) > MAX_ROW_BYTES:
        raise ProvenanceError("identity row too large")
    ledger = Path(ledger)
    with _append_lock:
        ledger.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        carried = []
        try:
            if ledger.stat().st_size + len(line) > LEDGER_ROTATE_BYTES:
                older = ledger.with_name(ledger.name + ".1")
                os.replace(ledger, older)
                carried = _still_live_lines(older, LEDGER_ROTATE_BYTES // 2)
        except FileNotFoundError:
            pass
        fd = os.open(ledger, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.writelines(carried)
            fh.write(line)


class Index:
    """Verified identities by (pid, start), reloaded when the ledger changes.

    Rows whose signature fails are skipped and counted, never trusted."""

    def __init__(self, ledger=LEDGER, public_key_path=PUBLIC_KEY):
        self.ledger = Path(ledger)
        self.public_key_path = Path(public_key_path)
        self._stamp = None
        self._by_binding = {}
        self.rejected = 0
        self._lock = threading.Lock()

    def _files(self):
        return [self.ledger.with_name(self.ledger.name + ".1"), self.ledger]

    def _current_stamp(self):
        stamp = []
        for path in self._files():
            try:
                st = path.stat()
                stamp.append((st.st_ino, st.st_size, st.st_mtime_ns))
            except OSError:
                stamp.append(None)
        try:
            st = self.public_key_path.stat()
            stamp.append((st.st_ino, st.st_mtime_ns))
        except OSError:
            stamp.append(None)
        return tuple(stamp)

    def _reload(self):
        public_key = load_public_key(self.public_key_path)
        by_binding, rejected = {}, 0
        for path in self._files():
            try:
                fh = open(path, encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    if len(line) > MAX_ROW_BYTES:
                        rejected += 1
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        rejected += 1
                        continue
                    record = verify_row(row, public_key)
                    if record is None:
                        rejected += 1
                        continue
                    b = record["binding"]
                    key = (b.get("pid"), b.get("start"))
                    # The latest issued identity for a binding wins (renewal).
                    old = by_binding.get(key)
                    if old is None or record["issued_boot_s"] >= old["issued_boot_s"]:
                        by_binding[key] = record
        self._by_binding, self.rejected = by_binding, rejected

    def get(self, pid, start):
        with self._lock:
            stamp = self._current_stamp()
            if stamp != self._stamp:
                self._reload()
                self._stamp = stamp
            return self._by_binding.get((int(pid), int(start)))


_default_index = None


def default_index():
    global _default_index
    if _default_index is None:
        _default_index = Index()
    return _default_index


def _provenance(record, chain):
    b = record["binding"]
    return Provenance(identity_id=record["id"], actor=record["actor"],
                      actor_basis=record["actor_basis"], session=record.get("session", ""),
                      release_id=record.get("release_id", ""), pid=b["pid"], start=b["start"],
                      chain=tuple(chain), capabilities=tuple(record.get("capabilities") or ()),
                      capabilities_enforced=bool(record.get("capabilities_enforced")),
                      expires_at=int(record.get("expires_at", 0)))


def lookup(pid, start, index=None):
    """Verified provenance for exactly this live process, or None."""
    index = index or default_index()
    record = index.get(pid, start)
    if record is None or live_problem(record):
        return None
    return _provenance(record, (int(pid),))


def attribute(pid, index=None):
    """Nearest verified identity on the live ancestry of `pid`, or None.

    Walks parent links through /proc, bounded to MAX_ANCESTRY hops. A
    process that escaped its launcher's tree (reparented to init after the
    launcher exited) is correctly left unattributed."""
    index = index or default_index()
    chain, seen = [], set()
    current = int(pid)
    for _ in range(MAX_ANCESTRY):
        if current <= 0 or current in seen:
            return None
        seen.add(current)
        stat = proc_stat(current)
        if stat is None:
            return None
        chain.append(current)
        record = index.get(current, stat[1])
        if record is not None and not live_problem(record, stat=stat):
            return _provenance(record, chain)
        current = stat[0]
    return None
