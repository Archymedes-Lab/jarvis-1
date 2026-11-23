"""The issuing side of execution identities, run inside the JARVIS daemon.

Only a process that can read the private key can issue identities. In
production that is the sealed daemon, through CAP_DAC_READ_SEARCH; see
identity.py. The authority:

  * issues one identity for the daemon itself at start (actor "jarvis",
    basis "observed"), so everything the daemon launches is attributable
    through its live ancestry;
  * answers requests on a Unix socket in ~/.jarvis/provenance/. The kernel
    reports the requester's pid and uid (SO_PEERCRED). The start time and
    executable are read from /proc. A pidfd (SO_PEERPIDFD) confirms the pid
    was not recycled in between. The request supplies only the declared
    actor (never "jarvis"), session, workspace, capabilities, purpose and TTL.

Anything the same user runs can connect. That is by design: the identity
says "this process asked to be attributed to a codex session", labelled
declared. It confers no trust (P2). Requests are bounded in size, time and
rate (P7). Any failure is logged and leaves the daemon running.
"""

import json
import os
import select
import socket
import struct
import threading
import time
from pathlib import Path

from jarvis.platform.provenance import identity as ident

SOCKET = ident.STATE_DIR / "authority.sock"
MAX_REQUEST = 4096
REQUEST_TIMEOUT_S = 2.0
RATE_PER_MINUTE = 30
SO_PEERPIDFD = 77          # Linux 6.5+
SELF_TTL_S = 6 * 3600      # renewed well before expiry by the renew loop


def _current_release_id():
    from jarvis.core.paths import REPO_ROOT
    from jarvis.platform.provenance import release
    manifest = release.read_manifest(REPO_ROOT)
    try:
        return release.manifest_release_id(manifest) if manifest else ""
    except ValueError:
        return ""


def _peer(conn):
    """(pid, uid, pidfd or -1) of the connected peer, from the kernel."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    pidfd = -1
    try:
        pidfd = struct.unpack("i", conn.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]
    except OSError:
        pass
    return pid, uid, pidfd


def _pidfd_alive(pidfd):
    """A pidfd polls readable once its process has exited."""
    if pidfd < 0:
        return True
    readable, _, _ = select.select([pidfd], [], [], 0)
    return not readable


class Authority:
    def __init__(self, private_key, *, ledger=ident.LEDGER, socket_path=SOCKET,
                 release_id="", clock=time.monotonic):
        self.key = private_key
        self.ledger = Path(ledger)
        self.socket_path = Path(socket_path)
        self.release_id = release_id
        self.clock = clock
        self._recent = []
        self._lock = threading.Lock()
        self.self_row = None
        self.stats = {"issued": 0, "refused": 0}

    # -- issuing ----------------------------------------------------------------

    def _rate_ok(self):
        now = self.clock()
        with self._lock:
            self._recent = [t for t in self._recent if now - t < 60]
            if len(self._recent) >= RATE_PER_MINUTE:
                return False
            self._recent.append(now)
            return True

    def _issue(self, *, actor, basis, pid, uid, ttl_s, **declared):
        stat = ident.proc_stat(pid)
        exe = ident.proc_exe(pid)
        if stat is None or not exe:
            raise ident.ProvenanceError("requesting process is not observable")
        parent_stat = ident.proc_stat(stat[0])
        parent = {"pid": stat[0], "start": parent_stat[1]} if parent_stat else None
        record = ident.make_identity(actor=actor, basis=basis, pid=pid, start=stat[1],
                                     exe=exe, uid=uid, release_id=self.release_id,
                                     ttl_s=ttl_s, parent=parent, **declared)
        row = ident.sign(record, self.key)
        ident.append(row, self.ledger)
        self.stats["issued"] += 1
        return row, stat

    def issue_self(self):
        """The daemon's own identity: actor jarvis, observed."""
        row, _ = self._issue(actor="jarvis", basis="observed", pid=os.getpid(),
                             uid=os.getuid(), ttl_s=SELF_TTL_S, session="daemon",
                             purpose="JARVIS daemon")
        self.self_row = row
        return row

    def handle(self, request, pid, uid, pidfd=-1):
        """One request -> response dict. Never raises."""
        try:
            if uid != os.getuid():
                raise ident.ProvenanceError("requester is another account")
            if not isinstance(request, dict) or request.get("op") != "issue":
                raise ident.ProvenanceError("unsupported request")
            actor = request.get("actor")
            if actor not in ident.DECLARABLE:
                raise ident.ProvenanceError(f"actor {actor!r} cannot be declared")
            if not self._rate_ok():
                raise ident.ProvenanceError("rate limit")
            caps = request.get("capabilities") or []
            if not isinstance(caps, list):
                raise ident.ProvenanceError("capabilities must be a list")
            row, stat = self._issue(
                actor=actor, basis="declared", pid=pid, uid=uid,
                ttl_s=min(int(request.get("ttl_s") or 3600), ident.MAX_TTL_S),
                session=request.get("session", ""), workspace=request.get("workspace", ""),
                capabilities=caps, purpose=request.get("purpose", ""),
                parent_identity=request.get("parent_identity"))
            if not _pidfd_alive(pidfd):
                raise ident.ProvenanceError("requesting process exited during issuance")
            return {"ok": True, "row": row}
        except (ident.ProvenanceError, ValueError, TypeError) as exc:
            self.stats["refused"] += 1
            return {"ok": False, "error": str(exc)[:200]}

    # -- socket -----------------------------------------------------------------

    def _serve_one(self, conn):
        pidfd = -1
        try:
            conn.settimeout(REQUEST_TIMEOUT_S)
            pid, uid, pidfd = _peer(conn)
            data = b""
            while len(data) <= MAX_REQUEST and not data.endswith(b"\n"):
                chunk = conn.recv(MAX_REQUEST + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) > MAX_REQUEST:
                response = {"ok": False, "error": "request too large"}
            else:
                try:
                    request = json.loads(data.decode("utf-8", "replace") or "null")
                except ValueError:
                    request = None
                response = self.handle(request, pid, uid, pidfd)
            conn.sendall(json.dumps(response).encode() + b"\n")
        except OSError:
            pass
        finally:
            if pidfd >= 0:
                os.close(pidfd)
            conn.close()

    def bind(self):
        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, 0o700)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(16)
        return server

    def serve_forever(self, server):
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                if server.fileno() == -1:
                    return                  # closed: stop serving
                time.sleep(0.1)             # transient (EMFILE, ECONNABORTED): back off
                continue
            self._serve_one(conn)

    def renew_forever(self):
        while True:
            time.sleep(SELF_TTL_S / 3)
            try:
                self.issue_self()
            except Exception as exc:          # never stop the daemon
                print(f"provenance: self renewal failed: {exc}", flush=True)


def start():
    """Start issuing inside the daemon. Returns a status string; never raises."""
    try:
        key = ident.load_private_key()
        if key is None:
            return "unavailable: the signing key is not readable by this process"
        public = ident.load_public_key()
        if public is None or ident.key_id(public) != ident.key_id(key.public_key()):
            return "unavailable: the public key is missing or does not match"
        authority = Authority(key, release_id=_current_release_id())
        authority.issue_self()
        server = authority.bind()
        threading.Thread(target=authority.serve_forever, args=(server,),
                         name="jarvis-provenance", daemon=True).start()
        threading.Thread(target=authority.renew_forever,
                         name="jarvis-provenance-renew", daemon=True).start()
        return "issuing"
    except Exception as exc:
        return f"unavailable: {type(exc).__name__}: {str(exc)[:160]}"


def request(payload, socket_path=SOCKET, timeout=REQUEST_TIMEOUT_S):
    """Client: ask the authority for an identity for the calling process."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(socket_path))
        conn.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n") and len(data) < 64 * 1024:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8", "replace"))
