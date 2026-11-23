"""Agent Execution Capsule: one attributable tree per agent or test session.

    jarvis capsule run --actor codex -- codex
    jarvis capsule run --actor test_suite -- python3 -m unittest discover -s tests

The launcher:

  1. creates a private workspace, ~/.local/state/jarvis/capsules/<actor>/<session>/
     (0700, refused under any world-writable directory), and points TMPDIR at
     its tmp/, so builds and test binaries never execute from /tmp (P6);
  2. becomes a child subreaper, so double-forked descendants stay in its tree
     instead of escaping to init;
  3. asks the daemon's authority for a signed identity bound to its own pid
     and verifies the reply against the public key and its own (pid, start
     time). An unsigned or mismatched reply is discarded;
  4. runs the command as its child, renews the identity before expiry, and
     forwards signals.

If the authority is unavailable the command still runs and the reason is
printed once. The tree then has no provenance. That can only mean more
findings, never fewer, so it is the safe failure (P3). Capabilities are
recorded as declared. They are not enforced yet.
"""

import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from jarvis.platform.provenance import authority
from jarvis.platform.provenance import identity as ident
from jarvis.platform.provenance.release import world_writable_ancestor

ROOT = Path(os.path.expanduser("~/.local/state/jarvis/capsules"))
DEFAULT_TTL_S = 4 * 3600
PR_SET_CHILD_SUBREAPER = 36
TMP_RETENTION_S = 7 * 86400
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def make_workspace(actor, session, root=ROOT):
    if actor not in ident.DECLARABLE:
        raise ident.ProvenanceError(f"actor must be one of {', '.join(ident.DECLARABLE)}")
    if not SESSION_RE.match(session):
        raise ident.ProvenanceError("session must be 1-64 of [A-Za-z0-9._-]")
    root = Path(root)
    workspace = root / actor / session
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in (root, root / actor, workspace):
        os.chmod(path, 0o700)
    bad = world_writable_ancestor(workspace)
    if bad:
        raise ident.ProvenanceError(f"workspace is under world-writable {bad}")
    (workspace / "tmp").mkdir(mode=0o700)
    return workspace


def prune_old_tmp(root=ROOT, now=None, retention_s=TMP_RETENTION_S):
    """Remove tmp/ of sessions that ended more than `retention_s` ago.

    Only the scratch tmp/ of a finished session is removed; its session.json
    record stays. Sessions without an end record are never touched."""
    import shutil
    now = time.time() if now is None else now
    removed = 0
    for record in Path(root).glob("*/*/session.json"):
        try:
            data = json.loads(record.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        ended = data.get("ended_at")
        tmp = record.parent / "tmp"
        if isinstance(ended, (int, float)) and now - ended > retention_s and tmp.is_dir():
            shutil.rmtree(tmp, ignore_errors=True)
            removed += 1
    return removed


def verify_reply(reply, public_key, pid, start):
    """The identity in an authority reply, only if it is signed and binds us."""
    if not isinstance(reply, dict) or not reply.get("ok"):
        return None
    record = ident.verify_row(reply.get("row"), public_key)
    if record is None:
        return None
    b = record["binding"]
    if b.get("pid") != pid or b.get("start") != start:
        return None
    return record


def obtain(actor, session, workspace, capabilities, purpose, ttl_s,
           socket_path=authority.SOCKET, public_key=None):
    """(record or None, reason). Never raises."""
    public_key = public_key or ident.load_public_key()
    if public_key is None:
        return None, "no provenance public key is installed"
    me = ident.proc_stat(os.getpid())
    try:
        reply = authority.request({"op": "issue", "actor": actor, "session": session,
                                   "workspace": str(workspace), "capabilities": capabilities,
                                   "purpose": purpose, "ttl_s": ttl_s}, socket_path)
    except (OSError, ValueError) as exc:
        return None, f"authority unreachable ({type(exc).__name__})"
    record = verify_reply(reply, public_key, os.getpid(), me[1] if me else -1)
    if record is None:
        return None, "authority reply " + (str(reply.get("error"))[:120]
                                           if isinstance(reply, dict) and reply.get("error")
                                           else "failed verification; discarded")
    return record, ""


def _set_subreaper():
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except OSError:
        return False


def run(actor, command, *, session=None, capabilities=(), purpose="", ttl_s=DEFAULT_TTL_S,
        root=ROOT, out=sys.stderr, socket_path=authority.SOCKET, public_key=None):
    """Run `command` inside a capsule. Returns its exit status."""
    if not command:
        raise ident.ProvenanceError("no command given")
    session = session or time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    prune_old_tmp(root)
    workspace = make_workspace(actor, session, root)
    capabilities = list(capabilities)
    public_key = public_key or ident.load_public_key()

    def request():
        return obtain(actor, session, workspace, capabilities, purpose, ttl_s,
                      socket_path=socket_path, public_key=public_key)

    record, reason = request()
    meta = {"actor": actor, "session": session, "command0": os.path.basename(command[0]),
            "started_at": int(time.time()), "launcher_pid": os.getpid(),
            "identity_id": record["id"] if record else None,
            "provenance": "signed" if record else f"none: {reason}",
            "capabilities": capabilities, "capabilities_enforced": False}
    record_path = workspace / "session.json"
    record_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    if record is None:
        print(f"jarvis capsule: provenance unavailable ({reason}); running without "
              "attribution", file=out, flush=True)
    subreaper = _set_subreaper()

    env = dict(os.environ)
    tmp = str(workspace / "tmp")
    env.update({"TMPDIR": tmp, "TMP": tmp, "TEMP": tmp, "JARVIS_CAPSULE": actor,
                "JARVIS_CAPSULE_SESSION": session})
    if record:
        env["JARVIS_EXECUTION_ID"] = record["id"]      # informational; not proof
    child = subprocess.Popen(command, env=env)

    stop = threading.Event()

    def renew():
        while not stop.wait(max(60, ttl_s // 2)):
            request()

    if record:
        threading.Thread(target=renew, name="capsule-renew", daemon=True).start()

    def forward(signum, _frame):
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(signum, forward)
    try:
        status = child.wait()
        if subreaper:
            # Reap orphans adopted while the command ran; do not wait for
            # ones still running (they lose attribution when we exit).
            try:
                while os.waitpid(-1, os.WNOHANG)[0] > 0:
                    pass
            except ChildProcessError:
                pass
    finally:
        stop.set()
        meta["ended_at"] = int(time.time())
        meta["exit_status"] = child.returncode
        record_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return status
