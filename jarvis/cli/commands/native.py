"""`jarvis native`: install, check and remove JARVIS on a Windows machine without WSL.

    jarvis native install [--port N]    per-user service, no administrator needed
    jarvis native status                one supervisor check
    jarvis native stop                  stop and unregister the service, keep the pairing (upgrades)
    jarvis native uninstall

The service is the native service loop (jarvis-native-service.ps1), registered
as a per-user scheduled task by its own -Install. The compiled edition runs it
with -Engine (this program); a source checkout with -Python. Nothing here needs
elevation or changes a Windows setting. The desktop app on this machine is
paired as an API client: its token goes, owner-only, to the app's own config
folder, and the port it should use next to it.

Invariants (tests/test_native_cli.py):
- Windows only: elsewhere the command refuses and changes nothing.
- A reinstall keeps the port the service already uses; a port held by
  something else is never shared, the next free one is taken and said.
- One install per computer: when another JARVIS daemon (the WSL edition, or an
  install this service did not make) answers on the default port, install
  refuses rather than start a second one beside it.
- The token is written once per install, never printed, never passed on a
  command line; an existing valid token is kept.
- Uninstall removes the task, the written-out payloads and the app's token and
  revokes that client; the evidence store (~/.jarvis) stays unless the owner
  deletes it.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

from jarvis.core import paths
from jarvis.platform import host

SERVICE_SCRIPT = "jarvis-native-service.ps1"
TASK_NAME = "jarvis native service"
DEFAULT_PORT = 8787
PORT_RANGE = range(8787, 8800)
HEALTH_WAIT_S = 180
# The desktop app's identifier (desktop/tauri.conf.json) names its config folder.
DESKTOP_APP_DIR = "local.jarvis.desktop"
DESKTOP_CLIENT_NAME = "desktop app on this computer"


def state_root(env=None):
    env = os.environ if env is None else env
    return os.path.join(env.get("LOCALAPPDATA") or os.path.expanduser("~"), "Jarvis", "NativeService")


def desktop_dir(env=None):
    env = os.environ if env is None else env
    return os.path.join(env.get("APPDATA") or os.path.expanduser("~"), DESKTOP_APP_DIR)


def compiled():
    return paths._embedded()[0] is not None


def _service_config(root):
    try:
        with open(os.path.join(root, "service.json"), encoding="utf-8-sig", errors="replace") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def port_free(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def choose_port(requested, previous, free=port_free):
    """(port, note). A requested port must be free (or be ours already); the
    port a previous install used is kept; otherwise 8787 or the next free one."""
    if requested:
        if requested == previous or free(requested):
            return requested, ""
        raise ValueError(f"port {requested} is in use by another program")
    if previous:
        return previous, ""
    for port in PORT_RANGE:
        if free(port):
            note = "" if port == DEFAULT_PORT else f"port {DEFAULT_PORT} is in use; using {port}"
            return port, note
    raise ValueError(f"no free port between {PORT_RANGE.start} and {PORT_RANGE.stop - 1}")


def _powershell():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _run_service_script(extra, timeout=180):
    script = str(paths.shipped_script(SERVICE_SCRIPT, paths.REPO_ROOT))
    cmd = [_powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-File", script, *extra]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return r.returncode, (r.stdout + r.stderr).strip()


def _health(port, timeout=4):
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=timeout) as resp:
            doc = json.loads(resp.read(1 << 20))
    except Exception as exc:  # noqa: BLE001 - urllib raises many kinds; any means "not answering"
        if getattr(exc, "code", None) == 503:
            try:
                doc = json.loads(exc.read(1 << 20))
            except Exception:  # noqa: BLE001
                return None
        else:
            return None
    return doc if isinstance(doc, dict) else None


def wait_healthy(port, wait=HEALTH_WAIT_S, sleep=time.sleep, probe=_health):
    deadline = time.monotonic() + wait
    while True:
        doc = probe(port)
        if doc and doc.get("live") is True:
            return doc
        if time.monotonic() >= deadline:
            return doc
        sleep(3)


def pair_desktop(store, directory, port):
    """Give the desktop app on this machine a client token and the port; keep a
    valid token that is already there. Returns 'paired', 'kept' or a reason."""
    from jarvis.web import apiclient, clients
    token_path = os.path.join(directory, "client.token")
    if clients.looks_like(apiclient.read_private(token_path)):
        status = "kept"
    else:
        if store is None:
            return "no store to pair the desktop app"
        _cid, token = clients.pair(store, DESKTOP_CLIENT_NAME)
        apiclient.save_private(token_path, token)
        status = "paired"
    port_path = os.path.join(directory, "port")
    tmp = port_path + ".new"
    with open(tmp, "w", encoding="ascii") as fh:
        fh.write(f"{int(port)}\n")
    os.replace(tmp, port_path)
    return status


def unpair_desktop(store, directory):
    from jarvis.web import clients
    for name in ("client.token", "port"):
        try:
            os.remove(os.path.join(directory, name))
        except OSError:
            pass
    revoked = 0
    if store is not None:
        for row in clients.listing(store):
            if row.get("name") == DESKTOP_CLIENT_NAME and not row.get("revoked_at"):
                revoked += bool(clients.revoke(store, row["id"]))
    return revoked


def _refuse_elsewhere():
    if host.KIND != "windows":
        print("jarvis native: this is for Windows without WSL. On Linux or WSL use the server "
              "edition's install.sh.", file=sys.stderr)
        return True
    return False


SERVICE_NAME = "JARVIS"     # what /api/health answers as `service`


def other_install(previous, probe=None):
    """The port of a JARVIS daemon this service did not start, or 0."""
    if previous:
        return 0
    doc = (probe or _health)(DEFAULT_PORT)
    return DEFAULT_PORT if doc and doc.get("service") == SERVICE_NAME else 0


class _Transcript:
    """Writes to a log file and, when there is one, the original stream. A program
    started without a console (the Setup's silent install) may have no stdout at
    all; its transcript must still say what happened."""

    def __init__(self, stream, fh):
        self.stream, self.fh = stream, fh

    def write(self, text):
        self.fh.write(text)
        if self.stream is not None:
            try:
                self.stream.write(text)
            except (OSError, ValueError):
                self.stream = None
        return len(text)

    def flush(self):
        self.fh.flush()
        if self.stream is not None:
            try:
                self.stream.flush()
            except (OSError, ValueError):
                self.stream = None


INSTALL_LOG = "install.log"


def cmd_install(args, store):
    """`native install`, with everything it prints also kept in install.log in the
    service's state folder."""
    if _refuse_elsewhere():
        return 2
    root = state_root()
    try:
        os.makedirs(root, exist_ok=True)
        fh = open(os.path.join(root, INSTALL_LOG), "w", encoding="utf-8", errors="replace")
    except OSError:
        return _install(args, store)
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _Transcript(saved[0], fh), _Transcript(saved[1], fh)
    try:
        return _install(args, store)
    finally:
        sys.stdout, sys.stderr = saved
        fh.close()


def _install(args, store):
    if _refuse_elsewhere():
        return 2
    root = state_root()
    previous = int(_service_config(root).get("port") or 0)
    other = other_install(previous)
    if other:
        print(f"jarvis native: JARVIS already runs on this computer (port {other}, for example the "
              "WSL edition). One install per computer: remove that one first.", file=sys.stderr)
        return 3
    try:
        port, note = choose_port(args.port, previous)
    except ValueError as exc:
        print(f"jarvis native: {exc}", file=sys.stderr)
        return 1
    if note:
        print(note)
    runner = ["-Engine", paths.self_executable()] if compiled() else ["-Python", sys.executable]
    code, out = _run_service_script(["-Install", *runner, "-Port", str(port)])
    if out:
        print(out)
    if code != 0:
        print("jarvis native: the service could not be registered", file=sys.stderr)
        return 1
    print(f"waiting for the service on port {port} ...", flush=True)
    doc = wait_healthy(port)
    if not doc or doc.get("live") is not True:
        print(f"jarvis native: registered, but not answering on port {port} yet; see "
              f"{os.path.join(root, 'daemon.err.log')}", file=sys.stderr)
        return 1
    if not args.no_desktop:
        try:
            print(f"desktop app: {pair_desktop(store, desktop_dir(), port)}")
        except (OSError, ValueError) as exc:
            print(f"desktop app: not paired ({exc}); run `jarvis desktop pair --name desktop`",
                  file=sys.stderr)
    from jarvis.service import schedule
    print(f"running {len(schedule.JOBS)} checks on this computer; "
          f"{len(schedule.NOT_APPLICABLE)} do not apply here (`jarvis native status --all`)")
    return 0


def cmd_status(args, store):
    if _refuse_elsewhere():
        return 2
    code, out = _run_service_script(["-Once"], timeout=60)
    print(out)
    if args.all:
        from jarvis.service import schedule
        for name, why in sorted(schedule.NOT_APPLICABLE.items()):
            print(f"  not here  {name:<22} {why}")
    return code


def cmd_stop(args, store):
    if _refuse_elsewhere():
        return 2
    code, out = _run_service_script(["-Remove"])
    if out:
        print(out)
    return code


def cmd_uninstall(args, store):
    if _refuse_elsewhere():
        return 2
    code, out = _run_service_script(["-Remove"])
    if out:
        print(out)
    revoked = unpair_desktop(store, desktop_dir())
    if revoked:
        print(f"revoked the desktop app's client token ({revoked})")
    scripts, digest = paths._embedded()
    if scripts is not None:
        shutil.rmtree(paths.payload_root(digest).parent, ignore_errors=True)
    print(f"kept your history and settings in {os.path.expanduser('~/.jarvis')}; "
          "delete that folder to remove them too")
    return 0 if code == 0 else 1


def add_parser(sub):
    p = sub.add_parser("native", help="install, check or remove the service on Windows without WSL")
    nsub = p.add_subparsers(dest="native_cmd", required=True)
    ip = nsub.add_parser("install", help="register the per-user service and start it (no administrator)")
    ip.add_argument("--port", type=int, default=0)
    ip.add_argument("--no-desktop", action="store_true", help="do not pair the desktop app")
    ip.set_defaults(fn=cmd_install)
    sp = nsub.add_parser("status", help="one supervisor check")
    sp.add_argument("--all", action="store_true", help="also list the checks that do not apply here")
    sp.set_defaults(fn=cmd_status)
    nsub.add_parser("stop", help="stop and unregister the service; pairing and data stay").set_defaults(fn=cmd_stop)
    up = nsub.add_parser("uninstall", help="stop and remove the service (your history stays)")
    up.set_defaults(fn=cmd_uninstall)
    return p
