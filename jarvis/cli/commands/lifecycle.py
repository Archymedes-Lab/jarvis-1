"""argus stop / argus start: turn monitoring off and on, on purpose.

    argus stop     stop the daemon and keep it stopped: the watchdog task and the
                   desktop app both see the marker and leave it alone
    argus start    clear the marker and start the daemon again

Without a marker, a daemon that disappears is restarted (that is the point of the
watchdog); with one, it is not. Uninstalling removes the task itself.
"""

import os
import subprocess
import sys

from jarvis.core.paths import self_executable
from jarvis.service import supervision

TASK_NAME = "jarvis native service"
NO_WINDOW = 0x08000000
DETACHED = 0x00000008


def _compiled_name():
    """The program's own file name when this is the compiled program, else ''."""
    name = os.path.basename(self_executable()).lower()
    return name if name.endswith(".exe") and not name.startswith(("python", "pythonw")) else ""


def _hidden(args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=60,
                          creationflags=NO_WINDOW if sys.platform.startswith("win") else 0)


def cmd_stop(args, store):
    supervision.mark_stopped()
    killed = False
    name = _compiled_name()
    if sys.platform.startswith("win") and name:
        # The compiled program is also its own collector workers: stop them all, but not this command.
        r = _hidden(["taskkill", "/F", "/T", "/FI", f"IMAGENAME eq {name}", "/FI", f"PID ne {os.getpid()}"])
        killed = r.returncode == 0
    print("Argus is stopped and will stay stopped (the watchdog and the app respect this)."
          if killed or not name else "Argus was not running; it will stay stopped.")
    if not name:
        print("This is not the compiled program, so no process was stopped: end the `serve` process yourself.",
              file=sys.stderr)
    print("Start it again with: argus start")
    return 0


def cmd_start(args, store):
    was = supervision.clear_stopped()
    if sys.platform.startswith("win"):
        task = _hidden(["schtasks", "/Run", "/TN", TASK_NAME])
        if task.returncode == 0:
            print("Argus is starting" + (" (the stop marker was cleared)." if was else "."))
            return 0
    exe = self_executable()
    command = [exe, "serve", "--port", str(args.port), "--supervised"] if _compiled_name() else \
        [exe, "-m", "jarvis", "serve", "--port", str(args.port), "--supervised"]
    flags = (NO_WINDOW | DETACHED) if sys.platform.startswith("win") else 0
    subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, creationflags=flags)
    print("Argus is starting" + (" (the stop marker was cleared)." if was else "."))
    return 0


def add_parser(sub):
    p = sub.add_parser("stop", help="stop the daemon and keep it stopped until `argus start`")
    p.set_defaults(fn=cmd_stop, no_store=True)
    p = sub.add_parser("start", help="start the daemon (clears `argus stop`)")
    p.add_argument("-p", "--port", type=int, default=8787)
    p.set_defaults(fn=cmd_start, no_store=True)
    return p
