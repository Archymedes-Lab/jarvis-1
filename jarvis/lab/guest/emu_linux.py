"""Harmless spyware-mechanism emulators. Run ONLY inside the disposable guest.

Each mode reproduces the *observable mechanism* of a technique and nothing
else: it opens a device read-only without ever reading from it, or runs a copy
of `sleep` from a hidden path or from memory. No keystroke, sound, pixel or file
content is read, stored or sent, and there is no network. The host never runs
this file; it is delivered inside the guest payload.

Prints `READY <pid>` for the process that carries the mechanism, then holds it
until signalled or until HOLD_S elapses.
"""

import glob
import os
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/opt/lab")
HOLD_S = 120
HIDE_DIR = "/home/ubuntu/.cache/updater"


def _ready(pid):
    print(f"READY {pid}", flush=True)


def _install_copy():
    os.makedirs(HIDE_DIR, exist_ok=True)
    path = os.path.join(HIDE_DIR, "agent")
    shutil.copy2("/usr/bin/sleep", path)
    os.chmod(path, 0o755)
    return path


def _wait_image(pid, path, deadline=10.0):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            if os.readlink(f"/proc/{pid}/exe").startswith(path):
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def _hold(child):
    def stop(*_):
        try:
            os.kill(child.pid, signal.SIGKILL)
        except OSError:
            pass
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        child.wait(timeout=HOLD_S)
    except subprocess.TimeoutExpired:
        stop()


def _launch_holding(fd_spec, delete_image):
    """Start a copy of sleep from a hidden path holding one descriptor."""
    path = _install_copy()
    shell = f"exec {fd_spec}; exec {path} {HOLD_S}" if fd_spec else f"exec {path} {HOLD_S}"
    child = subprocess.Popen(["/bin/bash", "-c", shell])
    if not _wait_image(child.pid, path):
        child.kill()
        sys.exit("image never appeared")
    if delete_image:
        os.unlink(path)
    _ready(child.pid)
    _hold(child)


def _keyboard_device():
    from jarvis.platform import spy_linux
    for entry in sorted(glob.glob("/dev/input/event*")):
        number = entry[len("/dev/input/event"):]
        if spy_linux.keyboard_event(number) is True:
            return entry
    return None


def deleted_image():
    _launch_holding("", True)


def memfd_exec():
    fd = os.memfd_create("jv", 0)
    with open("/usr/bin/sleep", "rb") as src:
        os.write(fd, src.read())
    pid = os.fork()
    if pid == 0:
        os.execve(f"/proc/self/fd/{fd}", ["sleep", str(HOLD_S)], dict(os.environ))
    end = time.monotonic() + 10
    while time.monotonic() < end:
        try:
            if os.readlink(f"/proc/{pid}/exe").startswith("/memfd:"):
                break
        except OSError:
            pass
        time.sleep(0.05)
    _ready(pid)
    signal.signal(signal.SIGTERM, lambda *_: (os.kill(pid, signal.SIGKILL), sys.exit(0)))
    os.waitpid(pid, 0)


def evdev_reader():
    dev = _keyboard_device()
    if not dev:
        sys.exit("no keyboard device")
    _launch_holding(f"3<{dev}", False)


def evdev_deleted():
    dev = _keyboard_device()
    if not dev:
        sys.exit("no keyboard device")
    _launch_holding(f"3<{dev}", True)


def snd_capture():
    devs = sorted(glob.glob("/dev/snd/pcmC*D*c"))
    if not devs:
        sys.exit("no capture device")
    _launch_holding(f"3<{devs[0]}", False)


def uinput_open():
    if not os.path.exists("/dev/uinput"):
        sys.exit("no uinput")
    _launch_holding("3<>/dev/uinput", False)


def clean_sleep():
    child = subprocess.Popen(["/usr/bin/sleep", str(HOLD_S)])
    _ready(child.pid)
    _hold(child)


MODES = {f.__name__: f for f in (deleted_image, memfd_exec, evdev_reader, evdev_deleted,
                                 snd_capture, uinput_open, clean_sleep)}

if __name__ == "__main__":
    MODES[sys.argv[1]]()
