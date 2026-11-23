"""The spool the network sensors write and the daemon reads.

Writes are atomic (temporary file, fsync, rename) so a reader never sees half a
file. Files are size-capped on both sides. Window files carry a sequence
number and the sensor's boot id, so a reader can tell a gap or a restart from
a quiet minute (ARGUS-SERVER.md I7).
"""

import json
import os
import re

SPOOL_DIR = os.environ.get("JARVIS_NET_DIR", "/var/lib/argus-net")
WINDOW_DIR = "windows"
MAX_FILE_BYTES = 4 * 1024 * 1024
WINDOW_NAME = re.compile(r"^w-(?P<start>\d{10})-(?P<boot>[0-9a-f]{8})-(?P<seq>\d{10})\.json$")


def write_json(path, data, mode=0o640):
    """Atomically replace `path` with `data` as JSON. Raises OSError."""
    body = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    if len(body) > MAX_FILE_BYTES:
        raise OSError(f"refusing to write {len(body)} bytes to {path}")
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path, max_bytes=MAX_FILE_BYTES):
    """The JSON at `path`, or raise OSError/ValueError. Refuses oversized files
    and symlinks (the spool is written by another account)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        body = fh.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"{path} is larger than {max_bytes} bytes")
    return json.loads(body.decode("utf-8", "replace"))


def window_name(start, boot, seq):
    """File name of one window: start time first so names sort in time order
    across sensor restarts (the sequence restarts with each boot id)."""
    return f"w-{int(start):010d}-{boot}-{seq:010d}.json"


def list_windows(spool=SPOOL_DIR):
    """[(start, boot, seq, path)] of window files, oldest first."""
    d = os.path.join(spool, WINDOW_DIR)
    try:
        names = os.listdir(d)
    except OSError:
        return []
    out = []
    for name in names:
        m = WINDOW_NAME.match(name)
        if m:
            out.append((int(m["start"]), m["boot"], int(m["seq"]), os.path.join(d, name)))
    return sorted(out)


def prune(spool=SPOOL_DIR, keep=24 * 60):
    """Delete all but the newest `keep` window files. Returns how many went."""
    files = list_windows(spool)
    gone = 0
    for *_key, path in files[:-keep] if keep else files:
        try:
            os.unlink(path)
            gone += 1
        except OSError:
            pass
    return gone
