"""The /procs live stream: the process feed pushed to a page as it changes.

A viewer gets a full snapshot of each domain, then every frame the feed
produces, each as one Server-Sent Event. Same contract as web/stream.py:
read-only, at most MAX_STREAMS at once, each ended after MAX_LIFETIME_S
(EventSource reconnects by itself), and a stale or failed source is sent as
such in the feed's status frames, never left looking calm. A viewer that falls
behind the feed's ring is resynchronised with a fresh snapshot instead of
being left with a wrong table.
"""

import threading
import time

MAX_STREAMS = 4
MAX_LIFETIME_S = 30 * 60
WAIT_S = 1.0
_slots = threading.BoundedSemaphore(MAX_STREAMS)


def acquire_slot():
    return _slots.acquire(blocking=False)


def release_slot():
    _slots.release()


def _event(text):
    return f"data: {text}\n\n".encode("utf-8")


def run(feed, write, *, gone=None, clock=time.monotonic, lifetime=MAX_LIFETIME_S):
    """Serve one viewer until it leaves or its lifetime ends."""
    feed.acquire()
    try:
        seq, frames = feed.snapshot()
        write(b"retry: 2000\n\n" + b"".join(_event(t) for t in frames))
        deadline = clock() + lifetime
        while clock() < deadline:
            if gone is not None and gone():
                return
            got = feed.frames_after(seq, WAIT_S)
            if got is None:
                seq, frames = feed.snapshot()
            else:
                seq, frames = got
            if frames:
                write(b"".join(_event(t) for t in frames))
            else:
                write(b": keepalive\n\n")
    finally:
        feed.release()
