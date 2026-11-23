"""Observation epochs: never compare wall clocks across a discontinuity.

A WSL VM is frozen during Windows standby, and on resume its wall clock is
corrected forward by Hyper-V time sync while CLOCK_MONOTONIC is not. Windows
and WSL also disagree on the local UTC offset. Comparing raw wall-clock
timestamps across such a gap manufactures "event before its process existed"
and "event from the future" artifacts.

An epoch is a span in which one monotonic clock is continuous. A new epoch
opens when:

  boot        the kernel boot id changed
  resume      CLOCK_BOOTTIME advanced beyond CLOCK_MONOTONIC (the kernel
              knows it was suspended)
  clock-step  wall minus monotonic moved forward by more than STEP_S plus
              a small slack (a frozen VM resumed, or the clock was set
              forward), or backward faster than the VM's clock discipline
              explains (the clock was set back; see MAX_BACKWARD_RATE)
  release     the running JARVIS release changed
  first       no earlier sample exists

Within one epoch, events are ordered by monotonic time. Across epochs only the
epoch sequence orders them, and a wall-clock difference is not computed at
all (wall_delta returns None). Opening an extra epoch is the safe error: it
only withholds a cross-gap comparison; missing one would permit a false one.
"""

import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass

BOOT_ID = "/proc/sys/kernel/random/boot_id"
STEP_S = 2.0      # larger than scheduling jitter between two clock reads
# Measured 2026-09-24 on this WSL2 VM: CLOCK_MONOTONIC runs ~10% fast and
# Hyper-V time sync steps the wall clock back ~2.95 s every ~30 s, so
# wall-minus-monotonic falls ~0.098 s per monotonic second in steps. That is
# clock discipline, not a discontinuity. A resume moves it the other way
# (forward, by the frozen time), so the two are told apart by sign.
MAX_BACKWARD_RATE = 0.15   # backward drift allowed per monotonic second
FORWARD_SLACK_RATE = 0.01  # forward drift allowed per monotonic second
KEEP = 64         # bounded ledger: the last 64 epochs
META = "observation_epochs_v1"


@dataclass(frozen=True)
class Sample:
    boot_id: str
    wall: float
    mono: float
    boottime: float
    release: str = ""

    @property
    def offset(self):
        """wall - monotonic: constant while the clock runs undisturbed."""
        return self.wall - self.mono

    @property
    def suspended(self):
        """Seconds the kernel spent suspended since boot."""
        return self.boottime - self.mono


def _boot_id(path=BOOT_ID):
    try:
        with open(path, errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _release():
    try:
        return os.path.realpath("/opt/jarvis/current")
    except OSError:
        return ""


def sample(boot_id_path=BOOT_ID, release=None):
    """Read every clock back to back. An unreadable boot id stays empty, which
    transition() treats as a discontinuity rather than as "same boot"."""
    mono = time.monotonic()
    try:
        boottime = time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        boottime = mono
    return Sample(_boot_id(boot_id_path), time.time(), mono, boottime,
                  _release() if release is None else release)


def transition(prev, cur):
    """Why `cur` cannot share `prev`'s epoch, or None when it can."""
    if prev is None:
        return "first"
    if not prev.boot_id or not cur.boot_id or prev.boot_id != cur.boot_id:
        return "boot"
    if cur.mono < prev.mono:
        # Monotonic time never runs backwards within one boot; if it did, the
        # samples are not from one clock and must not be ordered together.
        return "boot"
    if cur.suspended - prev.suspended > STEP_S:
        return "resume"
    if prev.release != cur.release:
        return "release"
    elapsed = cur.mono - prev.mono
    moved = cur.offset - prev.offset
    if moved > STEP_S + FORWARD_SLACK_RATE * elapsed:
        return "clock-step"
    if -moved > STEP_S + MAX_BACKWARD_RATE * elapsed:
        return "clock-step"
    return None


def coherent(before, after):
    """Two samples lie in one continuous epoch (for bounded confirmation)."""
    return transition(before, after) is None


@dataclass(frozen=True)
class Epoch:
    seq: int
    reason: str
    boot_id: str
    opened_wall: float
    opened_mono: float
    offset: float
    suspended: float
    release: str


class Ledger:
    """Bounded, append-only in intent: epochs are only ever opened, never
    rewritten; the oldest fall off past KEEP. `last` is the most recent
    sample so the next observe() compares against it."""

    def __init__(self, epochs=None, last=None):
        self.epochs = list(epochs or [])[-KEEP:]
        self.last = last

    @property
    def current(self):
        return self.epochs[-1] if self.epochs else None

    def observe(self, cur):
        """Fold one sample in. Returns the Epoch it opened, or None."""
        reason = transition(self.last, cur)
        self.last = cur
        if reason is None and self.current is not None:
            return None
        seq = (self.current.seq + 1) if self.current else 1
        epoch = Epoch(seq, reason or "first", cur.boot_id, cur.wall, cur.mono,
                      cur.offset, cur.suspended, cur.release)
        self.epochs = (self.epochs + [epoch])[-KEEP:]
        return epoch

    def stamp(self, cur=None):
        """A typed timestamp for an event observed now."""
        cur = cur or sample()
        self.observe(cur)
        return {"epoch": self.current.seq, "wall": cur.wall, "mono": cur.mono}

    def to_json(self):
        return json.dumps({"epochs": [asdict(e) for e in self.epochs],
                           "last": asdict(self.last) if self.last else None},
                          sort_keys=True)

    @classmethod
    def from_json(cls, text):
        """A corrupt or foreign ledger restarts empty: the next sample then
        opens a fresh epoch, which only withholds cross-gap comparisons."""
        try:
            raw = json.loads(text) if text else {}
            epochs = [Epoch(**e) for e in raw.get("epochs") or []]
            last = Sample(**raw["last"]) if raw.get("last") else None
        except (TypeError, ValueError, KeyError, AttributeError):
            return cls()
        seqs = [e.seq for e in epochs]
        if seqs != sorted(set(seqs)):
            return cls()
        return cls(epochs, last)


def ordered(a, b):
    """-1/0/1 ordering of two stamps, or None when it is not knowable.
    Same epoch: monotonic time. Different epochs: the epoch sequence. A stamp
    without an epoch is never ordered against anything."""
    ea, eb = a.get("epoch"), b.get("epoch")
    if not isinstance(ea, int) or not isinstance(eb, int):
        return None
    if ea != eb:
        return -1 if ea < eb else 1
    ma, mb = a.get("mono"), b.get("mono")
    if not isinstance(ma, (int, float)) or not isinstance(mb, (int, float)):
        return None
    return (ma > mb) - (ma < mb)


def wall_delta(a, b):
    """b - a in seconds, only within one epoch, measured on the monotonic
    clock (which ran ~10% fast on this WSL VM: a duration, not a wall time). None across epochs: a wall-clock subtraction there is exactly the
    comparison this module exists to refuse."""
    if ordered(a, b) is None or a.get("epoch") != b.get("epoch"):
        return None
    return b["mono"] - a["mono"]


def load(db_path):
    try:
        with sqlite3.connect("file:" + db_path + "?mode=ro", uri=True, timeout=1) as db:
            row = db.execute("SELECT v FROM meta WHERE k=?", (META,)).fetchone()
    except (sqlite3.Error, OSError):
        return Ledger()
    return Ledger.from_json(row[0] if row else None)


def record(db_path, cur=None):
    """Fold the current sample into the persisted ledger. Returns the opened
    Epoch or None. Needs an explicit store path, so a unit test that never
    passes one cannot write to the protected user's store."""
    if not db_path:
        return None
    from jarvis.core.store import Store

    ledger = load(db_path)
    opened = ledger.observe(cur or sample())
    store = Store(db_path)
    try:
        store.set_meta(META, ledger.to_json())
        store.commit()
    finally:
        store.close()
    return opened
