"""Live process table for the /procs view: both domains, only while watched.

Sources, one frame protocol:

  Windows  a helper process (platform/win/procfeed.ps1): one
           NtQuerySystemInformation call per 500 ms tick, diffed on the
           Windows side, image paths for new processes, and Sysmon process
           starts as they are written.
  Linux    a /proc pass on the same tick in a thread here, and Sysmon for
           Linux starts followed from the journal (platform/proclinux.py).
  Identity an optional judge (web/procidentity.py) that turns a process's
           path and hash into a three-word verdict, on one worker thread.

Frames sent to viewers, each with "h": "win" or "lin" (status excepted):

  snap    {"p": [row, ...]}                the whole table of one domain
  d       {"a": [row], "x": [key], "u": [[key, cpu, rss_kb]]}   one tick
  ev      {"pid", "ppid", "name", "i"}     a start as Sysmon wrote it
  i       {"i": [[key, ident], ...]}       identity verdicts, as they are made
  status  {"sources": {...}, "identity": {...}, "viewers": n}   every second

  row   = [key, pid, ppid, name, created_ms, cpu_pct, rss_kb, session, ident]
  key   = "pid:created_ms", so a reused pid is a different process
  ident = [place, path, hash] verdict words, or null while not judged

Invariants (docs/architecture/MECHANISMS.md, "helper" and "stream"):

  * Read-only and metadata only. Names, ids, times, CPU, memory and verdict
    words; never a path, a hash, a command line, an environment or a handle.
    Paths and hashes stay in this process for the judge and are removed from
    every frame here. Nothing here can start, signal or change a process: the
    helper's stdin carries no commands, its only meaning is "keep going".
  * Demand-driven and bounded. Nothing runs until a viewer acquires the feed;
    LINGER_S after the last one releases it everything stops. One helper, one
    sampler, one journal follower and one identity worker however many
    viewers. The frame ring holds RING frames; a viewer that falls behind it
    is resynchronised with a full snapshot. Unexpected helper or follower
    exits are capped at RESTARTS per RESTART_WINDOW_S; the identity queue at
    IDENTITY_QUEUE jobs.
  * Continuous. The Windows helper ends itself after 30 minutes; at RENEW_S
    its successor is started and takes over on its first table, so a long
    watch has no gap. A successor that does not report within HANDOFF_S is
    dropped and the current helper kept.
  * Never quiet when blind. Each source reports its state (starting, live,
    unavailable with a reason) and the time of its last frame; a source whose
    last frame is older than STALE_S is stale, and viewers are told so. An
    identity not yet judged is null, never a guess.
  * Separate from protection. The feed shares no lane, lock or store with the
    collectors; a stuck helper or a slow viewer cannot delay a collector.
"""

import json
import os
import subprocess
import threading
import time
from collections import deque

from jarvis.core.paths import load_win_script
from jarvis.platform import host, proclinux, windows

TICK_S = 0.5
LINGER_S = 15.0
STALE_S = 2.5
RING = 400
RESTARTS = 3
RESTART_WINDOW_S = 300.0
RENEW_S = 25 * 60.0         # the helper's own lifetime is 30 minutes
HANDOFF_S = 20.0            # a successor's first table must arrive within this
IDENTITY_QUEUE = 4096
IDENTITY_BATCH = 64
IDENTITY_REFRESH_S = 60.0   # re-judge everything: baselines move, "today" ends
START_MEMORY_S = 10.0       # how long a Sysmon start waits for its process row
MAX_LINE = 4 << 20
SCRIPT = "procfeed.ps1"
HOSTS = ("win", "lin")

# Fields a viewer may receive from a helper frame, by frame kind.
_SAFE_EV = ("pid", "ppid", "name")


def viewer_row(row, ident):
    """The 9-field row a viewer receives: the 8 metadata fields and the verdict."""
    return list(row[:8]) + [ident]


class _Helper:
    """One running Windows helper and the thread reading it."""

    def __init__(self, proc, started):
        self.proc, self.started = proc, started
        self.ready = threading.Event()      # its first table has been applied
        self.done = threading.Event()       # its output has ended
        self.renewable = True


class Feed:
    """The shared live table. acquire()/release() bracket each viewer."""

    def __init__(self, *, windows_enabled=None, linux_enabled=None, clock=time.monotonic,
                 wall=time.time, spawn=None, linux_reader=proclinux.read_linux,
                 exe_reader=proclinux.exe_path, follower=proclinux.StartFollower, identity=None):
        self.windows_enabled = host.has_windows() if windows_enabled is None else windows_enabled
        self.linux_enabled = host.has_linux() if linux_enabled is None else linux_enabled
        self.clock, self.wall = clock, wall
        self._spawn = spawn or self._spawn_helper
        self._read_linux, self._read_exe, self._follower_factory = linux_reader, exe_reader, follower
        self.identity = identity
        self._lock = threading.Condition()
        self._viewers = 0
        self._idle_since = None
        self._running = False
        self._stop = threading.Event()
        self._seq = 0
        self._ring = deque(maxlen=RING)
        self.tables = {h: {} for h in HOSTS}
        self.paths = {h: {} for h in HOSTS}        # key -> image path (never sent)
        self.hashes = {h: {} for h in HOSTS}       # key -> sha256 (never sent)
        self.idents = {h: {} for h in HOSTS}       # key -> [place, path, hash]
        self._starts = {h: {} for h in HOSTS}      # pid -> (clock, path, sha256) from Sysmon
        self.sources = {}
        self._helper = None                        # the active helper's process
        self._active = self._successor = None
        self._follower = None
        self._restarts = {"win": deque(), "lin": deque()}
        self._fast, self._slow = deque(), deque()
        self._work = threading.Event()
        self._identity_errors = 0
        for h, on in (("win", self.windows_enabled), ("lin", self.linux_enabled)):
            self.sources[h] = {"state": "idle" if on else "absent", "reason": "",
                               "last": None, "events": ""}

    def set_identity(self, identity):
        """Attach the judge once; later calls keep the first."""
        with self._lock:
            if self.identity is None:
                self.identity = identity

    # --- viewers ----------------------------------------------------------

    def acquire(self):
        with self._lock:
            self._viewers += 1
            self._idle_since = None
            if not self._running:
                self._start()

    def release(self):
        with self._lock:
            self._viewers = max(0, self._viewers - 1)
            if self._viewers == 0:
                self._idle_since = self.clock()

    @property
    def viewers(self):
        return self._viewers

    @property
    def running(self):
        return self._running

    # --- frames -------------------------------------------------------------

    def _push(self, frame):
        """Append one frame under the lock and wake every viewer."""
        self._seq += 1
        frame["seq"] = self._seq
        self._ring.append((self._seq, json.dumps(frame, separators=(",", ":"))))
        self._lock.notify_all()

    def _rows(self, h, rows=None):
        idents = self.idents[h]
        return [viewer_row(r, idents.get(r[0])) for r in (self.tables[h].values() if rows is None else rows)]

    def _snap_frame(self, h):
        return {"k": "snap", "h": h, "t": int(self.wall() * 1000), "p": self._rows(h)}

    def status(self):
        now = self.clock()
        out = {}
        for h, s in self.sources.items():
            age = None if s["last"] is None else round(now - s["last"], 2)
            state = s["state"]
            if state == "live" and (age is None or age > STALE_S):
                state = "stale"
            out[h] = {"state": state, "reason": s["reason"], "age_s": age, "events": s["events"]}
        identity = {"on": self.identity is not None, "queued": len(self._fast) + len(self._slow),
                    "errors": self._identity_errors}
        if self.identity is not None and hasattr(self.identity, "state"):
            identity.update(self.identity.state())
        return {"k": "status", "t": int(self.wall() * 1000), "sources": out,
                "identity": identity, "viewers": self._viewers}

    def snapshot(self):
        """(seq, [frame text]) to bring a new or lagging viewer up to date."""
        with self._lock:
            frames = [json.dumps(self._snap_frame(h), separators=(",", ":"))
                      for h in HOSTS if self.sources[h]["state"] != "absent"]
            frames.append(json.dumps(self.status(), separators=(",", ":")))
            return self._seq, frames

    def frames_after(self, seq, timeout):
        """(new seq, frames) after `seq`; None when `seq` fell out of the ring."""
        with self._lock:
            if self._seq == seq:
                self._lock.wait(timeout)
            if not self._ring or self._seq == seq:
                return seq, []
            oldest = self._ring[0][0]
            if seq < oldest - 1:
                return None
            return self._seq, [text for s, text in self._ring if s > seq]

    # --- lifecycle ------------------------------------------------------------

    def _start(self):
        # Each run has its own stop event: threads of a run that is shutting
        # down can never be revived by the next viewer's start.
        self._running = True
        stop = self._stop = threading.Event()
        threads = [("procfeed-linger", self._supervise), ("procfeed-identity", self._identity_loop)]
        if self.linux_enabled:
            self.sources["lin"].update(state="starting", reason="")
            threads += [("procfeed-linux", self._linux_loop), ("procfeed-linux-starts", self._linux_starts_loop)]
        if self.windows_enabled:
            self.sources["win"].update(state="starting", reason="")
            threads.append(("procfeed-windows", self._windows_loop))
        for name, target in threads:
            threading.Thread(target=target, args=(stop,), name=name, daemon=True).start()

    def _supervise(self, stop):
        while not stop.wait(1.0):
            with self._lock:
                self._push(self.status())
                if (self._viewers == 0 and self._idle_since is not None
                        and self.clock() - self._idle_since >= LINGER_S):
                    self._shutdown()

    def _shutdown(self):
        """Stop everything; called with the lock held."""
        self._stop.set()
        self._work.set()
        self._running = False
        for helper in (self._active, self._successor):
            if helper is not None:
                _end(helper.proc)
        self._active = self._successor = self._helper = None
        follower, self._follower = self._follower, None
        if follower is not None:
            follower.close()
        for h, s in self.sources.items():
            if s["state"] != "absent":
                s.update(state="idle", reason="no viewer", last=None, events="")
            self._forget(h)
        self._fast.clear()
        self._slow.clear()
        self._ring.clear()
        self._push(self.status())

    def _forget(self, h):
        for table in (self.tables, self.paths, self.hashes, self.idents, self._starts):
            table[h] = {}

    def stop(self):
        with self._lock:
            if self._running:
                self._shutdown()

    def _restart_allowed(self, h):
        """Count one unexpected restart of a source; False when over the cap."""
        now, recent = self.clock(), self._restarts[h]
        while recent and now - recent[0] > RESTART_WINDOW_S:
            recent.popleft()
        if len(recent) >= RESTARTS:
            return False
        recent.append(now)
        return True

    # --- identity ----------------------------------------------------------------

    def _note_row(self, h, row, path):
        """A row joined the table: remember its path and hash, queue a verdict.
        Called with the lock held."""
        key = row[0]
        start = self._starts[h].pop(row[1], None)      # its Sysmon start, if that came first
        self.paths[h][key] = path or (start[1] if start else "")
        if start and start[2]:
            self.hashes[h][key] = start[2]
        self._queue(self._fast, ("row", h, key))

    def _queue(self, queue, job):
        if self.identity is None or len(self._fast) + len(self._slow) >= IDENTITY_QUEUE:
            return False
        queue.append(job)
        self._work.set()
        return True

    def _note_start(self, h, start, frame):
        """A Sysmon start: keep its path and hash for the row that will follow,
        or hand them to the row that came first; queue the event. Lock held."""
        now = self.clock()
        starts = self._starts[h]
        for pid in [p for p, s in starts.items() if now - s[0] > START_MEMORY_S]:
            del starts[pid]
        row = next((r for r in self.tables[h].values() if r[1] == start["pid"]), None)
        if row is not None:
            key = row[0]
            if start["path"] and not self.paths[h].get(key):
                self.paths[h][key] = start["path"]
            if start["sha256"] and not self.hashes[h].get(key):
                self.hashes[h][key] = start["sha256"]
                self._queue(self._fast, ("row", h, key))
        elif len(starts) < IDENTITY_QUEUE:
            starts[start["pid"]] = (now, start["path"], start["sha256"])
        if not self._queue(self._fast, ("ev", h, frame, start["path"], start["sha256"])):
            self._push(frame)

    def _identity_loop(self, stop):
        refreshed = self.clock()
        while not stop.is_set():
            self._work.wait(1.0)
            if stop.is_set():
                return
            if self.identity is None:
                self._work.clear()
                continue
            if self.clock() - refreshed >= IDENTITY_REFRESH_S:
                refreshed = self.clock()
                with self._lock:
                    for h in HOSTS:
                        for key in self.tables[h]:
                            self._queue(self._fast, ("row", h, key))
            self._identity_batch(stop)

    def _identity_batch(self, stop):
        """Judge up to IDENTITY_BATCH fast jobs, else one slow lookup; send the changes."""
        with self._lock:
            jobs = [self._fast.popleft() for _ in range(min(IDENTITY_BATCH, len(self._fast)))]
            if not jobs and self._slow:
                jobs = [self._slow.popleft()]
            if not jobs:
                self._work.clear()
                return
            work = [self._job_input(job) for job in jobs]
        results = []
        for job, data in zip(jobs, work):
            if data is None or stop.is_set():
                continue
            try:
                results.append((job, self._judge(job, data)))
            except Exception:               # a judge bug must not stop the feed; it is counted
                results.append((job, (["unknown", "unknown", "unknown"], None)))
                with self._lock:
                    self._identity_errors += 1
        changed = {h: [] for h in HOSTS}
        with self._lock:
            if stop.is_set():
                return
            for job, (ident, sha) in results:
                kind, h = job[0], job[1]
                if kind == "ev":
                    frame = dict(job[2], i=ident)
                    self._push(frame)
                    continue
                key = job[2]
                if key not in self.tables[h]:
                    continue                     # exited while being judged
                if sha is not None:
                    self.hashes[h][key] = sha            # "" = looked up, none recorded
                if self.idents[h].get(key) != ident:
                    self.idents[h][key] = ident
                    changed[h].append([key, ident])
                if ident[2] == "pending":
                    self._queue(self._slow, ("hash", h, key))
            for h, items in changed.items():
                if items:
                    self._push({"k": "i", "h": h, "t": int(self.wall() * 1000), "i": items})

    def _job_input(self, job):
        """What the judge needs for one job, read under the lock; None if gone."""
        kind, h = job[0], job[1]
        if kind == "ev":
            return {"name": job[2].get("name", ""), "path": job[3], "sha": job[4]}
        key = job[2]
        row = self.tables[h].get(key)
        if row is None:
            return None
        return {"name": row[3], "pid": row[1], "created": row[4], "path": self.paths[h].get(key, ""),
                "sha": self.hashes[h].get(key, ""), "looked": key in self.hashes[h]}

    def _judge(self, job, data):
        """(ident, sha256 to remember or None) for one job, outside the lock."""
        kind, h = job[0], job[1]
        if kind == "hash":
            sha = self.identity.recorded_hash(h, data["pid"], data["created"])
            return self.identity.judge(h, data["name"], data["path"], sha), sha
        if kind == "ev":
            # The page uses this only if no table row shows the process: a start
            # too short to sample, judged against the start history.
            return self.identity.judge_start(h, data["name"], data["path"], data["sha"]), None
        ident = self.identity.judge(h, data["name"], data["path"], data["sha"])
        if kind == "row" and h == "win" and not data["looked"]:
            ident[2] = "pending"                 # the event log is asked next, slowly
        return ident, None

    # --- Linux ----------------------------------------------------------------

    def _linux_loop(self, stop):
        hz, cpus = proclinux.clock_ticks(), os.cpu_count() or 1
        prev, prev_t = {}, None
        first = True
        while not stop.is_set():
            started = self.clock()
            try:
                cur = self._read_linux()
            except OSError as exc:
                with self._lock:
                    self.sources["lin"].update(state="unavailable", reason=type(exc).__name__)
                    self._push(self.status())
                stop.wait(TICK_S)
                continue
            elapsed = TICK_S if prev_t is None else started - prev_t
            added, exited, updated = proclinux.diff(prev, cur, elapsed, hz, cpus)
            exes = {r[0]: self._read_exe(r[1]) for r in added}
            with self._lock:
                if stop.is_set():
                    return
                self.tables["lin"] = cur
                for key in exited:
                    for table in (self.paths, self.hashes, self.idents):
                        table["lin"].pop(key, None)
                for r in added:
                    self._note_row("lin", r, exes[r[0]])
                self.sources["lin"].update(state="live", reason="", last=self.clock())
                if first:
                    self._push(self._snap_frame("lin"))
                    first = False
                else:
                    self._push({"k": "d", "h": "lin", "t": int(self.wall() * 1000),
                                "a": self._rows("lin", added), "x": exited, "u": updated})
            prev, prev_t = cur, started
            stop.wait(max(0.0, TICK_S - (self.clock() - started)))

    def _linux_starts_loop(self, stop):
        """Sysmon for Linux starts, so a process shorter than one tick is seen."""
        while not stop.is_set():
            with self._lock:
                if not self._restart_allowed("lin"):
                    self.sources["lin"]["events"] = (
                        f"unavailable: follower failed {RESTARTS} times in {int(RESTART_WINDOW_S)} s")
                    return
            follower = self._follower_factory()
            try:
                follower.open()
                with self._lock:
                    if stop.is_set():            # shut down while it started: never leave it running
                        follower.close()
                        return
                    self._follower = follower
                    self.sources["lin"]["events"] = "waiting for Sysmon"
                for start in follower.starts(stop):
                    with self._lock:
                        if stop.is_set():
                            return
                        self.sources["lin"]["events"] = "sysmon"
                        frame = {"k": "ev", "h": "lin", "t": int(self.wall() * 1000),
                                 **{k: start[k] for k in _SAFE_EV}}
                        self._note_start("lin", start, frame)
                reason = f"follower exited ({follower.exit_code()})"
            except (OSError, ValueError) as exc:
                reason = f"follower did not start: {type(exc).__name__}"
            follower.close()
            with self._lock:
                if stop.is_set():
                    return
                self.sources["lin"]["events"] = "unavailable: " + reason
            stop.wait(5.0)

    # --- Windows ----------------------------------------------------------------

    def _spawn_helper(self):
        ps = windows.find_powershell()
        if not ps:
            raise OSError("powershell not found")
        return subprocess.Popen(
            [*windows.interop_launcher(), ps, "-NoProfile", "-NonInteractive",
             "-Command", load_win_script(SCRIPT)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=host.subprocess_cwd(), **host.spawn_options())

    def _windows_loop(self, stop):
        active = None
        while not stop.is_set():
            if active is None:
                with self._lock:
                    if not self._restart_allowed("win"):
                        self.sources["win"].update(
                            state="unavailable",
                            reason=f"helper failed {RESTARTS} times in {int(RESTART_WINDOW_S)} s")
                        self._push(self.status())
                        return
                    self.sources["win"].update(state="starting", reason="")
                active = self._launch(stop, successor=False)
                if active is None:
                    stop.wait(5.0)
                    continue
            if active.done.wait(0.5):
                self._lost(active, stop)
                active = None
                stop.wait(2.0)
            elif active.renewable and self.clock() - active.started >= RENEW_S:
                active = self._renew(active, stop)

    def _launch(self, stop, successor):
        """Start a helper and the thread reading it; None if it did not start."""
        try:
            proc = self._spawn()
        except (OSError, ValueError) as exc:
            if not successor:
                with self._lock:
                    self.sources["win"].update(state="unavailable",
                                               reason=f"helper did not start: {type(exc).__name__}")
                    self._push(self.status())
            return None
        helper = _Helper(proc, self.clock())
        with self._lock:
            if stop.is_set():
                _end(proc)
                return None
            if successor:
                self._successor = helper
            else:
                self._active, self._helper = helper, proc
        threading.Thread(target=self._pump, args=(helper, stop), name="procfeed-windows-read",
                         daemon=True).start()
        return helper

    def _renew(self, active, stop):
        """Hand over to a fresh helper before `active` reaches its lifetime."""
        successor = self._launch(stop, successor=True)
        deadline = self.clock() + HANDOFF_S
        while successor is not None and not stop.is_set() and self.clock() < deadline:
            if successor.ready.wait(0.2):
                _end(active.proc)                # the pump switched over under the lock
                return successor
            if successor.done.is_set():
                break
        with self._lock:
            if self._successor is successor:
                self._successor = None
        if successor is not None:
            _end(successor.proc)
        active.renewable = False                 # it will end at its lifetime and restart
        return active

    def _lost(self, helper, stop):
        """The active helper ended on its own: say so and drop its table."""
        _end(helper.proc)
        with self._lock:
            if self._active is helper:
                self._active = self._helper = None
            if stop.is_set():
                return
            self.sources["win"].update(state="unavailable",
                                       reason=f"helper exited ({helper.proc.poll()})")
            self._forget("win")
            self._push(self.status())

    def _pump(self, helper, stop):
        """Apply one helper's frames until its output ends."""
        try:
            for raw in iter(lambda: helper.proc.stdout.readline(MAX_LINE), b""):
                if stop.is_set():
                    return
                try:
                    frame = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(frame, dict):
                    continue
                with self._lock:
                    if stop.is_set():
                        return
                    if helper is self._successor and frame.get("k") == "snap":
                        self._active, self._successor, self._helper = helper, None, helper.proc
                    if helper is self._active:
                        self._apply_windows(frame)
                        if frame.get("k") == "snap":
                            helper.ready.set()
        except (OSError, ValueError):
            pass
        finally:
            helper.done.set()

    def _apply_windows(self, frame):
        """Fold one helper frame into the Windows table; called with the lock held."""
        kind = frame.get("k")
        src = self.sources["win"]
        t = frame.get("t") if isinstance(frame.get("t"), int) else int(self.wall() * 1000)
        if kind == "hello":
            src.update(events=str(frame.get("events", ""))[:80])
            return
        if kind == "bye":
            src.update(state="unavailable", reason="helper reached its lifetime")
            self._push(self.status())
            return
        if kind == "snap":
            self._apply_win_snap(frame.get("p", []))
            out = self._snap_frame("win")
        elif kind == "d":
            out = self._apply_win_delta(frame, t)
        elif kind == "ev":
            start = _win_start(frame)
            if start is None:
                return
            src.update(state="live", reason="", last=self.clock())
            self._note_start("win", start, {"k": "ev", "h": "win", "t": t,
                                            **{k: start[k] for k in _SAFE_EV}})
            return
        else:
            return
        src.update(state="live", reason="", last=self.clock())
        self._push(out)

    def _apply_win_snap(self, rows):
        table = {}
        for r in rows:
            if _row_ok(r):
                table[r[0]] = r[:8]
                if r[0] not in self.tables["win"]:
                    self._note_row("win", r, _path_of(r))
        for key in [k for k in self.tables["win"] if k not in table]:
            for t in (self.paths, self.hashes, self.idents):
                t["win"].pop(key, None)
        self.tables["win"] = table

    def _apply_win_delta(self, frame, t):
        table = self.tables["win"]
        added = []
        for r in frame.get("a", []):
            if _row_ok(r):
                table[r[0]] = r[:8]
                added.append(r[:8])
                self._note_row("win", r, _path_of(r))
        exited = [k for k in frame.get("x", []) if isinstance(k, str)]
        for k in exited:
            table.pop(k, None)
            for store in (self.paths, self.hashes, self.idents):
                store["win"].pop(k, None)
        updates = []
        for u in frame.get("u", []):
            if isinstance(u, list) and len(u) == 3 and u[0] in table:
                table[u[0]][5], table[u[0]][6] = u[1], u[2]
                updates.append(u)
        return {"k": "d", "h": "win", "t": t, "a": self._rows("win", added), "x": exited, "u": updates}


def _row_ok(row):
    return (isinstance(row, list) and len(row) in (8, 9) and isinstance(row[0], str)
            and isinstance(row[1], int) and isinstance(row[2], int))


def _path_of(row):
    return row[8] if len(row) == 9 and isinstance(row[8], str) else ""


def _win_start(frame):
    try:
        pid, ppid = int(frame.get("pid")), int(frame.get("ppid") or 0)
    except (TypeError, ValueError):
        return None
    sha = frame.get("sha256")
    return {"pid": pid, "ppid": ppid, "name": str(frame.get("name") or "?")[:260],
            "path": str(frame.get("path") or ""),
            "sha256": sha.lower() if isinstance(sha, str) and len(sha) == 64 else ""}


def _end(proc):
    """Close the helper's stdin (its signal to stop), then make sure it is gone."""
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


_FEED = None
_FEED_LOCK = threading.Lock()


def shared(identity=None):
    """The one feed of this process; `identity` is attached on first offer."""
    global _FEED
    with _FEED_LOCK:
        if _FEED is None:
            _FEED = Feed()
    if identity is not None:
        _FEED.set_identity(identity)
    return _FEED
