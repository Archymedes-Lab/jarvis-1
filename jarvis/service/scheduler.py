"""The always-on loop: run the audits one at a time, each on its own interval.

The collectors have wildly different costs. Reading /proc takes 20ms; a
PowerShell audit takes 15-60s because crossing the WSL interop boundary and
spinning up powershell.exe dominates everything else. So jobs run on their own
intervals, and never concurrently -- a single worker thread runs them one at a
time, because two simultaneous powershell.exe launches are slower than running
them back to back and would fight over the same interop pipe.

One exception: the jobs that prove JARVIS is watching at all run in a lane of
their own. They are cheap (a socket stat, a heartbeat read, a /proc walk plus
one short process listing), and behind a single queue they starved: on
2026-09-17 `intrusion` (48s) then `secrets` (192s) held the worker, `bridge`
and `scan` aged past their health limits, and the Windows monitor mailed
"monitoring unavailable" about a daemon that was perfectly alive. A long audit
must never be able to make JARVIS look dead.

The same reasoning, measured again on 2026-11-03, gives the collectors on a
five-minute cadence a lane of their own (FREQUENT): behind the post-boot sweep
they went stale for 16 minutes. PowerShell launches from every lane pass one
daemon-wide admission gate (platform/interop_gate.py), so more lanes never
mean more concurrent powershell.exe processes than the gate allows.
"""

import json
import os
import subprocess
import threading
import time
import traceback

from jarvis.core import collection, incidents, mechanisms, memory
from jarvis.core.store import Store
from jarvis.response import alert, defense, remediation
from jarvis.response.reporting import notifications
from jarvis.service import links, reliability, sdnotify
from jarvis.service.jobs import run_job
from jarvis.service.schedule import JOBS

# The priority lane: short jobs that health and the watchdogs judge freshness
# by. Each must stay well under a few seconds, or it starves its own lane.
# native (the event-log ingest, ~1.5s, run in a deadline-bounded child) and
# watchdogs (~0.2s) joined on 2026-09-23: behind the post-boot sweep of
# multi-minute collectors they waited 7+ minutes and went stale, blanking
# Monitoring while nothing was actually wrong. native is the only event-log
# writer in the daemon; readers take no lock and see committed batches only.
FAST = mechanisms.names(lane="fast")
# The bulk lane: jobs whose cost is DrvFS hashing and network, not the
# PowerShell interop pipe. `evidence` took 314 s of every 900 s (35 % of the
# main lane's duty) on 2026-10-10, pushing that lane past 100 %.
# 2026-10-11: world, feeds and rust_mirror make no PowerShell calls (network,
# DrvFS and Linux work only), so they move off the main lane too: its measured
# steady-state duty was 94% with evidence, leaving 6% to catch up after a
# restart, a WSL crash or a standby, and 32 of 51 collectors stayed stale.
BULK = mechanisms.names(lane="bulk")
# The frequent lane (2026-11-03): collectors on a cadence of five minutes or
# less. After a boot the main lane owes one sweep of every audit (1331 s
# measured, intrusion 299 s, secrets 168 s, firewall 117 s), and the
# five-minute collectors behind it went stale for 16 min with no error. Here
# they wait at most one pass of each other (duty 0.31). Their PowerShell
# launches pass the same interop gate as every other lane, which bounds
# concurrent launches daemon-wide (platform/interop_gate.py).
FREQUENT = mechanisms.names(lane="frequent")
# Lane -> (heartbeat attribute, running-job attribute). One table so a new
# lane cannot be started without its liveness and its current job reported.
LANE_ATTRS = {"fast": ("fast_heartbeat", "fast_current"),
              "frequent": ("frequent_heartbeat", "frequent_current"),
              "main": ("heartbeat", "current"),
              "bulk": ("bulk_heartbeat", "bulk_current")}
ISOLATED = set(mechanisms.names(isolated=True))
# Longest the cold-start gate may hold coverage and report back. One full
# sweep takes a few minutes; past this the audits run and report honestly
# on whatever has still not caught up.
COLD_START_HOLD_S = 900
# Wall-clock time that outran the monotonic clock by this much means the VM
# was paused: Windows Modern Standby and sleep freeze the WSL guest, whose
# monotonic clock stops while realtime is corrected on wake (measured
# 2026-09-24: ~4.3 h of lag across one night). NTP slews are far smaller.
RESUME_JUMP_S = 60.0
# A failed run inside its freshness budget keeps the last good result and is
# retried after RETRY_S, at most HOLD_MAX times in a row before it is recorded.
RETRY_S = 60
# After a job raised out of run_once, the lane waits this long before the next job.
LANE_ERROR_PAUSE_S = 5
# How often a paired phone's approvals are offered and its replies fetched (notify/replies.py). When no
# request is outstanding this does no network work at all.
PHONE_TICK_S = 5

# How often time-bounded containment (defense.expire) is checked for expiry.
EXPIRY_SWEEP_S = 60
# How overdue (as a share of its cadence) a forced job counts as, at least.
FORCED_FLOOR = 1.0
# How overdue a boot-scoped collector whose evidence predates the current boot
# counts as, at least: due now, competing on criticality like any job whose
# cadence just expired. Not the never-ran 99, which would put ~8 min of serial
# boot audits ahead of tier-0 sysmon ingestion. Measured 2026-10-27: with no
# floor, memscan/posture/spy still carried pre-reboot results 20 min after boot.
BOOT_FLOOR = 1.0
BOOT_SCOPED = frozenset(mechanisms.boot_scoped()) & set(JOBS)
HOLD_MAX = 3
RETRY_META = "collector_retry_"
# Lateness (as a share of cadence) at which a collector is starving: its
# evidence has aged past the hard deadline. Starving collectors are served
# before anything else, ordered by lateness x criticality. Matches
# reliability.STALE_AFTER.
STARVING = reliability.STALE_AFTER
# A repeated force request for a job that attempted within this long (capped
# at its own cadence) waits. On 2026-10-10 the Windows reviver re-forced a
# capped sysmon every ~30 s and it ran back to back for 7 hours, starving 36
# collectors. The request is kept, not dropped.
FORCE_COOLDOWN_S = 300


def reports_backlog(findings):
    """True when a run read one bounded page of a larger backlog and said so."""
    return any("catching up a backlog" in (f.get("title") or "")
               for f in findings or () if isinstance(f, dict))


# The last isolated child's (cpu seconds, peak RSS KiB), per lane thread.
_CHILD_COST = threading.local()


def _rss_kib():
    """This process's resident memory, from /proc (cheap; 0 when unknown)."""
    try:
        with open("/proc/self/statm", "rb") as fh:
            return int(fh.read().split()[1]) * (os.sysconf("SC_PAGE_SIZE") // 1024)
    except (OSError, ValueError, IndexError):
        return 0


def _children_cpu():
    """CPU of reaped child processes; 0 where `resource` does not exist (Windows)."""
    try:
        import resource
    except ImportError:
        return 0.0
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _isolated_job(name, hosts, db_path, timeout):
    """Run a fixed collector beyond the scheduler's process boundary.

    DrvFS calls can block a Python thread inside the kernel, where a future or
    thread timeout cannot recover it. A child process gives the scheduler a
    real deadline and releases the event-log writer lock when terminated.
    """
    from jarvis.core.paths import PACKAGE_DIR, self_executable
    command = [self_executable(), "-m", "jarvis.service.collector_worker",
               name, db_path, *hosts]
    # From the package root: `-m` resolves against the working directory, and
    # the Argus unit runs from "/" (found 2026-10-29), where it would not import.
    try:
        done = subprocess.run(command, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True,
                              errors="replace", cwd=str(PACKAGE_DIR.parent),
                              timeout=max(1.0, timeout), check=False)
    except subprocess.TimeoutExpired:
        return [], (f"collector exceeded its {timeout:.0f}s process deadline; "
                    "worker terminated to protect scheduler availability"), "unavailable"
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or f"worker exited {done.returncode}")[-800:]
        return [], f"isolated collector failed: {detail}", "unavailable"
    try:
        result = json.loads(done.stdout)
        _CHILD_COST.value = (float(result.get("cpu_s") or 0.0), int(result.get("max_rss_kib") or 0))
        findings = result["findings"]
        error = str(result.get("error") or "")[:800]
        status = result.get("status")
        if not isinstance(findings, list) or status not in (
                "complete", "partial", "unavailable"):
            raise ValueError("invalid result shape")
        return findings, error, status
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return [], f"isolated collector returned invalid evidence: {exc}", "unavailable"


BOOT_META = "host_boot_v1"


def host_boot_time():
    """Guest boot time from /proc/stat btime, or None. Never raises.

    btime is realtime minus uptime, so it moves whenever the WSL clock is
    stepped (374 s between two reads on 2026-10-27); use host_boot()."""
    try:
        with open("/proc/stat", encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii", errors="replace") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def host_boot(db_path):
    """Boot time of the current guest boot, fixed for the life of that boot.

    Read once per kernel boot id, seconds after boot when clock drift is
    smallest, and kept in the store, so later clock steps and daemon restarts
    do not move it. Falls back to a live btime read. Never raises."""
    boot_id, btime = _boot_id(), host_boot_time()
    if not boot_id:
        return btime
    try:
        store = Store(db_path)
        try:
            saved = json.loads(store.get_meta(BOOT_META) or "null")
            if isinstance(saved, dict) and saved.get("boot_id") == boot_id \
                    and isinstance(saved.get("at"), (int, float)):
                return float(saved["at"])
            if btime:
                store.set_meta(BOOT_META, json.dumps({"boot_id": boot_id, "at": btime}))
        finally:
            store.close()
    except Exception:
        pass
    return btime


class Scheduler(threading.Thread):
    """Runs the audits forever, one at a time, each on its own interval."""

    daemon = True

    def __init__(self, db_path, hosts):
        super().__init__(name="jarvis-scheduler")
        self.db_path = db_path
        self.hosts = hosts
        self.lane_errors = {}      # lane -> jobs that raised out of run_once (the lane kept running)
        # Give every cold-start job a real deadline. Using 0 here makes every
        # job that has not run yet appear decades more overdue than a recurring
        # short-interval job. The result is a full, multi-minute cold-start
        # sweep before scan/bridge/input_hook get their second turn.
        first_deadline = time.time()
        self.next_run = {name: first_deadline for name in JOBS}
        # Coverage judges persisted timestamps. On restart those timestamps are
        # necessarily from the previous process until each collector gets its
        # first turn; running coverage halfway through that cold-start sweep
        # sends a burst of false "stale" pages for perfectly healthy jobs later
        # in the dict. Hold the automatic coverage pass until every other job
        # has attempted once. A manually forced pass still runs immediately.
        # Only jobs coverage would actually flag hold the gate, and the hold
        # is bounded: under host pressure a daily collector can lose every
        # turn for hours, and a gate waiting on it froze the recorded score
        # and the coverage audit for 6h on 2026-09-22.
        self.cold_start_pending = self._cold_start_gate()
        self.forced = []
        self.retry_soon = set()
        # Real lateness: persisted evidence time and this process's last
        # attempt. next_run restarts at process start, so lateness measured
        # from it called six hours of staleness "a few minutes" after a restart.
        self.evidence_ts = self._seed_evidence()
        self.last_attempt = {}
        self.current = None
        # Bumped at the top of every loop iteration. The systemd watchdog pings
        # only while this keeps advancing, so a wedged scheduler — alive process,
        # frozen snapshots — gets the service restarted instead of going
        # unnoticed. It is deliberately not touched mid-job: the longest job
        # (~106s) must not look like a hang, but a multi-minute stall must.
        self.heartbeat = time.time()
        self.fast_heartbeat = time.time()
        self.fast_current = None
        self.fast_thread = None
        self.bulk_heartbeat = time.time()
        # Monotonic twins of the heartbeats. CLOCK_MONOTONIC stops with the
        # VM during standby, so an age measured on it counts only time in
        # which the lane could have run. Wall-clock ages called a daemon
        # "stalled" right after every resume (the reviver then restarted a
        # healthy daemon: 2026-10-20 14:48, 2026-10-22 16:19); health and
        # the systemd watchdog read these instead.
        self.heartbeat_mono = time.monotonic()
        self.fast_heartbeat_mono = time.monotonic()
        self.bulk_heartbeat_mono = time.monotonic()
        self.bulk_current = None
        self.bulk_thread = None
        self.frequent_heartbeat = time.time()
        self.frequent_heartbeat_mono = time.monotonic()
        self.frequent_current = None
        self.frequent_thread = None
        self.outages = None
        self.started_at = time.time()
        # The VM boots after Windows, so the guest boot bounds both: a result
        # older than it predates the current Windows boot too.
        self.boot_at = host_boot(db_path)
        self._boot_ready = None          # (boot_at, ready_at) once fully verified
        self.lock = threading.Lock()
        self._clock = (time.time(), time.monotonic())
        self.resumed_at = None
        self.resume_count = 0
        # Collector Reliability Plane: explicit contracts, freshness budgets,
        # leases and supervised recovery. See reliability.py. The scheduler
        # owns execution; the watchdog loop at the bottom of this module owns
        # recovery attempts. Leases stay in memory: a dead process loses them
        # and the next process judges by persisted snapshots, while a hung
        # worker keeps its expired lease visible until it is escalated.
        self.job_cost = {}               # name -> last run's cpu_s / rss growth (run_once)
        self.specs = reliability.build_specs(JOBS)
        self.reliability = reliability.ReliabilityState(self.specs)
        self._worker_seq = 0
        # Link Plane (links.py): the connections the jobs stand on. Ticked
        # from supervise_once; actions run one at a time off the supervisor
        # thread; state persists in one meta key and seeds the next process.
        self.links = links.LinkPlane().load(self._seed_meta(links.META))
        self._link_busy = threading.Lock()

    def _cold_start_gate(self):
        """Jobs whose persisted result coverage would call missing, failing
        or stale. A fresh result from the previous process already proves its
        collector; waiting on it can only delay the audits."""
        pending = set(JOBS) - {"coverage", "report"}
        try:
            store = Store(self.db_path)
            try:
                snaps = store.get_snapshots()
            finally:
                store.close()
        except Exception:
            return pending
        now = time.time()
        fresh = {name for name in pending
                 if (snaps.get(name) or {}).get("ts")
                 and not snaps[name].get("error")
                 and now - float(snaps[name]["ts"]) <= max(
                     JOBS[name][0] * 2, JOBS[name][0] + 300)}
        return pending - fresh

    def _seed_meta(self, key):
        """One persisted meta value at start, or "". Never raises."""
        try:
            store = Store(self.db_path)
            try:
                return store.get_meta(key, "") or ""
            finally:
                store.close()
        except Exception:
            return ""

    def _seed_evidence(self):
        """{job: persisted evidence time} at start. Never raises."""
        try:
            store = Store(self.db_path)
            try:
                snaps = store.get_snapshots()
            finally:
                store.close()
        except Exception:
            return {}
        return {name: float(s["ts"]) for name, s in snaps.items()
                if name in JOBS and s.get("ts")}

    def lateness(self, name, now=None):
        """How far past due this job's evidence is, as a share of its cadence,
        from the newer of its persisted evidence and its last attempt here. A
        job with neither counts as long overdue. An attempt resets lateness
        even when it failed, so a failing job cannot hold the top spot."""
        now = time.time() if now is None else now
        interval = max(1, JOBS[name][0])
        basis = max(self.evidence_ts.get(name, 0.0), self.last_attempt.get(name, 0.0))
        if basis <= 0:
            return 99.0
        late = max(0.0, now - basis) / interval
        if name in BOOT_SCOPED and self.boot_at and basis < self.boot_at:
            late = max(late, BOOT_FLOOR)
        return late

    def boot_readiness(self, snapshots):
        """Whether every boot-scoped collector has evidence from this boot.

        Derived from persisted snapshots alone, so a daemon restart inside
        one boot reports the same answer. pending: no result since boot;
        failed: the post-boot result is an error. ready_at is when the last of
        them first had a usable post-boot result (from the run receipts, which
        never change), so ready_after_s is boot -> fully verified and does not
        creep as the audits keep running. This is evidence currency, not a
        compromise verdict."""
        boot_at = self.boot_at
        if not boot_at:
            return {"known": False, "ready": False, "boot_at": None,
                    "pending": sorted(BOOT_SCOPED), "failed": [],
                    "reason": "host boot time unreadable; boot currency unknown"}
        pending, failed, last = [], [], 0.0
        for name in sorted(BOOT_SCOPED):
            snap = snapshots.get(name) or {}
            try:
                ts = float(snap.get("ts") or 0)
            except (TypeError, ValueError):
                ts = 0.0
            if ts < boot_at:
                pending.append(name)
            elif snap.get("error"):
                failed.append(name)
            else:
                last = max(last, ts)
        ready = not pending and not failed
        if ready:
            last = self._first_verified(boot_at, last)
        return {"known": True, "ready": ready, "boot_at": boot_at,
                "pending": pending, "failed": failed,
                "ready_at": last if ready else None,
                "ready_after_s": round(last - boot_at, 1) if ready else None}

    def _first_verified(self, boot_at, fallback):
        """Time each boot audit first returned usable evidence this boot; the
        latest of those. Cached per boot. Falls back to snapshot time when the
        receipts cannot be read (never raises)."""
        cached = self._boot_ready
        if cached and cached[0] == boot_at:
            return cached[1]
        try:
            store = Store(self.db_path)
            try:
                firsts = [store.db.execute(
                    "SELECT MIN(observed_at) FROM defender_runs WHERE job=? AND observed_at>=? "
                    "AND coverage!='unavailable'", (name, boot_at)).fetchone()[0]
                    for name in BOOT_SCOPED]
            finally:
                store.close()
        except Exception:
            return fallback
        if any(f is None for f in firsts):
            return fallback
        value = max(float(f) for f in firsts)
        self._boot_ready = (boot_at, value)
        return value

    def _lane_of(self, name):
        return ("fast" if name in FAST else "frequent" if name in FREQUENT
                else "bulk" if name in BULK else "main")

    def _note_resume(self):
        """Re-arm the cold-start hold after the host resumes from suspend.

        A resume leaves every persisted result as old as the suspend, exactly
        like a restart, but the process never restarted, so the cold-start
        gate stayed open: coverage and report then ran mid catch-up sweep,
        called waiting collectors stale, and recorded a collapsed score
        (10 at 07:56 on 2026-09-24; Monitoring read 8 until coverage's next
        run). Returns True when a resume was detected."""
        wall, mono = time.time(), time.monotonic()
        with self.lock:
            prev_wall, prev_mono = self._clock
            self._clock = (wall, mono)
        if (wall - prev_wall) - (mono - prev_mono) < RESUME_JUMP_S:
            return False
        pending = self._cold_start_gate()
        with self.lock:
            self.cold_start_pending = pending
            self.started_at = wall
            self.resumed_at = wall
            self.resume_count += 1
        if pending:
            self._open_wake_window(wall)
        return True

    def _open_wake_window(self, now):
        """Show "waking up, re-checking" on the dashboard for this sweep
        instead of a partial live score. Never raises."""
        try:
            from jarvis.response.reporting import score
            store = Store(self.db_path)
            try:
                score.open_wake_window(store, now)
            finally:
                store.close()
        except Exception:
            pass

    def wake_phase(self):
        """The scheduler's side of a re-verification window, for the score."""
        now = time.time()
        with self.lock:
            holding = sorted(self.cold_start_pending) if self._cold_start_holding(now) else []
            return {"holding": holding, "resumed_at": self.resumed_at,
                    "started_at": self.started_at,
                    "current": running_jobs(self)}

    def _cold_start_holding(self, now):
        return bool(self.cold_start_pending) and \
            now - self.started_at < COLD_START_HOLD_S

    # --- owner pause -----------------------------------------------------
    # A bounded break from collecting, for the owner who wants the computer
    # quiet. It is never indefinite: it ends by itself (PAUSE_MAX_S at most),
    # survives a restart only until that deadline, is recorded, and the lanes
    # keep their heartbeats so the watchdogs do not mistake it for a hang.
    PAUSE_META = "scheduler.paused_until"
    PAUSE_LOG = "scheduler.pause_log"
    PAUSE_MAX_S = 24 * 3600

    def paused_until(self, now=None):
        now = time.time() if now is None else now
        until = getattr(self, "_paused_until", None)
        if until is None:
            until = self._paused_until = self._load_pause()
        return until if until > now else 0

    def is_paused(self, now=None):
        return self.paused_until(now) > 0

    def _load_pause(self):
        try:
            store = Store(self.db_path)
            try:
                return float(store.get_meta(self.PAUSE_META, "") or 0)
            finally:
                store.close()
        except Exception:
            return 0.0

    def pause(self, seconds, now=None):
        """-> epoch the pause ends. Clamped to (0, PAUSE_MAX_S]."""
        now = time.time() if now is None else now
        seconds = max(60, min(int(seconds), self.PAUSE_MAX_S))
        self._paused_until = now + seconds
        self._record_pause("pause", now, self._paused_until)
        return self._paused_until

    def resume(self, now=None):
        now = time.time() if now is None else now
        self._paused_until = 0.0
        self._record_pause("resume", now, 0)

    def _record_pause(self, kind, now, until):
        try:
            store = Store(self.db_path)
            try:
                store.set_meta(self.PAUSE_META, str(until))
                try:
                    log = json.loads(store.get_meta(self.PAUSE_LOG, "") or "[]")
                except ValueError:
                    log = []
                log = (log if isinstance(log, list) else [])[-19:] + [{"ts": int(now), "event": kind, "until": int(until)}]
                store.set_meta(self.PAUSE_LOG, json.dumps(log))
            finally:
                store.close()
        except Exception:
            pass

    def force(self, name):
        """Queue a job to run soon. Repeated requests collapse into one."""
        if name in JOBS:
            with self.lock:
                if name not in self.forced:
                    self.forced.append(name)
            return True
        return False

    def _due(self, lane=None):
        """The job to run next. `lane` is "fast", "frequent", "main", "bulk" or None for any.

        Order (docs/architecture/LANE-FAIRNESS-AND-OUTAGE-RECORD.md):

        1. Starving jobs first: evidence older than STARVING x cadence,
           measured from real evidence and attempts, never from a next_run
           that a restart reset. No forced repeat of a job that just ran can
           jump them. On 2026-10-10 a re-forced sysmon held the only main
           worker for 7 hours while 36 collectors went stale.
        2. Then every other due or forced job, by relative lateness x
           criticality x failure pressure. A forced job counts as at least
           FORCED_FLOOR overdue, but a repeat request for a job that attempted
           within FORCE_COOLDOWN_S (capped at its cadence) waits.

        Relative lateness keeps every cadence represented. An absolute
        oldest-deadline policy starves the one-minute watchdogs behind every
        not-yet-run hourly collector after a restart or a long suspend.
        """
        if lane is None:
            member = lambda n: True  # noqa: E731
        else:
            member = lambda n: self._lane_of(n) == lane  # noqa: E731
        # Resource governor: under host pressure, deferrable Tier 1/2 jobs
        # yield to Tier 0 protection/ingestion. A governed job still runs
        # once it is 3x late, so deferral is a delay, never a drop, and
        # staleness accounting keeps working. Forced recovery bypasses this.
        with self.lock:
            forced = [n for n in self.forced if member(n)]
            queue_depth = len(self.forced)
        try:
            from jarvis.core import governor as governor_mod
            host_pressured, _reason = governor_mod.live_pressure(
                queue_depth=queue_depth)
        except Exception:
            host_pressured = False
        now = time.time()
        best, best_key = None, None
        for name, t in self.next_run.items():
            if not member(name):
                continue
            is_forced = name in forced
            if is_forced:
                cooldown = min(FORCE_COOLDOWN_S, JOBS[name][0])
                if now - self.last_attempt.get(name, 0.0) < cooldown:
                    is_forced = False          # kept queued; not yet eligible
            if name in ("coverage", "report") and self._cold_start_holding(now) \
                    and not is_forced:
                continue
            if t > now and not is_forced:
                continue
            late = self.lateness(name, now)
            starving = late >= STARVING
            overdue = late
            if is_forced:
                overdue = max(overdue, FORCED_FLOOR)
            elif host_pressured and governor_mod.should_defer(name, True) \
                    and late < 3.0:
                continue
            spec = self.specs.get(name)
            weight = reliability.CRITICALITY_WEIGHT.get(
                spec.criticality if spec else "medium", 1.0)
            failures = self.reliability.health[name].consecutive_failures \
                if name in self.reliability.health else 0
            score = overdue * weight * (1.0 + min(3, max(0, failures)) * 0.25)
            key = (starving, score)
            if best_key is None or key > best_key:
                best, best_key = name, key
        if best is not None and best in forced:
            with self.lock:
                if best in self.forced:
                    self.forced.remove(best)
        return best

    def _next_worker(self, lane):
        with self.lock:
            self._worker_seq += 1
            return f"{lane}-{self._worker_seq}"

    def reliability_status(self, snapshots=None):
        """Freshness/recovery plane state for health endpoints and dashboard.

        Never raises: a status page must not take down the daemon it reports
        on. Falls back to an empty snapshot map when the database is briefly
        locked.
        """
        try:
            if snapshots is None:
                store = Store(self.db_path)
                try:
                    snapshots = store.get_snapshots()
                finally:
                    store.close()
            with self.lock:
                resume = {"count": self.resume_count, "last_at": self.resumed_at,
                          "holding": sorted(self.cold_start_pending)
                          if self._cold_start_holding(time.time()) else []}
            outage = {}
            if self.outages is not None:
                outage = {**self.outages.status,
                          "open": self.outages.open_outages()}
            lateness = {name: round(self.lateness(name), 2) for name in JOBS}
            return {
                "statuses": self.reliability.all_statuses(snapshots),
                "summary": {**self.reliability.summary(snapshots),
                            "starving": sorted(n for n, v in lateness.items()
                                               if v >= STARVING),
                            "boot": self.boot_readiness(snapshots)},
                "resume": resume,
                "outages": outage,
                "links": self.links.summary(time.time()),
            }
        except Exception:
            return {"statuses": {}, "summary": {"levels": {}, "stale_collectors": [],
                                                "recovering": [], "violations": [],
                                                "expired_leases": []}}

    def supervise_once(self, snapshots=None):
        """One watchdog pass, independent of the scheduling lanes.

        Scheduler = runs collectors. This = makes sure the scheduler
        succeeded. LATE collectors are queued immediately, expired leases are
        marked as failures, and repeatedly failing collectors enter bounded
        retry (2s/5s/15s) rather than hammering the machine forever.
        Returns the list of collector names queued for recovery.
        """
        now = time.time()
        if snapshots is None:
            try:
                store = Store(self.db_path)
                try:
                    snapshots = store.get_snapshots()
                finally:
                    store.close()
            except Exception:
                return []
        queued = []
        # A worker that died without releasing its lease: record the failure
        # now instead of waiting minutes to infer it.
        for name in reliability.expired_leases(self.reliability.health, now=now):
            health = self.reliability.health[name]
            if health.recovery_state in ("idle",):
                health.recovery_state = "retrying"
            health.last_failure = now
            health.consecutive_failures += 1
            health.last_error = "collector lease expired without completion"
            health.active_lease = None
        for name, spec in self.specs.items():
            if name in ("coverage", "report"):
                continue
            snap = (snapshots or {}).get(name) or {}
            ts = snap.get("ts")
            age = (now - ts) if ts else None
            level = reliability.classify(
                age if age is not None else -1, spec.expected_interval)
            health = self.reliability.health[name]
            if level in ("LATE", "DEGRADED", "STALE") and not snap.get("error"):
                # Queue immediately on LATE so recovery starts before the
                # score loses coverage. The lane's forced queue is the
                # recovery-state signal the freshness invariant checks.
                with self.lock:
                    if name not in self.forced:
                        self.forced.append(name)
                        queued.append(name)
                if health.recovery_state == "idle":
                    health.recovery_state = "queued"
            if health.consecutive_failures >= 3 and \
                    health.recovery_state in ("queued", "retrying"):
                delay = reliability.retry_delay(
                    min(health.consecutive_failures - 3,
                        len(reliability.RETRY_DELAYS) - 1))
                health.next_retry_at = now + (delay or 0.0)
        if self.outages is not None:
            # Record up/failing/stale transitions. A recorder fault must not
            # change what supervision queued.
            try:
                self.outages.observe(self.specs, snapshots, now)
            except Exception:
                pass
        try:
            self._tick_links(snapshots, now)
        except Exception:
            pass
        return queued

    # --- the Link Plane --------------------------------------------------
    def _links_hold(self, now):
        """No reconnect during the cold-start hold, the resume grace or an
        owner pause: ages measured across a freeze are not silence (L6)."""
        with self.lock:
            resumed = self.resumed_at
        if self._cold_start_holding(now):
            return True
        if resumed and now - resumed < links.RESUME_GRACE_S:
            return True
        try:
            return bool(self.is_paused(now))
        except Exception:
            return False

    def _tick_links(self, snapshots, now):
        store = None
        try:
            store = Store(self.db_path)
        except Exception:
            store = None
        try:
            evidence = links.gather_evidence(snapshots, now, store=store, scheduler=self,
                                             plane=self.links, windows="win" in self.hosts)
            result = self.links.tick(evidence, now, hold=self._links_hold(now))
            for name, old, new, reason in result["transitions"]:
                self._note_link(f"link:{name}", "transition", now, state=new, previous=old, cause=reason)
            # A degraded feed that is losing events between reads runs sooner.
            for name, st in self.links.statuses.items():
                if st.get("tighten"):
                    job = links.BY_NAME[name].job
                    if job in JOBS:
                        with self.lock:
                            self.retry_soon.add(job)
            if self.links.dirty and store is not None:
                store.set_meta(links.META, self.links.dump())
                self.links.dirty = False
            if result["actions"] and self._link_busy.acquire(blocking=False):
                threading.Thread(target=self._perform_link_actions, args=(result["actions"],),
                                 name="jarvis-links", daemon=True).start()
        finally:
            if store is not None:
                store.close()

    def _note_link(self, subject, transition, at, **attrs):
        if self.outages is None:
            return
        try:
            self.outages.note(subject, transition, at, **attrs)
        except Exception:
            pass

    def _perform_link_actions(self, actions):
        """Run decided reconnects one at a time, record every outcome (L3).
        Holds _link_busy, acquired by the caller."""
        try:
            for link, action in actions:
                now = time.time()
                try:
                    error = self._link_action(link, action)
                except Exception as exc:  # noqa: BLE001 - one action must not stop the rest
                    error = f"{type(exc).__name__}"
                self.links.attempted(link.name, action, error, now)
                self._note_link(f"link:{link.name}", "reconnect", now, action=action,
                                outcome=error or "ok")
            try:
                store = Store(self.db_path)
                try:
                    store.set_meta(links.META, self.links.dump())
                    self.links.dirty = False
                finally:
                    store.close()
            except Exception:
                pass
        finally:
            self._link_busy.release()

    def _link_action(self, link, action):
        """The bounded primitives. '' on success, else a short reason. None of
        these restart the daemon, elevate, change policy or delete."""
        if action == links.QUEUE:
            return "" if self.force(link.job) else "unknown job"
        if action == links.INTEROP:
            import os

            from jarvis.platform import windows as collect_windows
            # Drop the cached socket so ensure_interop() rescans /run/WSL,
            # exactly what ps_json does on an empty reply; then re-verify.
            os.environ.pop("WSL_INTEROP", None)
            if not collect_windows.ensure_interop():
                self.force(link.job)
                return "no live interop socket under /run/WSL"
            self.force(link.job)
            return ""
        if action == links.TASK:
            from jarvis.platform import windows as collect_windows
            name = links.TASK_LINKS.get(link.name, "")
            if not name or "'" in name:
                return "no task name"
            # A task shown Running is stopped first only when its state file
            # has been silent for twice the link's budget: a long-running
            # loop that is merely late (right after a resume, say) is left
            # alone and only asked to start, which is a no-op while it runs.
            age = (self.links.statuses.get(link.name) or {}).get("age")
            stop = "$true" if age is None or age > 2 * link.max_silence else "$false"
            script = (
                f"$n='{name}'; $stop={stop}; $t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; "
                "if(-not $t){ $r=@{ok=$false;error='task not registered'} } else { "
                "if($stop -and $t.State -eq 'Running'){ Stop-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; "
                "Start-Sleep -Milliseconds 500 }; "
                "try { Start-ScheduledTask -TaskName $n -ErrorAction Stop; $r=@{ok=$true;was=[string]$t.State} } "
                "catch { $r=@{ok=$false;error=[string]$_.Exception.Message} } }; "
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Compress)))")
            out = collect_windows.ps_json(script, timeout=60)
            if not isinstance(out, dict):
                return "PowerShell gave no answer"
            return "" if out.get("ok") else str(out.get("error") or "task did not start")[:120]
        return "unknown action"

    def run(self):
        self.fast_thread = threading.Thread(target=self._lane, args=("fast",),
                                            name="jarvis-fast-lane", daemon=True)
        self.fast_thread.start()
        self.bulk_thread = threading.Thread(target=self._lane, args=("bulk",),
                                            name="jarvis-bulk-lane", daemon=True)
        self.bulk_thread.start()
        self.frequent_thread = threading.Thread(target=self._lane, args=("frequent",),
                                                name="jarvis-frequent-lane", daemon=True)
        self.frequent_thread.start()
        self._start_outage_record()
        self._lane("main")

    def _start_outage_record(self):
        """The outage record runs beside the lanes; failing to start it is
        visible in its status and never stops collection."""
        try:
            from jarvis.service import outages
            self.outages = outages.OutageRecorder()
            threading.Thread(target=outages.recorder_loop,
                             args=(self.outages, self),
                             name="jarvis-outage-record", daemon=True).start()
        except Exception:
            self.outages = None

    def lane_age(self, lane="main"):
        """Seconds since the lane last looped, on the monotonic clock."""
        beat = LANE_ATTRS[lane][0]
        return max(0.0, time.monotonic() - getattr(self, beat + "_mono"))

    def fast_alive(self):
        """The secondary lanes are alive (fast, frequent and bulk). The name
        predates the other lanes; watchdogs and protection health read it."""
        return all(t is None or t.is_alive()
                   for t in (self.fast_thread, self.frequent_thread, self.bulk_thread))

    def _lane(self, lane):
        store = Store(self.db_path)
        beat, running = LANE_ATTRS[lane]
        try:
            # Reconciliation is read-only at the protected-host boundary.  It
            # happens once per scheduler process, before new collections can
            # ever consider automatic containment; it cannot retry an action.
            if lane == "main":
                try:
                    defense.reconcile(store)
                except Exception:
                    pass
                try:
                    # Phone approvals hear about new proposals from the first collection on.
                    from jarvis.response.notify import replies
                    replies.register()
                except Exception:
                    pass
                if self.cold_start_pending:
                    self._open_wake_window(time.time())
            while True:
                setattr(self, beat, time.time())
                setattr(self, beat + "_mono", time.monotonic())
                self._note_resume()
                if lane == "main":
                    self._sweep_expiry(store)
                    self._phone_tick(store)
                if self.is_paused():
                    time.sleep(1)
                    continue
                name = self._due(lane)
                if name is None:
                    time.sleep(1)
                    continue
                setattr(self, running, name)
                failed = False
                try:
                    findings, err = self.run_once(store, name)
                except Exception as exc:
                    # A lane never dies because one job, or saving its state,
                    # raised: on 2026-11-05 "database is locked" from set_meta
                    # killed the frequent, bulk and main lanes in turn and the
                    # supervisors restarted the daemon three times. Record it,
                    # retry the job after RETRY_S, keep the lane running.
                    failed = True
                    findings, err = [], f"{type(exc).__name__}: {exc}"[:300]
                    self.lane_errors[lane] = self.lane_errors.get(lane, 0) + 1
                    print(f"lane {lane}: job {name} raised {err}; the lane continues", flush=True)
                finally:
                    setattr(self, running, None)
                    self.last_attempt[name] = time.time()
                    with self.lock:
                        soon = name in self.retry_soon
                        self.retry_soon.discard(name)
                    self.next_run[name] = time.time() + (
                        min(RETRY_S, JOBS[name][0]) if soon or failed else JOBS[name][0])
                    self.cold_start_pending.discard(name)
                    # Freed job memory goes back to the kernel instead of
                    # staying resident until the next peak (core/memory.py).
                    memory.trim()
                if failed:
                    time.sleep(LANE_ERROR_PAUSE_S)
                    continue
                # Page out anything that warrants it — especially a collector
                # that has stopped recording. Guarded so a mail failure can
                # never take down the scheduler.
                try:
                    notifications.deliver(store, name, findings, error=err)
                except Exception:
                    pass
        finally:
            store.close()

    def _sweep_expiry(self, store, now=None):
        """Lift time-bounded containment whose time is up, at most once a minute.

        Guarded like delivery: a failed lift is recorded on the ledger entry by
        defense.expire, and nothing here can take down the scheduler.
        """
        now = time.monotonic() if now is None else now
        if now < getattr(self, "_expiry_due", 0.0):
            return
        self._expiry_due = now + EXPIRY_SWEEP_S
        try:
            defense.expire(store)
        except Exception:
            pass

    def _phone_tick(self, store, now=None):
        """Offer queued approvals to paired phones and apply their answers, every few seconds.

        Guarded like the expiry sweep: nothing here can take down the scheduler."""
        now = time.monotonic() if now is None else now
        if now < getattr(self, "_phone_due", 0.0):
            return
        self._phone_due = now + PHONE_TICK_S
        try:
            from jarvis.response.notify import replies
            replies.tick(store, alert.load_conf())
        except Exception:
            pass

    def run_once(self, store, name):
        """Collect -> durable observation -> bounded response -> presentation.

        Response failure must not erase successfully collected evidence. A
        journal failure inhibits response and is visible in the job snapshot.
        Collectors with their own internal maintenance are not sandboxed by
        this pipeline; the privileged broker remains a separate migration.

        Reliability receipts: every run holds a lease that expires after the
        collector's execution timeout, so a dead worker is detectable without
        waiting minutes. Success clears the failure streak and the recovery
        state; failure increments the streak and enters bounded retry. The
        last successful snapshot is never rewritten by a failed rerun --
        last-known-good evidence survives collector failures.
        """
        started = time.time()
        spec = self.specs.get(name)
        timeout = spec.execution_timeout if spec else 45.0
        health = self.reliability.health.get(name)
        lease = None
        if health is not None:
            try:
                lease = reliability.acquire_lease(
                    health, threading.current_thread().name,
                    timeout, now=started)
            except Exception:
                lease = None
        findings, err, status = [], "", "unavailable"
        # What this run costs the machine: CPU of this lane thread (and of the
        # isolated child, when there is one) and how much resident memory the
        # daemon grew by. Cheap reads; shown in the Monitoring view.
        cpu0, rss0, kids0 = time.thread_time(), _rss_kib(), _children_cpu()
        _CHILD_COST.value = (0.0, 0)
        try:
            findings, err, status = self._collect(name, timeout)
        except Exception:
            err = traceback.format_exc()[-800:]
        child_cpu, child_rss = getattr(_CHILD_COST, "value", (0.0, 0))
        # Subprocesses (journalctl, PowerShell through /init) are reaped into
        # the process-wide children total; when lanes overlap this is an
        # upper bound for the job, hence "estimate".
        kids = max(0.0, _children_cpu() - kids0 - child_cpu)
        self.job_cost[name] = {"cpu_s": round(time.thread_time() - cpu0 + child_cpu + kids, 3),
                               "subprocess_cpu_s_estimate": round(kids, 3),
                               "rss_growth_kib": max(0, _rss_kib() - rss0),
                               "child_peak_kib": child_rss, "at": time.time()}

        try:
            receipt = store.record_observation(name, findings, coverage=status, error=err)
        except Exception:
            err = (err + "; defender journal failed; response inhibited: " +
                   traceback.format_exc()[-500:]).strip("; ")
        else:
            try:
                conf = alert.load_conf()
                # An explicit visibility finding can mean incomplete coverage
                # even when a legacy collector did not raise an exception.
                if receipt["coverage"] != "complete" and not err:
                    err = "collector coverage incomplete"
                findings, err = remediation.process(
                    store, conf, name, findings, err,
                    lambda: self._verify(name, timeout))
                findings = defense.process(store, conf, name, findings,
                                           coverage=incidents.coverage_status(
                                               findings, err, receipt["coverage"]))
            except Exception:
                err = (err + "; response failed: " + traceback.format_exc()[-500:]).strip("; ")
        duration_ms = max(0.0, time.time() - started) * 1000.0
        held = self._transient_hold(store, name, findings, err, health)
        if held is None:
            store.save_snapshot(name, findings, max(0.0, time.time() - started), err)
            self.evidence_ts[name] = time.time()
            # A collector that read one bounded page of a larger backlog says so;
            # run it again soon. Lateness ordering still serves anything more
            # overdue first, so the backlog drains in the lane's idle time.
            if reports_backlog(findings):
                with self.lock:
                    self.retry_soon.add(name)
            if not err:
                store.set_meta(RETRY_META + name, "")
        else:
            # Keep serving the last good result, which is still inside its
            # freshness budget, and try again soon. The failure stays on
            # record in the defender journal and in the retry note below.
            store.set_meta(RETRY_META + name, json.dumps(
                {"at": time.time(), "error": err[:300], "last_good": float(held["ts"])}))
            with self.lock:
                self.retry_soon.add(name)
        if health is not None and lease is not None:
            try:
                # An execution that outruns its timeout succeeded late: keep
                # the evidence, but flag the overrun so supervision can split
                # fast and expensive work instead of trusting the cadence.
                if duration_ms > timeout * 1000.0 and not err:
                    err = (err + "; collector overran execution timeout "
                           f"({duration_ms/1000.0:.0f}s > {timeout:.0f}s)").strip("; ")
                reliability.release_lease(
                    health, lease, success=not err, error=err,
                    duration_ms=duration_ms)
                if err:
                    if health.recovery_state == "idle":
                        health.recovery_state = "retrying"
                else:
                    # Success is the recovery: clear any queued-retry state so
                    # the invariant sees a fresh collector, not a stale one
                    # still marked for repair.
                    health.recovery_state = "idle"
                    health.next_retry_at = 0.0
            except Exception:
                pass
        if held is not None:
            # Notifications see the result that is still on record, so a
            # held retry neither pages an outage nor clears open findings.
            return list(held.get("findings") or []), ""
        return findings, err

    def _transient_hold(self, store, name, findings, err, health):
        """The last good snapshot to keep instead of recording this failed
        run, or None to record it.

        Holds only while all of these are true: the previous result was clean
        and is still inside the same freshness budget the score uses; this is
        one of the first HOLD_MAX consecutive failures; and the failed run
        reported nothing new at medium or above, so a finding is never hidden
        behind an older, cleaner result."""
        if not err or name in ("coverage", "report"):
            return None
        if health is not None and health.consecutive_failures >= HOLD_MAX:
            return None
        try:
            prev = store.get_snapshots().get(name) or {}
        except Exception:
            return None
        if not prev.get("ts") or prev.get("error"):
            return None
        interval = JOBS[name][0]
        if time.time() - float(prev["ts"]) > max(interval * 2, interval + 300):
            return None
        known = {alert.finding_key(f) for f in prev.get("findings") or ()
                 if isinstance(f, dict)}
        for f in findings:
            if (isinstance(f, dict)
                    and f.get("severity") in ("medium", "high", "critical")
                    and f.get("category") not in ("visibility", "collectors")
                    and alert.finding_key(f) not in known):
                return None
        return prev

    def _collect(self, name, timeout):
        if name in ISOLATED:
            return _isolated_job(name, self.hosts, self.db_path, timeout)
        with collection.observe() as observation:
            findings = list(run_job(name, self.hosts, self.db_path) or [])
        return findings, observation.error, observation.status

    def _verify(self, name, timeout):
        """Fresh remediation evidence through the same bounded collector path."""
        findings, error, _status = self._collect(name, timeout)
        if error:
            raise RuntimeError(error)
        return findings


def lane_age(scheduler, lane="main", now=None):
    """Monotonic age of a lane's heartbeat; wall-clock age for a scheduler
    that keeps no monotonic twin (tests, older fakes)."""
    method = getattr(scheduler, "lane_age", None)
    if callable(method):
        try:
            return float(method(lane))
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
    beat = LANE_ATTRS[lane][0]
    stamp = time.time() if now is None else now
    return max(0.0, stamp - getattr(scheduler, beat, stamp))


def running_jobs(scheduler):
    """Names of the jobs running in any lane now. Works on fakes that keep
    only some lanes' attributes."""
    return [n for _beat, attr in LANE_ATTRS.values()
            if (n := getattr(scheduler, attr, None))]


def watchdog_loop(scheduler):
    """Feed the systemd hardware-style watchdog, but only while healthy.

    Healthy == the scheduler thread is alive and has looped within
    STALL_LIMIT seconds. If it has wedged or died we simply stop pinging;
    systemd then hits WatchdogSec, kills the process and starts it clean.
    A monitor that quietly stops monitoring is the exact failure this whole
    module exists to prevent, so the watchdog treats "no progress" as death.
    """
    usec = sdnotify.watchdog_usec()
    if not usec:
        return
    interval = max(5.0, usec / 1_000_000 / 3)
    # A job may honestly run for minutes — `intel` does networked LLM calls —
    # so the bar for "wedged" is deliberately high. Killing a healthy daemon
    # mid-refresh would make this hardening an outage of its own. The
    # out-of-daemon selfcheck timer is the fast detector; this is the backstop.
    stall_limit = max(600.0, usec / 1_000_000 * 0.8)
    while True:
        time.sleep(interval)
        alive = scheduler.is_alive() and scheduler.fast_alive()
        # The fast lane's jobs take seconds, so a minute without a loop is a hang.
        # The frequent lane's runs are bounded at 60 s but not killed, so it
        # gets the main lane's generous bar: a wedge, never a slow PowerShell.
        progressed = (lane_age(scheduler, "main") < stall_limit and
                      lane_age(scheduler, "frequent") < stall_limit and
                      lane_age(scheduler, "fast") < 300)
        if alive and progressed:
            sdnotify.watchdog()
        # else: withhold the ping and let systemd restart us.


def reliability_watchdog_loop(scheduler, interval=20.0):
    """Health loop independent of the scheduling lanes.

    Scheduler = runs collectors. This = makes sure the scheduler succeeded.
    Every ``interval`` seconds it asks the reliability plane which collectors
    are going LATE and queues them immediately, expires dead leases, and
    records bounded-retry state -- so a collector becomes stale only after
    JARVIS has already noticed it going late and attempted recovery.
    """
    while True:
        time.sleep(max(5.0, interval))
        try:
            scheduler.supervise_once()
        except Exception:
            pass
