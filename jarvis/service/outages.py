"""The outage record: when something stopped watching, and for how long.

Every collector transition between up, failing and stale, every gap in the
daemon's own heartbeat, and every WSL VM and host power event that Windows
logs becomes a `sensor`/`state` event in the hash-chained event log. From there
the evidence job copies sealed segments into the administrator-only vault, and
the chain head is timestamped publicly. See
docs/architecture/LANE-FAIRNESS-AND-OUTAGE-RECORD.md.

Tamper-evident, not tamper-proof. Before a segment is vaulted, the WSL user
can rewrite it (up to about 20 minutes). A local administrator can rewrite it
until the next anchor. While the VM is frozen or crashed, nothing in it can
record anything. That interval is rebuilt afterwards from Windows' own logs,
which a standard user can neither write nor clear without leaving event
104/1102.

Times come from evidence, not from when JARVIS noticed. A collector went stale
at `last result + STALE_AFTER x interval`, even if the daemon was down then.

Durability: a transition goes to a spool file (fsync) before it is appended.
The event log cursor for this source records the highest record committed, so
a crash between the append and the spool rewrite never duplicates a record,
and a busy writer lock never loses one.

This module records only. It never restarts, contains, suppresses or scores.
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core import bugcheck
from jarvis.core import event as event_mod
from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError

SENSOR = "jarvis-outages"
CHANNEL = "outages"
SPOOL_DIR = Path(os.path.expanduser("~/.jarvis/outages"))
# A collector's states, worst first. "stale" = no evidence inside its hard
# deadline; "failing" = it ran, but the run reported an error.
UP, FAILING, STALE = "up", "failing", "stale"
STALE_AFTER = 2.0                 # x interval; matches reliability.STALE_AFTER
SKIP = frozenset({"coverage", "report"})
# A heartbeat gap this long is an outage of the monitor itself, not a slow pass.
GAP_S = 90.0
FLUSH_EVERY_S = 20.0
WINDOWS_EVERY_S = 600.0
WINDOWS_MAX = 200
WINDOWS_LOOKBACK_DAYS = 7
SPOOL_MAX = 5000
LOCK_ATTEMPTS = 3
LOCK_DELAY_S = 0.2
MAX_CAUSE = 160

# Windows events that explain why WSL or the whole host stopped. Read-only.
# Hyper-V-Worker-Admin (message texts read on this host 2026-10-11): 18500
# VM started, 18502 turned off, 18508 shut down by the guest operating system,
# 18515 shut down for a reset the guest initiated, 18590 the guest reported a
# fatal error. Other IDs are left out until their meaning is verified. System: Kernel-Power 41 unexpected
# power loss, 42 sleep, 107 resume, 506/507 Modern Standby enter/exit;
# Kernel-General 12/13 OS start/stop; EventLog 6005/6006 log service
# start/stop, 6008 unexpected shutdown; User32 1074 shutdown requested;
# WER-SystemErrorReporting 1001 the restart followed a stop error (bug check).
WINDOWS_QUERIES = (
    ("Microsoft-Windows-Hyper-V-Worker-Admin", (18500, 18502, 18508, 18515, 18590)),
    ("System", (41, 42, 107, 506, 507, 12, 13, 6005, 6006, 6008, 1074, 1001)),
    ("Application", (1000,)),
)
WINDOWS_MEANING = {
    18500: ("vm_started", "a virtual machine started"),
    18502: ("vm_turned_off", "a virtual machine was turned off"),
    18508: ("vm_guest_shutdown", "the guest operating system shut the virtual machine down"),
    18515: ("vm_reset", "the guest operating system reset the virtual machine"),
    18590: ("vm_fatal", "the guest operating system reported a fatal error"),
    41: ("host_power_loss", "Windows restarted without a clean shutdown"),
    42: ("host_sleep", "Windows entered sleep"),
    107: ("host_resume", "Windows resumed from sleep"),
    506: ("host_standby", "Windows entered Modern Standby"),
    507: ("host_standby_exit", "Windows left Modern Standby"),
    12: ("host_boot", "Windows started"),
    13: ("host_shutdown", "Windows shut down"),
    6005: ("host_boot", "the Windows event log service started"),
    6006: ("host_shutdown", "the Windows event log service stopped cleanly"),
    6008: ("host_unexpected_shutdown", "the previous Windows shutdown was unexpected"),
    1074: ("host_shutdown_requested", "a shutdown or restart was requested"),
    1001: ("host_bugcheck", "Windows restarted after a stop error"),
    1000: ("wsl_process_crash", "a WSL process crashed"),
}
# The provider each ID must come from. IDs are only unique per provider: in
# the System log, 12 and 13 are also written by UserModePowerService and
# Wininit (seen on this host), which have nothing to do with startup.
WINDOWS_PROVIDER = {
    18500: "Microsoft-Windows-Hyper-V-Worker", 18502: "Microsoft-Windows-Hyper-V-Worker",
    18508: "Microsoft-Windows-Hyper-V-Worker", 18515: "Microsoft-Windows-Hyper-V-Worker",
    18590: "Microsoft-Windows-Hyper-V-Worker",
    41: "Microsoft-Windows-Kernel-Power", 42: "Microsoft-Windows-Kernel-Power",
    107: "Microsoft-Windows-Kernel-Power", 506: "Microsoft-Windows-Kernel-Power",
    507: "Microsoft-Windows-Kernel-Power",
    12: "Microsoft-Windows-Kernel-General", 13: "Microsoft-Windows-Kernel-General",
    6005: "EventLog", 6006: "EventLog", 6008: "EventLog",
    1074: "User32", 1000: "Application Error",
    1001: "Microsoft-Windows-WER-SystemErrorReporting",
}
_WSL_APPS = re.compile(r"\b(wsl|wslhost|wslrelay|wslservice)\.exe\b", re.I)
_BUGCHECK = re.compile(r"0x[0-9A-Fa-f]{1,8}\s*\([^)]{0,200}\)")
_GUID = re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", re.I)

PS_WINDOWS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{ rows = @(); failed = @() }
$since = (Get-Date).AddDays(-__DAYS__)
$cursors = '__CURSORS__' | ConvertFrom-Json
foreach ($q in @(__QUERIES__)) {
  $after = [long]0
  if ($cursors.PSObject.Properties[$q.log]) { $after = [long]$cursors.($q.log) }
  try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $q.log; Id = $q.ids; StartTime = $since } `
            -MaxEvents __MAX__ -ErrorAction Stop | Where-Object { $_.RecordId -gt $after })
  } catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $o.failed += $q.log }
    $ev = @()
  }
  foreach ($e in $ev) {
    $first = ([string]$e.Message -split "`n")[0]
    $o.rows += [pscustomobject]@{
      log = $q.log; id = [int]$e.Id; record = [long]$e.RecordId
      provider = [string]$e.ProviderName
      time = $e.TimeCreated.ToUniversalTime().ToString('o')
      line = $first.Substring(0, [Math]::Min(300, $first.Length)) }
  }
}
"""


def _bugcheck(line):
    """'0x20001 HYPERVISOR_ERROR (0x11, ...)' from a WER 1001 message line."""
    match = _BUGCHECK.search(line)
    parsed = bugcheck.from_wer(match.group(0)) if match else None
    if not parsed:
        return None
    return f"{bugcheck.label(parsed[0])} ({', '.join(parsed[1])})"


def _utc(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()


def _epoch(iso):
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _short(text):
    text = " ".join(str(text or "").split())
    return text[:MAX_CAUSE]


def collector_state(snapshot, interval, now):
    """(state, started_at) for one collector from its persisted snapshot.

    started_at is when this state began, judged from the evidence: a stale
    collector went stale at last-result + STALE_AFTER x interval. Pure."""
    ts = (snapshot or {}).get("ts")
    if not ts or interval <= 0:
        return STALE, None
    ts = float(ts)
    if now - ts > STALE_AFTER * interval:
        return STALE, ts + STALE_AFTER * interval
    if (snapshot or {}).get("error"):
        return FAILING, ts
    return UP, ts


def _atomic_json(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class OutageRecorder:
    """Detects transitions, spools them durably, and appends them to the log.

    `observe` and `tick` are cheap and never raise; `flush` and
    `read_windows` do the I/O and report what happened instead of raising."""

    def __init__(self, spool_dir=SPOOL_DIR, log_root=DEFAULT_ROOT, host="wsl",
                 boot_time=None, process_start=None):
        self.dir = Path(spool_dir)
        self.log_root = Path(log_root)
        self.host = host
        self.lock = threading.Lock()
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_path = self.dir / "state.json"
        self.spool_path = self.dir / "pending.jsonl"
        self.heartbeat_path = self.dir / "heartbeat"
        self.state = self._load_state()
        self.boot_time = boot_time if boot_time is not None else _boot_time()
        self.process_start = process_start if process_start is not None else time.time()
        self._last_beat = None            # (wall, mono) of this process's last tick
        self.status = {"flushed": 0, "pending": 0, "last_error": "", "windows": {}}
        self._sync_counter()

    def _sync_counter(self):
        """Record numbers only ever grow. A lost or older state file must not
        reuse a number the log already committed: the cursor would then skip
        the new record as a duplicate."""
        top = max([int(self.state.get("record", 0))] +
                  [int(r.get("record", 0)) for r in self._pending()])
        try:
            with EventLog(self.log_root) as log:
                top = max(top, int((log.cursor(SENSOR, CHANNEL) or {}).get("record") or 0))
        except (LogError, OSError, ValueError):
            pass
        self.state["record"] = top

    # -- persistence ---------------------------------------------------------

    def _load_state(self):
        try:
            with open(self.state_path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                data.setdefault("open", {})
                data.setdefault("record", 0)
                data.setdefault("windows", {})
                data.setdefault("dropped", 0)
                return data
        except (OSError, ValueError):
            pass
        return {"open": {}, "record": 0, "windows": {}, "dropped": 0}

    def _save_state(self):
        _atomic_json(self.state_path, self.state)

    def _pending(self):
        out = []
        try:
            with open(self.spool_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not line.endswith("\n"):
                        break             # a torn final line was never committed
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
        except FileNotFoundError:
            pass
        return out

    def _spool(self, records):
        """Durably queue records. Over SPOOL_MAX, count them as a recorded gap."""
        if not records:
            return
        pending = len(self._pending())
        room = max(0, SPOOL_MAX - pending)
        keep, dropped = records[:room], len(records) - room
        if keep:
            with open(self.spool_path, "a", encoding="utf-8") as fh:
                for rec in keep:
                    fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        if dropped > 0:
            self.state["dropped"] = int(self.state.get("dropped", 0)) + dropped
        self._save_state()

    def _record(self, subject, transition, at, **attrs):
        self.state["record"] = int(self.state.get("record", 0)) + 1
        return {"record": self.state["record"], "subject": subject,
                "transition": transition, "at": float(at), "noted": time.time(),
                **{k: v for k, v in attrs.items() if v is not None}}

    def note(self, subject, transition, at, **attrs):
        """Record one event from another plane (link transitions and
        reconnect attempts). Durable like every other record; never raises."""
        try:
            with self.lock:
                records = [self._record(subject, transition, at, **attrs)]
                self._spool(records)
                return records
        except Exception as exc:
            self.status["last_error"] = f"note: {type(exc).__name__}"
            return []

    # -- detection -----------------------------------------------------------

    def observe(self, specs, snapshots, now=None):
        """Compare every collector with its last recorded state. Never raises.
        Returns the records spooled."""
        now = time.time() if now is None else now
        try:
            with self.lock:
                records = []
                opened = self.state["open"]
                for name, spec in sorted(specs.items()):
                    if name in SKIP:
                        continue
                    interval = int(getattr(spec, "expected_interval", 0) or 0)
                    snap = (snapshots or {}).get(name) or {}
                    state, since = collector_state(snap, interval, now)
                    prev = opened.get(name)
                    prev_state = prev["state"] if prev else UP
                    if state == prev_state:
                        continue
                    subject = f"collector:{name}"
                    if prev and prev_state != UP:
                        end = since if since is not None else now
                        records.append(self._record(
                            subject, "end", end, state=prev_state,
                            start=prev["start"], end=end,
                            duration_s=round(max(0.0, end - prev["start"]), 1),
                            cause=prev.get("cause")))
                        opened.pop(name, None)
                    if state != UP:
                        start = since if since is not None else now
                        cause = (_short(snap.get("error")) if state == FAILING else
                                 "no result inside 2x its interval" if snap.get("ts")
                                 else "no result on record")
                        records.append(self._record(
                            subject, "start", start, state=state, start=start,
                            interval_s=interval, cause=cause,
                            estimated=since is None or None))
                        opened[name] = {"state": state, "start": start, "cause": cause}
                self._spool(records)
                return records
        except Exception as exc:          # recording must never break supervision
            self.status["last_error"] = f"observe: {type(exc).__name__}"
            return []

    def tick(self, now=None, mono=None):
        """Heartbeat. Records a monitor gap when the previous beat is too old:
        across a restart (persisted beat) or a freeze (wall clock jumped while
        this process's monotonic clock did not). Never raises."""
        now = time.time() if now is None else now
        mono = time.monotonic() if mono is None else mono
        try:
            with self.lock:
                records = []
                if self._last_beat is None:
                    last = _read_float(self.heartbeat_path)
                    if last and now - last > GAP_S:
                        restarted = self.boot_time and self.boot_time > last
                        records.append(self._record(
                            "monitor:jarvis", "gap", last, state=STALE, start=last,
                            end=self.process_start,
                            duration_s=round(max(0.0, self.process_start - last), 1),
                            cause=("WSL VM restarted" if restarted else "daemon restarted"),
                            vm_boot=_utc(self.boot_time) if self.boot_time else None))
                else:
                    wall0, mono0 = self._last_beat
                    if (now - wall0) - (mono - mono0) > GAP_S:
                        # Frozen, not dead: the VM was paused (standby/sleep).
                        records.append(self._record(
                            "monitor:jarvis", "gap", wall0, state=STALE, start=wall0,
                            end=now, duration_s=round(now - wall0, 1),
                            cause="WSL VM paused (host standby or sleep)"))
                self._last_beat = (now, mono)
                _write_float(self.heartbeat_path, now)
                self._spool(records)
                return records
        except Exception as exc:
            self.status["last_error"] = f"tick: {type(exc).__name__}"
            return []

    # -- Windows lifecycle ---------------------------------------------------

    def read_windows(self, runner=None):
        """Pull new Windows lifecycle records since the per-log cursor and
        spool them. `runner(script)` returns the decoded payload or None."""
        if runner is None:
            from jarvis.platform.windows import ps_json

            def runner(script):
                return ps_json(script + "\n$json = [pscustomobject]$o | ConvertTo-Json -Depth 4 "
                               "-Compress\n[Convert]::ToBase64String([Text.Encoding]::UTF8"
                               ".GetBytes($json))", timeout=60)
        with self.lock:
            cursors = dict(self.state.get("windows") or {})
        queries = ",".join(
            "@{log='%s';ids=@(%s)}" % (log, ",".join(str(i) for i in ids))
            for log, ids in WINDOWS_QUERIES)
        script = (PS_WINDOWS.replace("__DAYS__", str(WINDOWS_LOOKBACK_DAYS))
                  .replace("__MAX__", str(WINDOWS_MAX))
                  .replace("__QUERIES__", queries)
                  .replace("__CURSORS__", json.dumps({k: int(v) for k, v in cursors.items()})))
        try:
            data = runner(script)
        except Exception as exc:
            data, why = None, type(exc).__name__
        else:
            why = "no answer from PowerShell"
        if not isinstance(data, dict):
            self.status["windows"] = {"ok": False, "error": why}
            return []
        rows = data.get("rows") or []
        if isinstance(rows, dict):
            rows = [rows]
        with self.lock:
            records = []
            for row in sorted((r for r in rows if isinstance(r, dict)),
                              key=lambda r: (str(r.get("log")), int(r.get("record") or 0))):
                log, eid, rec = str(row.get("log") or ""), int(row.get("id") or 0), int(row.get("record") or 0)
                if not log or rec <= int(cursors.get(log, 0)):
                    continue
                line = str(row.get("line") or "")
                if str(row.get("provider") or "") != WINDOWS_PROVIDER.get(eid):
                    cursors[log] = max(int(cursors.get(log, 0)), rec)
                    continue          # same ID, different provider: not ours
                if eid == 1000 and not _WSL_APPS.search(line):
                    cursors[log] = max(int(cursors.get(log, 0)), rec)
                    continue          # an unrelated application crash
                kind, meaning = WINDOWS_MEANING.get(eid, ("windows_event", "Windows event"))
                at = _epoch(row.get("time")) or time.time()
                vm = _GUID.search(line) if eid != 1001 else None   # 1001's GUID is a WER report
                app = _WSL_APPS.search(line)
                stop = _bugcheck(line) if eid == 1001 else None
                if stop:
                    meaning = f"{meaning}: {stop}"
                records.append(self._record(
                    "host:windows", kind, at, windows_log=log, windows_event=eid,
                    windows_record=rec, provider=_short(row.get("provider")),
                    cause=_short(meaning), vm=vm.group(0).upper() if vm else None,
                    app=app.group(0).lower() if app else None))
                cursors[log] = max(int(cursors.get(log, 0)), rec)
            self.state["windows"] = cursors
            self._spool(records)
            self.status["windows"] = {"ok": not data.get("failed"), "new": len(records),
                                      "failed": list(data.get("failed") or [])[:5]}
            return records

    # -- commit --------------------------------------------------------------

    def _event(self, rec):
        attrs = {k: v for k, v in rec.items() if k not in ("record", "at")}
        attrs["observation"] = "outage"
        return event_mod.make(
            host=self.host, sensor=SENSOR, channel=CHANNEL,
            generation=str(self.state.get("generation") or "1"),
            record=int(rec["record"]), source="jarvis-outage-record",
            source_event=0, time=_utc(rec["at"]), received=_utc(rec.get("noted", time.time())),
            category="sensor", action="state", target={"subject": rec["subject"]},
            attrs=attrs)

    def flush(self, open_log=None):
        """Append everything spooled. Returns (appended, error). The spool is
        rewritten only after the append's cursor line is durable."""
        with self.lock:
            pending = self._pending()
            dropped = int(self.state.get("dropped", 0))
            if dropped:
                pending.append(self._record("monitor:outage-record", "dropped", time.time(),
                                            state=FAILING, count=dropped,
                                            cause="spool full; transitions not recorded"))
            self.status["pending"] = len(pending)
            if not pending:
                return 0, ""
            log, error = None, ""
            opener = open_log or (lambda: EventLog(self.log_root, writer=True))
            for attempt in range(LOCK_ATTEMPTS):
                try:
                    log = opener()
                    break
                except (LogError, OSError) as exc:
                    error = f"{type(exc).__name__}: {exc}"[:200]
                    if attempt + 1 < LOCK_ATTEMPTS:
                        time.sleep(LOCK_DELAY_S)
            if log is None:
                self.status["last_error"] = error
                return 0, error           # spool intact; retried next pass
            try:
                committed = int((log.cursor(SENSOR, CHANNEL) or {}).get("record") or 0)
                fresh = sorted((r for r in pending if int(r.get("record", 0)) > committed),
                               key=lambda r: r["record"])
                if fresh:
                    top = fresh[-1]["record"]
                    log.append([self._event(r) for r in fresh],
                               {"sensor": SENSOR, "channel": CHANNEL, "record": top,
                                "status": "complete", "events": len(fresh)})
                    committed = top
                    if log.due():
                        log.seal()
                remaining = [r for r in pending
                             if int(r.get("record", 0)) > committed
                             and r.get("subject") != "monitor:outage-record"]
                tmp = self.spool_path.with_suffix(".tmp")
                with open(tmp, "w", encoding="utf-8") as fh:
                    for rec in remaining:
                        fh.write(json.dumps(rec, sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.spool_path)
                if dropped:
                    self.state["dropped"] = 0
                self._save_state()
                self.status["flushed"] += len(fresh)
                self.status["pending"] = len(remaining)
                self.status["last_error"] = ""
                return len(fresh), ""
            except (LogError, OSError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"[:200]
                self.status["last_error"] = error
                return 0, error
            finally:
                log.close()

    def open_outages(self):
        with self.lock:
            return {k: dict(v) for k, v in self.state["open"].items()}


def _boot_time():
    try:
        with open("/proc/stat", encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def _read_float(path):
    try:
        return float(Path(path).read_text().strip())
    except (OSError, ValueError):
        return None


def _write_float(path, value):
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(f"{value:.3f}\n")
    os.replace(tmp, path)


def recorder_loop(recorder, scheduler, stop=None, flush_every=FLUSH_EVERY_S,
                  windows_every=WINDOWS_EVERY_S, windows=True):
    """Background thread body: heartbeat, flush, and the 10-minute Windows read.
    Collector transitions are observed by the scheduler's supervise pass."""
    last_windows = 0.0
    while stop is None or not stop.is_set():
        recorder.tick()
        if windows and time.monotonic() - last_windows >= windows_every:
            last_windows = time.monotonic()
            try:
                recorder.read_windows()
            except Exception as exc:
                recorder.status["windows"] = {"ok": False, "error": type(exc).__name__}
        recorder.flush()
        if stop is not None:
            if stop.wait(flush_every):
                break
        else:
            time.sleep(flush_every)
