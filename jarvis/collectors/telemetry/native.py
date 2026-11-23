"""Native sensor delivery: drain the spool into the event log, and say what it cost.

The ingestion itself is `jarvis.platform.native.ingest`. This job is the part
that reports: whether the sensor exists and is alive, which channels it cannot
read, whether any delivery was lost or refused, and whether recorded history
still verifies. A detector reading the event log inherits every one of these
limits, so they are findings, not log lines.
"""

import json
import time

from jarvis.collectors.telemetry.history_verify import VERIFY_META, VERIFY_OVERDUE
from jarvis.core import collection, telemetry
from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.core.finding import win_finding as _finding
from jarvis.platform import mounts
from jarvis.platform.native import ingest

SENSOR = "native sensor"
# The CLI pins the source hash before elevation; the script alone now refuses
# an install without -SourceSha256.
INSTALL = "`jarvis sensor install` (one UAC prompt)"
# Gaps are events: they happened once, in one run. Keep re-reporting them for
# a week so a lost stretch of history is not visible for a single minute.
GAP_META = "native_gaps"
GAP_KEEP = 7 * 86400
GAP_CURRENT = 86400
# The daily whole-chain verification is its own job (history_verify, bulk
# lane, 300 s budget; see history_verify.py). It used to run inside this 45 s
# fast-lane collector: at 1.5 GiB of history it takes 75 s here, so the worker
# was killed every run, the completion stamp was never written, and the next
# run tried again -- native read "unavailable" for hours once a day
# (2026-10-21, 2026-10-22).

CHANNEL_FIX = {
    "Microsoft-Windows-TaskScheduler/Operational":
        "wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true",
}


def _gaps(store, fresh):
    now = time.time()
    try:
        kept = json.loads(store.get_meta(GAP_META, "[]") or "[]")
    except ValueError:
        kept = []
    kept = [g for g in kept if now - g.get("at", 0) < GAP_KEEP]
    kept += [{"at": now, "channel": ch, "gap": gap} for ch, gap in fresh]
    kept = kept[-50:]
    store.set_meta(GAP_META, json.dumps(kept))
    store.commit()
    return kept


# The event log allows one writer at a time. The CLI's `jarvis timeline --rebuild`,
# a manual `python3 -m jarvis.native`, or the previous run still closing can hold
# the lock for a moment. That is contention, not blindness — so a short retry
# comes before reporting a gap. Past it, report: a genuinely wedged writer is
# exactly what this finding exists to surface.
LOCK_RETRIES = 3
LOCK_RETRY_SECONDS = 4


def _open_writer(root):
    """-> (log, None) or (None, finding) after the retries are spent."""
    for attempt in range(LOCK_RETRIES + 1):
        try:
            return EventLog(root or DEFAULT_ROOT, writer=True), None
        except LogError as exc:
            if attempt >= LOCK_RETRIES:
                collection.failed(SENSOR, str(exc))
                return None, _finding(
                    "visibility", "medium", "Event log is busy or unavailable",
                    f"{exc}. The writer lock stayed held after "
                    f"{LOCK_RETRIES * LOCK_RETRY_SECONDS}s of retries — a manual "
                    "`jarvis timeline` or ingest run may still be open, or the "
                    "writer is wedged.", str(root or DEFAULT_ROOT))
            time.sleep(LOCK_RETRY_SECONDS)


def audit(store, hosts=("win",), spool=None, root=None):
    if "win" not in hosts:
        return []
    spool = spool or ingest.SPOOL
    # Fast gate first: on a stale Windows drive the spool cannot answer, and
    # neither the writer-lock retries below nor the ingest listing add
    # anything but load and noise. One finding names the mount and its fix.
    if mounts.under_windows_drive(spool) and mounts.windows_drive() == mounts.STALE:
        collection.failed(SENSOR, "windows drive mount stale")
        return [_finding(
            "visibility", "medium", "The Windows drive mount is stale",
            mounts.stale_detail() + " Native spool delivery waits until the "
            "mount answers again; nothing was deleted and no evidence was "
            "lost, but no fresh Windows telemetry arrived.", str(spool))]
    before = ingest.preflight(spool)
    if before.get("mount_stale"):
        collection.failed(SENSOR, "windows drive mount stale")
        return [_finding(
            "visibility", "medium", "The Windows drive mount is stale",
            f"{before.get('access_error') or mounts.stale_detail()} "
            "Native spool delivery waits until the mount answers again; "
            "nothing was deleted and no evidence was lost.", str(spool))]
    if before.get("access_error"):
        collection.failed(SENSOR, "spool unavailable")
        return [_finding(
            "visibility", "high", "The native sensor spool is unreachable",
            f"The configured spool could not be read: {before['access_error']}. "
            "This is an installed sensor with unavailable delivery, not an absent "
            "sensor. Check the Windows mount and JarvisNativeSensor service.",
            str(spool))]
    if before.get("installed") is not True:
        collection.failed(SENSOR, "not installed")
        return [_finding(
            "visibility", "medium", "The native Windows sensor is not installed",
            "Windows telemetry reaches JARVIS only through PowerShell queries over "
            "the WSL bridge: capped, sampled by time window, and blind whenever WSL "
            "is down. The sensor is a Windows service that records every Sysmon and "
            "Defender record in order, with losses reported rather than hidden. "
            f"Install it with {INSTALL}.", str(spool))]
    log, busy = _open_writer(root)
    if busy is not None:
        return [busy]
    try:
        report = ingest.run(log=log, spool=spool)
        out = []
        if report.get("mount_stale"):
            collection.failed(SENSOR, "windows drive mount stale")
            return [_finding(
                "visibility", "medium", "The Windows drive mount is stale",
                f"{report.get('access_error') or mounts.stale_detail()} "
                "Native spool delivery waits until the mount answers again; "
                "nothing was deleted and no evidence was lost.",
                str(spool))]
        if report.get("access_error"):
            collection.failed(SENSOR, "spool unavailable")
            return [_finding(
                "visibility", "high", "The native sensor spool is unreachable",
                f"The configured spool could not be read: {report['access_error']}. "
                "This is an installed sensor with unavailable delivery, not an absent "
                "sensor. Check the Windows mount and JarvisNativeSensor service.",
                str(spool))]
        if report["installed"] is not True:
            collection.failed(SENSOR, "not installed")
            return [_finding(
                "visibility", "medium", "The native Windows sensor is not installed",
                "Windows telemetry reaches JARVIS only through PowerShell queries over "
                "the WSL bridge: capped, sampled by time window, and blind whenever WSL "
                "is down. The sensor is a Windows service that records every Sysmon and "
                "Defender record in order, with losses reported rather than hidden. "
                f"Install it with {INSTALL}.", str(spool))]
        out += _health(report.get("health"))
        fresh_gaps = []
        for ch in report["channels"]:
            name = ch["channel"] or ch["directory"]
            if ch["error"]:
                collection.failed(SENSOR, f"{name}: delivery stopped")
                out.append(_finding(
                    "visibility", "high", f"Sensor delivery stopped for {_short(name)}",
                    f"{ch['error']}. Nothing after this batch is ingested until it is "
                    f"resolved — the cursor holds rather than skipping evidence.", name))
            if ch.get("quarantined"):
                # Delivery recovered from a stuck channel by preserving the
                # poisoned batch. That is not a clean observation, but the
                # channel is moving again and the loss is durable evidence —
                # so it pages once and the freshness gate treats it as
                # degraded-complete rather than permanent blindness.
                out.append(_finding(
                    "visibility", "high", "A sensor batch failed validation and was quarantined",
                    f"{ch['gaps'][-1] if ch['gaps'] else 'unknown reason'}. The batch bytes "
                    "are preserved under quarantine/ in the sensor spool; the loss is "
                    "recorded in the event history. Later batches were ingested.",
                    str(spool)))
                collection.succeeded(SENSOR)
            for gap in ch["gaps"]:
                fresh_gaps.append((name, gap))
            if ch["ack_error"]:
                out.append(_finding(
                    "visibility", "low", "The sensor spool cannot be acknowledged",
                    f"{ch['ack_error']}. The sensor keeps every batch until it is "
                    f"acknowledged and stops collecting at capacity. Re-run {INSTALL} "
                    f"to grant this account write access to the acks folder.", str(spool)))
                break
        for g in _gaps(store, fresh_gaps):
            # A gap is news for a day; after that it stays listed for the week
            # as a record of what could not be analysed, not a current loss.
            recent = time.time() - g.get("at", 0) < GAP_CURRENT
            out.append(_finding(
                "telemetry loss", "medium" if recent else "low",
                f"Records missing from {_short(g['channel'])}",
                f"{g['gap']} (recorded {time.strftime('%Y-%m-%d %H:%M', time.localtime(g['at']))}). "
                f"Events that were never read cannot be analysed; a log that wraps "
                f"faster than it is read needs a larger maximum size.", g["channel"]))
        out += _verify(store, log)
        # Persist the eight-stage chain status from this run's evidence; the
        # health endpoint reads it from the store rather than touching the
        # spool, so HTTP can never contend with the sensor.
        stats0 = report.get("log") or log.stats()
        verify_last = float(store.get_meta(VERIFY_META, 0) or 0)
        chain = telemetry.collect(
            {**report, "log": stats0},
            verify_at=verify_last if verify_last else None,
            freshness_limit=180)
        store.set_meta(telemetry.META, json.dumps(chain))
        store.commit()
        if not any(f["severity"] in ("high", "critical") for f in out if f["category"] == "visibility"):
            collection.succeeded(SENSOR)
        stats = report.get("log") or log.stats()
        pruned = (f"; {stats['pruned']} older segments removed by the space budget"
                  if stats["pruned"] else "")
        out.append(_finding(
            "telemetry", "ok", f"Native sensor delivered {report['events']} events this run",
            f"The event log holds events 1–{stats['last_seq']} in {stats['segments']} sealed "
            f"segments ({stats['sealed_bytes'] // 1024 // 1024} MiB) plus "
            f"{stats['unsealed_events']} unsealed{pruned}.", str(log.root)))
        return out
    finally:
        log.close()


def _short(channel):
    return channel.replace("Microsoft-Windows-", "").replace("/Operational", "")


def _health(health):
    if health is None:
        collection.failed(SENSOR, "no health file")
        return [_finding("visibility", "high", "The native sensor has never reported health",
                         "The spool exists but health.json does not: the service is "
                         "installed and not running, or cannot write its spool.", "health.json")]
    if health.get("status") == "unreadable":
        collection.failed(SENSOR, "health unreadable")
        return [_finding("visibility", "high", "The native sensor's health file is unreadable",
                         health.get("reason", ""), "health.json")]
    out = []
    if health.get("mode") == "isolated":
        monitor = health.get("monitor") or {}
        services = monitor.get("services") or {}
        failing = [name for name, state in services.items()
                   if isinstance(state, dict) and state.get("status") != "complete"]
        if monitor.get("status") == "unavailable" or len(services) != 3 or failing:
            collection.failed(SENSOR, "isolated monitor unavailable or channel recovery active")
            detail = monitor.get("reason") or (
                "Channel services requiring recovery: " + ", ".join(sorted(failing))
                if failing else "monitor did not report all three services")
            out.append(_finding("visibility", "high", "The native channel monitor is incomplete",
                                str(detail)[:300], "JARVIS Native Sensor Monitor"))
    age = health.get("age")
    if age is None or age > ingest.HEALTH_STALE:
        collection.failed(SENSOR, "health stale")
        mins = "an unknown time" if age is None else f"{int(age // 60)} minutes"
        out.append(_finding(
            "visibility", "high", "The native sensor has stopped reporting",
            f"Its last health report is {mins} old; it writes one every few seconds "
            f"while running. Check the JarvisNativeSensor service.", "JarvisNativeSensor"))
    if health.get("status") == "unavailable":
        out.append(_finding("visibility", "high", "The native sensor failed its last pass",
                            str(health.get("reason", ""))[:300], "JarvisNativeSensor"))
    for channel, state in (health.get("channels") or {}).items():
        if isinstance(state, dict) and state.get("status") == "unavailable":
            reason = str(state.get("reason", ""))
            fix = CHANNEL_FIX.get(channel)
            out.append(_finding(
                "visibility", "medium", f"The sensor cannot read {_short(channel)}",
                reason + (f". Enable it (elevated): {fix}" if fix and "disabled" in reason else ""),
                channel))
    used, cap = health.get("spool_bytes"), health.get("spool_capacity")
    if used and cap and used >= 0.75 * cap:
        out.append(_finding(
            "visibility", "high" if used >= cap else "medium", "The sensor spool is nearly full",
            f"{used // 1024 // 1024} of {cap // 1024 // 1024} MiB. At capacity the sensor "
            f"stops collecting rather than delete evidence.", "spool"))
    if health.get("compaction_error"):
        out.append(_finding("visibility", "low", "The sensor could not reclaim spool space",
                            str(health["compaction_error"])[:300], "spool"))
    return out


def _verify(store, log):
    """Visibility only: the ingestion run never verifies the chain itself
    (see history_verify); it reports when verification is overdue."""
    last = float(store.get_meta(VERIFY_META, 0) or 0)
    age = time.time() - last
    if last and age < VERIFY_OVERDUE:
        return []
    return [_finding(
        "visibility", "medium", "Recorded event history has not been verified recently",
        (f"The last whole-chain verification was {age / 3600:.0f} h ago" if last
         else "The chain has never been verified")
        + "; the history_verify job runs it daily with its own time budget. "
        "Until it completes, tampering with sealed segments would not be noticed.",
        str(log.root))]
