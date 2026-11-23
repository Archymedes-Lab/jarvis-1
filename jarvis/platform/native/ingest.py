"""Drain the native sensor's spool into the event log, in order, exactly once.

The sensor (`windows-sensor/JarvisSensor.cs`) runs as a Windows service with
no dependency on WSL. It resumes each channel from the last record ID it
published, and publishes immutable, sequence-numbered batch files. This module is the
other half of that contract:

  * batches are taken strictly in sequence per (sensor, channel); a missing
    or out-of-order batch stops that channel with the cursor unchanged, so a
    hole in delivery is an error that stays visible, never a silent skip
  * a batch is committed to the event log together with its cursor (one
    fsync'd write), so a crash replays at most the batch in flight and the
    replay is recognised by sequence number and digest
  * a changed log generation (the channel was cleared or recreated) is
    accepted only when the sensor recorded the gap; records the log
    overwrote before the sensor read them arrive as a recorded gap too
  * only after the commit is the batch acknowledged back to the sensor, which
    may then reclaim spool space; nothing here deletes the sensor's files

Every record is normalized and kept, including records no detector reads.
"""

import hashlib
import json
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core import event as event_mod
from jarvis.core.eventlog import EventLog
from jarvis.platform import host, mounts

from . import normalize
from .store import MAX_BATCH_BYTES, BatchError, validate

SPOOL = Path(os.environ.get("JARVIS_SENSOR_SPOOL")
             or host.program_data("Jarvis", "Sensor") or "/nonexistent/Jarvis/Sensor")
ISOLATED_CHANNELS = (
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
)
ISOLATED_SERVICES = dict(zip(ISOLATED_CHANNELS, (
    "JarvisSensorSysmon", "JarvisSensorDefender", "JarvisSensorTasks")))

# Per run: 400 batches is up to 200,000 records, a few minutes of a busy
# backlog. The rest waits for the next run with the cursor where it stopped.
MAX_BATCHES = 400
# The sensor writes health every pass (2s) — minutes of silence means it
# stopped, or cannot write, whatever its last health file claimed.
HEALTH_STALE = 300
# Where an unparsable batch file is preserved instead of left in place to
# block the channel forever. The filename carries the batch's sha256, so the
# preservation itself is tamper-evident.
QUARANTINE = "quarantine"


def read_health(spool=SPOOL):
    spool = Path(spool)
    try:
        mode = json.loads((spool / "mode.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        mode = None
    except (OSError, ValueError) as exc:
        return {"status": "unreadable", "reason": f"mode receipt: {str(exc)[:160]}"}
    if mode is not None:
        if mode != {"mode": "isolated", "schema": 1}:
            return {"status": "unreadable", "reason": "unknown native sensor mode receipt"}
        return _isolated_health(spool)
    try:
        with open(spool / "health.json", "rb") as fh:
            health = json.loads(fh.read(1024 * 1024).decode("utf-8-sig"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        return {"status": "unreadable", "reason": str(exc)[:200]}
    health["age"] = _age(health.get("time"))
    return health


def _isolated_health(spool):
    """Compose independent receipts without letting one healthy channel mask another."""
    states = {}
    receipts = []
    for channel in ISOLATED_CHANNELS:
        name = hashlib.sha256(channel.encode("utf-8")).hexdigest()[:16]
        try:
            raw = (spool / name / "health.json").read_bytes()[:1024 * 1024]
            receipt = json.loads(raw.decode("utf-8-sig"))
            state = receipt["channels"][channel]
            if (receipt.get("schema") != 2 or not isinstance(state, dict)
                    or receipt.get("service") != ISOLATED_SERVICES[channel]):
                raise ValueError("invalid channel receipt")
            age = _age(receipt.get("time"))
            if age is None or age < -60 or age > HEALTH_STALE:
                state = {**state, "status": "unavailable", "reason": "channel heartbeat stale"}
            states[channel] = state
            receipts.append(receipt)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            states[channel] = {"status": "unavailable", "reason": f"channel receipt missing or invalid: {type(exc).__name__}"}
    identities = {receipt.get("sensor_id") for receipt in receipts}
    devices = {receipt.get("device_id") for receipt in receipts}
    if len(identities) != 1 or None in identities or len(devices) != 1 or None in devices:
        for state in states.values():
            state["status"] = "unavailable"
            state["reason"] = "channel identity disagreement or missing receipt"
    ages = [_age(receipt.get("time")) for receipt in receipts]
    valid_ages = [age for age in ages if age is not None]
    try:
        monitor = json.loads((spool / "monitor.json").read_text(encoding="utf-8"))
        monitor["age"] = _age(monitor.get("time"))
        if (monitor.get("schema") != 1 or not isinstance(monitor.get("services"), dict)
                or monitor["age"] is None or monitor["age"] < -60
                or monitor["age"] > HEALTH_STALE):
            monitor = {"status": "unavailable", "reason": "monitor receipt stale or invalid"}
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        monitor = {"status": "unavailable", "reason": f"monitor receipt missing or invalid: {type(exc).__name__}"}
    return {
        "schema": 2, "mode": "isolated", "sensor_id": next(iter(identities)) if len(identities) == 1 else None,
        "device_id": next(iter(devices)) if len(devices) == 1 else None,
        "channels": states, "age": max(valid_ages) if valid_ages else None,
        "status": "unavailable" if any(s["status"] == "unavailable" for s in states.values()) else "complete",
        "reason": "; ".join(channel + ": " + str(state.get("reason", "unavailable"))
                           for channel, state in states.items() if state["status"] == "unavailable")[:300],
        "spool_bytes": sum(int(receipt.get("spool_bytes") or 0) for receipt in receipts),
        "spool_capacity": sum(int(receipt.get("spool_capacity") or 0) for receipt in receipts),
        "monitor": monitor,
    }


def _age(stamp):
    try:
        t = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return time.time() - t.timestamp()


def _batches(directory):
    """(sequence, path) for published batch files, oldest first."""
    out = []
    for p in directory.glob("*.json"):
        stem = p.stem
        if len(stem) == 20 and stem.isdigit():
            out.append((int(stem), p))
    return sorted(out)


def _quarantine(spool, directory, path, raw):
    """Preserve an unparsable batch file and move it out of the spool.

    Returns the quarantine path, or None when the bytes could not be kept
    (the caller must then leave the channel blocked rather than destroy
    evidence it cannot preserve)."""
    qdir = Path(spool) / QUARANTINE
    digest = hashlib.sha256(raw).hexdigest()
    dest = qdir / f"{directory.name}.{path.stem}.{digest[:16]}.json"
    try:
        qdir.mkdir(exist_ok=True)
        os.replace(path, dest)
        return dest
    except OSError:
        return None


def _write_ack(spool, dirname, batch, digest):
    acks = Path(spool) / "acks"
    try:
        acks.mkdir(exist_ok=True)
        path = acks / f"{dirname}.json"
        tmp = acks / f"{dirname}.{os.getpid()}.tmp"
        with open(tmp, "w") as fh:
            json.dump({"sensor_id": batch["sensor_id"], "channel": batch["channel"],
                       "through_sequence": batch["sequence"], "digest": digest,
                       "acknowledged_at": datetime.now(timezone.utc).isoformat()}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return None
    except OSError as exc:
        # The install grants this account write access to acks/ only. Without
        # it the sensor keeps everything and stops at its capacity, which is
        # the safe failure — so report it rather than treat it as fatal.
        return f"acknowledgement not written: {exc.strerror or exc}"


def _event(record, batch):
    try:
        return normalize.normalize(record, batch)
    except (normalize.NormalizeError, ValueError, KeyError) as exc:
        # A record that cannot be understood is still evidence that something
        # was logged. Keep it raw rather than block the channel on it forever.
        return event_mod.make(
            host=batch["host_id"], sensor=batch["sensor_id"], device=batch.get("device_id"),
            boot=batch.get("boot_id"), channel=batch["channel"],
            generation=batch["generation"], record=record["record_id"],
            source=normalize.SOURCES.get(batch["channel"], "windows-eventlog"),
            source_event=record["event_id"], time=record["time"],
            received=record.get("read_time") or record["time"],
            batch=batch["sequence"], category="unknown",
            action=f"event_{record['event_id']}",
            attrs={"_normalize_error": str(exc)[:200],
                   "_received_basis": "sensor_read" if record.get("read_time")
                                      else "event_time_fallback"}, raw=record["xml"])


def _split_at_reuse(events):
    """Split a batch whose record IDs go backwards at exactly one boundary.

    Windows reuses record IDs after a log clear, so a batch written across a
    clear contains two monotonic blocks whose ID ranges overlap. Each block
    is internally sound; only the boundary trips the duplicate check. Returns
    (head, tail) split at the boundary, or (events, []) when the batch is
    genuinely malformed (more than one boundary, or a non-monotonic block).
    """
    breaks = [i for i in range(1, len(events)) if events[i]["record_id"] <= events[i - 1]["record_id"]]
    if len(breaks) != 1:
        return events, []
    i = breaks[0]
    head, tail = events[:i], events[i:]
    mono = lambda block: all(block[j]["record_id"] < block[j + 1]["record_id"]
                             for j in range(len(block) - 1))
    if not head or not tail or not mono(head) or not mono(tail):
        return events, []
    return head, tail


def channel_hint(spool, directory, known):
    """The channel identity to key a quarantined batch under.

    A batch too malformed to name itself cannot identify its sensor or
    channel, but the cursor it must advance is keyed by that identity. The
    last valid batch on this directory supplies it; earlier ack records are
    the fallback; a hash-derived placeholder keeps a channel that has never
    produced a valid batch visible rather than nameless.
    """
    if known is not None:
        return known
    ack = Path(spool) / "acks" / f"{directory.name}.json"
    try:
        data = json.loads(ack.read_text(encoding="utf-8"))
        identity = (data.get("sensor_id"), data.get("channel"))
        if all(isinstance(x, str) and x for x in identity):
            return identity
    except (OSError, ValueError):
        pass
    return (f"unknown-sensor-{directory.name}", f"unknown-channel-{directory.name}")


def ingest_channel(log, spool, directory, budget, files=None, published_through=None):
    """Ingest one channel directory. Returns its accounting dict."""
    result = {"directory": directory.name, "batches": 0, "events": 0, "gaps": [],
              "error": None, "channel": None, "last_sequence": None, "status": None,
              "ack_error": None, "backlog": 0, "duplicates": 0, "quarantined": 0}
    last_batch = last_digest = None
    identity = None          # (sensor_id, channel) from the last valid batch
    files = _batches(directory) if files is None else files
    for i, (seq, path) in enumerate(files):
        if result["batches"] >= budget:
            result["backlog"] = len(files) - i
            break
        # Read and validate outside the commit path. A batch that cannot be
        # understood at all is preserved under quarantine/ and recorded as a
        # loss in the event history itself; the cursor then advances past it.
        # A file that cannot even be preserved keeps the channel blocked —
        # evidence is never destroyed just to unstick delivery.
        try:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_BATCH_BYTES + 1)
            if len(raw) > MAX_BATCH_BYTES:
                raise BatchError("batch exceeds size limit")
            parsed = json.loads(raw)
            # A batch that straddles a log clear is two sound monotonic blocks
            # whose ID ranges overlap — Windows reuses record IDs after a
            # clear — so validated whole it trips the duplicate check and
            # would wedge the channel forever. Split it before validation,
            # validate each block, and merge it back with the reuse recorded
            # as the gap it is. The boundary is in the batch's own structure,
            # so this applies on a fresh channel too, not only mid-stream.
            head, tail = ([], [])
            if isinstance(parsed, dict) and isinstance(parsed.get("events"), list):
                head, tail = _split_at_reuse(parsed["events"])
            reuse_at = 0
            if tail:
                # Index of the first post-clear record. It must survive to the
                # redelivery filter below: post-clear IDs reuse pre-clear ones,
                # so filtering them against the cursor's record_through drops
                # new observations as "duplicates" (silent loss, found by the
                # formal-verification review 2026-10-29).
                reuse_at = len(head)
                head_end, tail_start = head[-1]["record_id"], tail[0]["record_id"]
                # IDs restart after a clear, so there is no ID range for what
                # was lost: anything logged after record head_end and before the
                # clear is gone, and the log restarted at tail_start.
                reuse = (f"record IDs reset within batch {seq}: the event log was "
                         f"cleared or wrapped after record {head_end}; {len(head)} pre-clear "
                         f"records ingested, any records written after {head_end} and before "
                         f"the clear were lost, and the log restarted at record {tail_start}")
                if parsed.get("gap"):
                    reuse = f"{parsed['gap']}; {reuse}"
                validate({**parsed, "events": head})
                validate({**parsed, "events": tail})
                batch = {**parsed, "events": head + tail, "gap": reuse}
            else:
                batch = validate(parsed)
        except (OSError, ValueError) as exc:
            # `raw` may not exist if even the read failed; preserve what the
            # file held where possible so nothing is dropped unrecoverably.
            try:
                kept = _quarantine(spool, directory, path, raw)
            except UnboundLocalError:
                kept = None
            if kept is None:
                result["error"] = (f"{path.name}: {exc}; could not preserve the batch, "
                                   "so the cursor holds rather than lose it")[:300]
                break
            sensor_id, channel = channel_hint(spool, directory, identity)
            loss = (f"batch {seq} failed validation and was quarantined: {exc}")[:300]
            log.append([], {
                "sensor": sensor_id, "channel": channel,
                "sequence": seq, "generation": "quarantined", "status": "partial",
                "gap": loss, "digest": hashlib.sha256(raw).hexdigest(),
                "created_at": None, "events": 0,
                "quarantine": str(kept),
            })
            result["gaps"].append(loss)
            result["quarantined"] += 1
            # Latest quarantine wins: it is the ack watermark when no valid
            # batch follows to cover it.
            result["quarantine_identity"] = (sensor_id, channel, seq)
            continue
        if batch["sequence"] != seq:
            result["error"] = f"{path.name}: file name and sequence disagree"
            break
        result["channel"] = batch["channel"]
        identity = (batch["sensor_id"], batch["channel"])
        digest = hashlib.sha256(raw).hexdigest()
        cursor = log.cursor(batch["sensor_id"], batch["channel"])
        done = cursor["sequence"] if cursor else 0
        if seq < done:
            continue                       # committed earlier, awaiting reclamation
        if seq == done:
            if cursor.get("digest") != digest:
                result["error"] = (f"{path.name}: batch {seq} was replaced after it was "
                                   f"ingested — spool content changed under a committed cursor")
                break
            last_batch, last_digest = batch, digest
            continue
        gap = batch.get("gap")
        if seq != done + 1:
            if cursor is not None:
                result["error"] = (f"{path.name}: batch {done + 1} is missing; "
                                   f"cursor held at {done}")
                break
            # Nothing ingested for this channel yet and the spool starts later:
            # the earlier batches are gone. Say so in the history itself.
            first = f"first ingested batch is {seq}; batches 1-{seq - 1} were never received"
            # A reuse split and an unreceived prefix are two real gaps; the
            # cursor carries one gap string, so it carries both.
            gap = f"{gap}; {first}" if gap else first
        # A quarantined batch left the cursor's generation as "quarantined":
        # that marker is not a real generation change, so resume the real one
        # without demanding a gap record for it. The quarantine loss is
        # already its own recorded gap.
        generation_resume = cursor and cursor.get("generation") == "quarantined"
        if (cursor and not generation_resume
                and batch["generation"] != cursor["generation"] and not batch.get("gap")):
            result["error"] = f"{path.name}: log generation changed without a gap record"
            break
        # Record IDs only grow within a log generation, so one at or below the
        # highest already committed is a redelivery, not a new observation.
        seen = (cursor.get("record_through") or 0) if cursor and \
            batch["generation"] == cursor["generation"] else 0
        # Post-clear records reuse pre-clear IDs: they are new observations,
        # not redelivery, so only the pre-clear block filters against `seen`.
        if reuse_at:
            fresh = ([r for r in batch["events"][:reuse_at] if r["record_id"] > seen]
                     + batch["events"][reuse_at:])
        else:
            fresh = [r for r in batch["events"] if r["record_id"] > seen]
        result["duplicates"] += len(batch["events"]) - len(fresh)
        events = [_event(r, batch) for r in fresh]
        event_times = [e.get("time") for e in events if e.get("time")]
        boot_changed = (cursor and cursor.get("boot")
                        and batch.get("boot_id")
                        and cursor.get("boot") != batch.get("boot_id"))
        if gap:
            # A gap breaks the claim that the state reducer has seen every
            # transition. Later complete batches must not erase that boundary:
            # snapshot reconciliation is safe only for instances born after it.
            continuous_since = batch["created_at"]
        elif boot_changed:
            # Sysmon may start after core boot processes, so continuity from
            # the prior boot cannot prove those ProcessCreate events existed
            # in the current stream.
            continuous_since = min(event_times) if event_times else batch["created_at"]
        elif cursor and cursor.get("continuous_since"):
            continuous_since = cursor["continuous_since"]
        else:
            # The first native pass drains the retained Event Log from its
            # oldest record, so its oldest source time is the beginning of the
            # interval this stream can honestly claim to reconstruct.
            continuous_since = min(event_times) if event_times else batch["created_at"]
        log.append(events, {
            "sensor": batch["sensor_id"], "channel": batch["channel"], "sequence": seq,
            "generation": batch["generation"], "status": batch["status"], "gap": gap,
            "digest": digest, "created_at": batch["created_at"], "events": len(events),
            "host": batch["host_id"], "device": batch.get("device_id"),
            "boot": batch.get("boot_id"),
            "continuous_since": continuous_since,
            "record_through": max([seen] + [r["record_id"] for r in fresh]),
        })
        if gap:
            result["gaps"].append(gap)
        result["batches"] += 1
        result["events"] += len(events)
        last_batch, last_digest = batch, digest
    # Ack the highest consumed sequence. A valid batch's own ack covers any
    # earlier quarantine on the same channel (through_sequence semantics);
    # when no valid batch followed the poisoned one, ack the quarantined
    # sequence itself so the sensor does not keep the preserved copy queued.
    ack_upto = last_batch["sequence"] if last_batch is not None else None
    if result.get("quarantine_identity"):
        _sensor, _channel, quarantined_seq = result["quarantine_identity"]
        if ack_upto is None or ack_upto < quarantined_seq:
            ack_upto = quarantined_seq
    if ack_upto is not None:
        if last_batch is not None and ack_upto == last_batch["sequence"]:
            result["ack_error"] = _write_ack(spool, directory.name, last_batch, last_digest)
        else:
            sensor_id, channel, seq = result["quarantine_identity"]
            result["ack_error"] = _write_ack(spool, directory.name, {
                "sensor_id": sensor_id, "channel": channel, "sequence": seq,
            }, "")
        result["last_sequence"] = ack_upto
        result["status"] = last_batch["status"] if last_batch is not None else "partial"
    if published_through is not None:
        cursor = result["last_sequence"] or 0
        result["backlog"] = max(result["backlog"], max(0, published_through - cursor))
    return result


def _manifest_channels(log, spool, health, max_batches):
    """Known channel batches without enumerating the DrvFS spool.

    Directory enumeration under ``/mnt/c`` can block in the kernel even while
    individual file reads work. Sensor schema 2 already publishes each
    channel's high-water sequence in health.json, and the directory name is a
    deterministic hash of that channel. Use those two authenticated-by-content
    facts to address batch files directly. The extra candidate lets
    ``ingest_channel`` account for backlog after consuming its budget.

    Returns ``None`` for old/test health documents, which preserves the legacy
    directory scan for local fixtures and pre-schema-2 sensors.
    """
    if not isinstance(health, dict):
        return None
    states = health.get("channels")
    sensor_id = health.get("sensor_id")
    if health.get("schema") != 2 or not isinstance(states, dict) or not sensor_id:
        if health.get("mode") == "isolated":
            return []  # fail closed on identity disagreement; never scan unknown publishers
        return None
    channels = []
    for channel, state in states.items():
        if not isinstance(channel, str) or not isinstance(state, dict):
            continue
        through = state.get("last_sequence")
        if not isinstance(through, int) or isinstance(through, bool) or through < 1:
            continue
        dirname = hashlib.sha256(channel.encode("utf-8")).hexdigest()[:16]
        directory = Path(spool) / dirname
        cursor = log.cursor(sensor_id, channel)
        done = int(cursor.get("sequence") or 0) if cursor else 0
        start = max(1, done)
        if done:
            # Re-read the committed head when the retained file exists so a
            # replacement is detected. Once the sensor has legitimately
            # compacted it, continue at the next sequence without listing.
            try:
                mode = os.stat(directory / f"{done:020d}.json").st_mode
                if not stat.S_ISREG(mode):
                    start = done + 1
            except FileNotFoundError:
                start = done + 1
            except OSError:
                # Preserve the direct path: opening it below records the real
                # I/O error instead of silently converting blindness to empty.
                pass
        stop = min(through, start + max(1, max_batches))
        files = [(seq, directory / f"{seq:020d}.json")
                 for seq in range(start, stop + 1)]
        channels.append((directory, files, through))
    return channels


def preflight(spool=SPOOL):
    """Classify spool reachability without opening the event-log writer."""
    spool = Path(spool)
    report = {"spool": str(spool), "installed": None, "access_error": None,
              "health": None, "channels": [], "batches": 0, "events": 0,
              "sealed": None, "pruned": [], "mount_stale": False}
    # Fast gate: on a stale Windows drive every listing below fails with EIO.
    # Say so once here instead of once per channel, and touch nothing.
    if mounts.under_windows_drive(spool) and mounts.windows_drive() == mounts.STALE:
        report["installed"] = False
        report["mount_stale"] = True
        report["access_error"] = mounts.stale_detail()
        return report
    try:
        report["installed"] = stat.S_ISDIR(spool.stat().st_mode)
    except FileNotFoundError:
        report["installed"] = False
    except OSError as exc:
        import errno as _errno
        if exc.errno in (_errno.EIO, _errno.ENODEV, _errno.ESTALE):
            report["access_error"] = mounts.stale_detail()
            report["mount_stale"] = True
        else:
            report["access_error"] = str(exc)[:300]
        return report
    return report


def run(log=None, spool=SPOOL, max_batches=MAX_BATCHES):
    """One ingestion pass over every channel in the spool."""
    spool = Path(spool)
    report = preflight(spool)
    if report["installed"] is not True:
        return report
    report["health"] = read_health(spool)
    own = log is None
    log = log or EventLog(writer=True)
    try:
        manifest = _manifest_channels(log, spool, report["health"], max_batches)
        if manifest is None:
            # Legacy directory scan, kept for local fixtures and pre-schema-2
            # sensors. On a stale Windows drive this listing fails with EIO —
            # report it once as a mount outage, never as a per-channel story
            # and never as an uncaught exception out of the 60s native job.
            try:
                dirs = sorted(p for p in spool.iterdir()
                              if p.is_dir() and len(p.name) == 16
                              and all(c in "0123456789abcdef" for c in p.name))
            except OSError as exc:
                import errno as _errno
                if exc.errno in (_errno.EIO, _errno.ENODEV, _errno.ESTALE):
                    report["mount_stale"] = True
                    report["access_error"] = mounts.stale_detail()
                else:
                    report["access_error"] = str(exc)[:300]
                return report
            channels = [(directory, None, None) for directory in dirs]
        else:
            channels = manifest
        for directory, files, published_through in channels:
            share = max(1, (max_batches - report["batches"]) // max(1, len(channels)))
            ch = ingest_channel(log, spool, directory, share, files=files,
                                published_through=published_through)
            report["channels"].append(ch)
            report["batches"] += ch["batches"]
            report["events"] += ch["events"]
        header = log.seal()
        report["sealed"] = header["segment"] if header else None
        report["pruned"] = log.prune()
        report["log"] = log.stats()
    finally:
        if own:
            log.close()
    return report
