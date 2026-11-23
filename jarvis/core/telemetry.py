"""The native telemetry chain, stage by stage.

Eight independently observable stages between the sensor and the history:
installed, running, producing, arriving, ingested, gaps, integrity, fresh.
"Sensor works" is not one state — when any stage breaks, the status names
where. The native job computes this from the ingestion report it already
holds and persists it; the health path reads that answer without touching
the spool, so an HTTP request can never contend with the sensor.
"""
import json
import time

META = "native_delivery"

# Stages older than this are not answers, they are history: the health path
# reports the last known state but marks the whole chain "job silent" so a
# dead native job cannot look like a healthy chain.
STALE = 300

STAGES = ("installed", "running", "producing", "arriving", "ingested",
          "gaps", "integrity", "fresh")


def collect(report, verify_at, freshness_limit, now=None):
    """Stage states from one native job run. Pure: no IO beyond the report.

    `report` is jarvis.platform.native.ingest.run's return value; `verify_at`
    the timestamp of the last full chain verification; `freshness_limit` the
    native source's freshness budget in seconds.
    """
    now = time.time() if now is None else now
    health = report.get("health")
    backlog = sum(ch.get("backlog", 0) for ch in report["channels"])
    # Not-yet-consumed files in this pass are backlog too: the report only
    # counts what it saw past its own budget.
    backlog += sum(1 for ch in report["channels"] if ch.get("error"))
    last_sequence = max([ch.get("last_sequence") or 0 for ch in report["channels"]], default=0)
    gaps = [g for ch in report["channels"] for g in ch.get("gaps", [])]
    quarantined = sum(ch.get("quarantined", 0) for ch in report["channels"])
    age = None
    if isinstance(health, dict):
        age = health.get("age")

    def stage(state, detail):
        return {"state": state, "detail": detail[:240]}

    stages = {}
    if report.get("access_error"):
        stages["installed"] = stage(
            "unknown", f"sensor spool is unreachable: {report['access_error']}")
    else:
        stages["installed"] = (
            stage("ok", report.get("spool", "spool present")) if report.get("installed")
            else stage("down", "the sensor spool does not exist; install with "
                               "windows-sensor\\install.ps1 (elevated)"))
    running = health is not None and health.get("status") != "unreadable" \
        and age is not None and age <= 300
    stages["running"] = (
        stage("ok", f"health written {int(age)}s ago") if running else
        stage("down", "no readable, recent health file — the service is not "
                      "running or cannot write its spool"))
    producing = running and health.get("status") != "unavailable"
    stages["producing"] = (
        stage("ok", "sensor completed its last read pass") if producing else
        stage("down" if running else "unknown",
              str(health.get("reason", "no channel evidence"))[:200] if isinstance(health, dict)
              else "no health file to say what the sensor read"))
    arriving = report.get("batches", 0) > 0 or (backlog == 0 and running)
    stages["arriving"] = (
        stage("ok", f"{report.get('batches', 0)} batches delivered this pass"
                    + (f", {backlog} waiting" if backlog else "")) if arriving else
        stage("down", f"{backlog} batches stuck in the spool and none ingested"))
    ingested = report.get("events", 0) > 0 or (arriving and backlog == 0)
    stages["ingested"] = (
        stage("ok", f"{report.get('events', 0)} events committed to the history"
                    + (f", {quarantined} quarantined" if quarantined else ""))
        if ingested else stage("down", "nothing committed this pass"))
    stages["gaps"] = (
        stage("ok", "none detected this pass") if not gaps else
        stage("degraded", f"{len(gaps)} gap(s) recorded in the history: {gaps[0]}"))
    integrity_age = None if not verify_at else now - verify_at
    stages["integrity"] = (
        stage("ok", f"chain verified {int(integrity_age // 3600)}h ago")
        if integrity_age is not None and integrity_age <= 86400 else
        stage("degraded", "no verification within the last 24h"))
    stages["fresh"] = (
        stage("ok", "evidence within its freshness budget") if ingested else
        stage("down", f"no current evidence; budget is {freshness_limit}s"))
    channels = {}
    if isinstance(health, dict) and health.get("mode") == "isolated":
        delivered = {ch.get("channel"): ch for ch in report["channels"]
                     if ch.get("channel")}
        for name, source in (health.get("channels") or {}).items():
            source = source if isinstance(source, dict) else {}
            delivery = delivered.get(name) or {}
            active = source.get("status") in ("complete", "partial")
            error = delivery.get("error")
            waiting = int(delivery.get("backlog") or 0)
            channel_gaps = delivery.get("gaps") or []
            channels[name] = {
                "installed": stage("ok", "channel service configured") if active else
                    stage("unknown", "no valid channel receipt"),
                "running": stage("ok", "recent channel progress receipt") if active else
                    stage("down", str(source.get("reason") or "channel receipt unavailable")),
                "producing": stage("ok" if source.get("status") == "complete" else
                                   "degraded" if active else "down",
                                   "channel read pass status: " + str(source.get("status", "unknown"))),
                "arriving": stage("ok" if active and not error else "down",
                                  f"{waiting} batches waiting" if waiting else
                                  str(error or "spool addressed")),
                "ingested": stage("ok" if active and not error else "down",
                                  f"{delivery.get('events', 0)} events this pass"),
                "gaps": stage("degraded" if channel_gaps else "ok",
                              f"{len(channel_gaps)} gap(s) this pass"),
                "integrity": stages["integrity"],
                "fresh": stage("ok" if active and not error and waiting == 0 else "down",
                               "channel evidence current" if active and not error and waiting == 0
                               else "channel evidence incomplete"),
                "last_sequence": source.get("last_sequence"),
                "backlog": waiting,
            }
    return {"at": now, "stages": stages, "channels": channels, "backlog": backlog,
            "last_sequence": last_sequence, "gaps": len(gaps),
            "quarantined": quarantined, "checkpoint": last_sequence}


def parse(raw, now=None):
    """The persisted chain status from raw meta JSON; None if never run."""
    try:
        value = json.loads(raw or "")
    except ValueError:
        return None
    if not isinstance(value, dict) or "stages" not in value:
        return None
    now = time.time() if now is None else now
    value["current"] = now - value.get("at", 0) <= STALE
    return value


def read(store, now=None):
    """The persisted chain status from a Store; None if never run."""
    return parse(store.get_meta(META, ""), now)
