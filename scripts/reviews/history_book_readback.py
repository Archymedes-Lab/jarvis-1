"""Bounded read-only live acceptance receipt; import the installed release."""
import collections
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "/opt/jarvis/current")
from jarvis.core.eventlog import EventLog
from jarvis.core.store import Store
from jarvis.platform.provenance.release import manifest_release_id, read_manifest


def main():
    baseline = json.loads(Path("/tmp/jarvis-history-deploy-baseline.json").read_text())
    h = json.load(urllib.request.urlopen("http://127.0.0.1:8787/api/health", timeout=20))
    state = json.load(urllib.request.urlopen("http://127.0.0.1:8787/api/state", timeout=30))
    with EventLog() as log:
        stats = log.stats()
        verification = log.verify(anchor=baseline["head"])
        counts = collections.Counter()
        snapshots = set()
        latest_snapshot = 0
        for ev in log.iter_events(after=max(baseline["history_stats"]["last_seq"],
                                           log.last_seq - 5000), until=log.last_seq):
            if ev.get("source") == "process-snapshot":
                snapshots.add(ev["generation"])
                latest_snapshot = max(latest_snapshot, ev["seq"])
                if (ev.get("attrs") or {}).get("observation") == "process_present":
                    counts[ev["host"]] += 1
    store = Store()
    try:
        custody = json.loads(store.get_meta("evidence_v1", "{}"))
    finally:
        store.close()
    affected = {j["name"]: j for j in state.get("jobs", [])
                if j["name"] in ("scan", "native", "evidence")}
    current = [{k: f.get(k) for k in ("job", "category", "severity", "host", "title")}
               for f in state.get("findings", []) if f.get("job") in affected]
    def signatures(findings):
        return {tuple(f.get(k) for k in ("job", "category", "severity", "host", "title"))
                for f in findings}
    previous = signatures(baseline["findings"])
    present = signatures(current)
    vault = custody.get("vault_job") or {}
    result = {
        "at": time.time(), "release_id": manifest_release_id(read_manifest("/opt/jarvis/current")),
        "runtime_path": os.path.realpath("/opt/jarvis/current"),
        "health": {k: h.get(k) for k in ("healthy", "ready", "protection_healthy")},
        "sources": {k: h.get("sources", {}).get(k) for k in ("scan", "native", "bridge")},
        "native_sequence": h.get("telemetry_chain", {}).get("last_sequence"),
        "history": {k: stats.get(k) for k in ("last_seq", "segments", "sealed_through", "pruned",
                    "sealed_bytes", "unsealed_events", "retention", "payload_capacity_remaining")},
        "integrity": verification, "new_snapshot_groups": len(snapshots),
        "new_process_observations": dict(counts), "latest_snapshot_seq": latest_snapshot,
        "affected_jobs": affected,
        "findings_added": sorted(present - previous, key=str),
        "findings_absent": sorted(previous - present, key=str),
        "custody": {"at": custody.get("at"), "vaulted": custody.get("vaulted"),
                    "vault_job": vault, "anchors": custody.get("anchors")},
        "no_recording_blocked_finding": not any(
            f.get("title") == "Process history recording blocked" for f in current),
        "local_vault_limit": "ordinary-user deletion protection; administrator can still delete",
    }
    stamp = int(result["at"])
    output = Path(f"/tmp/jarvis-history-readback-{stamp}.json")
    output.write_text(json.dumps(result, indent=2)); output.chmod(0o600)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
