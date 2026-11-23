"""Self-defense scenarios: attack JARVIS's own evidence and see if it notices.

The Arena assumes JARVIS can be attacked, not only the machine around it. This
provider writes a baseline of events, lets the runner seal them into the hash
chain, then — in `post_seal` — tampers with that sealed history the way a
privileged attacker would: rewrite a segment, delete one, or truncate it. The
`integrity` detector then runs the event log's own verification. The scenario
passes only if the tampering is detected.

It operates solely on the run's throwaway event log. Nothing on the host is
touched, so it is safe to run anywhere despite describing an attack on JARVIS.
"""

import gzip
import json

from jarvis.platform.native import normalize


def _baseline(scenario, log):
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    batch = {"schema": 2, "sensor_id": "arena", "device_id": "arena", "boot_id": "arena",
             "host_id": "ARENA", "channel": normalize.SYSMON, "generation": f"arena-{scenario.id}",
             "sequence": 1, "previous_sequence": 0, "created_at": now.isoformat(),
             "bookmark": "", "status": "complete", "gap": None, "events": []}
    events = []
    for i in range(1, 6):
        xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
               "<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID></System>"
               f"<EventData><Data Name='UtcTime'>2026-09-18 12:00:0{i}.000</Data>"
               f"<Data Name='ProcessGuid'>{{arena-{i}}}</Data>"
               f"<Data Name='Image'>C:\\Windows\\System32\\svchost.exe</Data></EventData></Event>")
        record = {"record_id": i, "event_id": 1, "time": now.isoformat(), "mono_ms": i, "xml": xml}
        events.append(normalize.normalize(record, batch))
    return log.append(events, {"sensor": "arena", "channel": normalize.SYSMON,
                               "sequence": 1, "generation": batch["generation"]})


def produce(scenario, log):
    return _baseline(scenario, log)


def post_seal(scenario, log):
    mode = (scenario.spec or {}).get("mode", "edit")
    seg = log.segdir / f"{1:012d}.jseg"
    if not seg.exists():
        raise RuntimeError(f"{scenario.id}: nothing was sealed to tamper with")
    if mode == "delete":
        seg.unlink()                     # removed without a pruned record -> "missing"
        return
    if mode == "truncate":
        with open(seg, "r+b") as fh:
            fh.truncate(max(1, seg.stat().st_size // 2))
        return
    # edit: rewrite the payload so the chain's payload hash no longer matches.
    with gzip.open(seg, "rb") as fh:
        header = fh.readline()
        payload = fh.read()
    tampered = payload.replace(b"svchost.exe", b"evil.dll\x00\x00\x00") or payload + b"x"
    with open(seg, "wb") as raw:
        for part in (header, tampered):
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                gz.write(part)


def _reader_note():
    return json.dumps({"note": "operates only on the run's throwaway event log"})
