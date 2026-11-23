"""Replay retained history through the real Sysmon detectors.

Read-only: the event log and the journal are opened as a reader and the
detectors are given rows directly, so no finding is stored and no cursor moves.
Run it before a new technique rule is counted, to see what it would have
reported on this machine:

    nice -n 10 python3 -m scripts.dev.replay_techniques [last N events]
    nice -n 10 python3 -m scripts.dev.replay_techniques --linux [days]
"""
import collections
import sys
import time

from jarvis.collectors.telemetry import sysmon
from jarvis.core.eventlog import EventLog

EVENTS = (1, 3, 13, 22)
CHUNK = 20000


def main(last=None):
    log = EventLog()
    after = max(0, log.last_seq - last) if last else 0
    hits, example, seen, chunk, started = collections.Counter(), {}, 0, [], time.time()

    def flush():
        # Only the system drive is given as internal, so every program or copy
        # that names any other drive is reported: the most the drive rules can say.
        for f in sysmon.audit(events=sysmon.rows_from_events(chunk),
                              volumes={"C": ("Fixed", "")}):
            if f.get("techniques"):
                key = (f["severity"], f["title"])
                hits[key] += 1
                example.setdefault(key, f["detail"][:170])
        chunk.clear()

    for ev in log.iter_events(after=after):
        if ev.get("source") != "sysmon" or int(ev.get("source_event") or 0) not in EVENTS:
            continue
        chunk.append(ev)
        seen += 1
        if len(chunk) >= CHUNK:
            flush()
    flush()
    print(f"{seen} events replayed in {time.time() - started:.0f}s")
    for key, n in hits.most_common():
        print(n, key, "|", example[key])
    return hits


def linux(days=14):
    """Sysmon for Linux events from the journal, a day at a time."""
    from jarvis.collectors.telemetry import sysmon_linux
    from jarvis.collectors.telemetry.sysmon_linux import journal, rules
    hits, example, seen, started = collections.Counter(), {}, 0, time.time()
    events = journal._parse(journal._raw(time.time() - days * 86400))
    for at in range(0, len(events), CHUNK):
        chunk = events[at:at + CHUNK]
        seen += len(chunk)
        for f in rules._rules(chunk):
            if f.get("techniques"):
                key = (f["severity"], f["title"])
                hits[key] += 1
                example.setdefault(key, f["detail"][:170])
    print(f"{seen} Linux events from the last {days} days replayed in {time.time() - started:.0f}s"
          f" ({sysmon_linux.CHANNEL})")
    for key, n in hits.most_common():
        print(n, key, "|", example[key])
    return hits


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--linux" in sys.argv:
        linux(int(args[0]) if args else 14)
    else:
        main(int(args[0]) if args else None)
