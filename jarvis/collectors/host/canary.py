"""The canary job: watch planted bait and report when it is touched or taken.

Every pass: verify the tamper-evident journal; check planted decoys against
their plant-time fingerprints; scan new normalized file events in the event log
for activity on a decoy's path or name; ingest callback hits the owner's
listener recorded; check that the listener is alive and that every protected
class has bait beside it; anchor the journal head externally when due; and turn
the current state into findings. Planting is owner-driven (`jarvis canary`);
this job never creates bait, never touches the attacker, and never clears a
trip on its own: a trip, once recorded, stays reported until the owner retires
the token.
"""

import json
import sys

from jarvis.core import canary as canary_mod
from jarvis.core.finding import finding

META = "canary_v1"
# The installed Sysmon baseline (the same file sysmon_policy.BASELINE names; a
# test keeps the two equal). It decides which decoys the event-log lane can see.
SYSMON_BASELINE = "windows-sysmon/jarvis-windows-baseline.xml"
# Normalized events scanned per pass. A larger backlog continues next pass from
# the saved cursor, so one run can never be unbounded. Measured on the live log:
# ~3 s per pass at this cap. Events are streamed, not held, so peak memory is
# one event regardless of the cap (a full 200k materialized list peaked at
# 1.25 GB, which this host cannot spare).
MAX_EVENTS = 50_000

_VERB = {"removed": "taken", "copied": "copied", "modified": "touched",
         "accessed": "accessed"}
_WHAT = {"removed": "is gone (deleted or renamed away)",
         "copied": "was copied: a file with its name appeared elsewhere",
         "modified": "changed since it was planted",
         "accessed": "was read (access time advanced; a weak signal)"}
# Worst reason first, so one finding per token names the most serious touch.
_ORDER = ("copied", "removed", "modified", "accessed")


def _summary(store):
    try:
        state = json.loads(store.get_meta(META) or "null")
    except (TypeError, ValueError):
        return None
    return state if isinstance(state, dict) else None


def _unseen_decoys(active):
    """Labels of file decoys whose overwrite and deletion Sysmon would not log."""
    from jarvis.core.paths import repo_file
    try:
        rules = canary_mod.file_event_rules(
            repo_file(SYSMON_BASELINE).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        rules = {}
    unseen = []
    for token in active.values():
        if token.get("kind") != "file_decoy":
            continue
        seen = canary_mod.sysmon_visible(token.get("path"), rules)
        if not (seen["create"] or seen["delete"]):
            unseen.append(token.get("label") or token.get("id"))
    return sorted(unseen)


def findings_from_state(state, chain_broken, gaps=(), listener=None, unseen=()):
    """Findings for the current canary state. Pure, for direct testing."""
    out = []
    if chain_broken is not None:
        out.append(finding(
            "tampering", "critical", "Canary journal was tampered with",
            f"The append-only record of planted bait no longer verifies "
            f"({chain_broken.get('reason')} at sequence "
            f"{chain_broken.get('seq', chain_broken.get('index'))}). Someone with "
            "local access edited, deleted or reordered it. Compare against the "
            "off-box copy and the last external anchor before anything else writes "
            "here.", "canary journal"))
        # The chain cannot be trusted to enumerate tokens, so stop here.
        return out

    tokens = state.get("tokens", {})
    active = state.get("active", {})

    # Off-box callbacks are the strongest signal: the bait left this machine and
    # was opened elsewhere. That is exfiltration, whoever did it.
    for tid, hits in sorted(state.get("callbacks", {}).items()):
        label = tokens.get(tid, {}).get("label", tid)
        last = hits[-1]
        registry_note = ("" if tid in active else
                         " (not in the active registry: retired, or planted and "
                         "then removed from the record)")
        ip = last.get("ip") or "unknown address"
        ua = last.get("ua") or "unknown"
        out.append(finding(
            "tampering", "critical",
            f"Canary bait was opened off this machine: {label}",
            f"{len(hits)} callback hit(s) for token {tid}{registry_note}. Most "
            f"recent: from {ip}, user-agent {ua}. The bait was taken from this "
            "machine and opened elsewhere; treat anything it sat alongside as "
            "exfiltrated.", f"token {tid}"))

    # On-box and event-log trips, one finding per token naming its worst touch.
    for tid, reasons in sorted(state.get("tripped", {}).items()):
        token = tokens.get(tid, {})
        label = token.get("label", tid)
        where = token.get("path") or f"token {tid}"
        reason = next((r for r in _ORDER if r in reasons), sorted(reasons)[0])
        last = state.get("last_trip", {}).get(tid) or {}
        by = f" Last seen: {last['detail']}." if last.get("detail") else ""
        out.append(finding(
            "tampering", "high",
            f"Canary decoy was {_VERB.get(reason, 'touched')}: {label}",
            f"The planted decoy {where} {_WHAT.get(reason, 'was touched')}.{by} "
            "JARVIS does not write to planted decoys, so this was something else "
            "on the machine.", where))

    # Coverage: a protected class with no bait beside it is a blind spot.
    for gap in gaps:
        out.append(finding(
            "visibility", "medium",
            f"No canary beside protected data: {gap['class']}",
            "None of " + ", ".join(gap["dirs"]) + " holds an armed decoy, so an "
            "intruder can take this class of data without touching bait.",
            "canary coverage"))

    # Liveness: a callback that cannot arrive is a blind spot, not silence.
    has_doc = any(t.get("kind") == "doc_url" for t in active.values())
    status = (listener or {}).get("status")
    if status == "stale":
        out.append(finding(
            "visibility", "high", "Canary callback listener is not reporting",
            f"{listener['detail']}. Off-box opens of the bait cannot reach JARVIS "
            "until the listener is back.", "canary listener"))
    elif status == "unverified" and has_doc:
        out.append(finding(
            "visibility", "low", "Canary callback listener liveness is unverified",
            f"{listener['detail']}. Have the listener touch a heartbeat file and "
            "set canary.listener_heartbeat.", "canary listener"))
    elif status == "unconfigured" and has_doc:
        out.append(finding(
            "visibility", "medium", "Document canaries have no callback inbox",
            "doc_url tokens are planted but canary.callback_inbox is not set, so "
            "an off-box open could never be reported.", "canary listener"))

    # Decoys the event-log lane cannot see: only the fingerprint check covers
    # them, after the fact. Named by label, never by location.
    if unseen:
        out.append(finding(
            "visibility", "low",
            f"{len(unseen)} canary decoy(s) outside Sysmon's file rules",
            "Overwrite or deletion of " + ", ".join(unseen) + " is not logged by the "
            "installed Sysmon baseline, so only the fingerprint check (each pass, "
            "after the fact) covers them. Add their folders to the FileCreate and "
            "FileDeleteDetected include rules, or place them where those rules "
            "already look.", "canary coverage"))

    # Posture: an empty registry is visible rather than looking like safety.
    if active:
        out.append(finding(
            "visibility", "ok", f"{len(active)} canary token(s) armed",
            "Planted bait is being watched for tampering, copies and off-box "
            "callbacks.", "canary journal"))
    else:
        out.append(finding(
            "canary", "low", "No canary tokens are planted",
            "No bait is in place, so a quiet intruder leaves no canary signal. "
            "Plant decoys with `jarvis canary plant`.", "canary journal"))
    return out


def _event_lane(state, previous, *, events=None, eventlog_root=None):
    """(new trips, new cursor, error) from file events since the saved cursor."""
    from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
    cursor = previous.get("event_cursor")
    try:
        from jarvis.core.paths import self_executable
        images = {sys.executable, self_executable()}
        progress = {"last": cursor if type(cursor) is int else 0}

        def bounded(source):
            # Stream events through the matcher without holding them: peak memory
            # is one event, and `last` advances only over events actually seen.
            for n, ev in enumerate(source):
                if n >= MAX_EVENTS:
                    break
                progress["last"] = ev.get("seq", progress["last"])
                yield ev

        if events is None:
            log = EventLog(eventlog_root or DEFAULT_ROOT)
            try:
                if type(cursor) is not int:
                    # First pass: start at the present. Decoy history from before
                    # the canary job existed says nothing about the planted bait.
                    return [], log.last_seq, None
                trips = canary_mod.match_file_events(
                    bounded(log.iter_events(after=cursor)),
                    state.get("active", {}), self_images=images)
            finally:
                log.close()
        else:
            trips = canary_mod.match_file_events(
                bounded(events), state.get("active", {}), self_images=images)
    except (LogError, OSError, ValueError) as exc:
        return [], cursor, type(exc).__name__
    return trips, progress["last"], None


def audit(store, hosts=None, root=canary_mod.DEFAULT_ROOT, conf=None, now=None,
          network=True, submit=None, events=None, eventlog_root=None):
    import time

    now = now or time.time()
    # Config is handed down from the service layer (jobs.py); this collector does
    # not import `response`. An empty conf means "no inbox, no anchor configured".
    conf = conf or {}
    previous = _summary(store) or {}
    journal = canary_mod.CanaryJournal(root)

    broken = journal.verify()
    if broken is not None:
        # Do not append to a chain that no longer verifies: that would extend a
        # record an intruder has already broken. Report and stop writing.
        state = journal.state()
        store.set_meta(META, json.dumps({"at": int(now), "chain_ok": False,
                                        "broken": broken,
                                        "event_cursor": previous.get("event_cursor"),
                                        "active": len(state.get("active", {}))},
                                       sort_keys=True))
        store.commit()
        return findings_from_state(state, broken)

    state = journal.state()
    keys = set(state.get("trip_keys", set()))
    appended = False

    def record(trip):
        nonlocal appended
        key = (trip["id"], trip["reason"], canary_mod.norm_path(trip.get("path")))
        if key not in keys:
            keys.add(key)
            journal.append("trip", trip)
            appended = True

    # 1. on-box tripwire against plant-time fingerprints.
    for trip in canary_mod.onbox_trips(state.get("active", {}), now=now,
                                       check_access=bool(conf.get("check_access"))):
        record(trip)

    # 2. event-log lane: file events on a decoy's path or name.
    lane_trips, cursor, lane_err = _event_lane(
        state, previous, events=events, eventlog_root=eventlog_root)
    for trip in lane_trips:
        record(trip)

    # 3. off-box callbacks from the owner's own listener inbox.
    for hit in canary_mod.read_callbacks(
            conf.get("callback_inbox"),
            active_ids=set(state.get("tokens", {})),
            seen_hits=set(state.get("seen_hits", set()))):
        journal.append("callback", hit)
        appended = True

    # Re-derive after any appends so the findings reflect this pass.
    if appended:
        state = journal.state()

    gaps = canary_mod.coverage_gaps(conf.get("protect"), state.get("active", {}))
    listener = canary_mod.listener_state(
        conf.get("callback_inbox"), conf.get("listener_heartbeat"), now=now,
        max_age=int(conf.get("listener_max_age", 900)))

    # 4. anchor the head externally when due (32-byte digest only). The
    # OpenTimestamps submitter comes from the platform layer, which this
    # collector may import; core stays platform-independent.
    want_anchor = network and conf.get("anchor", True) is not False
    if submit is None and want_anchor:
        from jarvis.platform import timestamps
        submit = timestamps.submit
    last_anchor = previous.get("last_anchor")
    digest, anchor_err = canary_mod.anchor_head(
        journal, now=now, last=last_anchor,
        every=int(conf.get("anchor_every", 21600)),
        network=want_anchor, submit=submit)

    head = journal.head()
    summary = {"at": int(now), "chain_ok": True, "head": head,
               "active": len(state.get("active", {})),
               "tripped": sorted(state.get("tripped", {})),
               "callbacks": sorted(state.get("callbacks", {})),
               "event_cursor": cursor, "event_error": lane_err,
               "coverage_gaps": [g["class"] for g in gaps],
               "listener": listener.get("status"),
               "anchor_error": anchor_err}
    if digest:
        summary["last_anchor"] = {"hash": head["hash"], "at": int(now),
                                  "digest": digest}
    elif last_anchor:
        summary["last_anchor"] = last_anchor
    store.set_meta(META, json.dumps(summary, sort_keys=True))
    store.commit()

    out = findings_from_state(state, None, gaps=gaps, listener=listener,
                              unseen=_unseen_decoys(state.get("active", {})))
    if lane_err:
        out.append(finding(
            "visibility", "medium", "Canary event-log lane could not read history",
            f"{lane_err}: copies and deletions of decoys are checked only by "
            "fingerprint until the event log is readable again.", "canary journal"))
    return out
