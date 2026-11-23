"""Metadata-only Windows Core Audio route and session snapshot.

The sensor samples every five minutes. It cannot exclude shorter transitions,
actual sound, or WASAPI loopback capture; those remain explicit blind spots.

Each pass also reads the scalar peak meter of the active render endpoints for a
short bounded burst, to flag beep-like transients: a rise from silence that
falls back to silence within 1.5 s, inside the window. Only amplitude is seen,
never tone, content or audibility, and the burst covers a small slice of each
interval, so an absent beep is never evidence that none played.

Continuous coverage comes from the input hook's sound listener, which meters
every app session on every active output device each 25 ms and records each
sound episode (sound_events). This collector reports its beeps over the last
24 h and its health from the hook heartbeat; while the listener is not
reporting, coverage is the burst alone and that is said, never implied.
"""
import json
import time

from jarvis.collectors.host import beeptrace, privacyseal
from jarvis.collectors.host.inputwatch.common import SOUND_META
from jarvis.core import collection
from jarvis.core.paths import load_win_script
from jarvis.core.util import iso
from jarvis.platform.windows import ps_json

PS_AUDIO = load_win_script("audio_state.ps1")
_STATE_KEY = "audiowatch_latest_v1"
_MAX_ENDPOINTS = 64
_MAX_SESSIONS = 256
_MAX_EVENTS = 32
_BURST_MAX_MS = 15000
_INTERVAL_S = 300
# The hook beats every 60 s; five missed beats and the listener is not live.
_LISTENER_FRESH_S = 300
# A listener whose thread stopped sampling still beats; its own clock says so.
_LISTENER_SAMPLE_LAG_S = 120
_SOUND_WINDOW_S = 24 * 3600
_ROLES = {(flow, role) for flow in ("render", "capture")
          for role in ("console", "multimedia", "communications")}


def _finding(severity, title, detail, category="audio"):
    return {"host": "win", "severity": severity, "title": title,
            "detail": detail, "category": category,
            "where": "Windows Core Audio"}


def _valid(data):
    if not isinstance(data, dict) or any(
            not isinstance(data.get(key), list)
            for key in ("endpoints", "defaults", "sessions", "errors")):
        return False
    if (len(data["endpoints"]) > _MAX_ENDPOINTS
            or len(data["sessions"]) > _MAX_SESSIONS
            or len(data["defaults"]) != 6
            or len(data["errors"]) > 16):
        return False
    endpoints = data["endpoints"]
    defaults = data["defaults"]
    sessions = data["sessions"]
    if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
           or not 0 < len(row["id"]) <= 512
           or row.get("flow") not in ("render", "capture")
           or row.get("state") not in (1, 2, 4, 8)
           for row in endpoints):
        return False
    if len({row["id"] for row in endpoints}) != len(endpoints):
        return False
    if ({(row.get("flow"), row.get("role")) for row in defaults} != _ROLES
            or any(not isinstance(row.get("id"), (str, type(None)))
                   or isinstance(row.get("id"), str) and row["id"] not in
                   {endpoint["id"] for endpoint in endpoints}
                   for row in defaults)):
        return False
    ids = {row["id"] for row in endpoints}
    if not _valid_burst(data.get("burst"), ids):
        return False
    if any(not isinstance(row, dict) or row.get("endpoint") not in ids
           or row.get("flow") not in ("render", "capture")
           or row.get("state") not in (0, 1, 2)
           or not isinstance(row.get("pid"), int)
           or not 0 <= row["pid"] <= 0xffffffff
           or not isinstance(row.get("identityKnown"), bool)
           or not isinstance(row.get("singleProcess"), bool)
           or row.get("identityKnown") and not row.get("singleProcess")
           for row in sessions):
        return False
    return all(isinstance(error, str) and len(error) <= 160
               for error in data["errors"])


def _num(value, low, high):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and low <= value <= high)


def _valid_burst(burst, endpoint_ids):
    """The peak-meter burst is required: a helper without it is not a clean
    snapshot, so beep visibility cannot silently disappear."""
    if not isinstance(burst, dict):
        return False
    if not (_num(burst.get("durationMs"), 1, _BURST_MAX_MS)
            and _num(burst.get("elapsedMs"), 0, _BURST_MAX_MS * 2)
            and _num(burst.get("samples"), 0, 1_000_000)
            and _num(burst.get("endpointsSampled"), 0, 64)
            and _num(burst.get("sustained"), 0, 1_000_000)
            and isinstance(burst.get("truncated"), bool)
            and isinstance(burst.get("errors"), list)
            and len(burst["errors"]) <= 16
            and all(isinstance(e, str) and len(e) <= 160 for e in burst["errors"])
            and isinstance(burst.get("events"), list)
            and len(burst["events"]) <= _MAX_EVENTS):
        return False
    window = burst["durationMs"] * 2
    for row in burst["events"]:
        if (not isinstance(row, dict) or row.get("endpoint") not in endpoint_ids
                or not _num(row.get("startMs"), 0, window)
                or not _num(row.get("durationMs"), 1, 1500 + 200)
                or not _num(row.get("peak"), 0.0, 1.0)
                or not _num(row.get("pid"), 0, 0xffffffff)
                or not isinstance(row.get("identityKnown"), bool)
                or not isinstance(row.get("systemSounds"), bool)
                or row["identityKnown"] and not (
                    row["pid"] and isinstance(row.get("processStart"), str)
                    and row["processStart"])):
            return False
    return True


def _burst_findings(burst):
    findings = []
    groups = {}
    for row in burst["events"]:
        who = ("system sounds" if row["systemSounds"] else
               (row["pid"], row["processStart"]) if row["identityKnown"] else None)
        groups.setdefault((row["endpoint"], who), []).append(row)
    for (endpoint, who), rows in sorted(groups.items(), key=lambda kv: str(kv[0])):
        if who == "system sounds":
            actor = "system sounds session"
        elif who:
            actor = f"process {who[0]} started {who[1]}"
        else:
            actor = "no exact process identity"
        low = min(r["durationMs"] for r in rows)
        high = max(r["durationMs"] for r in rows)
        findings.append(_finding(
            "low", "short audio burst (beep-like)",
            f"endpoint {endpoint}: {len(rows)} burst(s) of {low}-{high} ms, "
            f"peak up to {max(r['peak'] for r in rows):.3f}; {actor}. Amplitude "
            "only: tone, content and audibility are not verified"))
    if burst["sustained"]:
        findings.append(_finding(
            "low", "continuous audio output during the burst window",
            f"{burst['sustained']} stretch(es) of sound spanned the window edge or "
            "lasted over 1.5 s, so they were not classified as beeps"))
    return findings


def _routes(data):
    return {(row["flow"], row["role"]): row.get("id")
            for row in data.get("defaults", [])}


def _active(data):
    # A bare PID is never an identity. Ignore ambiguous shared/system sessions
    # and exited processes for transition attribution.
    return {(row["endpoint"], row["pid"], row["processStart"])
            for row in data.get("sessions", [])
            if row.get("flow") == "render" and row.get("state") == 1
            and row.get("identityKnown") and row.get("singleProcess")
            and isinstance(row.get("processStart"), str)
            and row["processStart"]}


def _capture_active(data):
    return {(row["endpoint"], row["pid"], row["processStart"])
            for row in data.get("sessions", [])
            if row.get("flow") == "capture" and row.get("state") == 1
            and row.get("identityKnown") and row.get("singleProcess")
            and isinstance(row.get("processStart"), str)
            and row["processStart"]}


def _capture_findings(current, sealed):
    """An identified process holding an active capture stream is someone
    recording from a microphone right now; under a declared seal the gate
    should have refused it, so that is evidence of a reopened or bypassed gate."""
    findings = []
    for endpoint, pid, started in sorted(_capture_active(current)):
        if sealed:
            findings.append(_finding(
                "high", "microphone capture session active despite privacy seal",
                f"endpoint {endpoint}; process {pid} started {started} holds an "
                "active capture stream while microphone access is sealed; the "
                "gate was reopened or bypassed; check: jarvis privacy status"))
        else:
            findings.append(_finding(
                "medium", "microphone capture session active",
                f"endpoint {endpoint}; process {pid} started {started} holds an "
                "active capture stream; an active stream does not prove audio "
                "left the machine"))
    unknown = sum(row.get("state") == 1 and row.get("flow") == "capture"
                  and not (row.get("identityKnown") and row.get("singleProcess"))
                  for row in current.get("sessions", []))
    if unknown:
        findings.append(_finding(
            "high" if sealed else "medium",
            "microphone capture session without exact process identity",
            f"{unknown} active capture session(s) whose owning process could not "
            "be identified exactly" + ("; microphone access is sealed" if sealed
                                       else "")))
    return findings


def listener_state(store, now=None):
    """(live, beat, why): whether the continuous sound listener is reporting.

    Live needs a fresh heartbeat whose listener says it is running and whose
    own last-sample clock is current; anything else is not live, with why.
    """
    now = time.time() if now is None else now
    try:
        beat = json.loads(store.get_meta(SOUND_META, "") or "null")
    except (ValueError, TypeError):
        beat = None
    if not isinstance(beat, dict) or not isinstance(beat.get("ts"), (int, float)):
        return False, None, ("no heartbeat from the continuous sound listener: the "
                             "running input hook predates it or is not running")
    age = now - beat["ts"]
    if age > _LISTENER_FRESH_S:
        return False, beat, f"the last sound-listener heartbeat is {int(age)} s old"
    state = str(beat.get("state") or "")
    if not state.startswith("running"):
        return False, beat, f"the sound listener reports '{state or 'no state'}'"
    if beat["ts"] - float(beat.get("last_sample") or 0) > _LISTENER_SAMPLE_LAG_S:
        return False, beat, "the sound listener's thread has stopped sampling"
    return True, beat, ""


# The Windows sound service plays Beep() tones and keeps the Beep device open
# for that; any other process that keeps it open could hide a caller.
_BEEP_RENDERER = "taskhostw"


def _likely(row):
    """The unelevated helper's inference, or "" when it made none."""
    if "likely_app" not in row.keys():
        return ""
    if row["likely_pid"]:
        return row["likely_app"] or f"process {row['likely_pid']}"
    if row["likely_n"] > 1 and row["likely_list"]:
        return f"one of {row['likely_n']} ({row['likely_list']})"
    return ""


def _actor(row, traced=()):
    if row["source"] == "device":
        return "sound with no app session"
    if row["sys"] and row["caller"] == "found":
        return f"{row['caller_app'] or 'process ' + str(row['caller_pid'])} (Beep() call)"
    if row["sys"] and traced:
        names = sorted({o["name"] or f"process {o['pid']}" for o in traced})
        return f"{', '.join(names)} (Beep() call, kernel trace)"
    if row["sys"] and _likely(row):
        return f"the system sounds session, likely {_likely(row)} (inferred, not traced)"
    if row["sys"]:
        return "the system sounds session"
    if row["console_pid"]:
        return f"{row['console_app'] or 'process ' + str(row['console_pid'])} (console bell)"
    if row["known"] and row["app"]:
        return row["app"]
    return f"process {row['pid']} (exited or not inspectable)"


def _inference(row):
    """How the foreground inference was reached, for the finding's detail."""
    if row["likely_pid"]:
        who = (f"{row['likely_app'] or 'process'} {row['likely_pid']}"
               + (f" started {row['likely_start']}" if row["likely_start"] else "")
               + ", the only candidate in the foreground window's process tree")
    else:
        who = (f"one of {row['likely_n']} candidates in the foreground window's "
               f"process tree ({row['likely_list']})")
    return (f"Likely source, inferred and not proven: {who}. Short Beep() tones end "
            "before the helper can look, so this is who was in front, not who called")


def _who(latest, rows, traced=()):
    """What is known about who made the sound, for the finding's detail."""
    if latest["source"] == "device":
        return ("No app session carried it: an exclusive-mode or protected "
                "stream, so no program is named")
    if latest["sys"] and latest["caller"] == "found":
        return (f"Process {latest['caller_pid']}"
                + (f" started {latest['caller_start']}" if latest["caller_start"] else "")
                + " had the Beep device open while the tone played: it called "
                "Beep() (or Console.Beep); the Windows sound service played it")
    if latest["sys"] and traced:
        return ("The kernel file trace recorded "
                + beeptrace.describe(traced)
                + " opening the Beep device for this tone: it called Beep() (or "
                "Console.Beep); the Windows sound service played it")
    if latest["sys"]:
        states = {}
        for r in rows:
            states[r["caller"] or "not looked up"] = states.get(r["caller"] or "not looked up", 0) + 1
        tally = ", ".join(f"{n} {s}" for s, n in sorted(states.items()))
        if latest["caller"] == "none":
            why = ("No process held the Beep device, so this was a Windows event "
                   "sound or PlaySound, not Beep(); that program is not identified")
        elif latest["caller"] == "none visible":
            why = (f"No process this helper can inspect held the Beep device; "
                   f"{latest['caller_blocked_new']} handle(s) opened since the last "
                   "look belong to elevated or protected processes it cannot "
                   "inspect, so an elevated Beep() caller is not ruled out")
        else:
            why = f"The Beep() caller was not looked up ({latest['caller'] or 'older hook'})"
        guess = f". {_inference(latest)}" if _likely(latest) else ""
        return f"{why} (caller lookups: {tally}){guess}"
    if latest["console_pid"]:
        return (f"The console host (process {latest['pid']}) played its bell for process "
                f"{latest['console_pid']}"
                + (f" started {latest['console_start']}" if latest["console_start"] else "")
                + ", the program whose console it is, which printed the bell character")
    return (f"Process {latest['pid']}" + (f" started {latest['proc_start']}"
                                     if latest["proc_start"] else ""))


def sound_findings(store, now=None, trace=None):
    """Beeps the continuous listener recorded in the last 24 h, by source.

    A system-sounds tone the listener could not attribute is attributed by the
    broker's kernel trace when an open of the Beep device matches it in time;
    failing both, the listener's foreground inference is shown as such."""
    now = time.time() if now is None else now
    try:
        rows = store.db.execute(
            "SELECT * FROM sound_events WHERE ts >= ? AND sound = 'beep' "
            "ORDER BY ts DESC, id DESC", (int(now - _SOUND_WINDOW_S),)).fetchall()
    except Exception:
        return []
    groups, traced = {}, {}
    for row in rows:
        opens = beeptrace.callers(row, trace) if row["caller"] != "found" else []
        traced[row["id"]] = opens
        groups.setdefault(_actor(row, opens), []).append(row)
    findings = []
    for actor in sorted(groups):
        rows = groups[actor]
        latest = rows[0]
        idle = sum(1 for r in rows if r["idle_s"] >= 300)
        findings.append(_finding(
            "low", f"beep-like sound from {actor}",
            f"{len(rows)} beep(s) in 24 h; most recent {iso(latest['ts'])} "
            f"(~{latest['dur_ms']} ms, peak {latest['peak']:.2f}, foreground "
            f"{latest['fg'] or 'unknown'}, input idle {latest['idle_s']} s); "
            f"{idle} while nobody had used the machine for 5 min. "
            f"{_who(latest, rows, traced[latest['id']])}. Amplitude only: tone and content "
            "are not observed"))
    return findings


def _beep_lookup_findings(beat):
    """Health of the Beep() caller lookup and who keeps the device open."""
    if not beat or "beep_state" not in beat:
        return []           # a hook from before the lookup existed
    findings = []
    state = beat.get("beep_state") or ""
    if state != "running":
        findings.append(_finding(
            "medium", "Beep() caller lookup not working",
            f"the listener's caller lookup reports '{state or 'no state'}'; "
            "beeps are still recorded, but who called Beep() is not", "visibility"))
    holders = [h for h in str(beat.get("beep_holders") or "").split() if ":" in h]
    others = [h for h in holders if h.rsplit(":", 1)[0].lower() != _BEEP_RENDERER]
    if others:
        findings.append(_finding(
            "low", "a process keeps the Beep device open",
            f"{', '.join(others)} held \\Device\\Beep in the quiet baseline or "
            "for 10 s or more. The Windows sound service (taskhostw) does this to "
            "play tones; another holder's own Beep() calls cannot be told apart "
            "from its idle handle, so they would not be attributed"))
    return findings


def listener_findings(store, now=None, trace=None):
    """Recorded beeps plus a visibility finding when the listener is down."""
    live, beat, why = listener_state(store, now)
    findings = sound_findings(store, now, trace)
    if not live:
        findings.append(_finding(
            "medium", "continuous sound listener not reporting",
            why + "; beeps are seen only inside the 8 s burst of each 5-minute "
            "pass. After a release that includes the listener, restart the "
            "hook from a desktop WSL terminal: jarvis inputwatch --stop && "
            "jarvis inputwatch --start", "visibility"))
    else:
        findings.extend(_beep_lookup_findings(beat))
    return findings, live, beat


def compare(current, previous, sealed=False, listener=None):
    findings = []
    if previous.get("schema") == 1:
        before, after = _routes(previous), _routes(current)
        for flow, role in sorted(_ROLES):
            old, new = before.get((flow, role)), after.get((flow, role))
            if old != new:
                findings.append(_finding(
                    "medium" if flow == "capture" else "low",
                    "default audio route changed",
                    f"{flow}/{role}: {old or 'none'} -> {new or 'none'}; "
                    "source is not attributed and this is a sampled change"))
        for endpoint, pid, started in sorted(_active(current) - _active(previous)):
            findings.append(_finding(
                "low", "audio render session became active",
                f"endpoint {endpoint}; process {pid} started {started}; "
                "an active session does not prove audible output"))
    active = sum(row.get("state") == 1 and row.get("flow") == "render"
                 for row in current.get("sessions", []))
    unknown = sum(row.get("state") == 1 and not row.get("identityKnown")
                  for row in current.get("sessions", []))
    burst = current["burst"]
    findings.extend(_capture_findings(current, sealed))
    findings.extend(_burst_findings(burst))
    share = 100.0 * burst["elapsedMs"] / (_INTERVAL_S * 1000)
    if listener:
        coverage = (
            "Beeps: the continuous listener is live (about every 25 ms on "
            f"{listener.get('endpoints', 0)} output device(s), "
            f"{listener.get('sessions', 0)} app session(s); "
            f"{listener.get('episodes', 0)} episode(s), "
            f"{listener.get('dropped', 0)} dropped by its rate limit since the "
            "hook started); the 8 s burst "
            f"({burst['samples']} samples) is a cross-check")
    else:
        coverage = (
            f"Beeps: only the burst sampler, {burst['samples']} peak samples on "
            f"{burst['endpointsSampled']} endpoint(s) over {burst['elapsedMs']} ms "
            f"(about {share:.1f}% of the interval); a beep outside that window is "
            "not seen")
    findings.append(_finding(
        "low", "audio route and session inventory",
        f"{len(current['endpoints'])} endpoints, {active} active render "
        f"session(s), {unknown} active session(s) without exact process "
        "identity; five-minute snapshot, no stream-content or loopback "
        f"capture detection. {coverage}. Sound that bypasses Windows audio "
        "(firmware and embedded-controller beeps) is never seen"))
    return findings


def _presence_findings(store, data, now=None):
    """For each beep in the last 24 h: was the person at the computer, nobody,
    or possibly someone else (beepcheck.py)? Never raises."""
    from jarvis.collectors.host import beepcheck
    now = time.time() if now is None else now
    try:
        beeps = store.db.execute(
            "SELECT ts, app, fg, idle_s, sys, caller FROM sound_events WHERE ts >= ? AND sound = 'beep' "
            "ORDER BY ts DESC LIMIT 200", (int(now - _SOUND_WINDOW_S),)).fetchall()
        present = beepcheck.presence(data.get("presence")) if isinstance(data, dict) else None
        cols = ("ts", "app", "fg", "idle_s", "sys", "caller")
        return beepcheck.findings(store, [dict(zip(cols, tuple(b))) for b in beeps], present, now,
                                  finding=lambda sev, title, detail, where, category="audio":
                                  _finding(sev, title, detail, category))
    except Exception as exc:  # noqa: BLE001 - a presence fault must not hide the audio findings
        return [_finding("low", "beep presence check unavailable this pass", type(exc).__name__, "visibility")]


def audit(store, hosts=("wsl", "win")):
    if "win" not in hosts:
        collection.failed("audio", "Windows collection disabled")
        return [_finding("medium", "Windows audio routes are not monitored",
                         "Windows collection is disabled", "visibility")]
    trace, trace_why = beeptrace.load()
    sounds, live, beat = listener_findings(store, trace=trace)
    sounds += beeptrace.health(trace, trace_why, _finding)
    data = ps_json(PS_AUDIO, timeout=45)
    if not _valid(data):
        collection.failed("audio", "metadata probe returned no valid snapshot")
        return [_finding("medium", "audio route visibility unavailable",
                         "Core Audio returned no complete, valid snapshot; "
                         "previous evidence is retained", "visibility")] + sounds
    burst = data["burst"]
    meter_errors = sorted(set(burst["errors"]))[:4]
    if burst["truncated"]:
        meter_errors.append("beep event budget exhausted")
    if not burst["endpointsSampled"] or burst["elapsedMs"] < burst["durationMs"] // 2:
        meter_errors.append("peak meter burst did not cover its window")
    if data.get("errors") or data.get("truncated"):
        reasons = sorted(set(data["errors"]))[:4]
        if data.get("truncated"):
            reasons.append("endpoint or session budget exhausted")
        collection.failed("audio", "; ".join(reasons))
        return [_finding("medium", "audio route visibility incomplete",
                         "; ".join(reasons) + "; previous evidence is retained",
                         "visibility")] + sounds
    try:
        previous = json.loads(store.get_meta(_STATE_KEY, "{}")) or {}
    except (ValueError, TypeError):
        previous = {}
    seal = privacyseal.load_seal(store)
    sealed = bool(seal and "microphone" in seal.get("caps", {}))
    findings = compare(data, previous, sealed=sealed,
                       listener=beat if live else None) + sounds
    findings += _presence_findings(store, data)
    store.set_meta(_STATE_KEY, json.dumps(dict(data, schema=1, ts=time.time())))
    if meter_errors:
        # Routes and sessions are valid and kept; only beep visibility is partial.
        collection.failed("audio", "; ".join(meter_errors))
        findings.append(_finding(
            "medium", "audio beep detection incomplete",
            "; ".join(meter_errors) + "; route evidence is current, beep "
            "visibility for this pass is partial", "visibility"))
        return findings
    collection.succeeded("audio")
    return findings
