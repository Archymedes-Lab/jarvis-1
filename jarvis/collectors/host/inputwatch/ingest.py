"""Draining the helper's output into the store."""

import json
import os

from jarvis.core.util import now

from .common import (
    _M_DUPES,
    _M_OVERSIZE,
    _M_SESSION,
    HOST_META,
    OWN_PIDS_KEEP_S,
    OWN_PIDS_META,
    READ_CAP,
    SOUND_META,
    STATES_KEEP,
    STATES_META,
)
from .helper import _paths

_BEAT_COLS = ("real_keys", "injected_keys", "real_clicks", "injected_clicks",
              "real_moves", "injected_moves", "injected_keyups",
              "injected_move_bursts", "real_key_gaps", "real_key_sub20",
              "real_key_sub8", "cad_run_max", "lat_avg_ms", "lat_max_ms",
              "lat_over50", "lat_samples")

_BEAT_SQL = ("INSERT OR REPLACE INTO input_beats (ts," + ",".join(_BEAT_COLS)
             + ") VALUES (" + ",".join("?" * (len(_BEAT_COLS) + 1)) + ")")

_WINDOW_COLS = ("real_keys", "injected_keys", "real_key_gaps",
                "real_key_sub20", "real_key_sub8", "cad_run_max",
                "equals_keys", "slash_keys", "period_keys", "digit_keys")

_WINDOW_SQL = ("INSERT OR REPLACE INTO input_typing_windows (ts,"
               + ",".join(_WINDOW_COLS) + ") VALUES ("
               + ",".join("?" * (len(_WINDOW_COLS) + 1)) + ")")


_SOUND_SQL = ("INSERT INTO sound_events(ts,ms,sound,source,dur_ms,pulses,peak,"
              "endpoint,pid,app,proc_start,known,sys,quiet_ms,idle_s,open,fg,"
              "caller,caller_pid,caller_app,caller_start,caller_blocked_new,"
              "console_pid,console_app,console_start,"
              "likely_pid,likely_app,likely_start,likely_list,likely_n) "
              "VALUES(" + ",".join("?" * 30) + ")")
_SOUND_COUNTERS = ("samples", "endpoints", "sessions", "episodes", "beeps",
                   "dropped", "errors", "enumerations", "last_sample",
                   "beep_lookups", "beep_callers", "beep_uninspectable",
                   "beep_skipped", "beep_lookup_ms")
_SOUND_TEXT = (("state", 80), ("beep_state", 80), ("beep_holders", 200))
# What the Beep() caller lookup concluded for a system-sounds episode.
_CALLER_STATES = ("", "found", "none", "none visible", "pending", "skipped",
                  "lookup failed")


def _int(value, low, high):
    """An integer inside [low, high], or None. Booleans are not numbers here."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = int(value)
    return value if low <= value <= high else None


def _sound_row(rec):
    """A sound_events row from one listener line, or None when malformed.

    The helper is ours but its output file is user-writable, so every field is
    type- and range-checked; a line that fails is dropped, never half-stored.
    """
    ts = _int(rec.get("ts"), 1, 2**33)
    ms = _int(rec.get("ms"), 1, 2**43)
    dur = _int(rec.get("dur_ms"), 1, 3_600_000)
    pulses = _int(rec.get("pulses"), 1, 1_000_000)
    pid = _int(rec.get("pid"), 0, 0xFFFFFFFF)
    quiet = _int(rec.get("quiet_ms"), -1, 2**43)
    idle = _int(rec.get("idle_s"), -1, 2**33)
    peak = rec.get("peak")
    flags = [_int(rec.get(k), 0, 1) for k in ("known", "sys", "open")]
    if (None in (ts, ms, dur, pulses, pid, quiet, idle) or None in flags
            or rec.get("sound") not in ("beep", "sound")
            or rec.get("source") not in ("session", "device")
            or isinstance(peak, bool) or not isinstance(peak, (int, float))
            or not 0.0 <= peak <= 1.0):
        return None
    if rec["sound"] == "beep" and (dur > 1500 + 25 or flags[2]):
        return None
    caller = rec.get("caller", "")
    caller_pid = _int(rec.get("caller_pid", 0), 0, 0xFFFFFFFF)
    blocked_new = _int(rec.get("caller_blocked_new", -1), -1, 10_000_000)
    console_pid = _int(rec.get("console_pid", 0), 0, 0xFFFFFFFF)
    likely_pid = _int(rec.get("likely_pid", 0), 0, 0xFFFFFFFF)
    likely_n = _int(rec.get("likely_n", 0), 0, 64)
    if (caller not in _CALLER_STATES or None in (caller_pid, blocked_new, console_pid,
                                                  likely_pid, likely_n)
            or (caller == "found") != (caller_pid > 0)):
        return None
    # An inference only where nothing was found, only for the system-sounds
    # session, and a single pid only when it was the one candidate.
    if (likely_pid or likely_n) and (caller == "found" or not flags[1]):
        return None
    if likely_pid and likely_n != 1:
        return None
    text = {k: _clean(str(rec.get(k) or ""))[:n] for k, n in
            (("endpoint", 160), ("app", 64), ("proc_start", 40), ("fg", 64),
             ("caller_app", 64), ("caller_start", 40), ("console_app", 64),
             ("console_start", 40), ("likely_app", 64), ("likely_start", 40),
             ("likely_list", 160))}
    return (ts, ms, rec["sound"], rec["source"], dur, pulses, float(peak),
            text["endpoint"], pid, text["app"], text["proc_start"],
            flags[0], flags[1], quiet, idle, flags[2], text["fg"],
            caller, caller_pid, text["caller_app"], text["caller_start"],
            blocked_new, console_pid, text["console_app"], text["console_start"],
            likely_pid, text["likely_app"], text["likely_start"], text["likely_list"], likely_n)


def _sound_beat(rec, ts):
    """The heartbeat's sound-listener counters as stored JSON, or None."""
    sound = rec.get("sound")
    if not isinstance(sound, dict):
        return None
    out = {"ts": ts}
    for key, limit in _SOUND_TEXT:
        out[key] = _clean(str(sound.get(key) or ""))[:limit]
    for key in _SOUND_COUNTERS:
        value = _int(sound.get(key), 0, 2**53)
        if value is not None:
            out[key] = value
    return json.dumps(out, sort_keys=True)


def _clean(value):
    """JSON text safe for SQLite.

    A VK_PACKET emoji arrives as two events, each carrying half of a surrogate
    pair. json.loads keeps the lone half, and SQLite's UTF-8 encoder rejects it,
    so a lone surrogate is spelled out as U+XXXX instead of failing the drain.
    """
    if isinstance(value, str):
        return "".join(f"U+{ord(c):04X}" if 0xD800 <= ord(c) <= 0xDFFF else c
                       for c in value)
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def ingest(store):
    """Fold new helper output into the database, then truncate the file.

    The read is capped: a helper writing without bound is a fault, and past the
    cap that fact is recorded rather than loaded into memory. Heartbeats from
    more than one PID in a drain flag a duplicate helper.
    """
    _win_out, wsl_out = _paths()
    if not os.path.exists(wsl_out):
        return 0
    try:
        size = os.path.getsize(wsl_out)
        with open(wsl_out, "r+", encoding="utf-8", errors="replace") as fh:
            body = fh.read(READ_CAP)
            fh.seek(0)
            fh.truncate()
    except OSError:
        return 0
    if size > READ_CAP:
        store.set_meta(_M_OVERSIZE, now())

    beats, windows, events, beat_pids = [], [], [], set()
    bursts = []
    sounds = []
    sound_beat = None
    session = None
    controls = []
    host = None
    states = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "heartbeat":
            c = rec.get("counters") or {}
            ts = int(rec.get("ts") or now())
            beats.append((ts,)
                         + tuple(int(c.get(k) or 0) for k in _BEAT_COLS))
            window = rec.get("window") or {}
            if window:
                windows.append((ts,) + tuple(
                    int(window.get(k) or 0) for k in _WINDOW_COLS))
            if rec.get("pid"):
                beat_pids.add(int(rec["pid"]))
            if "session" in rec:
                session = f"{int(rec['session'])}:{int(rec.get('desktop', -1))}"
            sound_beat = _sound_beat(rec, ts) or sound_beat
            if isinstance(rec.get("hook"), dict):
                host = dict(_clean(rec["hook"]), ts=ts)
        elif rec.get("kind") == "hook-state":
            # The resident host's watchdog: Windows dropped the hook, or it
            # stayed deaf after a reinstall. Not an input event.
            states.append([int(rec.get("ts") or now()), str(rec.get("state") or "")[:16],
                           int(rec.get("unseen_ms") or 0), str(rec.get("fg") or "")[:64],
                           int(rec.get("kb_quiet_ms") or -1), int(rec.get("mouse_quiet_ms") or -1)])
        elif rec.get("kind") == "sound":
            row = _sound_row(rec)
            if row:
                sounds.append(row)
        elif rec.get("kind") in ("control-key", "control-state"):
            # Control activations are kept in full, with their own timestamp:
            # they carry no text, and the whole point is being able to say
            # which control moved, when, and whether a key explains it.
            kind = str(rec.get("kind"))
            if kind == "control-state":
                # Brightness lines carry the panel id and how long the whole
                # machine had been idle; volume lines carry mute state.
                idle = rec.get("idle_s")
                detail = "%s%s -> %s%s%s" % (
                    ("%s:%s " % (str(rec.get("app") or "?")[:40], rec.get("pid"))
                     if rec.get("control") == "app-volume" else
                     ("%s " % str(rec.get("display") or "")[:24]
                      if rec.get("control") == "brightness" and rec.get("display")
                      else "")),
                    rec.get("from"), rec.get("to"),
                    "  muted" if rec.get("muted") else "",
                    ("  idle %ds" % int(idle)
                     if isinstance(idle, (int, float)) and idle >= 0 else ""))
                keyed = int(rec.get("keyed", -1))
                gap = int(rec.get("key_gap_ms", -1))
            else:
                detail = str(rec.get("class") or "")[:40]
                keyed, gap = -1, -1
            controls.append((
                int(rec.get("ts") or now()), kind[:16],
                str(rec.get("control") or rec.get("class") or "")[:32],
                detail[:120], int(rec.get("injected") or 0),
                int(rec.get("lower_il") or 0), keyed, gap,
                str(rec.get("fg") or "")[:64]))
        elif rec.get("kind") == "inject-burst":
            rec = _clean(rec)
            bursts.append((str(rec.get("burst") or "")[:40],
                           int(rec.get("ts") or now()),
                           json.dumps(rec, ensure_ascii=False)[:200_000]))
        else:
            # Injected keys carry a full forensic record (vk, scan, character,
            # flags, extra info, ms time); older helper output and the real
            # punctuation/digit timestamps do not, and keep an empty one.
            forensic = "ms" in rec
            rec = _clean(rec)
            events.append(
                (int(rec.get("ts") or now()), str(rec.get("kind") or "key")[:16],
                 int(rec.get("lower_il") or 0), str(rec.get("class") or "")[:24],
                 str(rec.get("fg") or "")[:64], int(rec.get("ms") or 0),
                 str(rec.get("burst") or "")[:40],
                 json.dumps(rec, ensure_ascii=False)[:4000] if forensic else ""))
    if controls:
        store.db.executemany(
            "INSERT INTO control_events(ts,kind,control,detail,injected,"
            "lower_il,keyed,key_gap_ms,fg) VALUES(?,?,?,?,?,?,?,?,?)", controls)
    if beats:
        store.db.executemany(_BEAT_SQL, beats)
    if windows:
        store.db.executemany(_WINDOW_SQL, windows)
    if events:
        store.db.executemany(
            "INSERT INTO input_events(ts,kind,lower_il,class,fg,ms,burst,record) "
            "VALUES(?,?,?,?,?,?,?,?)", events)
    if bursts:
        store.db.executemany(
            "INSERT OR REPLACE INTO input_bursts(burst,ts,record) VALUES(?,?,?)",
            bursts)
    if sounds:
        store.db.executemany(_SOUND_SQL, sounds)
    if sound_beat is not None:
        store.set_meta(SOUND_META, sound_beat)
    if session is not None:
        store.set_meta(_M_SESSION, session)
    if host is not None:
        store.set_meta(HOST_META, json.dumps(host))
    if beat_pids:
        # Every pid that wrote a heartbeat into OUR output file is our helper.
        # The watcher audit used only the current pid, so after each restart
        # the previous JARVIS hook was reported as an unknown keylogger.
        try:
            own = {int(k): int(v) for k, v in json.loads(store.get_meta(OWN_PIDS_META, "{}") or "{}").items()}
        except (ValueError, TypeError, AttributeError):
            own = {}
        stamp = now()
        own.update({p: stamp for p in beat_pids})
        own = {p: t for p, t in own.items() if stamp - t < OWN_PIDS_KEEP_S}
        store.set_meta(OWN_PIDS_META, json.dumps({str(p): t for p, t in own.items()}))
    if states:
        try:
            kept = json.loads(store.get_meta(STATES_META, "[]") or "[]")
        except ValueError:
            kept = []
        store.set_meta(STATES_META, json.dumps((kept + states)[-STATES_KEEP:]))
    # Heartbeats from more than one PID in a single drain means two helpers are
    # writing to the same file and double-counting. Cheap and local — no
    # interop — so the healthy path can check it too.
    if len(beat_pids) > 1:
        store.set_meta(_M_DUPES,
                       f"{now()}:{','.join(str(p) for p in sorted(beat_pids))}")
    if beats or windows or events or bursts or sounds:
        # Minute windows give a useful 90-day baseline at only ~130k rows.
        # Raw cumulative beats and injected-event detail need much less history;
        # bounding all three keeps the SQLite file small indefinitely.
        stamp = now()
        store.db.execute("DELETE FROM input_typing_windows WHERE ts < ?",
                         (stamp - 90 * 86400,))
        store.db.execute("DELETE FROM input_beats WHERE ts < ?",
                         (stamp - 7 * 86400,))
        store.db.execute("DELETE FROM input_events WHERE ts < ?",
                         (stamp - 30 * 86400,))
        store.db.execute("DELETE FROM input_bursts WHERE ts < ?",
                         (stamp - 30 * 86400,))
        store.db.execute("DELETE FROM sound_events WHERE ts < ?",
                         (stamp - 30 * 86400,))
        store.commit()
    return len(events)
