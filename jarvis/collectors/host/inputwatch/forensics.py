"""Reconstructing an injected-input event the way an examiner would.

A finding that says "1 injected character" is an alarm, not an answer. This
module turns the hook's forensic records back into the questions someone
investigating it actually asks, in the order they ask them:

  what exactly was sent      the key, the character it produced, modifiers
  into what                  process, image path, integrity, window, control
  how it was sent            flags, VK_PACKET vs a real virtual key, extra info
  was a person there         time since the last real key, click and move
  who could have sent it     lower-integrity and just-started processes
  what else happened         control changes and typing around the same time
  what it most likely means  known senders that match the evidence

Windows never records which process called SendInput. Every attribution here
is therefore phrased as a suspect list with reasons, never as a verdict.
"""

import json
import time
import unicodedata

from jarvis.core.util import iso

# dwExtraInfo markers that identify the software that sent an event.
_EXTRA_SIGNATURES = (
    (lambda v: 0xFFC3D3E9 <= v <= 0xFFC3D44F,
     "AutoHotkey — the value is in the range it stamps on its own input"),
    (lambda v: (v & 0xFFFFFF00) == 0xFF515700,
     "Windows pen/touch — the MI_WP_SIGNATURE Windows puts on input it "
     "promotes from a pen or touch screen"),
)

# Senders that commonly inject and what they are. Matched against the
# lower-case process name of a suspect.
_KNOWN_SENDERS = {
    "textinputhost": "Windows text input host: the touch keyboard, emoji panel "
                     "(Win+.), clipboard history (Win+V) and voice typing "
                     "(Win+H) all type through it, from an AppContainer — "
                     "which is exactly what sets the lower-integrity flag",
    "tabtip": "the Windows touch keyboard",
    "osk": "the Windows on-screen keyboard",
    "ctfmon": "the Windows text services / IME host",
    "screenclippinghost": "the Windows snipping overlay",
    "searchhost": "Windows Search",
    "startmenuexperiencehost": "the Start menu",
    "shellexperiencehost": "the Windows shell (notifications, quick settings)",
    "powertoys": "PowerToys (Keyboard Manager remaps keys by re-injecting them)",
    "autohotkey": "AutoHotkey",
    "rdpclip": "the Remote Desktop clipboard agent",
}

# Sandboxed browser content processes run at low or untrusted integrity and
# usually outnumber everything else on the list. They are normally locked out
# of the input APIs, so they are collapsed rather than listed one by one.
_SANDBOXED = {"firefox", "chrome", "msedge", "brave", "opera", "vivaldi",
              "msedgewebview2", "acrord32", "acrobat"}


def _clock(ms):
    if not ms:
        return "?"
    return (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))
            + f".{int(ms) % 1000:03d}")


def _gap(ms):
    if ms is None or ms < 0:
        return "not seen since the hook started"
    if ms < 1000:
        return f"{ms} ms before"
    if ms < 120_000:
        return f"{ms / 1000:.1f} s before"
    return f"{ms / 60000:.0f} min before"


def character(rec):
    """The exact identity of one injected key-down, in words."""
    if rec.get("redacted"):
        return ("a printable character (redacted: part of a long auto-typed "
                "burst, the shape of a password manager)")
    chr_ = rec.get("chr") or ""
    vk, name = rec.get("vk", -1), rec.get("vk_name") or ""
    mods = [m for m in (rec.get("mods") or "").split("+") if m and m != "capslock"]
    parts = []
    if chr_.startswith("dead:"):
        parts.append(f"dead key {chr_[5:]!r} (accent waiting for the next key)")
    elif chr_ and (ord(chr_[0]) >= 0x20 and chr_[0] != "\x7f"
                   or chr_.startswith("U+")):
        label = chr_ if chr_.startswith("U+") else repr(chr_)
        try:
            uname = " ".join(unicodedata.name(c) for c in chr_)
            label += f" U+{ord(chr_[0]):04X} {uname}"
        except (ValueError, TypeError):
            pass
        parts.append(label)
    elif mods and name.startswith("VK_") and len(name) == 4:
        combo = "+".join(mods + [name[3:]])
        parts.append(combo + {"ctrl+V": " (paste)", "ctrl+C": " (copy)",
                              "ctrl+X": " (cut)", "ctrl+Z": " (undo)",
                              "ctrl+A": " (select all)"}.get(combo, ""))
    else:
        # Keys with no character: a plain name where one helps, otherwise the
        # virtual-key identity below says it on its own.
        friendly = {"VK_RETURN": "Enter", "VK_TAB": "Tab", "VK_BACK": "Backspace",
                    "VK_ESCAPE": "Escape", "VK_SPACE": "Space"}.get(name)
        if friendly or not name:
            parts.append(friendly or "an unidentified key")
    if name == "VK_PACKET":
        parts.append("sent as VK_PACKET — SendInput with KEYEVENTF_UNICODE, "
                     "no physical key involved")
    elif vk is not None and vk >= 0:
        parts.append(f"{name} (0x{vk:02X})"
                     + (f", scan 0x{rec['scan']:02X}" if rec.get("scan", -1) > 0 else "")
                     + (f", key label {rec['key_name']!r}" if rec.get("key_name") else ""))
    if mods:
        parts.append("held: " + "+".join(mods))
    return " · ".join(parts)


def _event_line(rec):
    kind = "down" if rec.get("kind") == "key" else "up  "
    flags = rec.get("flags") or "?"
    marks = ["injected"] + (["lower-IL"] if rec.get("lower_il") else [])
    what = character(rec) if rec.get("kind") == "key" else (
        rec.get("vk_name") or "(redacted)")
    return (f"{_clock(rec.get('ms'))} {kind} {what} · flags {flags} "
            f"[{', '.join(marks)}] · extraInfo {rec.get('extra', '?')}")


def _suspects(candidates):
    lines, sandboxed = [], {}
    for c in candidates or []:
        name = (c.get("name") or "?")
        low = name.lower()
        if low in _SANDBOXED and "started-recently" not in (c.get("why") or ""):
            sandboxed[name] = sandboxed.get(name, 0) + 1
            continue
        age = c.get("started_ms_before", -1)
        started = (f"started {_gap(age)}" if 0 <= age <= 3_600_000 else "long-running")
        known = next((v for k, v in _KNOWN_SENDERS.items() if k in low), "")
        lines.append(
            f"{name} pid {c.get('pid')} · {c.get('il')} integrity"
            + (" · AppContainer" if c.get("appcontainer") else "")
            + f" · {started} · {c.get('path') or 'path unreadable'}"
            + (f" — {known}" if known else ""))
    for name, n in sorted(sandboxed.items()):
        lines.append(f"{name} ×{n} sandboxed low-integrity processes — normally "
                     f"locked out of the input APIs; unlikely but not excluded")
    return lines


def _surroundings(store, ts):
    out = []
    try:
        rows = store.db.execute(
            "SELECT * FROM control_events WHERE ts BETWEEN ? AND ? ORDER BY ts",
            (ts - 120, ts + 120)).fetchall()
    except Exception:
        rows = []
    for r in rows:
        what = (f"{r['control']} {r['detail']}" if r["kind"] == "control-state"
                else f"{r['control']} key" + (" (injected)" if r["injected"] else ""))
        keyed = (" with no key behind it" if r["kind"] == "control-state"
                 and r["keyed"] == 0 else "")
        out.append(f"{iso(r['ts'])} ({r['ts'] - ts:+d} s) {what}{keyed} · "
                   f"focus {r['fg'] or 'unknown'}")
    try:
        win = store.db.execute(
            "SELECT * FROM input_typing_windows WHERE ts >= ? AND ts < ? "
            "ORDER BY ts LIMIT 1", (ts, ts + 180)).fetchone()
    except Exception:
        win = None
    if win is not None:
        out.append(f"typing in the minute to {iso(win['ts'])}: "
                   f"{win['real_keys']} real key-down(s), "
                   f"{win['injected_keys']} injected")
    return out


def _interpret(events, burst, fg):
    notes = []
    fg_proc = (burst or {}).get("fg_process") or {}
    path = (fg_proc.get("path") or "").lower()
    if fg.lower().startswith("msrdc"):
        notes.append(
            "msrdc.exe had focus. "
            + ("Its path is under WSL, so this is the WSLg window host: the key "
               "went to a Linux GUI app, not to Windows itself"
               if "\\wsl\\" in path else
               "It is both the Remote Desktop client and, from C:\\Program "
               "Files\\WSL, the WSLg host for Linux GUI apps"))
    downs = [e for e in events if e.get("kind") == "key"]
    if any(e.get("vk_name") == "VK_PACKET" for e in downs):
        notes.append("VK_PACKET means the sender passed a Unicode character, not "
                     "a key: how the emoji panel, touch keyboard, voice typing, "
                     "IMEs, password managers and scripted automation type")
    if any(e.get("lower_il") for e in events):
        notes.append("The lower-integrity flag narrows the sender to a process "
                     "below medium integrity: an AppContainer app (Windows' own "
                     "input panels run this way) or a low-integrity sandbox. "
                     "UIPI would stop it from typing into an elevated window")
    elif events:
        notes.append("No lower-integrity flag: the sender ran at the same or a "
                     "higher integrity level than a normal app")
    extras = set((burst or {}).get("extra_values") or
                 [e.get("extra") for e in events if e.get("extra")])
    for x in sorted(extras):
        try:
            v = int(str(x), 16)
        except ValueError:
            continue
        sig = next((label for test, label in _EXTRA_SIGNATURES if test(v)), "")
        if sig:
            notes.append(f"dwExtraInfo {x}: {sig}")
        elif v:
            notes.append(f"dwExtraInfo {x} is a non-zero sender tag with no "
                         f"known owner — search your automation tools for it")
    ups = [e for e in events if e.get("kind") == "key-up"]
    if downs and not ups and events and all("ms" in e for e in events):
        notes.append("Key-down with no key-up: a half keystroke. Real typing and "
                     "most tools send both; a truncated sequence is worth noting")
    if not burst:
        return notes
    since = burst.get("ms_since_real_key", -1)
    if since is not None and 0 <= since < 1500:
        notes.append("Real typing was happening within 1.5 s — consistent with a "
                     "remapper, IME or text panel acting on your own keystrokes")
    elif since is not None and (since < 0 or since > 60_000):
        notes.append("No real keystroke in the preceding minute — nobody was "
                     "typing when it arrived")
    return notes


def explain(store, event_rows):
    """-> (headline, evidence lines) for one group of injected key events.

    `event_rows` are input_events rows for the group, newest first. Rows from
    before forensic capture have no record; that is said plainly rather than
    guessed at."""
    records = []
    for r in event_rows:
        try:
            rec = json.loads(r["record"]) if r["record"] else None
        except (ValueError, KeyError, IndexError, TypeError):
            rec = None
        records.append((r, rec))

    legacy = [r for r, rec in records if rec is None]
    detailed = [rec for _r, rec in records if rec is not None]
    evidence = []
    headline = ""

    downs = [rec for rec in detailed if rec.get("kind") == "key"]
    if downs:
        seen = []
        for rec in downs:
            c = character(rec).split(" · ")[0]
            if c not in seen:
                seen.append(c)
        headline = "; ".join(seen[:4]) + (" …" if len(seen) > 4 else "")

    if legacy:
        evidence.append(
            f"{len(legacy)} event(s) at {', '.join(iso(r['ts']) for r in legacy[:5])}"
            f"{' …' if len(legacy) > 5 else ''} were recorded before forensic "
            f"capture: the helper then kept only the coarse class "
            f"'{legacy[0]['class']}', so the exact key cannot be recovered. "
            f"Every injected key since carries its full identity")

    bursts = []
    for rec in detailed:
        b = rec.get("burst")
        if b and b not in bursts:
            bursts.append(b)
    for b in bursts[:5]:
        try:
            row = store.db.execute("SELECT record FROM input_bursts WHERE burst=?",
                                   (b,)).fetchone()
            summary = json.loads(row["record"]) if row else {}
        except (ValueError, TypeError):
            summary = {}
        try:
            members = [json.loads(r["record"]) for r in store.db.execute(
                "SELECT record FROM input_events WHERE burst=? AND record!='' "
                "ORDER BY ms, id LIMIT 40", (b,)).fetchall()]
        except (ValueError, TypeError):
            members = [rec for rec in detailed if rec.get("burst") == b]
        evidence += _burst_evidence(store, b, summary, members)

    if not detailed and legacy:
        ts = legacy[0]["ts"]
        around = _surroundings(store, ts)
        if around:
            evidence.append("Around the newest event:")
            evidence += ["  " + line for line in around]
        notes = _interpret([{"lower_il": legacy[0]["lower_il"]}], None,
                           legacy[0]["fg"] or "")
        if notes:
            evidence.append("Reading:")
            evidence += ["  " + n for n in notes]
    return headline, evidence


def _burst_evidence(store, burst_id, s, members):
    out = []
    start = s.get("ms_start") or (members[0].get("ms") if members else 0)
    end = s.get("ms_end") or (members[-1].get("ms") if members else 0)
    count = s.get("events", len(members))
    spelled = ""
    if s.get("redacted"):
        comp = s.get("composition") or {}
        spelled = (f"; {s.get('printable')} printable characters redacted "
                   f"(upper {comp.get('upper', 0)}, lower {comp.get('lower', 0)}, "
                   f"digit {comp.get('digit', 0)}, symbol {comp.get('symbol', 0)}, "
                   f"space {comp.get('space', 0)})")
    elif s.get("text"):
        spelled = f"; spelled {s['text']!r}"
    out.append(f"Burst {burst_id} at {_clock(start)}: {count} event(s), "
               f"{s.get('downs', '?')} down / {s.get('ups', '?')} up, "
               f"over {max(0, (end or 0) - (start or 0))} ms{spelled}")

    out.append("  Timeline:")
    out += ["    " + _event_line(m) for m in members[:20]]
    if len(members) > 20 or count > len(members):
        out.append(f"    … {max(count, len(members)) - 20} more in input_events "
                   f"(burst {burst_id})")

    fg = s.get("fg") or (members[0].get("fg") if members else "")
    proc = s.get("fg_process") or {}
    target = (f"  Target: {fg or 'unknown'}"
              + (f" · {proc.get('il')} integrity" if proc.get("il") else "")
              + (f" · {proc['path']}" if proc.get("path") else ""))
    if s.get("fg_title") or s.get("fg_class"):
        target += f" · window {s.get('fg_title', '')!r} class {s.get('fg_class', '')}"
    if s.get("focus_class"):
        target += f" · focused control class {s['focus_class']}"
    out.append(target)

    if s:
        out.append(f"  Real input before it: key {_gap(s.get('ms_since_real_key'))}, "
                   f"click {_gap(s.get('ms_since_real_click'))}, "
                   f"mouse move {_gap(s.get('ms_since_real_move'))}")
    if s.get("unmatched"):
        out.append("  Unpaired: " + ", ".join(s["unmatched"]))
    if s.get("dropped_total"):
        out.append(f"  The helper has dropped {s['dropped_total']} injected event(s) "
                   f"under load since it started")

    suspects = _suspects(s.get("candidates"))
    out.append("  Possible senders (Windows does not record the sender; these are "
               "the processes that fit):" if suspects else
               "  Possible senders: no lower-integrity or just-started process "
               "in the desktop session" if s else
               "  Possible senders: not captured")
    out += ["    " + line for line in suspects[:15]]

    around = _surroundings(store, int((start or 0) / 1000))
    if around:
        out.append("  Around it:")
        out += ["    " + line for line in around]

    notes = _interpret(members, s, fg or "")
    if notes:
        out.append("  Reading:")
        out += ["    " + n for n in notes]
    return out
