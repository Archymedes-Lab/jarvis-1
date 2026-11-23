"""Who was at the controls when a beep played?

The owner asked (2026-11-02), after two unexplained beeps, for a way to tell a
beep from the person at this computer from one made by something outside or
by someone posing as them. The sound listener already says which program made
a sound when Windows lets it see one. This adds the other half: for each beep,
the evidence about presence at that moment, from three independent sources:

  * input: the low-level hook's counters. Every key, click and mouse move is
    marked physical or injected by Windows itself (LLKHF_INJECTED /
    LLMHF_INJECTED), so injected input near a beep means software was driving
    the machine;
  * sessions: any Windows session other than the local console (Remote
    Desktop, a second signed-in user) is another possible person;
  * remote control: a running remote-control or screen-sharing program means
    someone elsewhere may be seeing and driving the screen.

Verdicts (pure, tested in tests/test_beepcheck.py):

  local       physical input in the window and none of the above: the person
              at the keyboard (or a program they were using) made it
  remote      injected input, another session or a remote-control program:
              high, a security threat, with the evidence
  unattended  nobody touched the machine for 5 minutes and none of the above:
              medium, something played a sound on its own
  unknown     no input record covers the moment: said so, never "local"

It never captures audio, screen or keystroke content; counts only.
"""

from __future__ import annotations

import time

WINDOW_S = 30            # input that counts as "at the moment of the beep"
IDLE_S = 300             # matches the sound listener's "nobody used it" threshold
PRESENCE_FRESH_S = 360   # the audio job's 5-minute cadence plus slack
# Remote-control and screen-sharing programs, by process name (lowercase,
# without .exe). A reviewable list: a missing entry is "not recognised", never
# "absent".
REMOTE_TOOLS = (
    "teamviewer", "teamviewer_service", "anydesk", "rustdesk", "quickassist", "msra",
    "screenconnect.clientservice", "screenconnect.windowsclient", "connectwisecontrol.client",
    "remoting_host", "remoting_desktop", "parsecd", "splashtop", "srservice", "strwinclt",
    "logmein", "lmiguardiansvc", "vncserver", "winvnc", "tvnserver", "uvnc_service",
    "ammyy_admin", "supremo", "rport", "meshagent", "atera_agent", "zohoassist", "rdpclip",
)

# The probe runs inside jarvis/platform/win/audio_state.ps1 (its `presence` block).


def input_around(store, ts, window=WINDOW_S):
    """{real, injected} input counts in [ts - window, ts + 5], or None when no
    hook beat covers that moment. Beats carry cumulative counters per hook run,
    so a delta is taken between the beats that bracket the window."""
    cols = ("real_keys", "injected_keys", "real_clicks", "injected_clicks", "real_moves",
            "injected_moves", "injected_keyups", "injected_move_bursts")
    try:
        rows = store.db.execute(
            f"SELECT ts, {', '.join(cols)} FROM input_beats WHERE ts BETWEEN ? AND ? ORDER BY ts",
            (int(ts - window - 120), int(ts + 120))).fetchall()
    except Exception:
        return None
    rows = [tuple(r) for r in rows]
    before = [r for r in rows if r[0] <= ts - window]
    after = [r for r in rows if r[0] >= ts]
    if not before or not after:
        return None
    a, b = before[-1], after[0]
    delta = [max(0, (y or 0) - (x or 0)) for x, y in zip(a[1:], b[1:])]
    if any((y or 0) < (x or 0) for x, y in zip(a[1:], b[1:])):
        return None                       # the hook restarted in between: counters reset
    d = dict(zip(cols, delta))
    return {"real": d["real_keys"] + d["real_clicks"] + d["real_moves"],
            "injected": (d["injected_keys"] + d["injected_clicks"] + d["injected_moves"]
                         + d["injected_keyups"] + d["injected_move_bursts"]),
            "span_s": int(b[0] - a[0])}


def presence(data):
    """Other sessions and remote-control programs from the audio probe's `presence`."""
    if not isinstance(data, dict):
        return None
    others = []
    for s in data.get("sessions") or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name") or "").lower()
        state = str(s.get("state") or "").lower()
        user = str(s.get("user") or "")
        if name in ("services", "console") or not user or user.isdigit():
            continue
        if state in ("active", "conn", "connected"):
            others.append(f"{s.get('name')} ({user}, {s.get('state')})")
    procs = {str(p).lower() for p in data.get("procs") or []}
    tools = sorted(t for t in REMOTE_TOOLS if t in procs and t != "rdpclip")
    if "rdpclip" in procs and others:
        tools.append("rdpclip")          # the Remote Desktop clipboard helper, only with a session
    return {"sessions": others, "tools": tools, "error": str(data.get("error") or "")}


def verdict(beep, inputs, present):
    """(verdict, reasons) for one beep row. Pure."""
    reasons = []
    if present and present["sessions"]:
        reasons.append("another Windows session was active at the check right after it: "
                       + ", ".join(present["sessions"][:3]))
    if present and present["tools"]:
        reasons.append("remote-control software was running at the check right after it: "
                       + ", ".join(present["tools"][:4]))
    if inputs and inputs["injected"]:
        reasons.append(f"{inputs['injected']} injected input event(s) in the {WINDOW_S} s before it "
                       "(software, not a person, was typing or moving the mouse)")
    if reasons:
        return "remote", reasons
    if inputs is None:
        return "unknown", ["no input record covers that moment, so presence is not established"]
    if int(beep.get("idle_s") or 0) >= IDLE_S and not inputs["real"]:
        return "unattended", [f"nobody had touched the computer for {int(beep['idle_s']) // 60} min"]
    if inputs["real"]:
        return "local", [f"{inputs['real']} physical key, click or mouse event(s) in the "
                         f"{WINDOW_S} s before it, none injected"]
    return "unknown", ["no physical or injected input in the window"]


def findings(store, beeps, present, now=None, finding=None):
    """One finding per beep that is not explained as local, plus one summary."""
    now = time.time() if now is None else now
    out, counts = [], {"local": 0, "remote": 0, "unattended": 0, "unknown": 0}
    for b in beeps:
        row = dict(b)
        # Sessions and programs are read at each check, so they describe only
        # beeps since the previous one; older beeps are judged on input alone.
        recent = now - float(row["ts"]) <= PRESENCE_FRESH_S
        v, why = verdict(row, input_around(store, row["ts"]), present if recent else None)
        counts[v] += 1
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"]))
        if v == "remote":
            out.append(finding("high", f"beep while someone else may have been at the controls ({when})",
                               "; ".join(why) + f". The sound came from {row.get('app') or 'an unnamed source'}"
                               f" with {row.get('fg') or 'an unknown window'} in front. Check who is connected "
                               "(Settings > System > Remote Desktop, and any remote-support program) and "
                               "change your password from a device you trust if you did not expect this.",
                               "beep-presence", category="presence"))
        elif v == "unattended":
            out.append(finding("medium", f"beep with nobody at the computer ({when})",
                               "; ".join(why) + f"; it came from {row.get('app') or 'an unnamed source'}. "
                               "Something played a sound on its own: a reminder, an update, or a program "
                               "running unseen.", "beep-presence"))
    total = sum(counts.values())
    if total:
        out.append(finding("low", f"who was present for {total} beep(s) in 24 h",
                           f"{counts['local']} with only physical input from the person at the computer, "
                           f"{counts['remote']} with signs of someone else (injected input, another session "
                           f"or remote-control software), {counts['unattended']} with nobody present, "
                           f"{counts['unknown']} not established. Input is counted, never recorded.",
                           "beep-presence"))
    return out
