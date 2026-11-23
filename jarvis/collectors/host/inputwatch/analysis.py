"""Turning input telemetry into findings about synthetic input."""

import json
import re
import statistics
from collections import Counter

from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import iso, now
from jarvis.platform.windows import ps_json

from . import watchers
from .common import OWN_PIDS_META
from .forensics import explain
from .helper import running
from .ingest import ingest

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

BENIGN_INJECTORS = {
    "1password", "bitwarden", "keepass", "keepassxc", "lastpass", "dashlane",
    "autohotkey", "ahk", "osk", "tabtip", "magnify", "narrator",
    "mstsc", "rdpclip", "teamviewer", "anydesk", "rustdesk", "vncviewer",
    "synergy", "barrier", "deskflow", "sharemouse", "logioptionsplus",
    "logitech", "razer", "steam", "vmware", "virtualbox",
    "parsec", "moonlight", "sunshine", "obs64", "obs32",
}

# The hook emits media controls into both input_events and control_events.
# Add a VK here only after checking the hook's ControlClass mapping and a
# regression case; a VK name or foreground alone is never enough to dedupe.
CONTROL_VK = {0xB3: "media-play-pause"}


def _recent_own_pids(store):
    """Pids that wrote JARVIS heartbeats in the last 24 h (see ingest)."""
    try:
        own = json.loads(store.get_meta(OWN_PIDS_META, "{}") or "{}")
        return tuple(int(p) for p in own)
    except (ValueError, TypeError, AttributeError):
        return ()


def audit(store, hours=24, pids=None, supervised=False):
    out = []
    ingest(store)
    since = now() - hours * 3600
    # Control activations are recorded whether or not the hook is supervised:
    # they are their own record, not part of the liveness narrative.
    out.extend(_control_findings(store, hours))
    out.extend(_punct_findings(store, hours))
    out.extend(_digit_findings(store, hours))

    beat = store.db.execute(
        "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()

    # Which processes hook the keyboard and mouse, from the elevated broker's
    # Win32k audit trace. JARVIS's own hook is known by its supervised pids.
    if pids is None and not supervised:
        pids = running()
    out.extend(watchers.audit(own_pids=tuple(pids or ()) + _recent_own_pids(store)))

    # When the supervisor has already run it owns the liveness and latency
    # narrative; audit adds only what it alone produces — the injected-event
    # breakdown below.
    if not supervised:
        if pids is None:
            pids = running()
        if not pids:
            out.append(_finding(
                "input", "medium", "the injected-input monitor is not running",
                "synthetic keystrokes are only visible from inside a live hook, "
                "so nothing is being recorded — this is not a clean result",
                "jarvis inputwatch --start"))
        elif beat and now() - beat["ts"] > 300:
            out.append(_finding(
                "input", "high", "the input hook has stopped reporting",
                f"the helper is alive but its last heartbeat was "
                f"{iso(beat['ts'])} — a hook that was removed looks exactly "
                f"like a quiet keyboard", "inputwatch"))
        else:
            totals = (f"{beat['real_keys']} real keystrokes / "
                      f"{beat['injected_keys']} injected "
                      f"(+{beat['injected_keyups']} injected key-ups), "
                      f"{beat['real_moves']} real cursor moves / "
                      f"{beat['injected_moves']} injected in "
                      f"{beat['injected_move_bursts']} bursts"
                      if beat else "no counts yet")
            out.append(_finding(
                "input", "ok", "the injected-input monitor is running",
                f"pid {pids[0]} — {totals}", "inputwatch"))
        out += _latency_findings(store, beat)
        out += _typing_findings(store, beat)

    out.extend(injected_findings(store, since))
    return sort_findings(out)


def injected_findings(store, since):
    """Findings for input that no hardware produced, from the stored hook events.

    Reads the store only, so it can be judged on its own (the coverage map's
    probe gives it a store of its own with one synthetic event)."""
    out = []
    # Only injected kinds. input_events also holds the timestamps of real
    # punctuation and digit presses (punct-key, digit-key) and injected key-ups;
    # grouping those in reported your own typing as "injected" input.
    rows = store.db.execute(
        """SELECT fg, kind, class, lower_il, COUNT(*) n,
                  MIN(ts) first, MAX(ts) last
             FROM input_events WHERE ts>=? AND kind IN ('key','click','move')
            GROUP BY fg, kind, class, lower_il
            ORDER BY COUNT(*) DESC""", (since,)).fetchall()
    for r in rows:
        fg = (r["fg"] or "").lower()
        benign = any(b in fg for b in BENIGN_INJECTORS)
        if r["kind"] == "click" and benign:
            continue
        sev = ("low" if benign else
               "critical" if r["lower_il"] else
               "high" if r["kind"] == "key" else "medium")
        why = ("this program injects input as part of its normal job"
               if benign else
               "injected from a lower integrity level — the shape of one "
               "process driving another's window" if r["lower_il"] else
               "no hardware produced this event")
        headline, evidence = "", []
        paired_control = False
        if r["kind"] == "key":
            members = store.db.execute(
                "SELECT * FROM input_events WHERE ts>=? AND kind='key' AND "
                "fg IS ? AND class IS ? AND lower_il=? ORDER BY ts DESC, id DESC "
                "LIMIT 50", (since, r["fg"], r["class"], r["lower_il"])).fetchall()
            headline, evidence = explain(store, members)
            if (not benign and not r["lower_il"] and r["n"] <= len(members)
                    and _keyless(members)):
                sev = "low"
                why = ("key events with no key in them (virtual key 0xFF, scan "
                       "code 0, no character or modifier), which cannot type or "
                       "trigger anything")
            paired_control = (not r["lower_il"] and r["n"] <= len(members)
                              and _represented_control_keys(store, members))
            if paired_control:
                sev = "low"
                why = ("the same non-printable media control activations are "
                       "recorded and assessed in control_events")
        finding = _finding(
            "input", sev,
            (f"{r['n']} injected media control activation(s) also recorded"
             if r["kind"] == "key" and paired_control else
             f"{r['n']} injected {r['class'] or r['kind']}"
             f"{'s' if r['n'] > 1 else ''}"
             f"{' ' + headline if headline else ''}") + " while "
            f"{r['fg'] or 'an unknown window'} had focus",
            f"{why} — first {iso(r['first'])}, last {iso(r['last'])}",
            "input_events")
        if evidence:
            finding["forensics"] = evidence
        out.append(finding)
    return out


def _represented_control_keys(store, members):
    """True only when every key-down is the same event in the control stream.

    Both streams originate in the hook, but neither table is silently removed.
    Matching the event's exact second, control class, foreground, integrity and
    count avoids classifying a stray control near a real typed key as a pair.
    """
    if not members or len(members) > 50:
        return False
    expected = Counter()
    for row in members:
        try:
            rec = json.loads(row["record"]) if row["record"] else {}
        except (TypeError, ValueError):
            return False
        control = CONTROL_VK.get(rec.get("vk"))
        if (not control or rec.get("chr") or rec.get("injected") != 1
                or rec.get("lower_il") != row["lower_il"]):
            return False
        expected[(row["ts"], control, row["lower_il"], row["fg"] or "")] += 1
    times = sorted({key[0] for key in expected})
    marks = ",".join("?" * len(times))
    observed = Counter()
    for row in store.db.execute(
            "SELECT ts, control, lower_il, fg FROM control_events WHERE "
            f"kind='control-key' AND injected=1 AND ts IN ({marks})", times):
        observed[(row["ts"], row["control"], row["lower_il"], row["fg"] or "")] += 1
    return all(observed[key] >= count for key, count in expected.items())


def _keyless(rows):
    """True when every event carries no key at all: VK 0xFF, scan code 0, no
    character, no modifier. Rows recorded before forensic capture cannot be
    inspected, so they never qualify."""
    if not rows:
        return False
    for r in rows:
        try:
            rec = json.loads(r["record"]) if r["record"] else None
        except (ValueError, TypeError, KeyError, IndexError):
            rec = None
        if not isinstance(rec, dict) or rec.get("vk") != 255 or rec.get("scan") \
                or rec.get("chr") or rec.get("mods"):
            return False
    return True


def _latency_findings(store, beat, probe_registry=True):
    """Is anything making the cursor and keyboard feel slow?

    Every low-level hook sits in a chain and delays each event until it
    returns. That is the mechanism behind "the cursor is slower than it used
    to be" — a keylogger, a screen recorder or an overlay doing work on the
    input thread shows up here as milliseconds.

    Windows drops a hook that exceeds `LowLevelHooksTimeout` (default 300ms),
    so software that wants to keep a slow hook alive has a reason to raise
    that value. An unexplained increase is worth seeing. That check reads the
    registry over the interop boundary, so `probe_registry=False` lets the
    frequent watchdog skip it and leave it to the full audit.
    """
    out = _stall_findings(store)
    if not beat or not beat["lat_samples"]:
        return out

    avg, mx = beat["lat_avg_ms"], beat["lat_max_ms"]
    over = beat["lat_over50"]
    pct = (100.0 * over / beat["lat_samples"]) if beat["lat_samples"] else 0

    if avg >= 30 or pct >= 10:
        sev = "high" if (avg >= 60 or pct >= 25) else "medium"
        out.append(_finding(
            "input", sev, f"input events are arriving {avg} ms late on average",
            f"peak {mx} ms; {over} of {beat['lat_samples']} events "
            f"({pct:.0f}%) took over 50 ms to reach this hook. Every low-level "
            f"hook in the chain delays input until it returns, so this is what "
            f"a keylogger, screen recorder or overlay feels like. Note that "
            f"JARVIS's own hook is in that chain and contributes part of it — "
            f"stop it with `jarvis inputwatch --stop` and see whether the "
            f"figure follows.", "input_beats"))
    else:
        out.append(_finding(
            "input", "ok", f"input latency is {avg} ms average, {mx} ms peak",
            f"{beat['lat_samples']} events sampled — nothing in the hook chain "
            f"ahead of JARVIS is adding perceptible delay. {CHAIN_BLIND_SPOT}",
            "input_beats"))

    if not probe_registry:
        return out

    d = ps_json(
        "$v = (Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
        "-Name LowLevelHooksTimeout -EA SilentlyContinue).LowLevelHooksTimeout;"
        "$m = Get-ItemProperty 'HKCU:\\Control Panel\\Mouse' -EA SilentlyContinue;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$v; sens=$m.MouseSensitivity; speed=$m.MouseSpeed;"
        " th1=$m.MouseThreshold1; th2=$m.MouseThreshold2; trails=$m.MouseTrails})))",
        timeout=60)
    out += _pointer_findings(d)
    t = (d or {}).get("t")
    if t and int(t) > 300:
        out.append(_finding(
            "input", "high", f"LowLevelHooksTimeout has been raised to {t} ms",
            "Windows removes a low-level hook that takes longer than this to "
            "return. Raising it above the 300 ms default keeps slow hooks "
            "alive — which is something a keylogger benefits from and normal "
            "software rarely needs",
            r"HKCU\Control Panel\Desktop"))
    return out


# What the latency figures cannot see. Windows calls the newest low-level hook
# first, so the JARVIS hook measures only hooks installed after it; one that
# was installed earlier runs after it and its delay never reaches this number.
# Raw-input and key-state polling loggers add no delay at all.
CHAIN_BLIND_SPOT = (
    "This measures only hooks installed after the JARVIS hook: one installed "
    "earlier runs after it and its delay is invisible here, and raw-input or "
    "polling loggers add no delay at all, so a smooth cursor is not evidence "
    "that nothing is watching input.")

STALL_EVENTS = 3        # events over 50 ms within one heartbeat interval
STALL_GAP_S = 180       # beats further apart than this span hook downtime
STALL_INTERVALS_LOW = 3  # fewer stalled intervals than this are isolated hiccups


def stall_minutes(rows):
    """Heartbeat intervals in which input stalled, from cumulative beats.

    Each beat carries counters that grow for the life of one helper session,
    so a figure like "peak 250 ms" is the session's worst moment, not now.
    Differencing consecutive beats recovers when it happened. A counter that
    goes down marks a new session, and a long gap spans downtime; neither
    pair is differenced. Pure: `rows` are (ts, lat_over50, lat_samples,
    lat_max_ms) in time order.
    """
    out = []
    for prev, cur in zip(rows, rows[1:]):
        if cur[2] < prev[2] or cur[1] < prev[1] or cur[0] - prev[0] > STALL_GAP_S:
            continue
        slow = cur[1] - prev[1]
        if slow >= STALL_EVENTS:
            out.append({"ts": cur[0], "slow": slow, "events": cur[2] - prev[2],
                        "peak_rose_to": cur[3] if cur[3] > prev[3] else None})
    return out


def _stall_findings(store, hours=24):
    """The cursor that "sometimes feels heavy": when did input actually stall?"""
    rows = store.db.execute(
        "SELECT ts, lat_over50, lat_samples, lat_max_ms FROM input_beats "
        "WHERE ts>=? ORDER BY ts", (now() - hours * 3600 - STALL_GAP_S,)).fetchall()
    stalls = [s for s in stall_minutes([tuple(r) for r in rows])
              if s["ts"] >= now() - hours * 3600]
    if not stalls:
        return []
    worst = sorted(stalls, key=lambda s: -s["slow"])[:3]
    return [_finding(
        "input", ("medium" if len(stalls) >= 30 else
                  "low" if len(stalls) >= STALL_INTERVALS_LOW else "ok"),
        f"input stalled in {len(stalls)} heartbeat interval(s) in the last {hours} h",
        "worst: " + "; ".join(
            f"{iso(s['ts'])} — {s['slow']} of {s['events']} events over 50 ms"
            + (f", peak {s['peak_rose_to']} ms" if s["peak_rose_to"] else "")
            for s in worst)
        + ". A stall is a symptom, not a verdict: a busy CPU, a GPU or driver "
        "hiccup, or any program with an input hook can cause it. Compare the "
        "times with what was running. " + CHAIN_BLIND_SPOT, "input_beats")]


# Windows defaults for HKCU\Control Panel\Mouse. A change here alters how the
# cursor feels without anything being wrong, so it is reported as an
# explanation, never as a problem.
POINTER_DEFAULTS = {"sens": ("10", "pointer speed", "10 of 20"),
                    "speed": ("1", "enhance pointer precision", "on"),
                    "trails": ("0", "pointer trails", "off")}


def _pointer_findings(d):
    if not isinstance(d, dict) or all(d.get(k) is None for k in POINTER_DEFAULTS):
        return []
    changed = []
    for key, (default, label, shown) in POINTER_DEFAULTS.items():
        value = d.get(key)
        if value is not None and str(value) != default:
            changed.append(f"{label} is {value} (default {shown})")
    if not changed:
        return [_finding("input", "ok", "pointer settings are the Windows defaults",
                         "speed, acceleration and trails are unchanged, so they "
                         "do not explain a change in how the cursor feels",
                         r"HKCU\Control Panel\Mouse")]
    return [_finding(
        "input", "ok", "pointer settings differ from the Windows defaults",
        "; ".join(changed) + ". These change how the cursor feels and are not "
        "a sign of compromise; if you did not change them, note when the cursor "
        "started feeling different.", r"HKCU\Control Panel\Mouse")]


def _cadence_findings(beat):
    """Real keystrokes arriving faster or more evenly than a person can type.

    Hardware-level injection — a malicious HID filter driver, a BadUSB device,
    an IOCTL straight to kbdclass — sets no injected flag; the events are
    identical to human typing. Timing is the only tell it leaves: nobody holds
    a sub-8 ms inter-key cadence, or a long run of gaps all within 2 ms of each
    other. Key auto-repeat is already excluded on the helper side.
    """
    if not beat:
        return []
    gaps = beat["real_key_gaps"] or 0
    if gaps < 30:                       # too little typing to characterise
        return []
    sub8, sub20 = beat["real_key_sub8"] or 0, beat["real_key_sub20"] or 0
    run = beat["cad_run_max"] or 0
    p8, p20 = 100.0 * sub8 / gaps, 100.0 * sub20 / gaps

    if p8 >= 5 or run >= 40:
        extra = (f", and a run of {run} consecutive gaps stayed within 2 ms of "
                 f"each other" if run >= 20 else "")
        return [_finding(
            "input", "high",
            "real keystrokes are arriving faster than a human types",
            f"{sub8} of {gaps} inter-key gaps ({p8:.0f}%) were under 8 ms{extra}. "
            f"Driver- or hardware-level injection carries no injected flag — "
            f"cadence like this is the only signal it leaves.", "input_beats")]
    if p20 >= 25 or run >= 20:
        extra = f"; longest even run {run}" if run >= 10 else ""
        return [_finding(
            "input", "medium",
            "real keystrokes show a machine-like cadence",
            f"{sub20} of {gaps} gaps ({p20:.0f}%) were under 20 ms{extra} — fast "
            f"automation, a very fast typist, or a stuck repeat. Worth a look at "
            f"what had focus.", "input_beats")]
    return [_finding(
        "input", "ok", "keystroke cadence looks human",
        f"{gaps} inter-key gaps sampled, {p20:.0f}% under 20 ms, longest even "
        f"run {run}", "input_beats")]


def _typing_findings(store, beat):
    """Rolling, contentless typing anomalies from one-minute aggregates.

    This deliberately cannot answer "what was typed". It can answer whether a
    minute was implausibly dense, machine-fast, or dominated by the three key
    families the operator asked to watch (=, / and .).
    """
    rows = store.db.execute(
        "SELECT * FROM input_typing_windows WHERE ts >= ? ORDER BY ts DESC",
        (now() - 300,)).fetchall()
    if not rows:
        return _cadence_findings(beat)

    total = lambda key: sum(int(r[key] or 0) for r in rows)
    keys = total("real_keys")
    gaps = total("real_key_gaps")
    sub20 = total("real_key_sub20")
    sub8 = total("real_key_sub8")
    run = max((int(r["cad_run_max"] or 0) for r in rows), default=0)
    summary = {"real_key_gaps": gaps, "real_key_sub20": sub20,
               "real_key_sub8": sub8, "cad_run_max": run}
    out = _cadence_findings(summary) if gaps >= 30 else []

    labels = (("equals/plus", "equals_keys"),
              ("slash/question", "slash_keys"),
              ("period/greater-than", "period_keys"),
              ("digit", "digit_keys"))
    for label, column in labels:
        count = total(column)
        share = 100.0 * count / keys if keys else 0.0
        # Coding naturally uses punctuation, and PINs/OTP entry use digits, so
        # concentration alone is a low signal. It becomes medium only alongside
        # machine-fast cadence.
        if count >= 20 and share >= 35:
            machine_like = (sub8 >= 5 or run >= 20)
            out.append(_finding(
                "input", "medium" if machine_like else "low",
                f"typing is unusually concentrated on the {label} key",
                f"{count} of {keys} real key-down events ({share:.0f}%) in the "
                f"last five minutes used this physical key family"
                + (" alongside machine-like timing" if machine_like else
                   " — often benign, but retained as an anomaly signal"),
                "input_typing_windows"))

    latest = int(rows[0]["real_keys"] or 0)
    baseline = [int(r[0]) for r in store.db.execute(
        "SELECT real_keys FROM input_typing_windows "
        "WHERE ts < ? AND ts >= ? AND real_keys > 0 ORDER BY ts DESC LIMIT 5000",
        (rows[0]["ts"], now() - 90 * 86400)).fetchall()]
    if len(baseline) >= 30:
        median = statistics.median(baseline)
        mad = statistics.median(abs(n - median) for n in baseline)
        threshold = max(600, median + 8 * max(mad, 5))
        if latest > threshold:
            out.append(_finding(
                "input", "medium", "typing volume spiked above its baseline",
                f"{latest} key-down events in one minute versus a median of "
                f"{median:.0f} across {len(baseline)} active baseline minutes; "
                "content was not recorded", "input_typing_windows"))
    return out



# A control that moved with no key behind it is the one shape that separates
# "you pressed the volume key" from "something drove the machine as you". It is
# not proof of compromise: a media app, a headset dock, a meeting client and
# Windows itself all move the master level legitimately. It is proof that the
# change did not come from the keyboard in front of you, which is the fact the
# keyboard hook alone can never establish.
CONTROL_WINDOW = 24 * 3600


def _idle_seconds(detail):
    """The 'idle Ns' suffix the ingest writes on a brightness line, or -1."""
    m = re.search(r"idle (\d+)s", detail or "")
    return int(m.group(1)) if m else -1


def _control_findings(store, hours=24):
    since = now() - min(hours, 168) * 3600
    try:
        rows = store.db.execute(
            "SELECT * FROM control_events WHERE ts >= ? ORDER BY ts DESC",
            (since,)).fetchall()
    except Exception:
        return []
    if not rows:
        return [_finding("input", "ok", "no control activations recorded",
                         "no volume, media or launch control moved in the last "
                         "%dh" % hours, "control_events")]

    out = []
    keys = [r for r in rows if r["kind"] == "control-key"]
    states = [r for r in rows if r["kind"] == "control-state"
              and r["control"] not in ("app-volume", "brightness")]
    apps = [r for r in rows if r["kind"] == "control-state" and r["control"] == "app-volume"]
    bright = [r for r in rows if r["kind"] == "control-state" and r["control"] == "brightness"]
    injected = [r for r in keys if r["injected"]]
    unkeyed = [r for r in states if r["keyed"] == 0]

    if injected:
        first = injected[0]
        media_only = all(r["control"] == "media-play-pause" and not r["lower_il"]
                         for r in injected)
        out.append(_finding(
            "input", "medium" if media_only else "high",
            "media play/pause was injected by software" if media_only else
            "a control key was injected by software",
            "%d injected control activation(s) in %dh; most recent %s at %s"
            "%s. A synthesised control key is software pressing it for you; "
            "the sender is not identified by this hook."
            % (len(injected), hours, first["control"], iso(first["ts"]),
               " (from a lower-integrity process)" if first["lower_il"] else ""),
            "control_events"))

    if unkeyed:
        first = unkeyed[0]
        out.append(_finding(
            "input", "medium",
            "the volume changed with no key press behind it",
            "%d unkeyed change(s) in %dh; most recent %s at %s, foreground %s. "
            "Media apps, headsets and Windows itself do this legitimately — but "
            "so does anything driving this machine as if it were you."
            % (len(unkeyed), hours, first["detail"], iso(first["ts"]),
               first["fg"] or "unknown"),
            "control_events"))

    if apps:
        # An app changing its own level while you use it is ordinary (a video
        # player's slider). One whose level moved while another window had
        # focus, with no key behind it, was changed from outside the app.
        def _app(r):
            return (r["detail"] or "").split(":", 1)[0].lower()
        outside = [r for r in apps if r["keyed"] == 0 and _app(r)
                   and not (r["fg"] or "").lower().startswith(_app(r))]
        latest = apps[0]
        if outside:
            first = outside[0]
            out.append(_finding(
                "input", "medium", "an app's volume was changed from outside it",
                "%d per-app change(s) in %dh happened while another window had focus "
                "and no key was pressed; most recent %s at %s, foreground %s. The "
                "Windows volume mixer, a headset app or an audio tool does this "
                "legitimately — so does software acting on your machine."
                % (len(outside), hours, first["detail"], iso(first["ts"]),
                   first["fg"] or "unknown"), "control_events"))
        out.append(_finding(
            "input", "low", "per-app volume changes are recorded",
            "%d per-app change(s) in %dh; most recent %s at %s, foreground %s"
            % (len(apps), hours, latest["detail"], iso(latest["ts"]),
               latest["fg"] or "unknown"), "control_events"))

    if bright:
        # Brightness has no keyed/unkeyed tell: on most laptops the brightness
        # hotkey goes through ACPI and never produces a virtual key, and
        # Windows moves the level itself (adaptive brightness, battery and
        # idle dimming). So every change is recorded with its idle context
        # and reported low; it is a lead for the forensic timeline, never an
        # impersonation claim on its own. A software-driven change is only
        # distinguishable by what else the timeline shows around it.
        latest = bright[0]
        active = [r for r in bright if "idle" in (r["detail"] or "")
                  and _idle_seconds(r["detail"]) < 5]
        out.append(_finding(
            "input", "low", "display brightness changed",
            "%d change(s) in %dh, %d while someone was actively using the "
            "machine; most recent %s at %s, foreground %s. Source is not "
            "attributed: a hotkey, the Settings slider, adaptive brightness, "
            "battery or idle dimming, or software setting it through WMI all "
            "look the same here; the 5-minute controls sample is the cross-check."
            % (len(bright), hours, len(active), latest["detail"],
               iso(latest["ts"]), latest["fg"] or "unknown"),
            "control_events"))

    keyed = [r for r in states if r["keyed"] == 1]
    out.append(_finding(
        "input", "ok", "control activations are being logged",
        "%d control key press(es) and %d state change(s) in %dh — %d matched a "
        "key press, %d did not" % (len(keys), len(states), hours, len(keyed),
                                   len(unkeyed)),
        "control_events"))
    return out


# Punctuation key-downs are timestamped individually so a key that appears
# without being pressed can be located in time and attributed to a window.
# A phantom key is only diagnosable if you know exactly when it happened.
def _punct_findings(store, hours=24):
    since = now() - min(hours, 168) * 3600
    try:
        rows = store.db.execute(
            "SELECT ts, kind, class, fg FROM input_events "
            "WHERE ts >= ? AND (kind = 'punct-key' OR class IN "
            "('period-greater','slash-question','equals-plus')) "
            "ORDER BY ts DESC LIMIT 200", (since,)).fetchall()
    except Exception:
        return []
    if not rows:
        return []
    injected = [r for r in rows if r["kind"] != "punct-key"]
    if injected:
        first = injected[0]
        return [_finding(
            "input", "critical", "a punctuation key was injected by software",
            "%d injected punctuation key(s); most recent %s at %s in %s. "
            "Nothing pressed it — it was synthesised."
            % (len(injected), first["class"], iso(first["ts"]),
               first["fg"] or "an unknown window"), "input_events")]
    first = rows[0]
    return [_finding(
        "input", "ok", "punctuation key presses are timestamped",
        "%d real punctuation key press(es) in %dh, none injected; most recent "
        "%s at %s in %s" % (len(rows), hours, first["class"], iso(first["ts"]),
                            first["fg"] or "an unknown window"),
        "input_events")]


# Digits 0-9 (top row and numpad) are timestamped the same way as punctuation:
# enough to say "digit-3 at 22:36 in WindowsTerminal", not enough to rebuild
# surrounding text. Injected digit presses keep the critical path.
def _digit_findings(store, hours=24):
    since = now() - min(hours, 168) * 3600
    try:
        rows = store.db.execute(
            "SELECT ts, kind, class, fg FROM input_events "
            "WHERE ts >= ? AND (kind = 'digit-key' OR class LIKE 'digit-_') "
            "ORDER BY ts DESC LIMIT 200", (since,)).fetchall()
    except Exception:
        return []
    if not rows:
        return []
    injected = [r for r in rows if r["kind"] != "digit-key"]
    if injected:
        first = injected[0]
        return [_finding(
            "input", "critical", "a digit key was injected by software",
            "%d injected digit key(s); most recent %s at %s in %s. "
            "Nothing pressed it — it was synthesised."
            % (len(injected), first["class"], iso(first["ts"]),
               first["fg"] or "an unknown window"), "input_events")]
    first = rows[0]
    return [_finding(
        "input", "ok", "digit key presses are timestamped",
        "%d real digit key press(es) in %dh, none injected; most recent "
        "%s at %s in %s" % (len(rows), hours, first["class"], iso(first["ts"]),
                            first["fg"] or "an unknown window"),
        "input_events")]


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
