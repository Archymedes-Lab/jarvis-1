"""Spyware positive controls: what to emulate, what must be detected, how to score it.

Every control is a *harmless* emulation of a spyware mechanism, run only inside
a disposable VM (never on the protected machine). A control states the
telemetry it should produce, the verdict the reasoning engine should reach,
the maximum detection latency, the human protection and the recovery. A control
marked `known_blind` is the honesty check: the mechanism is one no sensor
observes, so the *correct* result is that it is NOT detected and the blind spot
is named; detecting it would mean a sensor improved and the register is stale.

Pure: scoring takes guest-reported evidence and applies the current engine.
"""

from dataclasses import dataclass

from jarvis.core.reasoning import engine
from jarvis.core.reasoning.vocab import KINDS, SIGNATURES, Observation, Subject

FLAGGED = frozenset({"SUSPECT_CHAIN", "VISIBILITY_CONTRADICTION"})
MAX_OBS = 64
MAX_TEXT = 120


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    platform: str                     # linux | win
    emulator: str                     # mode name inside the guest asset
    expect_verdict: str
    expect_kinds: tuple = ()          # facts the sensor must produce
    known_blind: bool = False
    needs: str = ""                   # device or capability the guest must offer
    max_latency_s: float = 10.0
    telemetry: str = ""
    human_protection: str = "inform the owner; never automatic containment"
    recovery: str = "terminate the emulator; the disposable guest is discarded"
    safety: str = "isolated_emulation"


LINUX = (
    Control("L01-deleted-image", "Process running from a deleted file", "linux", "deleted_image",
            "VISIBILITY_CONTRADICTION", ("conceal.deleted_image",),
            telemetry="/proc/<pid>/exe link ends in '(deleted)'"),
    Control("L02-memfd-exec", "Process executed from an anonymous memory file", "linux", "memfd_exec",
            "VISIBILITY_CONTRADICTION", ("conceal.deleted_image",),
            telemetry="/proc/<pid>/exe is /memfd:<name> (deleted)"),
    Control("L03-keyboard-device-reader", "Non-service process holding a keyboard event device", "linux",
            "evdev_reader", "UNEXPLAINED_CAPABILITY", ("cap.keyboard.evdev",), needs="keyboard",
            telemetry="open descriptor on /dev/input/event* whose sysfs capabilities include KEY_A"),
    Control("L04-keyboard-reader-deleted", "Keyboard device reader whose image was deleted", "linux",
            "evdev_deleted", "VISIBILITY_CONTRADICTION", ("cap.keyboard.evdev", "conceal.deleted_image"),
            needs="keyboard", telemetry="evdev descriptor plus a deleted image",
            human_protection="depth 3 forensic capture is proposed and waits for explicit authorization"),
    Control("L05-microphone-capture-device", "Non-service process holding a capture PCM device", "linux",
            "snd_capture", "UNEXPLAINED_CAPABILITY", ("cap.audio.mic",), needs="sound",
            telemetry="open descriptor on /dev/snd/pcmC*D*c"),
    Control("L06-synthetic-input-device", "Process holding /dev/uinput", "linux", "uinput_open",
            "UNEXPLAINED_CAPABILITY", ("cap.input.injection",), needs="uinput",
            telemetry="open descriptor on /dev/uinput"),
    Control("L07-clean-process", "Ordinary sleeping process (false-positive guard)", "linux",
            "clean_sleep", "NO_SIGNAL", telemetry="none expected"),
)

WINDOWS = (
    Control("W01-hook-autostart-unsigned", "Unsigned keyboard hook with autostart and no window", "win",
            "hook_autostart", "SUSPECT_CHAIN", ("cap.keyboard.hook", "persist.autostart"),
            max_latency_s=30.0, telemetry="Win32k audit row (hook type 13) plus a Run-key entry"),
    Control("W02-hook-only", "Unsigned keyboard hook, nothing else", "win", "hook_only",
            "UNEXPLAINED_CAPABILITY", ("cap.keyboard.hook",), max_latency_s=30.0,
            telemetry="Win32k audit row (hook type 13)"),
    Control("W03-system-name-masquerade", "Executable named like a system binary in a temp folder", "win",
            "masquerade", "VISIBILITY_CONTRADICTION", ("conceal.masquerade",), max_latency_s=30.0,
            telemetry="process name svchost.exe with an image outside the Windows directory"),
    Control("W04-key-state-polling", "Key-state polling loop (blind spot)", "win", "poll_keys",
            "NO_SIGNAL", known_blind=True, max_latency_s=30.0,
            telemetry="none: Windows does not log GetAsyncKeyState (measured 2026-09-23)"),
    Control("W05-screen-duplication", "Desktop pixel reads by BitBlt (blind spot)", "win", "bitblt",
            "NO_SIGNAL", known_blind=True, max_latency_s=30.0,
            telemetry="none: not consent-gated and no sensor watches it"),
    Control("W06-clean-process", "Ordinary sleeping process (false-positive guard)", "win", "clean_sleep",
            "NO_SIGNAL", max_latency_s=30.0, telemetry="none expected"),
)

ALL = LINUX + WINDOWS


def by_platform(platform):
    return tuple(c for c in ALL if c.platform == platform)


def subject_from_evidence(raw):
    """Rebuild a Subject from guest-reported JSON. Untrusted: bounded and validated."""
    if not isinstance(raw, dict):
        return None
    obs = []
    for o in (raw.get("observations") or [])[:MAX_OBS]:
        if isinstance(o, dict) and o.get("kind") in KINDS:
            obs.append(Observation(o["kind"], str(o.get("source", "guest"))[:MAX_TEXT],
                                   fresh=o.get("fresh") is not False, complete=o.get("complete") is not False))
    sig = raw.get("signature")
    return Subject(key=str(raw.get("key", ""))[:MAX_TEXT], host=str(raw.get("host", ""))[:8],
                   label=str(raw.get("label", ""))[:MAX_TEXT],
                   signature=sig if sig in SIGNATURES else "unknown",
                   publisher=str(raw.get("publisher", ""))[:MAX_TEXT],
                   path_class=str(raw.get("path_class", "unknown"))[:20],
                   age_days=raw.get("age_days") if isinstance(raw.get("age_days"), int) else None,
                   has_window=raw.get("has_window") if isinstance(raw.get("has_window"), bool) else None,
                   runs_script=raw.get("runs_script") is True, observations=obs)


def evaluate(control, evidence):
    """One control's outcome from one guest evidence record."""
    base = {"id": control.id, "title": control.title, "expected": control.expect_verdict,
            "known_blind": control.known_blind, "max_latency_s": control.max_latency_s}
    status = (evidence or {}).get("status")
    if status == "skipped":
        return {**base, "outcome": "skipped", "reason": str(evidence.get("reason", ""))[:MAX_TEXT]}
    if status != "ran":
        return {**base, "outcome": "error", "reason": str((evidence or {}).get("reason", "no evidence"))[:MAX_TEXT]}
    subject = subject_from_evidence(evidence.get("subject"))
    if subject is None:
        return {**base, "outcome": "error", "reason": "target process was not observed"}
    row = engine.assess(subject)
    latency = evidence.get("latency_s")
    latency = latency if isinstance(latency, (int, float)) and latency >= 0 else None
    got_kinds = {o.kind for o in subject.observations if o.positive()}
    missing = [k for k in control.expect_kinds if k not in got_kinds]
    verdict_ok = row["verdict"] == control.expect_verdict
    if control.known_blind:
        outcome = "blind_confirmed" if row["verdict"] == "NO_SIGNAL" else "blind_spot_closed"
    elif control.expect_verdict == "NO_SIGNAL":
        outcome = "clean_ok" if verdict_ok else "false_positive"
    else:
        outcome = "detected" if verdict_ok and not missing else "missed"
    slow = latency is not None and latency > control.max_latency_s
    return {**base, "outcome": outcome, "verdict": row["verdict"], "missing_kinds": missing,
            "latency_s": latency, "too_slow": slow, "depth": row["observation_depth"],
            "needs_human": row["depth_needs_human"], "blind_mechanisms": row["blind_mechanisms"][:6],
            "cleaned": evidence.get("cleaned") is True}


def summarize(results):
    counts = {}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    lat = [r["latency_s"] for r in results if r.get("latency_s") is not None and r["outcome"] == "detected"]
    bad = [r["id"] for r in results if r["outcome"] in ("missed", "false_positive", "blind_spot_closed", "error")
           or r.get("too_slow") or (r.get("cleaned") is False and r["outcome"] != "skipped")]
    return {"counts": counts, "problems": bad,
            "max_detected_latency_s": max(lat) if lat else None,
            "passed": not bad,
            "complete": not any(r["outcome"] in ("skipped", "error") for r in results),
            "reading": "skipped controls are coverage gaps, not passes; blind_confirmed means the "
                       "documented blind spot is still a blind spot"}
