"""Synthetic positive controls and legitimate look-alikes, with expectations.

Positives emulate the observable behaviour of each spyware class as typed
facts; they never run anything. Look-alikes are ordinary software that holds
the same capabilities. `selftest()` measures both on the current engine, so a
rule change that trades false positives for detections shows up as numbers.
These describe this vocabulary only: they are not evidence about real malware
coverage or about sensors that cannot see a mechanism.
"""

from jarvis.core.reasoning import engine
from jarvis.core.reasoning.vocab import Observation, Subject

FLAGGED = {"SUSPECT_CHAIN", "VISIBILITY_CONTRADICTION"}
INFORM = {"UNEXPLAINED_CAPABILITY"} | FLAGGED


def _s(key, facts, *, sig="none", pub="", path="user_writable", age=3, window=None):
    return Subject(key=key, host="win", label=key, signature=sig, publisher=pub,
                   path_class=path, age_days=age, has_window=window,
                   observations=[Observation(k, "corpus") for k in facts])


POSITIVES = [
    ("keylogger", _s("keylogger", ["cap.keyboard.hook", "persist.autostart", "egress.external"]),
     "SUSPECT_CHAIN"),
    ("screen_spy", _s("screen_spy", ["cap.screen.capture", "stage.local_buffer", "egress.beacon"]),
     "SUSPECT_CHAIN"),
    ("mic_spy_no_ui", _s("mic_spy", ["cap.audio.mic", "conceal.no_ui", "egress.external"]),
     "SUSPECT_CHAIN"),
    ("infostealer", _s("stealer", ["cap.credential.store", "stage.local_buffer", "egress.external"],
                       path="temp"), "SUSPECT_CHAIN"),
    ("rat", _s("rat", ["cap.input.injection", "cap.screen.capture", "persist.autostart",
                       "egress.beacon"]), "SUSPECT_CHAIN"),
    ("hidden_by_contradiction", _s("hidden", ["conceal.contradiction"]), "VISIBILITY_CONTRADICTION"),
    ("system_name_masquerade", _s("svchost-lookalike", ["conceal.masquerade", "egress.external"],
                                  path="temp"), "VISIBILITY_CONTRADICTION"),
    ("linux_evdev_deleted_image", Subject(
        key="evdev", host="wsl", path_class="user_writable", signature="none",
        observations=[Observation("cap.keyboard.evdev", "proc"),
                      Observation("conceal.deleted_image", "proc")]), "VISIBILITY_CONTRADICTION"),
]

LOOKALIKES = [
    ("obs_recorder", _s("obs", ["cap.screen.capture", "cap.audio.mic", "cap.video.camera",
                                "persist.autostart", "egress.external"],
                        sig="valid", pub="OBS Project", path="program_files", age=400),
     "EXPECTED_DECLARED"),
    ("zoom_call", _s("zoom", ["cap.audio.mic", "cap.video.camera", "cap.screen.capture",
                              "egress.external", "persist.autostart"],
                     sig="valid", pub="Zoom Video Communications, Inc.", path="program_files", age=90),
     "EXPECTED_DECLARED"),
    ("teamviewer", _s("teamviewer", ["cap.screen.capture", "cap.input.injection", "egress.beacon",
                                     "persist.autostart"],
                      sig="valid", pub="TeamViewer", path="program_files", age=200),
     "EXPECTED_DUAL_USE"),
    ("riot_vanguard", _s("vgk", ["cap.memory.read", "cap.keyboard.hook", "persist.autostart"],
                         sig="valid", pub="Riot Games", path="program_files", age=300),
     "EXPECTED_DUAL_USE"),
    ("codex_desktop_agent", _s("codex", ["cap.screen.capture", "cap.input.injection"],
                               sig="valid", pub="OpenAI OpCo", path="store_package", age=30),
     "EXPECTED_DUAL_USE"),
    ("windows_shell", _s("shell", ["cap.keyboard.hook", "cap.screen.capture"],
                         sig="valid", pub="Microsoft Windows", path="os", age=900),
     "EXPECTED_DECLARED"),
    ("password_manager", _s("pwm", ["cap.keyboard.hook", "cap.clipboard.monitor"],
                            sig="valid", pub="Bitwarden", path="program_files", age=120),
     "EXPECTED_DECLARED"),
    ("dev_tool_network_only", _s("devserver", ["egress.external", "persist.autostart"],
                                sig="none", path="user_writable", age=2), "NO_SIGNAL"),
    ("unsigned_overlay_hook_only", _s("overlay", ["cap.keyboard.hook"], sig="none",
                                      path="user_writable", age=60), "UNEXPLAINED_CAPABILITY"),
    ("recorder_reading_credentials", _s("obs-evil", ["cap.screen.capture", "cap.credential.store"],
                                        sig="valid", pub="OBS Project", path="program_files", age=400),
                                     "UNEXPLAINED_CAPABILITY"),
    ("wrong_location_for_publisher", _s("fake-ms", ["cap.keyboard.hook", "cap.screen.capture"],
                                        sig="valid", pub="Microsoft Windows", path="user_writable",
                                        age=400), "UNEXPLAINED_CAPABILITY"),
]


def selftest():
    """Detection and false-positive counts for the current engine."""
    detected, missed, false_pos, drift = 0, [], [], []
    for name, subject, expect in POSITIVES:
        got = engine.assess(subject)["verdict"]
        if got in FLAGGED:
            detected += 1
        else:
            missed.append((name, got))
        if got != expect:
            drift.append((name, expect, got))
    for name, subject, expect in LOOKALIKES:
        got = engine.assess(subject)["verdict"]
        if got in FLAGGED:
            false_pos.append((name, got))
        if got != expect:
            drift.append((name, expect, got))
    return {"positives": len(POSITIVES), "detected": detected, "missed": missed,
            "lookalikes": len(LOOKALIKES), "false_positives": false_pos,
            "expectation_drift": drift,
            "scope": "synthetic typed facts only; says nothing about sensors that cannot "
                     "observe a mechanism (see blind_mechanisms)"}
