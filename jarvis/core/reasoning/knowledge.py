"""How each spyware class works, and which legitimate software looks like it.

This is the reasoning engine's domain knowledge: mechanism, what it must do to
be useful to its operator (so we know what to look for next), what JARVIS
cannot see, and the benign categories that legitimately hold the same
capabilities. Knowledge is descriptive; it never authorizes a response.
"""

# id -> archetype. `capture` is any-of; `needs` are the stages a working
# instance must eventually show (it has to keep or send what it captures).
ARCHETYPES = {
    "keylogger": {
        "title": "Keystroke logger",
        "capture": ("cap.keyboard.hook", "cap.keyboard.evdev"),
        "mechanism": ("Records typed keys, by a global keyboard hook, a raw-input "
                      "sink, an evdev reader, or by polling key state in a loop. "
                      "Polling installs nothing and is invisible to hook audits."),
        "needs": ("stage", "egress"),
        "next_checks": ("which other instances share this parent or image",
                        "outbound connections from this same instance",
                        "recent writes by this instance into user-writable folders"),
    },
    "screen_spy": {
        "title": "Screen recorder / stalkerware screenshotter",
        "capture": ("cap.screen.capture",),
        "mechanism": ("Grabs screenshots or video on a timer or on window change, "
                      "through a consent-gated capture API or, more quietly, GDI/DXGI "
                      "duplication that leaves no consent record."),
        "needs": ("stage", "egress"),
        "next_checks": ("periodic image or archive files from this instance",
                        "upload-sized outbound transfers after captures"),
    },
    "av_spy": {
        "title": "Microphone or camera spy",
        "capture": ("cap.audio.mic", "cap.video.camera"),
        "mechanism": ("Opens the microphone or camera without a visible session, often "
                      "while the user is away, and ships recordings out."),
        "needs": ("stage", "egress"),
        "next_checks": ("consent-store last-used times against the user's own calls",
                        "whether the device indicator or a visible UI existed"),
    },
    "infostealer": {
        "title": "Credential and data stealer",
        "capture": ("cap.credential.store", "cap.clipboard.monitor"),
        "mechanism": ("Copies browser cookies, saved passwords, wallet and key files, "
                      "packs them and sends them once, then may exit."),
        "needs": ("stage", "egress"),
        "next_checks": ("one-shot outbound burst shortly after the store access",
                        "archive creation in a temp or user-writable folder"),
    },
    "rat": {
        "title": "Remote access trojan",
        "capture": ("cap.input.injection", "cap.screen.capture", "cap.memory.read"),
        "mechanism": ("Gives an operator live control: screen, synthetic input, files and "
                      "processes, over a persistent outbound channel that survives reboot."),
        "needs": ("persist", "egress"),
        "next_checks": ("persistent outbound channel and its first-seen date",
                        "autostart entry created near first sighting"),
    },
    "covert_process": {
        "title": "Covert or disguised process",
        "capture": (),
        "mechanism": ("Avoids being listed or being recognised: hooks enumeration APIs, "
                      "runs from a deleted or memory-only image, or borrows a system name. "
                      "Independent views disagree about it."),
        "needs": (),
        "next_checks": ("re-run every enumeration view and compare instance identity",
                        "threads, images or sockets with no owning process record"),
    },
}

# Publisher -> declared product category. A category only explains capabilities
# in `expects`, and only when the signature is valid and the signer matches.
# Explained is not authorized: dual-use categories still ask the owner.
CATEGORIES = {
    "os_component": {"publishers": ("Microsoft Windows", "Microsoft Corporation"),
                     "paths": ("os",), "dual_use": False,
                     "expects": ("cap.keyboard.hook", "cap.screen.capture", "cap.audio.mic",
                                 "cap.video.camera", "cap.clipboard.monitor",
                                 "cap.input.injection", "cap.memory.read")},
    "microsoft_app": {"publishers": ("Microsoft Corporation",),
                      "paths": ("program_files", "store_package", "unknown"), "dual_use": False,
                      "expects": ("cap.audio.mic", "cap.video.camera", "cap.screen.capture",
                                  "cap.keyboard.hook", "cap.clipboard.monitor")},
    "remote_support": {"publishers": ("TeamViewer", "AnyDesk Software", "ConnectWise",
                                      "Splashtop", "RealVNC"),
                       "paths": ("program_files", "user_writable", "unknown"), "dual_use": True,
                       "expects": ("cap.screen.capture", "cap.input.injection",
                                   "cap.keyboard.hook", "cap.clipboard.monitor")},
    "screen_recorder": {"publishers": ("OBS Project", "TechSmith", "Loom"),
                        "paths": ("program_files", "user_writable", "unknown"), "dual_use": False,
                        "expects": ("cap.screen.capture", "cap.audio.mic", "cap.video.camera")},
    "video_call": {"publishers": ("Zoom Video Communications", "Google LLC", "Slack Technologies",
                                  "Discord Inc."),
                   "paths": ("program_files", "user_writable", "unknown"), "dual_use": False,
                   "expects": ("cap.audio.mic", "cap.video.camera", "cap.screen.capture")},
    "anti_cheat": {"publishers": ("Riot Games", "Epic Games", "Valve", "BattlEye"),
                   "paths": ("program_files", "os", "unknown"), "dual_use": True,
                   "expects": ("cap.memory.read", "cap.keyboard.hook")},
    "ai_desktop_agent": {"publishers": ("OpenAI OpCo", "Anthropic PBC"),
                         "paths": ("store_package", "program_files", "unknown"), "dual_use": True,
                         "expects": ("cap.screen.capture", "cap.input.injection",
                                     "cap.keyboard.hook")},
    "password_manager": {"publishers": ("1Password", "AgileBits", "Bitwarden", "Proton AG"),
                         "paths": ("program_files", "user_writable", "unknown"), "dual_use": False,
                         "expects": ("cap.keyboard.hook", "cap.clipboard.monitor",
                                     "cap.input.injection")},
    "accessibility": {"publishers": ("Nuance", "Freedom Scientific", "NV Access"),
                      "paths": ("program_files", "unknown"), "dual_use": False,
                      "expects": ("cap.keyboard.hook", "cap.input.injection",
                                  "cap.screen.capture")},
}


# Linux has no Authenticode equivalent, so identity for a core OS daemon rests on
# its kernel-verified exe path (path_class == "os", from readlink, not a self-reported
# name) plus an exact, narrow, reviewed name-to-capability mapping — never a blanket
# exemption for "looks like a system name". Each entry is justified by documented
# behavior of that specific daemon, found live: the isolated-lab false-positive guard
# (2026-09-30) flagged systemd-logind reading a keyboard event device, which is exactly
# its documented job (logind.conf HandlePowerKey/HandleLidSwitch/HandleLidSwitchDocked
# watch the power and lid-switch input devices). A test pins that every key here is
# also in vocab.LINUX_SYSTEM_NAMES, so this list can never explain a name that
# masquerade detection would not itself recognize as a real system name.
LINUX_OS_COMPONENTS = {
    "systemd-logind": frozenset({"cap.keyboard.evdev"}),
}


_SUFFIXES = {"inc", "llc", "ltd", "limited", "pbc", "corporation", "corp", "co", "gmbh",
             "ag", "sa", "opco", "software", "technologies"}


def normalize_publisher(name):
    """Signer name reduced to its identifying words: case, punctuation and
    corporate suffixes dropped. Equality after this is the only match rule, so
    "Zoom Video Communications, Inc." matches but "Zoom" or "Zoom Fake" do not."""
    words = "".join(c if c.isalnum() or c.isspace() else " " for c in (name or "").lower()).split()
    while words and words[-1] in _SUFFIXES:
        words.pop()
    return " ".join(words)


def categories_for(publisher, path_class):
    """Every category whose publisher matches exactly and whose path class fits."""
    name = normalize_publisher(publisher)
    if not name:
        return []
    return [cid for cid, cat in CATEGORIES.items()
            if path_class in cat["paths"]
            and any(name == normalize_publisher(p) for p in cat["publishers"])]
