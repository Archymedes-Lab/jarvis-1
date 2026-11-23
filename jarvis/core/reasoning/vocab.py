"""Observation vocabulary, stages and per-mechanism observability (pure).

Every fact JARVIS can reason about is one of a fixed set of kinds. A kind has a
stage in the spyware chain and a weight. Free text never influences a verdict.
"""

from dataclasses import dataclass, field

STAGES = ("capture", "conceal", "persist", "stage", "egress", "evade")

# kind -> (stage, weight 1..3, meaning)
KINDS = {
    "cap.keyboard.hook": ("capture", 2, "global keyboard hook or raw-input sink"),
    "cap.keyboard.evdev": ("capture", 2, "reads keyboard-capable input event devices (Linux)"),
    "cap.screen.capture": ("capture", 2, "screen capture API in use or consented"),
    "cap.audio.mic": ("capture", 2, "microphone stream recently used"),
    "cap.video.camera": ("capture", 2, "camera stream recently used"),
    "cap.clipboard.monitor": ("capture", 1, "watches clipboard changes"),
    "cap.credential.store": ("capture", 3, "opens browser credential or key stores"),
    "cap.input.injection": ("capture", 2, "injects synthetic keyboard or mouse input"),
    "cap.memory.read": ("capture", 2, "reads another process's memory or ptrace"),
    "conceal.contradiction": ("conceal", 3, "views disagree about this process instance"),
    "conceal.masquerade": ("conceal", 3, "system-style name from an unexpected location"),
    "conceal.deleted_image": ("conceal", 2, "running from a deleted or memory-only file"),
    "conceal.unbacked_exec": ("conceal", 2, "executable memory with no backing image"),
    "conceal.no_ui": ("conceal", 1, "no visible window and not a service"),
    "persist.autostart": ("persist", 1, "starts at logon or boot"),
    "stage.local_buffer": ("stage", 2, "grows a local buffer or archive of captures"),
    "egress.external": ("egress", 1, "holds external network connections"),
    "egress.beacon": ("egress", 2, "regular-interval outbound contact"),
    "evade.telemetry_tamper": ("evade", 3, "interferes with logging or security telemetry"),
}
STRONG_CONCEAL = frozenset({"conceal.contradiction", "conceal.masquerade",
                            "conceal.deleted_image"})
STAGE_CAP = {"capture": 4, "conceal": 4, "persist": 2, "stage": 2,
             "egress": 3, "evade": 4}

# Signed programs that run whatever script they are given: their signature says
# nothing about the code that acted, so it can never explain a capability.
SCRIPT_HOSTS = frozenset({"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                          "mshta.exe", "python.exe", "pythonw.exe", "node.exe", "java.exe",
                          "javaw.exe", "rundll32.exe", "regsvr32.exe", "autohotkey.exe",
                          "autohotkey64.exe", "autohotkeyu64.exe"})
# Names an attacker borrows because people and tools ignore them. Running under one of
# these names from outside the operating system's own directories is disguise.
WINDOWS_SYSTEM_NAMES = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "winlogon.exe",
    "wininit.exe", "explorer.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "spoolsv.exe",
    "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "searchindexer.exe", "fontdrvhost.exe",
    "wmiprvse.exe", "dllhost.exe", "audiodg.exe", "msmpeng.exe", "lsm.exe", "system"})
LINUX_SYSTEM_NAMES = frozenset({
    "systemd", "sshd", "cron", "crond", "rsyslogd", "dbus-daemon", "systemd-journald",
    "systemd-logind", "systemd-udevd", "networkd-dispatcher", "polkitd", "agetty", "init"})
LINUX_KERNEL_THREAD_PREFIXES = ("kworker", "ksoftirqd", "migration", "rcu_", "kthreadd", "kswapd",
                                "watchdog", "cpuhp", "khugepaged", "jbd2")


def _one_edit_apart(a, b):
    """True when two names differ by one substitution, insertion, deletion or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def is_masquerade(name, path_class, *, windows=True):
    """A system name, or a one-edit lookalike of one, running from outside the OS location."""
    low = (name or "").lower()
    if not low or path_class == "os":
        return False
    names = WINDOWS_SYSTEM_NAMES if windows else LINUX_SYSTEM_NAMES
    if low in names:
        return True
    return len(low) >= 6 and any(_one_edit_apart(low, n) for n in names if len(n) >= 6)


JARVIS_COMPONENT = "jarvis_component"     # set only from supervisor-verified pids

SIGNATURES = ("valid", "invalid", "none", "unknown")
PATH_CLASSES = ("os", "program_files", "store_package", "user_writable",
                "temp", "unknown")

# mechanism -> (status, why). Engineering assessments, not live measurements;
# `blind` means absence of a fact proves nothing about that mechanism.
OBSERVABILITY = {
    "keyboard hook": ("limited", "win32k input audit sees hooks and raw-input sinks"),
    "keyboard polling": ("blind", "GetAsyncKeyState polling installs nothing to observe (measured 2026-09-23)"),
    "keyboard event device": ("limited", "readable only for the same user or with privilege"),
    "screen capture (consent-gated API)": ("current", "capture consent history names the executable"),
    "screen capture (BitBlt/DXGI duplication)": ("blind", "not consent-gated and no sensor watches it"),
    "microphone/camera (consent-gated)": ("current", "consent store records last use per executable"),
    "microphone/camera (driver-level)": ("blind", "kernel or driver paths bypass the consent store"),
    "clipboard monitoring": ("blind", "no sensor watches clipboard listeners"),
    "credential store access": ("limited", "depends on file-access telemetry policy"),
    "input injection": ("current", "injected-input flag is recorded by the hook"),
    "process memory read": ("limited", "Sysmon process-access masks; protected processes are closed"),
    "local staging": ("blind", "no file-write sensor for arbitrary directories"),
    "beaconing": ("limited", "connection snapshots exist; no flow-timing history yet"),
    "hidden process": ("limited", "user-mode cross-view only; no supported kernel sensor yet"),
}
CAPTURE_MECHANISMS = {
    "cap.keyboard.hook": ("keyboard hook", "keyboard polling"),
    "cap.keyboard.evdev": ("keyboard event device",),
    "cap.screen.capture": ("screen capture (consent-gated API)",
                           "screen capture (BitBlt/DXGI duplication)"),
    "cap.audio.mic": ("microphone/camera (consent-gated)",
                      "microphone/camera (driver-level)"),
    "cap.video.camera": ("microphone/camera (consent-gated)",
                         "microphone/camera (driver-level)"),
    "cap.clipboard.monitor": ("clipboard monitoring",),
    "cap.credential.store": ("credential store access",),
    "cap.input.injection": ("input injection",),
    "cap.memory.read": ("process memory read",),
}
STAGE_MECHANISM = {"stage": "local staging", "egress": "beaconing",
                   "conceal": "hidden process"}


@dataclass(frozen=True)
class Observation:
    kind: str
    source: str
    fresh: bool = True
    complete: bool = True

    def positive(self):
        """Only fresh, complete observations count as evidence."""
        return self.fresh and self.complete and self.kind in KINDS


@dataclass
class Subject:
    """One process instance. `label` is local display only, never sent remotely."""
    key: str
    host: str = ""
    label: str = ""
    signature: str = "unknown"          # SIGNATURES
    publisher: str = ""                 # signer CN, local only
    path_class: str = "unknown"         # PATH_CLASSES
    age_days: int | None = None
    has_window: bool | None = None
    runs_script: bool = False           # image is a script host (see SCRIPT_HOSTS)
    declared: str = ""                  # owner-verified identity, e.g. JARVIS_COMPONENT
    observations: list = field(default_factory=list)
