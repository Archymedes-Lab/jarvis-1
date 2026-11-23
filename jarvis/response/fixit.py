"""Remediation commands for findings that have one.

Not every finding has a fix that is a command — a coverage gap means "write a
collector," a suspicious process means "go look at it," not "run this." This
module only speaks up when there is a real, safe, single next step, and stays
silent otherwise rather than inventing one.

Matching is on the finding's title (a prefix or substring, whichever the
collector's wording needs) plus, where the command has to be parameterised,
a bit of the detail text. Getting the match wrong just means no suggestion is
shown — never a wrong command attached to the wrong finding — so match tightly
enough to be certain, not just to be broad.
"""

import re

# GUID -> name, kept identical to posture.sections.ASR_KEY so the fix command lists
# exactly the rules that collector checked, not a generic "all of ASR" blob.
_ASR_KEY = {
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a":
        "block Office apps creating child processes",
    "3b576869-a4ec-4529-8536-b80a7769e899":
        "block Office apps creating executable content",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc":
        "block obfuscated scripts",
    "d3e037e1-3eb8-44c8-a917-57927947596d":
        "block JS/VBS launching downloaded content",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2":
        "block credential theft from LSASS",
    "56a863a9-875e-4185-98a7-b882c64b5ce5":
        "block abuse of vulnerable signed drivers",
}

_ASR_CMD = ("elevated PowerShell: Add-MpPreference "
            "-AttackSurfaceReductionRules_Ids " +
            ",".join(_ASR_KEY) +
            " -AttackSurfaceReductionRules_Actions Enabled")

_RULE_NAME = re.compile(r"^\s*([^—]+?)\s*—")


def _rule_name(detail):
    m = _RULE_NAME.match(detail or "")
    return m.group(1).strip() if m else ""


# Each entry: (predicate(title, detail, where) -> bool,
#              fix(title, detail, where) -> str)
_RULES = [
    (lambda t, d, w: t.startswith("Credential Guard is not running"),
     # 2 = enabled without UEFI lock. 1 locks it into firmware, after which it
     # cannot be turned off from Windows. Credential Guard also needs
     # virtualization-based security, which the posture check reports apart.
     lambda t, d, w: "elevated PowerShell: scripts\\repair\\apply-reported-hardening.ps1 "
                     "(or set HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard "
                     "EnableVirtualizationBasedSecurity=1 and ...\\Control\\LSA "
                     "LsaCfgFlags=2), then reboot"),

    (lambda t, d, w: "ASR rules are not enforcing" in t,
     lambda t, d, w: _ASR_CMD),

    (lambda t, d, w: t.startswith("BitLocker status is not readable"),
     lambda t, d, w: "elevated PowerShell: Get-BitLockerVolume  "
                     "(if it comes back unencrypted: manage-bde -on C: "
                     "-RecoveryPasswordProtector)"),

    (lambda t, d, w: t.startswith("Defender exclusions"),
     lambda t, d, w: "elevated PowerShell: Get-MpPreference | "
                     "Select-Object -ExpandProperty ExclusionPath"),

    (lambda t, d, w: t.startswith("virtualisation-based security is not running"),
     lambda t, d, w: "elevated PowerShell, then reboot: "
                     "Set-ItemProperty -Path "
                     "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' "
                     "-Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord"),

    (lambda t, d, w: t.startswith("HVCI") or "memory integrity" in t.lower(),
     lambda t, d, w: "elevated PowerShell, then reboot: "
                     "Set-ItemProperty -Path "
                     "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
                     "\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
                     "-Name Enabled -Value 1 -Type DWord"),

    (lambda t, d, w: t.startswith("auditd is installed but not running"),
     lambda t, d, w: "sudo systemctl enable --now auditd"),

    (lambda t, d, w: t.startswith("account hidden from the sign-in screen"),
     lambda t, d, w: (
         f"elevated PowerShell — unhide: reg delete "
         f"\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
         f"\\SpecialAccounts\\UserList\" /v {t.rsplit(':', 1)[-1].strip()} /f "
         f" — or disable it outright: net user "
         f"{t.rsplit(':', 1)[-1].strip()} /active:no")),

    (lambda t, d, w: t == "permissive inbound rule" and _rule_name(d),
     lambda t, d, w: f"elevated PowerShell: Disable-NetFirewallRule "
                     f"-DisplayName \"{_rule_name(d)}\""),

    (lambda t, d, w: "Control Flow Guard is not enforced" in t
                     or "mandatory ASLR" in t,
     lambda t, d, w: "elevated PowerShell: Set-ProcessMitigation -System "
                     "-Enable CFG,ForceRelocateImages"),

    (lambda t, d, w: "CET / hardware shadow stack" in t,
     lambda t, d, w: "Windows Security -> App & browser control -> Exploit "
                     "protection -> Program settings -> System settings -> "
                     "Hardware-enforced Stack Protection -> On (compatible "
                     "mode) -- no PowerShell equivalent for this one"),

    (lambda t, d, w: "interop bridge" in t.lower() or "bridge is down" in d.lower(),
     lambda t, d, w: "from Windows (not inside WSL): wsl --shutdown"),

    (lambda t, d, w: t == "the monitor is not running",
     lambda t, d, w: "sudo systemctl restart jarvis.service"),

    (lambda t, d, w: t == "the monitor will not start on boot",
     lambda t, d, w: "sudo systemctl enable jarvis.service"),

    (lambda t, d, w: t.startswith("collector") and t.endswith("crashed"),
     lambda t, d, w: "sudo systemctl restart jarvis.service  "
                     "(then `jarvis selfcheck` to confirm it stuck)"),
]


# ── ASEP / autostart / unsigned-binary judgment calls ───────────────────────
#
# These are not wrong-or-right the way "auditd is off" is. An unsigned
# autostart binary or an odd Run key is very often a legitimate vendor being
# sloppy (see: logi_download_assistant.exe), so the fix here is always
# "verify, then act" — inspect first, remove only if you don't recognise it —
# never a bare delete. Some ASEP titles (Winlogon, IFEO, Active Setup, COM
# hijack, LSA package, print monitor, netsh helper, time provider, Explorer
# extension, accessibility binary, masquerading process) are deliberately left
# with no suggestion at all: their `where` is an abbreviated subkey fragment,
# not a full path, and a registry key guessed wrong in this territory (LSA,
# Winlogon) can break the ability to log in. Silence beats a wrong guess here.

def _first(detail, sep):
    return (detail.split(sep, 1)[0] if sep in detail else detail).strip()


def _after(detail, sep):
    return (detail.split(sep, 1)[1] if sep in detail else "").strip()


def _clean_svc_path(path):
    """A usable file path from firewall.py's "service installed recently",
    or "" if it is missing or was cut off by that collector's [:90] truncation
    — a truncated path fed to Get-AuthenticodeSignature just fails to resolve,
    so falling back to the by-name command is more useful than a broken one.
    """
    path = path.strip()
    if not path or path == "path unknown" or len(path) >= 90:
        return ""
    return path.strip('"')


_RULES += [
    (lambda t, d, w: t == "custom systemd service",
     lambda t, d, w: f"systemctl status {d or w}  "
                     f"(inspect before touching it — this may be part of "
                     f"JARVIS itself; disable only if you don't recognise "
                     f"it: sudo systemctl disable --now {d or '<unit>'})"),

    (lambda t, d, w: t == "startup folder item" and w,
     lambda t, d, w: f"inspect first: Get-Item \"{w}\" | Select-Object "
                     f"Target,LinkType  (if you don't recognise it: "
                     f"Remove-Item -LiteralPath \"{w}\")"),

    (lambda t, d, w: t == "autostart registry entry" and " = " in d and w,
     lambda t, d, w: (
         f"verify {_first(d, ' = ')} first — if unwanted: "
         f"reg delete \"{w}\" /v \"{_first(d, ' = ')}\" /f")),

    (lambda t, d, w: t == "service installed recently",
     lambda t, d, w: (
         lambda name, path: (
             f"Get-AuthenticodeSignature \"{path}\"" if path else
             f"Get-Service \"{name}\" | Format-List *") +
         f"  (if you don't recognise it: sc.exe delete \"{name}\")"
     )(re.sub(r"\s*×\d+$", "", _first(d, " — ")), _clean_svc_path(_after(d, " — ")))),

    (lambda t, d, w: t.startswith("autostart binary is unsigned") and w,
     lambda t, d, w: f"Get-AuthenticodeSignature \"{w}\"  "
                     f"(if you don't recognise the publisher: "
                     f"Remove-Item -LiteralPath \"{w}\")"),

    (lambda t, d, w: t == "scheduled task",
     lambda t, d, w: f"schtasks /query /tn \"{_first(d, ' → ')}\" /v /fo "
                     f"list  (inspect only — task path/name are not "
                     f"reliably separable here to delete safely)"),
]


def suggest(finding):
    """Return a command string for this finding, or "" if there is none."""
    title = finding.get("title", "")
    detail = finding.get("detail", "")
    where = finding.get("where", "")
    for pred, fix in _RULES:
        try:
            if pred(title, detail, where):
                return fix(title, detail, where)
        except Exception:
            continue
    return ""
