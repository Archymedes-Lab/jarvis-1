"""Posture rules, one function per area, each reading the sample and returning findings."""

from jarvis.core import observation
from jarvis.platform.windows import aslist

from .common import _finding

CONHOST = "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}"
# Defender's AntivirusSignatureAge encodes "not initialized" as 65535.
SIGNATURE_AGE_SENTINELS = {65535: "Defender reported its not-initialized value (65535)"}


# The five ASR rules that matter most on a workstation that runs Office and a
# browser, by GUID. There are more; these are the ones whose absence shows up
# in real intrusion reports.
ASR_KEY = {
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
# Rules worth having on a workstation but whose absence is advice, not a
# medium: several break specific workflows (USB tools, Adobe Reader plug-ins).
ASR_MORE = {
    # Not a key rule since 2026-11-11: it blocks every program Microsoft's cloud has not
    # seen often or for long, which includes new installers, in-house tools and this
    # product's own unsigned builds (measured on the owner's machine: 76 blocks of Argus
    # and other first-party programs in nine days, every one shown to the person as
    # "your administrator caused Windows Security to block this action"). Worth having
    # on a machine that installs little; advice, not a deduction. See collectors/host/winblocks.py.
    "01443614-cd74-433a-b99e-2ecdc07bfc25":
        "block programs Microsoft has not seen often or for long (also blocks new installers and your own builds)",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "block Win32 API calls from Office macros",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": "block process creation from PsExec and WMI",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "block persistence through WMI subscriptions",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "advanced ransomware protection",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "block executable content from email and webmail",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "block Office communication apps creating child processes",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "block untrusted or unsigned processes from USB",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "block Adobe Reader creating child processes",
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": "block web shell creation on servers",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "block rebooting into Safe Mode",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "block copying or impersonating system tools",
}
# ASR action codes: 0 off, 1 block, 2 audit, 6 warn.
ASR_BLOCK = "1"
ASR_SOFT = {"2": "audit", "6": "warn"}
# Get-ProcessMitigation -System vocabulary.
MIT_ON, MIT_OFF, MIT_DEFAULT = "ON", "OFF", "NOTSET"


def _truthy(v):
    """Registry booleans are not always 1.

    RunAsPPL is 2 when LSA protection is enabled with a UEFI lock, which is the
    *stronger* setting — reading only "1" as true reported a hardened machine
    as unprotected.
    """
    t = str(v).strip().lower()
    if t in ("true", "yes", "on"):
        return True
    try:
        return int(t) > 0
    except (TypeError, ValueError):
        return False


def _unreadable(v):
    """PowerShell returns a human sentence instead of data when not elevated."""
    if v is None:
        return True
    t = str(v)
    return ("must be an administrator" in t.lower()
            or "access is denied" in t.lower()
            or t.strip() in ("", "N/A"))


def _malware_defense(d):
    """Malware defense."""
    out = []
    dfn = d.get("defender") or {}
    pref = d.get("mppref") or {}
    mode = str(dfn.get("AMRunningMode") or "")
    if not dfn:
        out.append(_finding("malware defense", "high",
                            "Defender status could not be read",
                            "another product may have replaced it"))
    else:
        if not dfn.get("RealTimeProtectionEnabled"):
            out.append(_finding(
                "malware defense", "critical", "real-time protection is off",
                "nothing is scanning files as they are written",
                "Set-MpPreference -DisableRealtimeMonitoring $false"))
        if not dfn.get("IsTamperProtected"):
            out.append(_finding(
                "malware defense", "high", "Tamper Protection is off",
                "without it, code running as admin can silently disable "
                "Defender — which is the first thing most intrusions do",
                "Windows Security > Virus & threat protection > "
                "Manage settings > Tamper Protection ON"))
        # Typed reading: 65535 is Defender's "unknown", seen while the engine
        # is still starting; it is not an age and must not read as 179 years.
        # A missing or malformed value is unknown too, never a fresh age.
        age = observation.judge(
            observation.reading("Defender signature age",
                                dfn.get("AntivirusSignatureAge"),
                                SIGNATURE_AGE_SENTINELS, "Get-MpComputerStatus"),
            lambda days: days <= 3)
        if not age.known:
            out.append(_finding(
                "visibility", "low", "Defender signature age is not known yet",
                f"{age.reason} (sensor {age.health}); unknown, not current; the next "
                "posture run re-reads it", "Get-MpComputerStatus"))
        elif age.verdict == observation.KNOWN_UNSAFE:
            out.append(_finding(
                "malware defense", "high" if age.value > 14 else "medium",
                f"malware signatures are {age.value} days old",
                "signature updates ship several times a day",
                "Update-MpSignature"))
        if not dfn.get("BehaviorMonitorEnabled"):
            out.append(_finding(
                "malware defense", "high", "behaviour monitoring is off",
                "signature-only detection misses anything novel",
                "Set-MpPreference -DisableBehaviorMonitoring $false"))
        if mode and mode.lower() not in ("normal", "0"):
            out.append(_finding(
                "malware defense", "medium",
                f"Defender is running in {mode} mode",
                "passive mode means it is not the primary protection"))

    if not pref:
        # An absent preference read is not "off": the broker's boot-time sample
        # had none and read as three protections disabled plus every ASR rule.
        out.append(_finding(
            "visibility", "medium", "Defender preferences could not be read",
            "PUA blocking, Network Protection and attack-surface-reduction rules "
            "are unverified this run, not known to be off", "Get-MpPreference"))
        return out
    if str(pref.get("PUAProtection")) not in ("1", "True"):
        out.append(_finding(
            "malware defense", "medium",
            "potentially-unwanted-application blocking is not enabled",
            "Defender has already flagged two PUA bundlers on this machine",
            "Set-MpPreference -PUAProtection Enabled"))
    if str(pref.get("EnableNetworkProtection")) not in ("1", "True"):
        out.append(_finding(
            "malware defense", "medium", "Network Protection is not enabled",
            "blocks outbound connections to known-malicious hosts at the OS level",
            "Set-MpPreference -EnableNetworkProtection Enabled"))
    if str(pref.get("EnableControlledFolderAccess")) not in ("1", "True"):
        out.append(_finding(
            "malware defense", "low", "Controlled Folder Access is off",
            "this is the anti-ransomware guard on Documents and similar folders",
            "Set-MpPreference -EnableControlledFolderAccess Enabled"))

    excl = aslist(pref.get("ExclusionPath")) + aslist(pref.get("ExclusionProcess"))
    real_excl = [e for e in excl if not _unreadable(e)]
    if excl and not real_excl:
        out.append(_finding(
            "visibility", "medium", "Defender exclusions are not readable",
            "listing exclusions needs an elevated shell — an excluded path is "
            "invisible to scanning, so this is worth checking by hand",
            "run `jarvis posture` from an elevated PowerShell"))
    for e in real_excl:
        out.append(_finding(
            "malware defense", "high", f"Defender exclusion: {e}",
            "an excluded path is not scanned at all; malware that finds an "
            "exclusion list will use it"))

    ids = [str(x).lower() for x in aslist(pref.get("AttackSurfaceReductionRules_Ids"))]
    actions = [str(a) for a in aslist(pref.get("AttackSurfaceReductionRules_Actions"))]
    action_of = dict(zip(ids, actions))
    enabled = {i for i, a in action_of.items() if a == ASR_BLOCK}
    missing = [(g, n) for g, n in ASR_KEY.items() if g not in enabled]
    if missing:
        out.append(_finding(
            "attack surface", "medium",
            f"{len(missing)} of {len(ASR_KEY)} key ASR rules are not enforcing",
            "; ".join(n for _, n in missing[:4])
            + ("; …" if len(missing) > 4 else ""),
            "Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> "
            "-AttackSurfaceReductionRules_Actions Enabled"))
    soft = [(g, n, ASR_SOFT[action_of[g]]) for g, n in ASR_MORE.items()
            if action_of.get(g) in ASR_SOFT]
    absent = [n for g, n in ASR_MORE.items() if g not in action_of or action_of[g] == "0"]
    if soft or absent:
        parts = []
        if soft:
            parts.append(f"{len(soft)} only {'/'.join(sorted({m for _, _, m in soft}))}: "
                         + "; ".join(n for _, n, _ in soft[:4]))
        if absent:
            parts.append(f"{len(absent)} not configured: " + "; ".join(absent[:3])
                         + ("; …" if len(absent) > 3 else ""))
        out.append(_finding(
            "attack surface", "low",
            f"{len(soft) + len(absent)} further ASR rules are not blocking",
            " · ".join(parts),
            "Set-MpPreference -AttackSurfaceReductionRules_Ids <guid> "
            "-AttackSurfaceReductionRules_Actions Enabled (review each rule's "
            "workflow impact first)"))
    return out


def _memory_defense(d):
    """Memory defense: the OS-wide mitigations between a memory bug and code
    execution, and what keeps credentials out of readable memory. Per-process
    state (CFG, CET on each running image, unbacked executable memory) is the
    memory scan's job; this section reads the system defaults and the pins."""
    out = []
    m = d.get("mitigations")
    if not isinstance(m, dict):
        out.append(_finding(
            "visibility", "low", "system exploit mitigations could not be read",
            "Get-ProcessMitigation -System returned nothing; DEP, SEHOP, ASLR, "
            "CFG and shadow-stack defaults are unverified this run, not known off",
            "Get-ProcessMitigation -System"))
    else:
        def state(key):
            return str(m.get(key) or "").upper()
        if state("dep") == MIT_OFF:
            out.append(_finding(
                "memory defense", "high", "DEP is disabled system-wide",
                "data pages are executable, so any stack or heap overflow runs "
                "shellcode directly",
                "Set-ProcessMitigation -System -Enable DEP"))
        elif state("dep") == MIT_DEFAULT:
            out.append(_finding(
                "memory defense", "low", "DEP is at its default, not pinned on",
                "64-bit programs always get DEP; 32-bit programs only opt in. "
                "Pinning it makes every 32-bit program opt out instead",
                "Set-ProcessMitigation -System -Enable DEP"))
        if state("sehop") == MIT_OFF:
            out.append(_finding(
                "memory defense", "medium", "SEHOP is disabled system-wide",
                "exception-handler overwrite, the classic 32-bit exploit path, "
                "is not checked", "Set-ProcessMitigation -System -Enable SEHOP"))
        for key, name in (("aslr_bottomup", "bottom-up ASLR"),
                          ("aslr_highentropy", "high-entropy ASLR")):
            if state(key) == MIT_OFF:
                out.append(_finding(
                    "memory defense", "medium", f"{name} is disabled system-wide",
                    "addresses become predictable, which is what return-oriented "
                    "exploits need", "Set-ProcessMitigation -System -Enable "
                    + ("BottomUp" if key == "aslr_bottomup" else "HighEntropy")))
        if state("aslr_forcerelocate") != MIT_ON:
            out.append(_finding(
                "memory defense", "low", "mandatory ASLR is not forced for all images",
                "images built without relocation data keep fixed addresses; forcing "
                "it can break a few old programs, so it is a deliberate choice",
                "Set-ProcessMitigation -System -Enable ForceRelocateImages"))
        if state("cfg") == MIT_OFF:
            out.append(_finding(
                "memory defense", "medium", "Control Flow Guard is disabled system-wide",
                "indirect calls are not validated even in programs compiled for it",
                "Set-ProcessMitigation -System -Enable CFG"))
        if state("user_shadow_stack") != MIT_ON:
            out.append(_finding(
                "memory defense", "low",
                "hardware shadow stacks are not enforced system-wide",
                "the memory scan reports which running programs lack CET; the "
                "system default leaves it to each program. Needs a CET-capable CPU "
                "(Intel 11th gen or AMD Zen 3 and later)",
                "Set-ProcessMitigation -System -Enable UserShadowStack"))
    if not _truthy(d.get("kernelshadow")):
        out.append(_finding(
            "memory defense", "low",
            "kernel-mode hardware-enforced stack protection is not enabled",
            "return addresses in the kernel are not checked against a shadow stack; "
            "needs VBS and a CET-capable CPU, and some drivers are incompatible",
            "Windows Security > Device security > Core isolation > Kernel-mode "
            "Hardware-enforced Stack Protection"))
    if str(d.get("wdigest") or "") == "1":
        out.append(_finding(
            "memory defense", "high", "WDigest keeps plaintext passwords in LSASS",
            "UseLogonCredential=1 stores the logon password in clear text in "
            "memory, where any LSASS read recovers it",
            r"reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "
            r"/v UseLogonCredential /t REG_DWORD /d 0"))
    lsa = d.get("lsa") or {}
    if _truthy(lsa.get("runasppl")) and str(lsa.get("runasppl")) != "2" \
            and not _truthy(lsa.get("runasppl_boot")):
        out.append(_finding(
            "memory defense", "low", "LSA protection is on without a UEFI lock",
            "an administrator can clear RunAsPPL and reboot; the UEFI-locked "
            "setting (value 2) survives that",
            "run the LSA protection UEFI lock tool, or set RunAsPPL to 2 on a "
            "Secure Boot machine"))
    return out


def _platform_integrity(d):
    """Platform integrity."""
    out = []
    sb = d.get("secureboot")
    if sb is False:
        out.append(_finding(
            "platform integrity", "high", "Secure Boot is off",
            "the boot chain is not verified, which is what a bootkit needs",
            "enable Secure Boot in UEFI firmware settings"))
    elif sb is None:
        out.append(_finding("platform integrity", "low",
                            "Secure Boot state could not be read",
                            "usually means a legacy/BIOS boot"))

    tpm = d.get("tpm") or {}
    if tpm.get("TpmPresent") is None:
        out.append(_finding(
            "visibility", "low", "TPM state is not readable",
            "Get-Tpm needs an elevated shell — this is not the same as the "
            "TPM being absent, and the difference matters for BitLocker",
            "run elevated to confirm"))
    elif not tpm.get("TpmPresent"):
        out.append(_finding("platform integrity", "medium", "no TPM present",
                            "BitLocker and Credential Guard both rely on it"))
    elif not tpm.get("TpmReady"):
        out.append(_finding("platform integrity", "medium", "the TPM is not ready",
                            "present but not initialised"))

    dg = d.get("deviceguard") or {}
    running = {str(x) for x in aslist(dg.get("running"))}
    if str(dg.get("vbs")) not in ("2",):
        out.append(_finding(
            "platform integrity", "medium",
            "virtualisation-based security is not running",
            "VBS underpins Memory Integrity and Credential Guard",
            "Windows Security > Device security > Core isolation"))
    if "2" not in running:
        out.append(_finding(
            "platform integrity", "medium", "Memory Integrity (HVCI) is off",
            "HVCI is what stops an unsigned or vulnerable driver loading into "
            "the kernel — the BYOVD technique this machine's own audits look for",
            "Windows Security > Device security > Core isolation > "
            "Memory integrity ON"))
    if "1" not in running:
        out.append(_finding(
            "account & access", "medium", "Credential Guard is not running",
            "without it, credentials in LSASS can be read by admin-level code",
            "Core isolation, or the Device Guard policy"))

    if not _truthy((d.get("lsa") or {}).get("runasppl")):
        out.append(_finding(
            "account & access", "medium", "LSA protection (RunAsPPL) is off",
            "LSA runs unprotected, so tools like mimikatz can open it",
            r"reg add HKLM\System\CurrentControlSet\Control\Lsa "
            r"/v RunAsPPL /t REG_DWORD /d 1"))
    return out


def _data_at_rest(d):
    """Data at rest."""
    out = []
    vols = aslist(d.get("bitlocker"))
    if not vols:
        out.append(_finding(
            "visibility", "medium", "BitLocker status is not readable",
            "Get-BitLockerVolume needs elevation. Unreadable is not the same "
            "as unencrypted — but if this drive is not encrypted, anyone with "
            "physical access can read the .env secrets and credential-vault "
            "files in your project directories",
            "run elevated, or check Settings > Privacy & security > "
            "Device encryption"))
    for v in vols:
        if v.get("mount", "").upper().startswith("C") and \
                str(v.get("status")).lower() not in ("on", "1"):
            out.append(_finding(
                "data at rest", "high",
                f"the system drive {v.get('mount')} is not encrypted",
                "anyone with physical access can read this disk from another "
                "machine — including the .env secrets and credential vault "
                "in your project directories",
                "manage-bde -on C: (or Settings > Device encryption)"))
    return out


def _account_access(d):
    """Account & access."""
    out = []
    uac = d.get("uac") or {}
    if uac.get("enabled") is not None and not _truthy(uac.get("enabled")):
        out.append(_finding("account & access", "critical", "UAC is disabled",
                            "every process runs elevated without a prompt",
                            "set EnableLUA to 1 and reboot"))
    elif str(uac.get("consent")) == "0":
        out.append(_finding(
            "account & access", "high", "UAC never prompts for elevation",
            "ConsentPromptBehaviorAdmin=0 elevates silently",
            "set ConsentPromptBehaviorAdmin to 2 (prompt on secure desktop)"))

    al = d.get("autologon") or {}
    if _truthy(al.get("auto")):
        detail = "this machine logs in without a password"
        if al.get("pwd"):
            detail += " and the password is stored in the registry in cleartext"
        out.append(_finding("account & access", "high",
                            "automatic logon is enabled", detail,
                            "remove AutoAdminLogon and DefaultPassword"))

    for u in aslist(d.get("users")):
        # PasswordRequired is False for any account backed by a Microsoft
        # account or signing in with a PIN, which is the normal case on a
        # personal Windows 11 machine — it does not mean there is no password.
        if u.get("enabled") and not u.get("pwdreq") and not u.get("lastpwd"):
            out.append(_finding(
                "account & access", "low",
                f"account '{u.get('name')}' has no local password set",
                "normal for a Microsoft-account or PIN login; a real finding "
                "only if this is a local-only account"))
    admins = [a.get("name", "") for a in aslist(d.get("admins"))]
    if len(admins) > 3:
        out.append(_finding(
            "account & access", "low",
            f"{len(admins)} accounts are local administrators",
            ", ".join(a.split("\\")[-1] for a in admins[:6])))
    return out


def _attack_surface(d):
    """Attack surface."""
    out = []
    if d.get("smb1") is None:
        out.append(_finding(
            "visibility", "low", "SMBv1 feature state is not readable",
            "needs elevation to query optional features"))
    elif str(d.get("smb1")).lower() == "enabled":
        out.append(_finding(
            "attack surface", "critical", "SMBv1 is installed",
            "the protocol WannaCry and NotPetya spread over; nothing needs it",
            "Disable-WindowsOptionalFeature -Online "
            "-FeatureName SMB1Protocol"))
    rdp = d.get("rdp") or {}
    if rdp.get("denied") is not None and str(rdp.get("denied")) == "0":
        sev = "high" if str(rdp.get("nla")) != "1" else "medium"
        out.append(_finding(
            "attack surface", sev, "Remote Desktop is enabled",
            "inbound RDP is one of the most attacked services on the internet"
            + ("; network-level authentication is also off" if sev == "high" else ""),
            "disable RDP, or require NLA and never expose it directly"))
    # ServiceControllerStatus: 1 = Stopped, 4 = Running.
    if str(d.get("winrm")).lower() in ("running", "4"):
        out.append(_finding(
            "attack surface", "medium", "WinRM is running",
            "remote PowerShell is a lateral-movement path",
            "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"))
    ss = str(d.get("smartscreen_shell") or d.get("smartscreen") or "")
    if ss.lower() in ("off", "0"):
        out.append(_finding(
            "attack surface", "medium", "SmartScreen is off",
            "downloaded executables are not reputation-checked",
            "Windows Security > App & browser control > "
            "Reputation-based protection"))
    # Smart App Control blocks unsigned, unknown binaries: the carrier for most
    # commodity spyware. 0 off, 1 on, 2 evaluation; the value is protected.
    sac = d.get("sac")
    if sac is None:
        out.append(_finding(
            "visibility", "low", "Smart App Control state is not readable",
            "the CI policy value is absent or unreadable this run; unknown, not off",
            "Windows Security > App & browser control > Smart App Control"))
    elif str(sac) == "0":
        out.append(_finding(
            "attack surface", "medium", "Smart App Control is off",
            "unsigned, unknown binaries run without a reputation check; unsigned "
            "developer tools would be blocked once it is on, so trial evaluation mode",
            "Windows Security > App & browser control > Smart App Control settings"))
    elif str(sac) == "2":
        out.append(_finding(
            "attack surface", "low", "Smart App Control is in evaluation mode",
            "it is learning and blocks nothing yet; it turns itself off if it decides "
            "this machine is not a fit, so re-check after a week",
            "Windows Security > App & browser control > Smart App Control settings"))
    return out


def _visibility(d):
    """Visibility."""
    out = []
    ps = d.get("pslog") or {}
    if not _truthy(ps.get("scriptblock")):
        out.append(_finding(
            "logging", "medium", "PowerShell script block logging is off",
            "this is the single most useful log for reconstructing what an "
            "attacker ran — and this machine has already had a remote script "
            "piped into an elevated shell",
            r"reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell"
            r"\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1"))
    if not _truthy(ps.get("transcript")):
        out.append(_finding(
            "logging", "low", "PowerShell transcription is off",
            "transcripts record command output, not just the commands",
            "enable Transcription policy with an output directory"))

    ch = d.get("consolehost")
    if isinstance(ch, dict) and str(ch.get("console") or "").upper() != CONHOST:
        out.append(_finding(
            "operations", "low", "Background monitors can flash terminal windows",
            "the default terminal is Windows Terminal (or 'Let Windows decide'), "
            "which ignores -WindowStyle Hidden, so JARVIS's scheduled PowerShell "
            "monitors open visible windows every minute",
            r"powershell -ExecutionPolicy Bypass -File scripts\repair\fix-console-host.ps1"))

    upd = d.get("updates") or {}
    hot = aslist(d.get("hotfix"))
    if hot:
        out.append(_finding(
            "visibility", "ok",
            f"most recent update {hot[0].get('id')} on {hot[0].get('on', '')[:10]}",
            f"last successful search {str(upd.get('lastsearch') or '?')[:19]}"))
    else:
        out.append(_finding("visibility", "medium",
                            "no installed updates could be listed",
                            "update history is unreadable"))
    return out


def _licensing(d):
    """Licensing."""
    out = []
    for lic in aslist(d.get("license")):
        status = lic.get("status")
        name = (lic.get("name") or "Windows")[:60]
        if status == 1:
            out.append(_finding(
                "licensing", "ok", f"Windows is activated ({name})",
                "activation state does not affect security posture either way"))
        else:
            states = {0: "unlicensed", 2: "in grace period",
                      3: "additional grace", 4: "non-genuine grace",
                      5: "notification mode", 6: "extended grace"}
            out.append(_finding(
                "licensing", "low",
                f"Windows is not activated ({states.get(status, status)})",
                "this does not reduce security: Defender, Windows Update and "
                "the firewall all keep working unactivated. What matters is "
                "how activation is attempted — a script piped from the web "
                "into an elevated shell is a full-trust event, and this "
                "machine's PowerShell history shows exactly that"))
    return out


# In the order they are reported before sorting.
SECTIONS = (_malware_defense, _platform_integrity, _memory_defense, _data_at_rest,
            _account_access, _attack_surface, _visibility, _licensing)
