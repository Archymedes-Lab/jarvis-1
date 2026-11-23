"""The posture audit: one sample, every section, sorted."""

from jarvis.platform import broker
from jarvis.platform.windows import ps_json

from .collect import PS_POSTURE, elevated_data
from .common import _finding, sort_findings
from .sections import SECTIONS

# Defender protections a stale sample can wrongly show as off. The broker's
# elevated sample may date from boot, before the engine finished starting:
# on 2026-09-23 it read real-time protection off for two hours after a
# reboot while Defender was on, and on 2026-09-24 it carried signature age
# 65535 (Defender's "unknown") and no preferences at all, which read as
# Network Protection, PUA blocking and every ASR rule off. None of these
# need elevation to read live; exclusions do, so they are never replaced.
LIVE_DEFENDER = ("RealTimeProtectionEnabled", "BehaviorMonitorEnabled",
                 "IsTamperProtected", "AMRunningMode")
LIVE_STATUS_EXTRA = ("AntivirusSignatureAge",)
LIVE_PREF = ("PUAProtection", "EnableNetworkProtection", "EnableControlledFolderAccess",
             "AttackSurfaceReductionRules_Ids", "AttackSurfaceReductionRules_Actions")
SIGNATURE_AGE_UNKNOWN = 65535
PS_DEFENDER_LIVE = (
    "$s=Get-MpComputerStatus -ErrorAction Stop;"
    "$p=Get-MpPreference -ErrorAction SilentlyContinue;"
    "$o=@{RealTimeProtectionEnabled=[bool]$s.RealTimeProtectionEnabled;"
    "BehaviorMonitorEnabled=[bool]$s.BehaviorMonitorEnabled;"
    "IsTamperProtected=[bool]$s.IsTamperProtected;AMRunningMode=[string]$s.AMRunningMode;"
    "AntivirusSignatureAge=[int]$s.AntivirusSignatureAge};"
    "if($p){$o.pref=@{PUAProtection=[int]$p.PUAProtection;"
    "EnableNetworkProtection=[int]$p.EnableNetworkProtection;"
    "EnableControlledFolderAccess=[int]$p.EnableControlledFolderAccess;"
    "AttackSurfaceReductionRules_Ids=@($p.AttackSurfaceReductionRules_Ids);"
    "AttackSurfaceReductionRules_Actions=@($p.AttackSurfaceReductionRules_Actions|ForEach-Object{[int]$_})}};"
    "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -Depth 4 $o)))")


def _needs_live(dfn, pref):
    if not all(dfn.get(k) for k in LIVE_DEFENDER[:3]):
        return True
    age = dfn.get("AntivirusSignatureAge")
    if not isinstance(age, int) or age >= SIGNATURE_AGE_UNKNOWN:
        return True
    return not isinstance(pref, dict) or any(k not in pref or pref.get(k) is None
                                             for k in LIVE_PREF[:3])


def _confirm_defender(d):
    """Re-read Defender live when the sample says a protection is off, carries
    the unknown signature age, or lacks preferences, and let the current state
    stand. A failed live read changes nothing, so a protection that is really
    off is still reported; fields the live read did not return are kept."""
    dfn = d.get("defender") if isinstance(d, dict) else None
    if not isinstance(dfn, dict):
        return
    pref = d.get("mppref")
    if not _needs_live(dfn, pref):
        return
    live = ps_json(PS_DEFENDER_LIVE, timeout=60)
    if not isinstance(live, dict) or not all(k in live for k in LIVE_DEFENDER):
        return
    dfn.update({k: live[k] for k in LIVE_DEFENDER + LIVE_STATUS_EXTRA if k in live})
    lp = live.get("pref")
    if isinstance(lp, dict):
        merged = dict(pref) if isinstance(pref, dict) else {}
        merged.update({k: lp[k] for k in LIVE_PREF if k in lp})
        d["mppref"] = merged


def audit(hosts=("win",), elevate=False):
    if "win" not in hosts:
        return []
    elev_err = ""
    d = None
    if elevate:
        d, elev_err = elevated_data()
    if d is None:
        # The elevated broker's run sees BitLocker, TPM, Defender exclusions
        # and optional features; the unelevated one reports those unreadable.
        d, _why = broker.result("posture")
    if d is None:
        d = ps_json(PS_POSTURE, timeout=400)
    if not d:
        return [_finding("visibility", "medium", "posture audit unavailable",
                         "powershell.exe returned no data")]
    _confirm_defender(d)
    out = []
    if elevate and elev_err:
        out.append(_finding(
            "visibility", "medium", "elevated audit did not run",
            f"{elev_err} — falling back to the unelevated result, so the "
            f"checks that need administrator remain unread"))

    for section in SECTIONS:
        out.extend(section(d))
    return sort_findings(out)
