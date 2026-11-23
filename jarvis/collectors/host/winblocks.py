"""What Windows Security blocked, said in plain words.

Windows shows a blocked action as "Your administrator caused Windows Security to
block this action" and nothing else: not which rule, not which program, not what
to do. The record is in the Defender event log (attack surface reduction 1121 and
1122, controlled folder access 1123 and 1124). This collector reads it and says
what happened.

Two kinds of block matter differently:

  * A block of something attack-like (a program reaching for sign-in secrets, an
    Office document starting a program, a script unpacking itself) is Windows
    stopping an attack step. It is reported at the weight of what was attempted.
  * A block of an ordinary new program by the reputation rule is Windows being
    cautious. It is reported low, with the reason, so the person is not left
    guessing. When the blocked program is part of this product, that is said
    plainly and higher: part of the protection did not run.

Invariants
  1. Read-only: nothing is unblocked, excluded or reconfigured, and no command
     that does so is ever run by this collector. A finding may *name* the
     administrator command; running it is the owner's decision.
  2. No lost visibility: a read that failed or was cut by its cap is said; an
     unknown rule id is reported with its id, never dropped.
  3. Bounded: one read of the last 24 hours, capped in the reader; findings fold
     per rule and blocked program.
  4. Naming this product's own files is for explanation only. It grants nothing:
     no finding is lowered or skipped because a path looks like Argus.

Limits, stated: only blocks Windows recorded in the last 24 hours and still in
the log; a rule in audit mode is reported as "would have blocked"; the program
named is what Windows recorded, which for the sign-in-secrets rule is the program
that reached, not the one that asked it to; nothing here judges whether a block
was right.
"""

import ntpath
import re

from jarvis.core import collection
from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.platform import windows

CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
PS_READER = load_win_script("winblocks.ps1")
MAX_FINDINGS = 40
REPUTATION = "01443614-cd74-433a-b99e-2ecdc07bfc25"
LSASS = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

# rule id -> (what Windows stopped, severity when a block is recorded)
RULES = {
    REPUTATION: ("a program Microsoft has not seen often or for long", "low"),
    LSASS: ("a program reading Windows' store of sign-in secrets", "high"),
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": ("an Office app starting another program", "high"),
    "3b576869-a4ec-4529-8536-b80a7769e899": ("an Office app writing a program to disk", "high"),
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": ("Adobe Reader starting another program", "high"),
    "26190899-1602-49e8-8b27-eb1d0a1ce869": ("an Office communication app starting another program", "high"),
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": ("an Office macro calling Windows directly", "high"),
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": ("a script that hides what it does", "high"),
    "d3e037e1-3eb8-44c8-a917-57927947596d": ("a script starting something it downloaded", "high"),
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": ("an unsigned program run from a USB drive", "medium"),
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": ("a program that arrived by email", "high"),
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": ("a program started remotely through PsExec or WMI", "medium"),
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": ("something setting itself to run through WMI", "high"),
    "c1db55ab-c21a-4637-bb3f-a12568109d35": ("a program behaving like ransomware", "high"),
    "56a863a9-875e-4185-98a7-b882c64b5ce5": ("a driver with a known weakness being installed", "high"),
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": ("a web shell being written on a server", "high"),
    "33ddedf1-c6e0-47cb-833e-de6133960387": ("a restart into Safe Mode", "medium"),
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": ("a copy or look-alike of a Windows system tool", "medium"),
}
# Windows' own services reach for sign-in secrets constantly and Windows blocks them
# harmlessly (measured 2026-11-11: 41 such records in nine days, all svchost.exe).
WINDOWS_DIR = re.compile(r"^[a-z]:\\windows\\(system32|syswow64)\\[^\\]+$", re.I)
# This product's own programs, to say so when one of them is what was blocked.
OWN = re.compile(r"(\\programs\\argus\\|\\program files\\argus|\\programdata\\jarvis\\|"
                 r"\\(argus|jarvis)[-_a-z0-9. ]*\.exe$|\\argus-instinct-setup[^\\]*\.exe$)", re.I)


def _base(path):
    return ntpath.basename(path or "") or "an unnamed program"


def _valid(data):
    if not isinstance(data, dict):
        return None
    try:
        out = {"read": int(data["read"]), "more": bool(data["more"]),
               "errors": [str(e)[:120] for e in windows.aslist(data.get("errors"))][:6], "groups": []}
        for g in windows.aslist(data.get("groups")):
            if not isinstance(g, dict):
                return None
            eid = int(g["id"])
            if eid not in (1121, 1122, 1123, 1124):
                return None
            out["groups"].append({"id": eid, "rule": str(g.get("rule") or "").lower()[:40],
                                  "path": str(g.get("path") or "")[:400], "process": str(g.get("process") or "")[:400],
                                  "count": max(1, int(g["count"])), "last": str(g.get("last") or "")[:40],
                                  "own_check": g.get("own_check") is True})
    except (KeyError, TypeError, ValueError):
        return None
    return out


def describe(group):
    """One finding for one (rule, blocked program, by) group."""
    eid, rule, path, process = group["id"], group["rule"], group["path"], group["process"]
    count, last = group["count"], group["last"]
    times = f"{count} time{'s' if count != 1 else ''} in the last 24 hours" + (f", last at {last}" if last else "")
    audit = eid in (1122, 1124)
    verb = "would have blocked" if audit else "blocked"
    if eid in (1123, 1124):
        return _finding(
            "windows security", "low" if audit else "medium",
            f"Windows {verb} {_base(process)} changing a protected folder",
            f"Controlled folder access {verb} {_base(process)} writing to {path or 'a protected folder'}, {times}. "
            "If you trust that program, an administrator can allow it in Windows Security under Ransomware "
            "protection. If you do not recognise it, that is worth a look.", process or CHANNEL)
    what, severity = RULES.get(rule, (f"an action under rule {rule or 'with no id'}", "medium"))
    own = bool(OWN.search(path) or OWN.search(process))
    if rule == REPUTATION and group.get("own_check"):
        # Argus's own file check opened the file and Windows refused the read. The file is
        # blocked from running on this machine; nothing tried to run it.
        return _finding(
            "windows security", "low", f"Windows refused Argus's check of {_base(path)}",
            f"{path}, {times}. Argus opens new programs in download and temporary folders to check "
            "their signature, and Windows Security refuses because its rule against programs it has not "
            "seen often or for long covers this file. That also means the file cannot run here. Argus "
            "now checks each such file once, not on every pass. If you no longer need the file, deleting "
            "it ends these records.", path or CHANNEL)
    if rule == LSASS and WINDOWS_DIR.match(path or ""):
        severity = "low"
        note = (" The program is one of Windows' own services; Windows blocks these routinely and "
                "nothing was lost.")
    elif rule == REPUTATION and own:
        severity = "high"
        # Windows records a refused open and a refused start the same way, so say both.
        note = (" This is part of Argus itself. Windows refused to let it be opened or started, so if this "
                "was an attempt to install or run it, that part did not run and your protection is reduced. "
                "Windows blocks it because the file is new and not yet signed by a publisher it knows. "
                "An administrator can allow this one file (elevated PowerShell): "
                f"Add-MpPreference -AttackSurfaceReductionOnlyExclusions '{path}' . That allows only this "
                "path; do not exclude a whole folder that ordinary programs can write to.")
    elif rule == REPUTATION:
        note = (" This rule stops any program Microsoft has not seen often or for long: new installers, "
                "tools you built, and real threats alike. If you meant to run it and trust where it came "
                "from, an administrator can allow that one file. If you did not start it, leave it blocked.")
    else:
        note = (" Windows stopped it; nothing ran. This is how several attacks begin, so if you did not "
                "expect it, look at what was open at the time.")
    if audit:
        severity = "low"
        note = " The rule is in audit mode, so nothing was stopped." + note
    title = (f"Windows {verb} part of Argus: {_base(path)}" if own and rule == REPUTATION
             else f"Windows {verb} {what}: {_base(path)}")
    by = f", started by {_base(process)}" if process and rule != LSASS else ""
    return _finding("windows security", severity, title,
                    f"{path or _base(path)}{by}, {times}.{note}", path or CHANNEL)


def audit(hosts=("wsl", "win"), reader=None):
    if "win" not in hosts:
        return []
    data = (reader or (lambda: windows.ps_json(PS_READER, timeout=45)))()
    if data is None:
        collection.failed("winblocks", "Windows did not answer")
        return [_finding("visibility", "low", "Windows Security's block record was not read",
                         "Windows did not answer; nothing is known about blocked actions this pass.", CHANNEL)]
    answer = _valid(data)
    if answer is None or answer["errors"]:
        why = "; ".join(answer["errors"]) if answer else "the reader's answer was malformed"
        collection.failed("winblocks", why[:160])
        return [_finding("visibility", "low", "Windows Security's block record was not read",
                         f"{why}; nothing is known about blocked actions this pass.", CHANNEL)]
    groups = sorted(answer["groups"], key=lambda g: -g["count"])
    out = [describe(g) for g in groups[:MAX_FINDINGS]]
    if answer["more"] or len(groups) > MAX_FINDINGS:
        out.append(_finding("visibility", "low", "Windows blocked more than is listed",
                            f"{answer['read']} block records were read and more exist than this pass lists; "
                            "the most frequent are shown.", CHANNEL))
    collection.succeeded("winblocks")
    return out
