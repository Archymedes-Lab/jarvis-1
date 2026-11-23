"""Evidence that turns an inventory finding into inventory.

The security score's rule is "inventory is not risk": a list of what starts
at login, what services exist, which processes query LSASS is a record, not a
threat. Collectors still report those items at medium when they cannot tell
a vendor's updater from a dropped implant. This module is where that
difference is proven, one finding type at a time, and nowhere else.

A finding is lowered only when the program it names is a file Windows
validates by signature or its exact bytes match a reviewed signed package
payload. Script hosts are never enough: a signed
powershell.exe or rundll32.exe says nothing about what it was told to run.
Anything unresolvable, unsigned, missing or unverifiable keeps its severity.
"""

import re

from jarvis.platform import signatures

# Signed interpreters and loaders: their signature proves nothing about the
# code they are running.
SCRIPT_HOSTS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "python.exe", "pythonw.exe",
    "node.exe", "java.exe", "javaw.exe", "wsl.exe", "bash.exe", "conhost.exe",
    "msiexec.exe", "installutil.exe", "regasm.exe", "msbuild.exe",
})


def _after(sep):
    def pick(finding):
        detail = str(finding.get("detail") or "")
        return detail.split(sep, 1)[1] if sep in detail else ""
    return pick


def _where(finding):
    return str(finding.get("where") or "")


def _run_value(finding):
    return str((finding.get("response_target") or {}).get("value") or "") \
        or _after(" = ")(finding)


def _program_field(finding):
    return str(finding.get("program") or "") or _after(" — ")(finding)


def _shortcut(finding):
    link = _where(finding)
    return signatures.lnk_targets([link]).get(signatures.normalize(link), "") \
        if link.lower().endswith(".lnk") else ""


# (job, title predicate) -> how to find the program the finding is about.
RULES = (
    ("control", lambda t: t == "autostart registry entry", _run_value),
    ("control", lambda t: t == "startup folder item", _shortcut),
    ("firewall", lambda t: t == "service installed recently", _program_field),
    ("sysmon", lambda t: t.endswith(" queried LSASS"), _where),
    # The file itself is unsigned; a Store/System package that installed it
    # into WindowsApps can still be the verified publisher.
    ("spy", lambda t: t.startswith("autostart binary is unsigned"), _where),
)


def _program(command):
    path = signatures.executable(command)
    return path if re.match(r"^[A-Za-z]:\\", path) else ""


def apply(job, findings):
    """Lower proven inventory to low, noting the proof in its detail."""
    pending = []
    for f in findings or ():
        if not isinstance(f, dict) or f.get("severity") != "medium":
            continue
        for rule_job, matches, locate in RULES:
            if job == rule_job and matches(str(f.get("title") or "")):
                program = _program(locate(f))
                name = program.rsplit("\\", 1)[-1].lower()
                if program and name not in SCRIPT_HOSTS:
                    pending.append((f, program))
                break
    if not pending:
        return findings
    verdicts = signatures.verify([p for _, p in pending])
    for f, program in pending:
        verdict = verdicts.get(signatures.normalize(program))
        who = signatures.publisher(verdict)
        if who:
            f["severity"] = "low"
            proof = (f"{program} exactly matches the payload of a valid "
                     f"Microsoft WHCP-signed {who} driver package"
                     if verdict.get("source") == "package_payload" else
                     f"{program} is signed by {who}")
            f["detail"] = f"{f.get('detail') or ''} — verified: {proof}"
    return findings
