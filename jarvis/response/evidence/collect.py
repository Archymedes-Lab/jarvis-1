"""Named sets of artefacts worth collecting together.

Profiles exist so an investigation grabs a complete, reproducible set rather
than whatever the operator remembered at the time. Each entry records why it
is collected, because a case reviewed weeks later is read by someone who was
not present.
"""

from jarvis.platform import host

WINEVT = r"C:\Windows\System32\winevt\Logs"
# An unknown account stays unknown: the target is then reported unreachable,
# never read from another person's profile.
APPDATA = r"C:\Users\%s\AppData" % (host.windows_user() or "unknown Windows user")

#: profile -> [(target path, kind, why)]
PROFILES = {
    "windows-logs": [
        (WINEVT + r"\Microsoft-Windows-Windows Defender%4Operational.evtx",
         "eventlog", "detections, exclusions and scan history"),
        (WINEVT + r"\Microsoft-Windows-PowerShell%4Operational.evtx",
         "eventlog", "script-block and module logging, when enabled"),
        (WINEVT + r"\Windows PowerShell.evtx",
         "eventlog", "engine lifecycle and pipeline execution"),
        (WINEVT + r"\Microsoft-Windows-Sysmon%4Operational.evtx",
         "eventlog", "process creation, network and file events"),
    ],
    "powershell-history": [
        (APPDATA + r"\Roaming\Microsoft\Windows\PowerShell\PSReadline"
                   r"\ConsoleHost_history.txt",
         "history", "command text; no timestamps and no exit status"),
    ],
    "linux-logs": [
        ("/var/log/auth.log", "syslog", "authentication and sudo"),
        ("/var/log/syslog", "syslog", "general system log"),
    ],
}


def profile_names():
    return sorted(PROFILES)


def collect_profile(case, profile, search=True):
    """Collect one profile into `case`. Returns a per-target result list.

    Unreadable targets are reported, not raised: a profile is a best-effort
    sweep, and which targets were unreachable is itself part of the record.
    """
    targets = PROFILES.get(profile)
    if targets is None:
        raise KeyError("unknown profile %r; known: %s"
                       % (profile, ", ".join(profile_names())))
    results = []
    for path, kind, why in targets:
        res = case.add_file(path, kind=kind, note=why, search=search)
        results.append(res)
    ok = sum(1 for r in results if r.get("ok"))
    case.note("collected profile %s: %d/%d targets"
              % (profile, ok, len(results)))
    return results
