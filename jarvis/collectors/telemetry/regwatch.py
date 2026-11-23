"""Writes to security-relevant registry key families, judged by who wrote them.

The registry rules in techniques.py match one key and one value each. Measured
2026-11-10 against Atomic Red Team: of 221 tests that write a registry value,
those 18 rules caught 11. An attacker has thousands of values to choose from;
what does not vary is *where* security settings live and *what kind of program*
normally changes them.

So this module states an invariant per key family instead of a pattern per
value: these families are changed by Windows components, Group Policy and
installers, not by a command-line tool, a script host or a program running
from a folder a standard user can write. A write that breaks that is reported,
whatever the value is.

Invariants
  1. Judged by writer, never by value: the value written is not inspected and
     never quoted (it can carry a credential or a command).
  2. One problem, one finding: a write a specific registry rule already
     reported is not reported again here; writes fold per family and writer.
  3. Bounded: the tables are fixed; findings quote one key of at most 160
     characters and a count.
  4. Single signal: severity is medium, never higher (ALERT-QUALITY rule 4).

Limits, stated: only keys the Sysmon policy records are seen; a write made by
a Windows component on an attacker's behalf (a policy pushed through WMI, an
installer run with a crafted package) is not reported by this rule; the writer
is the process that made the call, not who asked it to.
"""

import re

# (family id, regex over the registry key, technique ids, what the family controls)
FAMILIES = (
    ("policies", r"\\Software\\(Microsoft\\Windows\\CurrentVersion\\Policies|Policies\\Microsoft)\\",
     ("T1112",), "Windows policy settings (what the system and its security features are allowed to do)"),
    ("defender", r"\\Microsoft\\Windows Defender\\", ("T1562.001",), "Microsoft Defender settings"),
    ("lsa", r"\\Control\\(Lsa|SecurityProviders)\\", ("T1547.005", "T1556"),
     "how Windows checks passwords and which security packages it loads"),
    ("winlogon", r"\\Windows NT\\CurrentVersion\\Winlogon\\", ("T1547.004",),
     "what runs when someone signs in"),
    ("autorun", r"\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)\\", ("T1547.001",),
     "programs started automatically at sign-in"),
    ("ifeo", r"\\Windows NT\\CurrentVersion\\(Image File Execution Options|SilentProcessExit)\\",
     ("T1546.012",), "debugger and exit hooks attached to programs"),
    ("accessibility", r"\\Windows NT\\CurrentVersion\\Accessibility\\", ("T1546.008",),
     "accessibility tools reachable from the sign-in screen"),
    ("appinit", r"\\Windows NT\\CurrentVersion\\Windows\\(AppInit_DLLs|LoadAppInit_DLLs)$", ("T1546.010",),
     "libraries loaded into every program"),
    ("timeprovider", r"\\Services\\W32Time\\", ("T1547.003",), "time service providers (libraries run by the system)"),
    ("netprovider", r"\\(Services\\[^\\]+\\NetworkProvider|Control\\NetworkProvider)\\", ("T1556.008",),
     "network providers, which see sign-in passwords"),
    ("service", r"\\Services\\[^\\]+\\(ImagePath|Parameters\\ServiceDll)$", ("T1543.003",),
     "which program a Windows service runs"),
    ("environment", r"\\Control\\Session Manager\\(Environment\\|KnownDLLs\\|AppCertDlls\\)", ("T1574",),
     "system-wide search paths and libraries"),
    ("remote", r"\\Control\\Terminal Server\\", ("T1021.001",), "remote desktop access"),
    ("proxy", r"\\CurrentVersion\\Internet Settings\\(ProxyServer|ProxyEnable|AutoConfigURL)$", ("T1090",),
     "the proxy this account's traffic goes through"),
    # Sysmon writes a user's classes hive as HKU\\<SID>_Classes\\..., the machine's as ...\\Classes\\...
    ("openwith", r"(\\|_)Classes\\[^\\]+\\shell\\open\\command\\", ("T1546.001",),
     "which program opens a kind of file or link"),
)
_FAMILIES = tuple((fid, re.compile(rx, re.I), tids, what) for fid, rx, tids, what in FAMILIES)

# Programs that change the registry because someone typed or scripted it.
TOOLS = frozenset({
    "reg", "regedit", "regedt32", "regini", "powershell", "powershell_ise", "pwsh", "cmd", "wscript",
    "cscript", "mshta", "rundll32", "regsvr32", "wmic", "msbuild", "installutil", "python", "pythonw",
    "node", "perl", "ruby", "bash", "wsl", "sh", "certutil",
})
# Folders a standard user can write. A program there is not a Windows component or a
# machine-wide installation. Autostart entries are left to the autostart inventory
# (collectors/persistence/asep.py): per-user applications register themselves there all day.
# ProgramData is a shared-data tree: its root permits user-created folders, while
# individual vendor folders may be protected. Neither fact establishes the writer's
# provenance from a path. Report such writes conservatively; no vendor-name exemption.
SHARED_DATA = re.compile(r"^[a-z]:\\programdata\\", re.I)
USER_WRITABLE = re.compile(r"^[a-z]:\\(users|temp|windows\\temp|perflogs)\\", re.I)
USER_PATH_SKIP = frozenset({"autorun", "openwith", "proxy"})
SEVERITY = "medium"
MAX_KEY = 160


def _base(image):
    name = (image or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith((".exe", ".com")) else name


def family(key):
    """(family id, technique ids, what it controls) for a registry key, or None."""
    key = (key or "")[:1024]
    for fid, rx, tids, what in _FAMILIES:
        if rx.search(key):
            return fid, tids, what
    return None


def writer_kind(image, fid):
    """Writer evidence: tool, user-path, shared-data (unknown provenance), or none."""
    if _base(image) in TOOLS:
        return "tool"
    if fid not in USER_PATH_SKIP and USER_WRITABLE.search((image or "").replace("/", "\\")):
        return "user-path"
    if fid not in USER_PATH_SKIP and SHARED_DATA.search((image or "").replace("/", "\\")):
        return "shared-data"
    return ""


def judge(image, key):
    """-> (family id, technique ids, what, writer kind) when the write breaks the invariant, else None."""
    fam = family(key)
    if not fam:
        return None
    kind = writer_kind(image, fam[0])
    return (fam[0], fam[1], fam[2], kind) if kind else None


def describe(image, what, kind, key, count, when):
    """(title, detail) for one folded finding."""
    who = _base(image) or "an unknown program"
    if kind == "shared-data":
        return (f"{who} changed {what.split(' (')[0]}",
                f"{who} wrote to {key[:MAX_KEY]}" + (f" at {when}" if when else "")
                + (f", {count} writes in this family" if count > 1 else "")
                + f". This part of the registry holds {what}. The writer runs under ProgramData, "
                  "whose subfolders have different permissions. Its location alone does not establish "
                  "trusted provenance; legitimate vendor security engines may also run there. "
                  "Confirm the executable signature and directory permissions before judging this change. "
                  "The value written is not shown.")
    reason = ("a command-line or scripting tool" if kind == "tool"
              else "a program running from a folder any account can write")
    title = f"{who} changed {what.split(' (')[0]}"
    detail = (f"{who}, {reason}, wrote to {key[:MAX_KEY]}"
              + (f" at {when}" if when else "") + (f", {count} writes in this family" if count > 1 else "")
              + f". This part of the registry holds {what}; Windows components, Group Policy and installers "
                "change it, not this kind of program. The value written is not shown. Whether you or "
                "software you run did this is for you to confirm.")
    return title, detail
