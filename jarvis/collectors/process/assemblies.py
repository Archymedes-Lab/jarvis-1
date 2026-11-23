"""PE images and .NET assemblies that sit in memory with no file behind them.

memscan.ps1 reports every PE header at the start of committed private or
pagefile-backed memory: a module that was copied into a process rather than
loaded by the Windows loader. That is how reflective DLL loading, manual
mapping and in-memory .NET execution (execute-assembly, download cradles)
work, and it is also how Windows PowerShell's own Add-Type loads the C# that
five JARVIS scripts compile at run time. On 2026-09-28 every in-memory
assembly on this machine was one of those.

So a copied-in assembly is recognised as JARVIS's own only when all of these
hold, and is reported otherwise:

  * its host runs exactly a reviewed script from the sealed release: a
    -Command launch whose decoded script text hashes to that script, or, for
    the resident input hook, a -File launch of the installed copy whose
    fingerprint equals the release copy;
  * every identifier in the assembly's metadata #Strings heap (types,
    methods, fields, native imports, references) is a token of that script or
    one of the names the C# compiler generates for language constructs;
  * the host holds no more such assemblies than the script compiles.

Recognition is inventory, never silence: recognised images are counted in a
low finding. A native image with no file is high. An unrecognised managed
image is high outside PowerShell, high in PowerShell when it names injection
or credential APIs or known offensive tooling, and medium otherwise. Jev may
annotate an unrecognised image with an advisory probability, which never
changes severity.
"""

import hashlib
import re

from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import load_win_script, win_script
from jarvis.platform import host as machine
from jarvis.platform.provenance.persistence import normalized_text_hash

# The JARVIS scripts that compile C# with Add-Type. "resident" scripts run as
# a long-lived -File task; the others are launched with -Command from WSL.
OWN_SCRIPTS = {
    "inputhook.ps1": {"resident": True},
    "memscan.ps1": {},
    "hidden.ps1": {},
    "audio_state.ps1": {},
    "window_trace.ps1": {"template": ("__SECONDS__", range(1, 601))},
    # Launched with -Command only while someone watches /procs.
    "procfeed.ps1": {},
}

# Names csc emits for language constructs rather than copying from source:
# the module type, constructors, primitive CLR type names, the attributes it
# applies, and the members `foreach`, `lock`, `using`, delegates, string
# concatenation, `typeof` and indexers lower to. Measured from the three
# live Add-Type assemblies on 2026-09-28, plus the remaining primitives.
COMPILER_NAMES = frozenset({
    "<Module>", "ctor", "cctor", "mscorlib", "Core", "CompilerServices",
    "value__", "method", "result",
    "Boolean", "Byte", "SByte", "Char", "Int16", "UInt16", "Int32", "UInt32",
    "Int64", "UInt64", "Single", "Double", "Decimal", "String", "Object",
    "IntPtr", "UIntPtr", "Void", "ValueType", "Enum",
    "CompilationRelaxationsAttribute", "RuntimeCompatibilityAttribute",
    "DllImportAttribute", "OutAttribute", "StructLayoutAttribute",
    "MarshalAsAttribute", "ComImportAttribute", "GuidAttribute",
    "InterfaceTypeAttribute", "PreserveSigAttribute",
    "Concat", "GetTypeFromHandle", "RuntimeTypeHandle", "Chars", "Item",
    "Dispose", "IDisposable", "GetEnumerator", "MoveNext", "Current",
    "Enumerator", "IEnumerable", "KeyValuePair", "Monitor", "Exit",
    "Invoke", "BeginInvoke", "EndInvoke", "AsyncCallback", "IAsyncResult",
    "MulticastDelegate", "ThreadStart", "Component", "ComponentModel",
})

# Native APIs whose presence in an unrecognised in-memory assembly means it
# can inject, steal credentials, log keys or blind the defences. Exact names;
# a trailing A/W is ignored.
SENSITIVE_APIS = frozenset({
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "NtQueueApcThread", "SetThreadContext", "NtSetContextThread",
    "NtMapViewOfSection", "NtUnmapViewOfSection", "VirtualProtectEx",
    "OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser",
    "MiniDumpWriteDump", "LsaCallAuthenticationPackage",
    "LsaEnumerateLogonSessions", "CredEnumerate", "CryptUnprotectData",
    "SetWindowsHookEx", "GetAsyncKeyState", "AmsiScanBuffer", "EtwEventWrite",
})

# Names of offensive tools and techniques. Matched case-insensitively inside
# identifiers; only the list entry that matched is ever reported or sent.
OFFENSIVE_TERMS = (
    "mimikatz", "sekurlsa", "rubeus", "kerberoast", "seatbelt", "sharphound",
    "dcsync", "shellcode", "payload", "beacon", "meterpreter", "stager",
    "inject", "lsass", "keylog", "amsibypass", "bypassamsi", "patchetw",
    "unhook", "cobalt", "sliver", "covenant", "donut",
)

POWERSHELL_EXES = (r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                   r"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe")

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CACHE = {}          # script name -> (identifiers, compiles, command hashes)


def _script_facts(name):
    """(identifier set, Add-Type count, accepted -Command SHA-256s) of a reviewed script."""
    if name not in _CACHE:
        try:
            text = load_win_script(name)
            with open(win_script(name), encoding="utf-8", errors="replace") as fh:
                translated = fh.read()
        except OSError:
            _CACHE[name] = (frozenset(), 0, frozenset())
            return _CACHE[name]
        idents = frozenset(_TOKEN.findall(text))
        compiles = sum(1 for line in text.splitlines()
                       if re.search(r"\bAdd-Type\b", line.split("#", 1)[0]))
        bodies = {text, translated}
        template = OWN_SCRIPTS[name].get("template")
        if template:
            marker, values = template
            bodies = {b.replace(marker, str(v)) for b in bodies for v in values}
        hashes = frozenset(hashlib.sha256(b.encode("utf-8")).hexdigest() for b in bodies)
        _CACHE[name] = (idents, compiles, hashes)
    return _CACHE[name]


def tokens(identifier):
    """The source-level tokens a metadata string came from."""
    base = re.sub(r"`\d+$", "", identifier)
    out = []
    for part in base.split("."):
        part = re.sub(r"^(get_|set_|add_|remove_)", "", part)
        if part:
            out.append(part)
    return out


def unexplained(strings, module, idents):
    """Metadata strings not accounted for by the script and the compiler."""
    stem = (module or "").rsplit(".", 1)[0]
    left = []
    for s in strings or ():
        if s in (module, stem) or s.startswith("op_"):
            continue
        if re.fullmatch(r"[A-Za-z0-9_]+\.dll", s, re.I) and s[:-4] in idents:
            continue
        if any(t not in idents and t not in COMPILER_NAMES for t in tokens(s)):
            left.append(s)
    return left


def sensitive(strings):
    hits = set()
    for s in strings or ():
        name = re.sub(r"(?<=[a-z])[AW]$", "", s)
        if name in SENSITIVE_APIS:
            hits.add(name)
    return sorted(hits)


def offensive(strings):
    joined = "\n".join(strings or ()).lower()
    return sorted(t for t in OFFENSIVE_TERMS if t in joined)


def _wsl_path(win_path):
    if not win_path or not re.match(r"^[A-Za-z]:\\", win_path):
        return ""
    return machine.local_path(win_path)


def host_script(host, local_app_data):
    """The reviewed script a PowerShell host is verifiably running, or ""."""
    if (host.get("exe") or "").casefold() not in POWERSHELL_EXES:
        return ""
    if host.get("launch") == "command":
        sha = (host.get("command_sha256") or "").lower()
        for name, facts in OWN_SCRIPTS.items():
            if not facts.get("resident") and sha and sha in _script_facts(name)[2]:
                return name
        return ""
    if host.get("launch") == "file" and local_app_data:
        for name, facts in OWN_SCRIPTS.items():
            if not facts.get("resident"):
                continue
            expected = local_app_data.rstrip("\\") + "\\Jarvis\\" + name
            if (host.get("file") or "").casefold() != expected.casefold():
                continue
            installed = normalized_text_hash(_wsl_path(host["file"]))
            if installed and installed == normalized_text_hash(str(win_script(name))):
                return name
    return ""


def classify(procs, hosts, local_app_data):
    """Each copied-in image with its verdict. Pure apart from reading scripts."""
    by_pid = {int(h.get("pid") or 0): h for h in hosts or () if isinstance(h, dict)}
    out = []
    for p in procs or ():
        images = [i for i in (p.get("foreign") or []) if isinstance(i, dict)]
        if not images:
            continue
        pid = int(p.get("pid") or 0)
        host = by_pid.get(pid, {})
        script = "" if p.get("self") else host_script(host, local_app_data)
        idents, compiles, _ = _script_facts(script) if script else (frozenset(), 0, None)
        recognised = 0
        for image in images:
            strings = image.get("strings") or []
            row = {"pid": pid, "name": p.get("name") or "", "host": host, "image": image,
                   "sensitive": sensitive(strings), "offensive": offensive(strings),
                   "unexplained": [], "script": script}
            if p.get("self") and image.get("managed"):
                row["verdict"] = "self"
            elif not image.get("managed"):
                row["verdict"] = "native"
            elif not image.get("parsed"):
                row["verdict"] = "unparsed"
            else:
                left = unexplained(strings, image.get("module"), idents) if script else None
                if script and not left and recognised < compiles:
                    recognised += 1
                    row["verdict"] = "recognised"
                else:
                    if left is None:
                        left = unexplained(strings, image.get("module"), frozenset())
                    row["unexplained"] = left[:8]
                    row["verdict"] = "unrecognised"
            out.append(row)
    return out


def severity(row):
    if row["verdict"] in ("self", "recognised"):
        return "low"
    if row["verdict"] == "native":
        return "high"
    in_powershell = (row["host"].get("exe") or "").casefold() in POWERSHELL_EXES
    if not in_powershell or row["sensitive"] or row["offensive"]:
        return "high"
    return "medium"


def features(row):
    """Metadata-only features for the advisory Jev judgment. Never names,
    identifiers, paths or command lines: fixed-list hits and coarse facts."""
    img, host = row["image"], row["host"]
    size = int(img.get("size") or 0)
    return {
        "host_executable": (host.get("exe") or row["name"]).replace("/", "\\").rsplit("\\", 1)[-1].lower(),
        "launch": host.get("launch") or "unknown",
        "parent_executable": (host.get("parent_exe") or "").rsplit("\\", 1)[-1].lower(),
        "managed": bool(img.get("managed")),
        "executable_memory": bool(img.get("exec")),
        "private_memory": bool(img.get("private")),
        "size_bucket": "under 64 KiB" if size < 65536 else "under 1 MiB" if size < 1 << 20 else "1 MiB or more",
        "sensitive_native_apis": row["sensitive"],
        "offensive_terms": row["offensive"],
        "identifier_count": int(img.get("strings_total") or 0),
        "unexplained_identifier_count": len(row["unexplained"]),
    }


def findings(rows, advise=None):
    """Findings for classified images. `advise(row) -> str` may add a line."""
    out = []
    own = [r for r in rows if r["verdict"] in ("self", "recognised")]
    if own:
        scripts = sorted({r["script"] or "the memory scanner" for r in own})
        out.append(_finding(
            "injected code", "low",
            f"{len(own)} in-memory .NET assemblies verified as JARVIS's own",
            "compiled at run time by " + ", ".join(scripts) + "; each host runs the "
            "reviewed script exactly and every metadata identifier is accounted for "
            "by that script", "Add-Type"))
    for r in rows:
        if r["verdict"] in ("self", "recognised"):
            continue
        img, sev = r["image"], severity(r)
        kind = "native module" if r["verdict"] == "native" else ".NET assembly"
        detail = (f"a {kind} ({int(img.get('size') or 0) // 1024} KiB, "
                  f"{'executable' if img.get('exec') else 'non-executable'} "
                  f"{'private' if img.get('private') else 'pagefile-backed'} memory) "
                  "was copied into this process instead of loaded from a file")
        if img.get("module"):
            detail += f"; module name {img['module']}"
        if r["sensitive"]:
            detail += "; imports " + ", ".join(r["sensitive"])
        if r["offensive"]:
            detail += "; names offensive tooling: " + ", ".join(r["offensive"])
        if r["verdict"] == "unrecognised" and r["unexplained"]:
            detail += "; identifiers not from any reviewed JARVIS script: " + ", ".join(r["unexplained"])
        if r["verdict"] == "unparsed":
            detail += "; its metadata could not be read"
        host = r["host"]
        if host:
            detail += (f". Host launched via {host.get('launch') or 'unknown'}"
                       + (f" from {host.get('parent_exe')}" if host.get("parent_exe") else ""))
        detail += (". Capture a memory dump of the process before acting; do not "
                   "terminate it first")
        if advise:
            note = advise(r)
            if note:
                detail += ". " + note
        out.append(_finding(
            "injected code", sev,
            f"{r['name']} holds a {kind} with no file behind it",
            detail, f"pid {r['pid']}"))
    return out
