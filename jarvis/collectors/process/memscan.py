"""Instruction-level inspection: code with no file behind it, and hooked stubs.

Everything else here reasons about files, registry values and processes. This
module looks one level down, at what is actually mapped and executable inside a
running process, and asks three questions:

**Is there executable memory that no file backs?** A module loaded from disk is
`MEM_IMAGE`. Code written into a process at runtime — reflective loading, manual
mapping, module stomping, plain shellcode — is `MEM_PRIVATE` and executable,
because there is no file for it to be backed by. That distinction is the single
most durable signal for in-memory implants: it does not depend on knowing the
malware, only on the fact that code has to be executable to run.

**Do ntdll's syscall stubs still look like syscall stubs?** On x64 every one
starts `4C 8B D1 B8 <ssn>` — `mov r10,rcx; mov eax,SSN`. A jump at byte zero
means something is intercepting the call before the kernel sees it. That is how
userland hooks work, whether the hooker is an EDR or an implant.

**Are the exploit mitigations actually on?** CFG, ACG and CET/shadow-stack are
what stand between a memory bug and an execution primitive.

**Is a whole module in memory that no file backs?** A PE header copied into
private or pagefile-backed memory is reflective loading, manual mapping or an
in-memory .NET assembly. JIT output never looks like that, so this check is
independent of the JIT excuse below; `assemblies.py` decides which of those
images JARVIS's own Add-Type scripts produced.

The honest caveat, and it is a large one: **just-in-time compilers legitimately
produce exactly the artifact this looks for.** Browsers, Node, .NET, Java and
every JS engine allocate private executable memory as their normal operation,
and on a developer's machine that is most of what is running. So JIT processes
are classified as expected rather than reported, and the finding for anything
else says how much and where — not "malware". Sampling memory also cannot prove
absence: a region can be allocated, executed and freed between two passes.
"""


import os
import re

from jarvis.collectors.process import assemblies
from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import win_script
from jarvis.platform import broker, host
from jarvis.platform.windows import aslist, ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"injected code": 0, "hooked syscalls": 1, "mitigations": 2,
             "visibility": 3}
# System mitigations Windows enables when left unset.
SYSTEM_DEFAULT_ON = frozenset({"cfg"})

SCAN_PS1 = str(win_script("memscan.ps1"))

# Runtimes that compile code at run time. Private executable memory is their
# normal operating state, not evidence of anything.
JIT_PROCESSES = {
    "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera",
    "node", "bun", "deno", "electron", "code", "cursor", "discord",
    "slack", "teams", "ms-teams", "spotify", "obsidian", "notion",
    "java", "javaw", "dotnet", "powershell", "pwsh", "python", "python3",
    "ollama", "lmstudio", "unity", "unrealeditor", "steamwebhelper",
    "widgets", "searchhost", "startmenuexperiencehost", "shellexperiencehost",
    "textinputhost", "applicationframehost", "explorer", "windowsterminal",
    "razer synapse", "logioptionsplus", "nvcontainer", "riotclientux",
    # Electron and WebView2 apps embed the same JS engine, so they JIT too.
    "chatgpt classic", "chatgpt", "claude", "signal", "whatsapp", "vivaldi",
    "chromium", "widgetboard", "m365copilot", "systemsettings", "crossdeviceservice",
}

# Browser sandboxes patch ntdll in their own processes to enforce policy —
# Chromium and Gecko both intercept exactly these two calls so a renderer
# cannot open another process or map a section outside the sandbox. The first
# live run found 49 processes "hooked" and every one was firefox,
# msedgewebview2 or an Electron app, patching only these two stubs. That is the
# browser working correctly, and reporting it as userland interception would
# bury a real hook under fifty false ones.
SANDBOX_STUBS = {"NtOpenProcess", "NtMapViewOfSection", "NtCreateSection",
                 "NtCreateThreadEx", "NtSetContextThread"}
SANDBOXED_APPS = {
    "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera",
    "vivaldi", "chromium", "electron", "discord", "slack", "teams",
    "ms-teams", "spotify", "obsidian", "notion", "chatgpt classic",
    "chatgpt", "claude", "cursor", "code", "signal", "whatsapp",
}

# EDR and anti-cheat products hook ntdll on purpose. Their presence is worth
# naming, not alarming about.
KNOWN_HOOKERS = {
    "msmpeng", "mssense", "sensecncproxy", "cylancesvc", "csfalconservice",
    "sentinelagent", "sophosed", "avp", "avgsvc", "avastsvc", "mbamservice",
    "elastic-endpoint", "carbonblack", "cbdefense", "tanium", "traps",
    "cyoptics", "wdfilter", "cyveraservice", "vgk", "vgtray", "vanguard",
    "easyanticheat", "battleye", "faceit",
}


def _run(timeout=420):
    # Elevated, the scan opens every process instead of about half of them.
    data, _why = broker.result("memscan")
    if data:
        return dict(data, _elevated=True), ""
    try:
        with open(SCAN_PS1, encoding="utf-8", errors="replace") as fh:
            script = fh.read()
    except OSError as exc:
        return None, f"could not read the scan helper: {exc}"
    data = ps_json(script, timeout=timeout)
    if not data:
        return None, "powershell.exe returned no data"
    return data, ""


def _human(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return str(n)


# Markers of a .NET single-file executable: the host, the core library and
# the JIT's own attach state are linked into the one image, so no separate
# coreclr.dll/clrjit.dll module is loaded to explain its JIT memory.
SINGLE_FILE_MARKERS = (b"singlefilehost", b"System.Private.CoreLib", b"CLRJitAttachState")
SINGLE_FILE_RUNTIME = ".NET single-file host (JIT linked into the executable)"
_EMBEDDED = {}      # (path, size, mtime) -> runtime label or ""


def _has_markers(path, markers=SINGLE_FILE_MARKERS, chunk=8 << 20):
    left, tail = set(markers), b""
    overlap = max(len(m) for m in markers)
    with open(path, "rb") as fh:
        while left:
            block = fh.read(chunk)
            if not block:
                break
            window = tail + block
            left = {m for m in left if m not in window}
            tail = window[-overlap:]
    return not left


def _authenticode_valid(win_path):
    script = ("$s=Get-AuthenticodeSignature -LiteralPath '" + win_path.replace("'", "''") +
              "';[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
              "(ConvertTo-Json -Compress @{status=[string]$s.Status})))")
    result = ps_json(script, timeout=60)
    return isinstance(result, dict) and result.get("status") == "Valid"


def _wsl_path(win_path):
    if not win_path or not re.match(r"^[A-Za-z]:\\", win_path):
        return ""
    return host.local_path(win_path)


def _embedded_runtime(win_path):
    """The JIT runtime linked into a validly signed .NET single-file
    executable, or "". Unsigned or unverifiable images explain nothing: the
    markers alone are just strings an implant could carry."""
    wsl = _wsl_path(win_path)
    if not wsl:
        return ""
    try:
        st = os.stat(wsl)
    except OSError:
        return ""
    key = (win_path.lower(), st.st_size, int(st.st_mtime))
    if key not in _EMBEDDED:
        try:
            verdict = (SINGLE_FILE_RUNTIME if _has_markers(wsl)
                       and _authenticode_valid(win_path) else "")
        except OSError:
            verdict = ""
        _EMBEDDED[key] = verdict
    return _EMBEDDED[key]


def audit(hosts=("win",), advise=None):
    if "win" not in hosts:
        return []
    data, err = _run()
    if err:
        return [_finding("visibility", "medium", "memory scan unavailable", err)]

    out = []
    mem = data.get("memory") or {}
    opened = int(mem.get("opened") or 0)
    denied = int(mem.get("denied") or 0)
    procs = aslist(mem.get("procs"))

    if denied and data.get("_elevated"):
        # Elevated, what remains is Protected Process Light (lsass, csrss,
        # Defender): closed to administrator by design, openable only from the
        # kernel. That is this collector's boundary, not a lapse in coverage.
        out.append(_finding(
            "limits", "low",
            f"{denied} protected processes are outside the memory scan",
            f"{opened} were scanned with an administrator token. The rest run as "
            f"Protected Process Light, which Windows keeps closed to administrator "
            f"— only a kernel driver could read them", "OpenProcess"))
    elif denied:
        out.append(_finding(
            "visibility", "medium" if denied > opened else "low",
            f"{denied} processes could not be opened for inspection",
            f"{opened} were scanned. Reading another user's or a protected "
            f"process's memory needs elevation, so anything hiding in one of "
            f"those is outside this result — run elevated for full coverage",
            "OpenProcess"))

    # -- unbacked executable memory ---------------------------------------
    # Grouped by program, not by pid: a browser with twenty renderers is one
    # fact about that browser, not twenty findings.
    jit_total = 0
    groups = {}
    for p in procs:
        name = (p.get("name") or "").lower()
        regions = int(p.get("regions") or 0)
        if not regions:
            continue
        if name in JIT_PROCESSES:
            jit_total += 1
            continue
        g = groups.setdefault(name, {"pids": [], "regions": 0, "bytes": 0,
                                     "rwx": 0, "runtimes": set(), "unexplained": 0})
        g["pids"].append(p.get("pid"))
        g["regions"] += regions
        g["bytes"] += int(p.get("bytes") or 0)
        g["rwx"] += int(p.get("rwx") or 0)
        runtime = p.get("runtime") or _embedded_runtime(p.get("path"))
        if runtime:
            g["runtimes"].add(runtime)
        else:
            g["unexplained"] += 1

    for name, g in groups.items():
        # RWX is the stronger signal: writable *and* executable at once is what
        # a stager needs and what most legitimate code deliberately avoids.
        sev = "high" if g["rwx"] else "medium"
        if g["bytes"] < 8192 and not g["rwx"]:
            sev = "low"
        # Every process of this program has a JIT engine loaded, which accounts
        # for the memory. Kept as inventory rather than dropped, so a program
        # that stops loading its runtime and keeps the memory shows up again.
        jit = sorted(g["runtimes"]) if not g["unexplained"] else []
        if jit:
            sev = "low"
        n_pids = len(g["pids"])
        where = (f"pid {g['pids'][0]}" if n_pids == 1
                 else f"{n_pids} processes, e.g. pid {g['pids'][0]}")
        out.append(_finding(
            "injected code", sev,
            f"{name} has executable memory no file backs"
            + (f" ({n_pids} processes)" if n_pids > 1 else ""),
            f"{g['regions']} private executable region"
            f"{'s' if g['regions'] > 1 else ''}, {_human(g['bytes'])}"
            + (f", {g['rwx']} writable at the same time (RWX)"
               if g["rwx"] else "")
            + (f" — the process hosts the {', '.join(jit)} JIT runtime, which "
               "compiles code into exactly this kind of memory." if jit else
               " — code written into the process at runtime rather than loaded "
               "from disk. Confirm with a memory dump before acting; packers, "
               "installers and anti-cheat do this legitimately."),
            where))
    if jit_total:
        out.append(_finding(
            "injected code", "ok",
            f"{jit_total} JIT processes have private executable memory, as expected",
            "browsers, Node, .NET and Java compile code at run time — this is "
            "their normal operation, not a finding", "JIT allowlist"))

    # -- whole images copied into memory -----------------------------------
    rows = assemblies.classify(procs, aslist(data.get("hosts")),
                               data.get("local_app_data") or "")
    out.extend(assemblies.findings(rows, advise=advise))

    # -- hooked syscall stubs ----------------------------------------------
    hooked = [p for p in procs if (p.get("stubs") or "").strip()]
    sandboxed, unexplained = [], []
    for p in hooked:
        name = (p.get("name") or "").lower()
        names = [s.split("=")[0] for s in (p.get("stubs") or "").split(";")
                 if "=" in s]
        if name in SANDBOXED_APPS and set(names) <= SANDBOX_STUBS:
            sandboxed.append(p)
        else:
            unexplained.append((p, name, names))

    if sandboxed:
        # One line for the whole class. Fifty identical findings is not fifty
        # facts, and it hides the one that would matter.
        by_app = {}
        for p in sandboxed:
            by_app[(p.get("name") or "").lower()] = \
                by_app.get((p.get("name") or "").lower(), 0) + 1
        out.append(_finding(
            "hooked syscalls", "ok",
            f"{len(sandboxed)} browser processes patch ntdll for sandboxing, "
            f"as expected",
            ", ".join(f"{n} ×{c}" for n, c in sorted(by_app.items()))
            + " — Chromium and Gecko intercept NtOpenProcess and "
              "NtMapViewOfSection so a renderer cannot escape its sandbox",
            "browser sandbox"))

    for p, name, names in unexplained:
        known = name in KNOWN_HOOKERS
        out.append(_finding(
            "hooked syscalls", "low" if known else "high",
            f"{name} [pid {p.get('pid')}] has {len(names)} patched ntdll stub"
            f"{'s' if len(names) != 1 else ''}",
            f"{', '.join(names[:6])}"
            + (f" and {len(names) - 6} more" if len(names) > 6 else "")
            + (" — this is a security product hooking on purpose"
               if known else
               " — the first bytes are not a syscall prologue, so these calls "
               "are being intercepted in userland before reaching the kernel"),
            f"pid {p.get('pid')}"))
    if not hooked and opened:
        out.append(_finding(
            "hooked syscalls", "ok",
            "ntdll syscall stubs are intact in every process scanned",
            f"{opened} processes checked against the expected "
            f"`mov r10,rcx; mov eax,SSN` prologue", "ntdll"))

    # -- mitigations --------------------------------------------------------
    sysm = data.get("system") or {}
    for key, label, why in (
            ("cet", "CET / hardware shadow stack",
             "returns are not validated against a shadow stack, so ROP stays "
             "viable"),
            ("cfg", "Control Flow Guard",
             "indirect calls are not validated against a table of legal targets"),
            ("aslr", "mandatory ASLR (ForceRelocateImages)",
             "images without relocation info load at predictable addresses")):
        val = str(sysm.get(key) or "").upper()
        # NOTSET means "use the Windows default". CFG's system default is on
        # (Windows Security: "Use default (On)"; a running CFG-built process
        # reports it enabled with no setting), so only an explicit OFF weakens
        # it. Mandatory ASLR and CET default to off, so NOTSET is off.
        unset_is_off = key not in SYSTEM_DEFAULT_ON
        if val and ("OFF" in val or "FALSE" in val
                    or (val == "NOTSET" and unset_is_off)):
            out.append(_finding(
                "mitigations", "medium",
                f"system-wide {label} is not enforced", why,
                "Get-ProcessMitigation -System"))

    for m in aslist(data.get("mitigations")):
        weak = []
        if "OFF" in str(m.get("cfg") or "").upper():
            weak.append("CFG")
        if "OFF" in str(m.get("dep") or "").upper():
            weak.append("DEP")
        if weak:
            out.append(_finding(
                "mitigations", "high" if "DEP" in weak else "medium",
                f"{m.get('name')} runs without {', '.join(weak)}",
                "a memory-corruption bug in this process is much closer to "
                "code execution without it", f"pid {m.get('pid')}"))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
