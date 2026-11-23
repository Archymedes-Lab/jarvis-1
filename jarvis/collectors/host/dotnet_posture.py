""".NET runtime hijack points and the AMSI provider chain.

The CLR honours a handful of settings before any managed code runs. Each one
is a documented way to load an attacker's DLL or managed code into every
.NET process a user (or, at machine scope, every account) starts, or to
switch off the runtime telemetry that would record it:

  profiler variables          COR_/CORECLR_ PROFILER*, ENABLE_PROFILING (T1574.012)
  DOTNET_STARTUP_HOOKS        managed code run before Main
  APPDOMAIN_MANAGER_ASM/TYPE  AppDomainManager injection
  AltJit/JitName/GCName       the runtime loads a replacement JIT or GC DLL
  ETWEnabled = 0              runtime ETW (assembly loads, JIT) goes silent

AMSI is how Defender sees scripts and in-memory assemblies before they run.
Removing or redirecting its provider, or turning AmsiEnable off, is a common
bypass. The baseline measured on this machine on 2026-09-28 was: no CLR
variables, only the default .NETFramework values, and exactly Defender's AMSI
provider. Every deviation is reported; nothing is changed.
"""

import re

from jarvis.core import collection
from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

PS_DOTNET = load_win_script("dotnet_posture.ps1")
WHERE = ".NET runtime configuration"

DEFENDER_AMSI = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"
DEFENDER_DLL = re.compile(
    r'^"?(?:C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[0-9.\-]+'
    r'|C:\\Program Files\\Windows Defender)\\MpOav\.dll"?$', re.I)

# Environment variables that inject code into .NET processes.
INJECTION_VARS = re.compile(
    r"^(COR|CORECLR)_(ENABLE_PROFILING|PROFILER|PROFILER_PATH(_32|_64)?)$"
    r"|^DOTNET_STARTUP_HOOKS$|^APPDOMAIN_MANAGER_(ASM|TYPE)$", re.I)
# CLR settings, via COMPlus_/DOTNET_ variables or .NETFramework registry
# values, that load a replacement runtime component.
COMPONENT_SETTINGS = {"altjit", "altjitname", "altjitngen", "jitname", "gcname"}
# Developer conveniences that change nothing about what the runtime loads.
BENIGN_VARS = {"dotnet_cli_telemetry_optout", "dotnet_nologo", "dotnet_root",
               "dotnet_root_x86", "dotnet_cli_home",
               "dotnet_skip_first_time_experience", "dotnet_cli_ui_language"}
DEFAULT_REGISTRY = {"enable64bit", "installroot", "useryujit",
                    "dbgjitdebuglaunchsetting", "onlyuselatestclr"}


def _finding(severity, title, detail, where=WHERE):
    return {"host": "win", "category": "dotnet", "severity": severity,
            "title": title, "detail": detail, "where": where}


def _setting(name):
    """The CLR setting a COMPlus_/DOTNET_ variable carries, lower-cased."""
    m = re.match(r"^(COMPLUS_|DOTNET_)(.+)$", name, re.I)
    return m.group(2).lower() if m else ""


def analyse(data):
    out = []
    env = [e for e in aslist(data.get("env")) if isinstance(e, dict)]
    registry = [r for r in aslist(data.get("registry")) if isinstance(r, dict)]

    for e in env:
        name, value, scope = e.get("name") or "", e.get("value") or "", e.get("scope") or ""
        setting = _setting(name)
        reach = ("every account's .NET processes" if scope == "machine"
                 else "every .NET process this user starts")
        if INJECTION_VARS.match(name):
            out.append(_finding(
                "high", f"{name} makes the .NET runtime load code into {reach}",
                f"{scope} environment: {name}={value}. Unless an APM or profiling "
                "tool you installed set this, it is code injection into every "
                ".NET program, including elevated ones", f"{scope} environment"))
        elif setting == "etwenabled" and value.strip() in ("0", "0x0"):
            out.append(_finding(
                "high", f"{name}=0 switches off .NET runtime telemetry",
                f"{scope} environment: assembly loads and JIT events stop being "
                "reported, which blinds detection of in-memory .NET tooling",
                f"{scope} environment"))
        elif setting in COMPONENT_SETTINGS:
            out.append(_finding(
                "high", f"{name} makes the .NET runtime load a replacement component",
                f"{scope} environment: {name}={value}", f"{scope} environment"))
        elif name.lower() not in BENIGN_VARS:
            out.append(_finding(
                "low", f"{name} changes .NET runtime behaviour",
                f"{scope} environment: {name}={value}", f"{scope} environment"))

    for r in registry:
        name, value, key = r.get("name") or "", r.get("value") or "", r.get("key") or ""
        low = name.lower()
        if low == "etwenabled" and value.strip() in ("0", "0x0"):
            out.append(_finding("high", "the .NET Framework's runtime telemetry is switched off",
                                f"{key}\\ETWEnabled=0", key))
        elif low in COMPONENT_SETTINGS:
            out.append(_finding("high", f"the .NET Framework is set to load a replacement {name}",
                                f"{key}\\{name}={value}", key))
        elif low == "dbgmanageddebugger":
            out.append(_finding(
                "medium", "a program is registered to launch when any .NET program crashes",
                f"{key}\\DbgManagedDebugger={value}. Visual Studio installs its own; "
                "any other value runs on every unhandled exception", key))
        elif low not in DEFAULT_REGISTRY:
            out.append(_finding("low", f".NET Framework registry setting {name}",
                                f"{key}\\{name}={value}", key))

    providers = [p for p in aslist(data.get("amsi")) if isinstance(p, dict)]
    defender = [p for p in providers if (p.get("clsid") or "").upper() == DEFENDER_AMSI]
    if not providers:
        out.append(_finding(
            "high", "no AMSI provider is registered",
            "nothing scans PowerShell, script hosts or in-memory .NET assemblies "
            "before they run; removing the provider is a known AMSI bypass",
            "HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers"))
    elif not defender:
        out.append(_finding(
            "medium", "Defender's AMSI provider is not registered",
            "registered: " + ", ".join(f"{p.get('clsid')} -> {p.get('dll')}" for p in providers)
            + ". Expected when another antivirus replaced Defender; otherwise a bypass",
            "HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers"))
    for p in defender:
        if not DEFENDER_DLL.match((p.get("dll") or "").strip()):
            out.append(_finding(
                "high", "Defender's AMSI provider points at an unexpected DLL",
                f"{p.get('clsid')} -> {p.get('dll') or '(no DLL)'}; the provider is "
                "loaded into every process that uses AMSI",
                "HKCR\\CLSID\\" + DEFENDER_AMSI))
    for p in providers:
        if p not in defender:
            out.append(_finding(
                "medium", "an additional AMSI provider is registered",
                f"{p.get('clsid')} -> {p.get('dll') or '(no DLL)'}. It is loaded "
                "into every process that uses AMSI and sees every script it scans; "
                "confirm it belongs to installed security software",
                "HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers"))
    for a in aslist(data.get("amsi_enable")):
        if isinstance(a, dict) and str(a.get("value")).strip() in ("0", "0x0"):
            out.append(_finding("high", "AMSI is switched off for Windows Script Host",
                                f"{a.get('key')}\\AmsiEnable=0", a.get("key") or WHERE))

    if not out:
        benign = sorted({str(e.get("name")) for e in env
                         if str(e.get("name") or "").lower() in BENIGN_VARS})
        benign_note = ("; harmless developer variables: " + ", ".join(benign)) if benign else ""
        out.append(_finding(
            "ok", "no .NET runtime hijack settings; Defender's AMSI provider is in place",
            f"{len(env)} CLR variables, {len(registry)} .NETFramework registry values "
            f"(all defaults), {len(providers)} AMSI provider(s){benign_note}"))
    return out


def audit(hosts=("win",)):
    if "win" not in hosts:
        return []
    data = ps_json(PS_DOTNET, timeout=60)
    if not isinstance(data, dict):
        collection.failed("dotnet", "probe returned no data")
        return [_finding("medium", ".NET runtime configuration could not be read",
                         "powershell.exe returned no data; hijack points are unverified")]
    errors = [str(e) for e in aslist(data.get("errors"))][:8]
    out = analyse(data)
    if errors:
        # AMSI's key missing is itself reported above; other read errors mean
        # part of the configuration went unseen.
        unseen = [e for e in errors if "AMSI provider key" not in e]
        if unseen:
            out.append(_finding("low", "part of the .NET runtime configuration was unreadable",
                                "; ".join(unseen)))
    collection.succeeded("dotnet")
    return out
