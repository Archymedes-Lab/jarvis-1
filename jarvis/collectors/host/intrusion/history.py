"""PowerShell history: the commands an intrusion leaves behind in PSReadLine."""

import re
from urllib.parse import urlsplit

from jarvis.platform.windows import aslist

from .common import _finding

SUSPICIOUS_HISTORY = re.compile(
    r"\b(irm|invoke-restmethod|iwr|invoke-webrequest|curl|wget)\b[^|;\n]*\|\s*(iex|invoke-expression)\b|"
    r"frombase64string|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}|"
    r"downloadstring|downloadfile|"
    r"set-mppreference\s+-disable|add-mppreference\s+-exclusionpath|"
    r"disable-windowsoptionalfeature|"
    r"new-object\s+system\.net\.webclient|"
    # ClickFix delivers its payload as pasted -Command text; -File runs a
    # script that already exists on disk, so the flag says nothing about
    # where that file came from and matches routinely (including JARVIS's
    # own -ExecutionPolicy Bypass -File invocations of its reviewed repair
    # scripts). Only -Command/-c is the actual paste-and-run vector.
    r"bypass\s+-\w*\s*command|start-process\s+-verb\s+runas",
    re.I,
)


# Exact hostname matching: the missing-d MAS lookalike has a documented
# malware-download record (https://urlhaus.abuse.ch/url/3740911/).
# A history entry records a command, not successful payload execution.
HISTORY_MALWARE_HOSTS = frozenset({"get.activate.win"})


def _history_malware_hosts(line):
    hosts = set()
    for url in re.findall(r"https?://[^\s\"'`<>|)]+", line, re.I):
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host in HISTORY_MALWARE_HOSTS:
            hosts.add(host)
    return hosts


# Download-and-execute is also how half of developer tooling installs itself, so
# shape alone cannot separate `iex (irm chocolatey.org/install.ps1)` from a
# ClickFix payload. What does separate them is where the code comes from: an
# HTTPS URL on a known vendor's own domain. A lure has to host its payload
# somewhere, and it is never here.
VENDOR_INSTALL = re.compile(
    r"https://([a-z0-9-]+\.)*("
    r"chocolatey\.org|community\.chocolatey\.org|"
    r"astral\.sh|ollama\.com|rustup\.rs|sh\.rustup\.rs|"
    r"get\.scoop\.sh|scoop\.sh|nodejs\.org|python\.org|"
    r"aka\.ms|microsoft\.com|windows\.net|"
    r"githubusercontent\.com/(docker|nvm-sh|Homebrew|oven-sh|pyenv)/|"
    r"deb\.nodesource\.com|get\.docker\.com|starship\.rs|deno\.land|bun\.sh"
    r")/",
    re.I,
)


# A vendor domain only excuses the URL. If the same line also turns off a
# defence or hides itself, the origin is beside the point.
NEVER_BENIGN = re.compile(
    r"set-mppreference\s+-disable|add-mppreference\s+-exclusionpath|"
    r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}|frombase64string|"
    r"-w(indowstyle)?\s+hidden|disable-windowsoptionalfeature",
    re.I,
)


def _history_severity(line: str) -> str:
    if _history_malware_hosts(line):
        return "critical"
    if NEVER_BENIGN.search(line):
        return "high"
    if VENDOR_INSTALL.search(line):
        return "low"
    return "high"


def _history_findings(data):
    hist = aslist(data.get("psHistory"))
    out = []
    for h in hist:
        if not isinstance(h, str) or not SUSPICIOUS_HISTORY.search(h):
            continue
        hosts = _history_malware_hosts(h)
        sev = _history_severity(h)
        if hosts:
            title = "PowerShell history references a known malware host: " + ", ".join(sorted(hosts))
            detail = h[:300] + " — recorded command; successful download/execution is not established"
        else:
            title = ("download-and-execute from a known vendor domain"
                     if sev == "low" else "suspicious PowerShell command in history")
            detail = h[:150]
        out.append(_finding("clickfix", sev, title, detail,
                            data.get("psHistoryPath", "")))
    # Inspect every collected line before presenting results; old high/critical
    # commands must not disappear behind a list of benign installer entries.
    if hist and not out:
        out.append(_finding("clickfix", "ok", "PowerShell history clean",
                            f"{len(hist)} recent commands, none matching known "
                            "download-and-execute or defence-tampering shapes", ""))
    return out
