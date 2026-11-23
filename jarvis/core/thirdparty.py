"""Third-party security tools and rule sources: licence, use and commercial verdict.

Argus-1 is sold as a closed, compiled product and as founder-delivered audits
for clients. A tool or rule set is acceptable only when its licence permits that
use. This register is the reviewed record; tests/test_thirdparty.py fails if the
code starts running a program that is not registered here, or registered with a
verdict other than cleared/restricted.

Licences were read from each project's own licence file on 2026-11-02 (GitHub
licence API and the files themselves). This is an engineering record, not legal
advice: counsel should confirm the "restricted" and "avoid" rows before launch.

How Argus uses a tool decides most of it: every engine below is a separate
program the operator installed and Argus runs as a subprocess. Argus never
bundles, links or installs them, so copyleft engines (GPL, LGPL) impose nothing
on Argus's own code. Rule and data sets are different: their licences govern
use, and some forbid use for clients.

verdict:
  cleared     usable in the product and in paid client audits, obligations met
  restricted  usable only as stated in `conditions` (enforced in code where possible)
  avoid       not to be integrated (licence conflicts with the business model)
"""

from dataclasses import dataclass

VERDICTS = ("cleared", "restricted", "avoid")


@dataclass(frozen=True)
class Source:
    name: str
    kind: str            # engine | rules | data
    licence: str         # SPDX expression or the licence's own name
    use: str             # how Argus uses it today, or "not integrated"
    verdict: str
    conditions: str = ""
    fit: str = ""        # what it adds to the paid server audit (the first offer)


# Programs and content Argus runs or reads today.
INTEGRATED = (
    Source("osquery", "engine", "Apache-2.0 OR GPL-2.0-only",
           "operator-installed osqueryi, run with fixed queries (collectors/host/osquery.py)", "cleared",
           "if ever bundled, take it under Apache-2.0 and ship its NOTICE",
           fit="tamper evidence: a second reader's view of the client's processes, ports and modules"),
    Source("yara", "engine", "BSD-3-Clause",
           "operator-installed yara over one path with explicit rules (response/tools.py)", "cleared"),
    Source("bandit", "engine", "Apache-2.0",
           "operator-installed bandit over found codebases (collectors/appcode/tools.py)", "cleared"),
    Source("semgrep", "engine", "LGPL-2.1",
           "operator-installed semgrep with an operator-supplied local rules path only", "cleared"),
    Source("semgrep-rules", "rules", "Semgrep Rules License v1.0",
           "never shipped, fetched or selected by Argus", "restricted",
           "'only for your own internal business purposes'; not 'available to others as a service': "
           "never in a client audit; appcode refuses a rules path carrying this licence"),
    Source("sysmon-for-linux", "engine", "MIT (eBPF library LGPL-2.1)",
           "operator-installed sensor whose journal Argus reads", "cleared"),
    Source("auditd", "engine", "GPL-2.0-or-later",
           "distribution audit tools queried as programs (ausearch, auditctl)", "cleared"),
    Source("sigma-rules", "rules", "DRL-1.1",
           "a compiled subset shipped as data (intel/data/sigma_rules.json, built by "
           "scripts/security/sigma_compile.py) and evaluated by core/sigma.py", "cleared",
           "every finding from a rule names its author (core.sigma.attribution; a rule without an "
           "author is refused); the shipped file keeps each rule's author and id, the source "
           "repository and commit, and the DRL; the licence text ships in THIRD-PARTY-NOTICES",
           fit="community detections over Sysmon process and registry events, credited per finding"),
    Source("signature-base", "rules", "DRL-1.1",
           "compiled literal-only subset shipped as intel/data/content_rules.json", "cleared",
           "author, source repository, pinned commit and licence retained; findings credit the "
           "matching author; unsupported and differently licensed rules excluded; DRL text in "
           "THIRD-PARTY-NOTICES",
           fit="read-only bounded local file-content matching, advisory only"),
    Source("osv.dev", "data", "Apache-2.0 (service); per-advisory data licences, e.g. CC-BY-4.0",
           "downloaded advisory dumps matched offline (osv job)", "cleared",
           "credit the advisory source (GitHub Advisory Database is CC-BY-4.0) in reports"),
)

# Evaluated 2026-11-02 for the next integrations; nothing here runs yet.
CANDIDATES = (
    Source("yara-forge", "rules", "GPL-3.0", "not integrated", "restricted",
           "never compiled into Argus; only as an operator-supplied rules path"),
    Source("lynis", "engine", "GPL-3.0", "not integrated", "cleared", "operator-installed program only",
           fit="hardening section of the audit report from the client's own Lynis run"),
    Source("openscap", "engine", "LGPL-2.1", "not integrated", "cleared", "operator-installed program only",
           fit="compliance profile results (CIS/STIG via SCAP Security Guide) for clients who need them"),
    Source("scap-security-guide", "rules", "BSD-3-Clause", "not integrated", "cleared"),
    Source("trivy", "engine", "Apache-2.0", "not integrated", "cleared",
           fit="container and filesystem vulnerability section beside Argus's OSV results"),
    Source("grype", "engine", "Apache-2.0", "not integrated", "cleared",
           fit="alternative to Trivy for the vulnerability section"),
    Source("falco", "engine", "Apache-2.0", "not integrated", "cleared",
           fit="runtime alerts from clients already running Falco"),
    Source("falco-rules", "rules", "Apache-2.0", "not integrated", "cleared"),
    Source("suricata", "engine", "GPL-2.0", "not integrated", "cleared", "read its local logs only",
           fit="network alerts from clients already running Suricata"),
    Source("zeek", "engine", "BSD-3-Clause", "not integrated", "cleared",
           fit="network metadata from clients already running Zeek"),
    Source("clamav", "engine", "GPL-2.0", "not integrated", "restricted",
           "engine fine as a separate program; signature database terms not yet reviewed"),
    Source("crowdsec", "engine", "MIT", "not integrated", "restricted",
           "engine fine; community blocklist terms not yet reviewed, and sharing signals off the "
           "machine conflicts with Argus's privacy rules"),
    Source("chainsaw", "engine", "GPL-3.0", "not integrated", "cleared", "operator-installed program only"),
    Source("hayabusa", "engine", "AGPL-3.0", "not integrated", "avoid",
           "network copyleft; risky for hosted features"),
    Source("velociraptor", "engine", "AGPL-3.0", "not integrated", "avoid",
           "network copyleft; risky for hosted features"),
    Source("wazuh", "engine", "GPL-2.0 and AGPL-3.0 (engine)", "not integrated", "avoid",
           "competing platform with an AGPL engine"),
)

# Programs Argus looks up that are part of the operating system or the owner's own
# tooling, not security integrations: no licence question for the product.
PLATFORM = frozenset({
    "systemctl", "dpkg", "git", "docker", "podman", "ssh-keygen", "npm",
    "powershell.exe", "pwsh.exe", "opencode", "friday", "journalctl", "zstd", "unzstd",
})

# The program name each integrated source is invoked by.
PROGRAMS = {"osqueryi": "osquery", "yara": "yara", "bandit": "bandit", "semgrep": "semgrep",
            "sysmon": "sysmon-for-linux", "ausearch": "auditd", "auditctl": "auditd"}

BY_NAME = {s.name: s for s in INTEGRATED + CANDIDATES}

SEMGREP_RULES_LICENCE_MARK = "Semgrep Rules License"


def conformance():
    """Problems with the register itself; [] when it is consistent."""
    out = []
    names = [s.name for s in INTEGRATED + CANDIDATES]
    for name in sorted({n for n in names if names.count(n) > 1}):
        out.append(f"{name}: registered twice")
    for s in INTEGRATED + CANDIDATES:
        if s.verdict not in VERDICTS:
            out.append(f"{s.name}: unknown verdict {s.verdict}")
        if s.verdict in ("restricted", "avoid") and not s.conditions:
            out.append(f"{s.name}: {s.verdict} without conditions")
        if s.kind not in ("engine", "rules", "data"):
            out.append(f"{s.name}: unknown kind {s.kind}")
    for s in INTEGRATED:
        if s.verdict == "avoid":
            out.append(f"{s.name}: integrated but marked avoid")
    for program, source in PROGRAMS.items():
        if source not in BY_NAME:
            out.append(f"{program}: maps to unregistered {source}")
    return out


def rules_licence_conflict(path, opener=open, isdir=None, listdir=None):
    """The restricted licence a rules path carries, or ''. Looks at licence
    files in the path and up to two parents (a clone's root)."""
    import os
    isdir = isdir or os.path.isdir
    listdir = listdir or os.listdir
    d = path if isdir(path) else os.path.dirname(path)
    for _ in range(3):
        try:
            names = listdir(d)
        except OSError:
            names = []
        for name in names:
            if name.upper().startswith(("LICENSE", "LICENCE", "COPYING")):
                try:
                    with opener(os.path.join(d, name), errors="replace") as fh:
                        head = fh.read(4096)
                except OSError:
                    continue
                if SEMGREP_RULES_LICENCE_MARK in head:
                    return SEMGREP_RULES_LICENCE_MARK
        parent = os.path.dirname(d.rstrip("/")) or "/"
        if parent == d:
            break
        d = parent
    return ""
