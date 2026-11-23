"""Detection benchmark: Atomic Red Team commands, as text, through the real rule matcher.

Nothing is executed. Each test's executor command is turned into the process starts
it would produce if run as written, and jarvis.collectors.telemetry.techniques.match
decides. This measures the process-command-line rule layer only, as an upper bound:
a command typed inside an already running PowerShell session produces no process
start at all, and other collectors (registry, memory, persistence, network) are not
exercised here.

    python3 -m scripts.security.atomic_bench INDEX.yaml [--json OUT] [--floor scripts/security/atomic_floor.json]

With --floor the run is a gate: it exits 1 when fewer tests are caught than the recorded
floor, when a benign control command raises a finding, or when a detector crashes.

INDEX.yaml is atomics/Indexes/index.yaml from redcanaryco/atomic-red-team (MIT), fetched
by the person running this into its own directory; it is data, parsed with yaml.safe_load,
and is not vendored here. PyYAML is a development-only dependency of this tool.
Results of 2026-11-10: docs/security/DETECTION-BENCHMARK-2026-11-10.md.
"""
import collections
import hashlib
import json
import re
import sys

import yaml

from jarvis.collectors.telemetry import sysmon
from jarvis.collectors.telemetry import techniques as t
from jarvis.collectors.telemetry.sysmon_linux import rules as linux_rules
from jarvis.core import sigma

PLAT = {"windows": t.WIN, "linux": t.LINUX}
SHELL = {"command_prompt": ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c {}"),
         "powershell": ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -Command {}"),
         "sh": ("/bin/sh", "sh -c {}"), "bash": ("/bin/bash", "bash -c {}")}
# --builtin-only measures the built-in rules alone (the baseline before community rules).
COMMUNITY = "--builtin-only" not in sys.argv
PROGRAM = re.compile(r"[A-Za-z0-9_.:\\\\/~+-]+")
BUILTINS = {"echo", "set", "cd", "if", "for", "rem", "exit", "export", "then", "fi", "do", "done", "else",
            "function", "return", "foreach", "try", "catch", "while", "param", "write-host", "start-sleep"}
SPLIT = re.compile(r"\s*(?:&&|\|\||[;&|])\s*")


def fill(command, args):
    def sub(m):
        spec = args.get(m.group(1)) or {}
        return str(spec.get("default", ""))
    return re.sub(r"#\{([^}]+)\}", sub, command or "")


def events(executor, command, platform):
    """(image, cmdline, parent) process starts the command would produce."""
    shell_image, wrap = SHELL[executor]
    out = []
    for line in command.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "REM ", "rem ", "::")):
            continue
        out.append((shell_image, wrap.format(line), ""))
        for seg in SPLIT.split(line):
            seg = seg.strip()
            if not seg:
                continue
            first = seg.split()[0].strip('"\'')
            # Only something that could be a program is a process start: not a
            # PowerShell cmdlet, an assignment, a redirect target or a shell builtin.
            if not PROGRAM.fullmatch(first) or first.lower() in BUILTINS:
                continue
            if executor == "powershell" and "-" in first and not first.lower().endswith(".exe"):
                continue
            if platform == t.WIN and "." not in first.rsplit("\\", 1)[-1]:
                first += ".exe"
            out.append((first, seg, shell_image))
    return out


REG_ADD = re.compile(r'reg(?:\.exe)?\s+add\s+"?([^"/]+?)"?\s+(/.*)$', re.I)
PS_SET = re.compile(r'(?:New|Set)-ItemProperty\b(.*)$', re.I)
HIVES = {"hklm:": "HKLM", "hkcu:": "HKU\\S-1-5-21-1-1-1-1001", "hkey_local_machine": "HKLM",
         "hkey_current_user": "HKU\\S-1-5-21-1-1-1-1001", "hkcu": "HKU\\S-1-5-21-1-1-1-1001", "hklm": "HKLM"}


def _key(raw):
    raw = raw.strip().strip('"\'').replace("/", "\\")
    head, _, rest = raw.partition("\\")
    return HIVES.get(head.lower(), head) + "\\" + rest.strip("\\")


def _details(kind, data):
    data = data.strip().strip('"\'')
    if "dword" in kind.lower() or re.fullmatch(r"(0x[0-9a-f]+|\d+)", data, re.I):
        try:
            return "DWORD (0x%08x)" % int(data, 0)
        except ValueError:
            pass
    return data


def registry_writes(command):
    """(key, details) value writes a `reg add` or Set-ItemProperty line would make."""
    out = []
    for line in command.splitlines():
        m = REG_ADD.search(line)
        if m:
            opts = m.group(2)
            name = re.search(r'/v\s+("[^"]*"|\S+)', opts, re.I)
            data = re.search(r'/d\s+("[^"]*"|\S+)', opts, re.I)
            kind = re.search(r'/t\s+(\S+)', opts, re.I)
            if name and data:
                out.append((_key(m.group(1)) + "\\" + name.group(1).strip('"'),
                            _details(kind.group(1) if kind else "", data.group(1))))
        m = PS_SET.search(line)
        if m:
            opts = m.group(1)
            path = re.search(r'-Path\s+("[^"]*"|\'[^\']*\'|\S+)', opts, re.I) or re.search(r'^\s+("[^"]*"|\'[^\']*\'|HK\S+)', opts)
            name = re.search(r'-Name\s+("[^"]*"|\'[^\']*\'|\S+)', opts, re.I)
            data = re.search(r'-Value\s+("[^"]*"|\'[^\']*\'|\S+)', opts, re.I)
            kind = re.search(r'-(?:Property)?Type\s+(\S+)', opts, re.I)
            if path and name and data:
                out.append((_key(path.group(1)) + "\\" + name.group(1).strip('"\''),
                            _details(kind.group(1) if kind else "", data.group(1))))
    return out


def _win_path(image):
    """A bare program name is where Windows would find it: its system folder. A
    tool the test brings along keeps the path the test gives it."""
    return image if "\\" in image else "C:\\Windows\\System32\\" + image


def full_detectors(evs, regs, platform, n):
    """Findings from the real detector entry points for one test's process starts
    and registry writes: sysmon.audit(events=...) on Windows, the Sysmon for Linux
    rule pass on Linux. -> [(severity, title, techniques)]"""
    if platform == t.WIN:
        canon = []
        for i, (image, cmdline, parent) in enumerate(evs):
            canon.append({"source": "sysmon", "source_event": 1, "seq": i, "record": i,
                          "time": "2026-11-10T12:00:%02d.000Z" % (i % 60),
                          "process": {"image": _win_path(image), "cmdline": cmdline,
                                      "guid": "{%08d-0000-0000-0000-%012d}" % (n, i), "pid": 4000 + i},
                          "parent": {"image": parent or "C:\\Windows\\explorer.exe",
                                     "guid": "{%08d-0000-0000-0000-999999999999}" % n}})
        for j, (key, details) in enumerate(regs):
            canon.append({"source": "sysmon", "source_event": 13, "seq": 900 + j, "record": 900 + j,
                          "time": "2026-11-10T12:01:%02d.000Z" % (j % 60),
                          "process": {"image": "C:\\Windows\\System32\\reg.exe",
                                      "guid": "{%08d-0000-0000-0000-%012d}" % (n, 900 + j), "pid": 5000 + j},
                          "target": {"key": key, "details": details}})
        found = sysmon.audit(events=sysmon.rows_from_events(canon), volumes={"C": ("Fixed", "")},
                             community_rules=COMMUNITY)
    else:
        events = [{"id": 1, "Image": image if image.startswith("/") else "/usr/bin/" + image,
                   "CommandLine": cmdline, "ParentImage": parent or "/usr/bin/bash", "User": "victim",
                   "ProcessGuid": "{%08d-0000-0000-0000-%012d}" % (n, i), "ProcessId": str(4000 + i),
                   "ParentProcessGuid": "{%08d-0000-0000-0000-999999999999}" % n,
                   "UtcTime": "2026-11-10 12:00:%02d.000" % (i % 60)}
                  for i, (image, cmdline, parent) in enumerate(evs)]
        found = linux_rules._rules(events, community_rules=COMMUNITY)
    return [(f.get("severity"), f.get("title", ""), tuple(f.get("techniques") or ())) for f in found
            if f.get("severity") in ("critical", "high", "medium", "low")]


def script_block(command):
    """What the script-block collector's rules say about a PowerShell test's text
    (the test run in a PowerShell session with script-block logging on)."""
    idx, _error = sigma.index(sigma.WIN_PS)
    return [(r.severity, r.title + " (community rule)", r.tids)
            for r in idx.match(sigma.prepare(sigma.WIN_PS, {"text": command, "path": ""}))]


BENIGN = {t.WIN: ("command_prompt", ["dir C:\\Users", "notepad.exe notes.txt", "git status", "ping 127.0.0.1",
                                     "python.exe build.py", "code .", "ipconfig", "copy a.txt b.txt",
                                     "npm install", "tar -xf archive.tar", "where python", "type readme.md"]),
          t.LINUX: ("bash", ["ls -la", "git pull", "make test", "python3 manage.py runserver", "df -h",
                             "tail -f app.log", "apt list --installed", "cat README.md", "grep -r TODO src",
                             "docker ps", "ssh-add -l", "tar czf backup.tgz docs"])}


def check_floor(summary, floor, index_sha256):
    """Why this run fails the gate; [] when it passes.

    The floor is what a reviewed run measured on one exact index. Detection may
    rise (then the floor is raised in the same change); it may not fall, benign
    commands may not raise findings, and no detector may crash on an input."""
    problems = []
    if floor.get("index_sha256") != index_sha256:
        return [f"the index is not the one the floor was measured on ({index_sha256[:12]}...)"]
    if summary["tests"] != floor["tests"]:
        problems.append(f"{summary['tests']} tests were modelled, the floor was measured on {floor['tests']}")
    for key in ("any_finding", "win", "linux"):
        if summary[key] < floor[key]:
            problems.append(f"{key}: {summary[key]} caught, below the floor of {floor[key]}")
    if summary["benign_findings"] > floor.get("benign_findings", 0):
        problems.append(f"{summary['benign_findings']} benign control commands raised a finding")
    if summary["crashes"]:
        problems.append(f"{summary['crashes']} inputs crashed a detector")
    return problems


def main():
    index = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
    seen, rows, crashes, benign_hits = set(), [], collections.Counter(), 0
    for tactic, techniques in index.items():
        for tid, entry in (techniques or {}).items():
            for test in (entry or {}).get("atomic_tests") or []:
                guid = test.get("auto_generated_guid")
                ex = test.get("executor") or {}
                if guid in seen or ex.get("name") not in SHELL:
                    continue
                for platform in [PLAT[p] for p in test.get("supported_platforms", []) if p in PLAT]:
                    if (platform == t.WIN) != (ex["name"] in ("command_prompt", "powershell")):
                        continue
                    seen.add(guid)
                    command = fill(ex.get("command"), test.get("input_arguments") or {})
                    hits, disc = [], set()
                    for image, cmdline, parent in events(ex["name"], command, platform):
                        hits += [r for r, _ in t.match(image, cmdline, platform, parent, extra=())]
                        disc |= t.discovery(image, cmdline, platform)
                    regs = registry_writes(command) if platform == t.WIN else []
                    reg = [r for key, details in regs for r in t.registry(key, details)]
                    try:
                        found = full_detectors(events(ex["name"], command, platform), regs, platform, len(rows))
                        if COMMUNITY and ex["name"] == "powershell":
                            found += script_block(command)
                    except Exception as exc:  # a detector crash on odd input is itself a result
                        found = []
                        crashes[type(exc).__name__ + ": " + str(exc)[:80]] += 1
                    process_only = bool(hits)
                    hits += reg
                    parent_tid = tid.split(".")[0]
                    right = any(tid in r.tids or parent_tid in r.tids
                                or any(x.split(".")[0] == parent_tid for x in r.tids) for r in hits)
                    sev = min((["critical", "high", "medium", "low"].index(r.severity) for r in hits
                               if r.severity in ("critical", "high", "medium", "low")), default=None)
                    rows.append({"tid": tid, "tactic": tactic, "platform": platform, "executor": ex["name"],
                                 "name": test.get("name", ""), "rule": bool(hits), "process": process_only, "regwrites": len(regs), "reg": bool(reg),
                                 "full": bool(found), "full_alert": any(f[0] in ("critical", "high") for f in found),
                                 "full_right": any(tid in f[2] or any(x.split(".")[0] == tid.split(".")[0] for x in f[2]) for f in found),
                                 "titles": sorted({f[1][:70] for f in found})[:4], "right": right,
                                 "discovery": bool(disc) and not hits,
                                 "severity": None if sev is None else ["critical", "high", "medium", "low"][sev]})
                    break
    def rate(rs):
        n = len(rs)
        if not n:
            return "0"
        r = sum(x["rule"] for x in rs); c = sum(x["right"] for x in rs); d = sum(x["discovery"] for x in rs)
        return f"{n:5d} tests | any rule {r:4d} ({100*r/n:4.1f}%) | right technique {c:4d} ({100*c/n:4.1f}%) | discovery list only {d:4d} | nothing {n-r-d:4d} ({100*(n-r-d)/n:4.1f}%)"
    def full(rs):
        n = len(rs) or 1
        a = sum(x["full"] for x in rs); b = sum(x["full_alert"] for x in rs); c = sum(x["full_right"] for x in rs)
        return f"{len(rs):5d} tests | any finding {a:4d} ({100*a/n:4.1f}%) | high or critical {b:4d} ({100*b/n:4.1f}%) | right technique {c:4d} ({100*c/n:4.1f}%)"
    print("FULL DETECTORS (sysmon.audit / Sysmon for Linux rule pass)")
    print("ALL      ", full(rows))
    for key in ("platform", "tactic"):
        for value in sorted({x[key] for x in rows}):
            print(f"{key}={value:22}", full([x for x in rows if x[key] == value]))
    print("detector crashes:", dict(crashes))
    for platform, (executor, commands) in BENIGN.items():
        hit = [(c, full_detectors(events(executor, c, platform), [], platform, 0)) for c in commands]
        benign_hits += sum(bool(f) for _, f in hit)
        print(f"benign control {platform}: {sum(bool(f) for _, f in hit)} of {len(hit)} raised a finding", [(c, f) for c, f in hit if f][:4])
    print("RULE MATCHER ONLY (techniques.match + registry rules)")
    print("ALL      ", rate(rows))
    for key in ("platform", "executor", "tactic"):
        for value in sorted({x[key] for x in rows}):
            print(f"{key}={value:22}", rate([x for x in rows if x[key] == value]))
    rw = [x for x in rows if x["regwrites"]]
    print(f"tests that write a registry value: {len(rw)}; caught by a registry rule {sum(x['reg'] for x in rw)}; "
          f"caught only by the registry layer {sum(x['reg'] and not x['process'] for x in rw)}")
    techs = collections.defaultdict(list)
    for x in rows:
        techs[x["tid"]].append(x)
    full = sum(all(x["rule"] for x in v) for v in techs.values())
    some = sum(any(x["rule"] for x in v) for v in techs.values())
    print(f"techniques: {len(techs)} with a runnable test; at least one test caught {some}; every test caught {full}; none caught {len(techs)-some}")
    sev = collections.Counter(x["severity"] for x in rows if x["rule"])
    print("severity of the best rule hit:", dict(sev))
    missed = collections.Counter(x["tid"] for x in rows if not x["rule"])
    print("most-missed techniques:", missed.most_common(25))
    summary = {"tests": len(rows), "any_finding": sum(x["full"] for x in rows),
               "win": sum(x["full"] for x in rows if x["platform"] == t.WIN),
               "linux": sum(x["full"] for x in rows if x["platform"] == t.LINUX),
               "benign_findings": benign_hits, "crashes": sum(crashes.values())}
    print("summary:", json.dumps(summary, sort_keys=True))
    if "--floor" in sys.argv:
        problems = check_floor(summary, json.load(open(sys.argv[sys.argv.index("--floor") + 1], encoding="utf-8")),
                               hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
        for line in problems:
            print("DETECTION GATE:", line)
        if problems:
            sys.exit(1)
        print("DETECTION GATE: passed")
    if "--json" in sys.argv:
        json.dump(rows, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=0)


if __name__ == "__main__":
    main()
