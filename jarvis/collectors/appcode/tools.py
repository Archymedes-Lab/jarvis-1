"""bandit and semgrep, when the operator already has them; never installed here.

bandit is offline. semgrep runs only with an operator-supplied local rules path
and with metrics off (Jev advisory 2026-10-28: 0.91 for local-only): its
registry rules need the network and its defaults report usage. Each run has a
timeout, and a tool that fails is reported as such, not as clean.
"""

import json
import os
import subprocess
import time

from jarvis.core import thirdparty
from jarvis.core.finding import LOCAL_HOST

TIMEOUT_S = 180
MAX_LISTED = 8
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
       "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
EXCLUDE = "node_modules,vendor,venv,.venv,tests,test,site-packages"


def _f(severity, title, detail, where):
    return {"category": "appcode", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}


def _run(argv, timeout=TIMEOUT_S, env=None):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=env or ENV, cwd="/")
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def _rel(path, project):
    return os.path.relpath(path, project) if path.startswith(project) else path


def _bandit(exe, project, run, timeout=TIMEOUT_S):
    code, out = run([exe, "-r", project, "-f", "json", "-q", "-x", EXCLUDE],
                    timeout=timeout, env=ENV)
    try:
        results = json.loads(out).get("results") if code in (0, 1) else None
    except (ValueError, AttributeError):
        results = None
    if results is None:
        return _f("low", "bandit could not scan a project",
                  f"bandit exited {code}; this project's Python is not judged by bandit", project)
    keep = [r for r in results if r.get("issue_severity") == "HIGH"
            or (r.get("issue_severity") == "MEDIUM" and r.get("issue_confidence") == "HIGH")]
    if not keep:
        return None
    listed = "; ".join(f"{_rel(str(r.get('filename')), project)}:{r.get('line_number')} "
                       f"{r.get('test_id')} {str(r.get('issue_text') or '')[:80]}"
                       for r in keep[:MAX_LISTED])
    return _f("medium", f"bandit: serious Python issues in {os.path.basename(project) or project}",
              f"{len(keep)}: " + listed + (" ..." if len(keep) > MAX_LISTED else ""), project)


def _semgrep(exe, project, rules_path, run, timeout=TIMEOUT_S):
    code, out = run([exe, "scan", "--config", rules_path, "--json", "--metrics=off",
                     "--disable-version-check", "--quiet", project], timeout=timeout, env=ENV)
    try:
        results = json.loads(out).get("results") if code in (0, 1) else None
    except (ValueError, AttributeError):
        results = None
    if results is None:
        return _f("low", "semgrep could not scan a project",
                  f"semgrep exited {code} with the rules at {rules_path}", project)
    errors = [r for r in results if (r.get("extra") or {}).get("severity") == "ERROR"]
    keep = errors or results
    if not keep:
        return None
    listed = "; ".join(f"{_rel(str(r.get('path')), project)}:{(r.get('start') or {}).get('line')} "
                       f"{r.get('check_id')}" for r in keep[:MAX_LISTED])
    return _f("medium" if errors else "low",
              f"semgrep: issues in {os.path.basename(project) or project}",
              f"{len(keep)}: " + listed + (" ..." if len(keep) > MAX_LISTED else ""), project)


def run(projects, *, which, run=_run, semgrep_rules=None, stop=None):
    """Findings from whichever tools are installed, per project, until `stop`
    (a time.monotonic() deadline); projects left over are said so."""
    out = []
    bandit = which("bandit")
    semgrep = which("semgrep") if semgrep_rules and os.path.exists(semgrep_rules) else None
    if semgrep and thirdparty.rules_licence_conflict(semgrep_rules):
        # Semgrep's own rules are licensed for internal business use only and not
        # "available to others as a service" (core/thirdparty.py): never in an audit.
        semgrep = None
        out.append(_f("low", "semgrep not run: its rules path carries the Semgrep Rules License",
                      f"{semgrep_rules} holds rules licensed only for the licensee's internal "
                      "business purposes, which excludes client audits. Point semgrep_rules at "
                      "rules you wrote or that are licensed for this use.", "appcode"))
    if not (bandit or semgrep):
        return out
    for n, project in enumerate(projects):
        left = TIMEOUT_S if stop is None else stop - time.monotonic()
        if left < 5:
            out.append(_f("low", "external code scanners stopped at the time budget",
                          f"{len(projects) - n} codebases were not scanned by bandit/semgrep "
                          f"this run: {', '.join(projects[n:n + 5])}", "appcode"))
            break
        timeout = min(TIMEOUT_S, left)
        for f in ((_bandit(bandit, project, run, timeout) if bandit else None),
                  (_semgrep(semgrep, project, semgrep_rules, run, timeout) if semgrep else None)):
            if f:
                out.append(f)
    return out
