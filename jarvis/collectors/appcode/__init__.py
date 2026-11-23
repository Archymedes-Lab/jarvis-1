"""Vulnerabilities in the application code this server runs (ARGUS-SERVER.md W12).

One bounded walk finds every codebase on the server (a folder with .git or a
project manifest, discover.py) under the application roots (configured
`code_roots`, else /srv, /var/www, /opt, /home, /usr/local, /app) and the
folders systemd services and containers run code from, lists them, and feeds:

    dependencies  lockfiles and virtual environments -> inventory.json, matched
                  locally against the OSV advisories the daily `osv` job keeps
                  (deps.py); malicious packages and CISA KEV CVEs ranked first
    code          line rules for injection, eval, deserialisation, disabled TLS
                  checks and debug mode (rules.py), one finding per project and
                  rule, capped at medium because they are heuristic
    credentials   the secrets collector's patterns over code and config files,
                  capped at high; reported as file:line and a fingerprint
    permissions   world-writable code: anyone on the host can change what runs
    web roots     .env files and .git folders inside a document root
    tools         bandit / semgrep when already installed (tools.py)

Findings carry file:line, never code or secret values. JARVIS's own install
and state are excluded. Anything unscanned (budget reached, unreadable, no OSV
data) is said so, never reported as clean.
"""

import json
import os
import shutil
import time

from jarvis.collectors import credentials, webroots
from jarvis.core import osvindex, paths
from jarvis.core.finding import LOCAL_HOST

from . import deps, discover, lockfiles, rules, tools

DEFAULT_ROOTS = ("/srv", "/var/www", "/opt", "/home", "/usr/local", "/app")
CONF_ROOTS, ENV_ROOTS = "code_roots", "JARVIS_CODE_ROOTS"
CONF_SEMGREP, ENV_SEMGREP = "semgrep_rules", "JARVIS_SEMGREP_RULES"
MAX_LISTED = 8
CAP = {"critical": "high"}
_UNSET = object()


def _f(severity, title, detail, where):
    return {"category": "appcode", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}


def _conf(key, env):
    if os.environ.get(env):
        return os.environ[env]
    try:
        with open(paths.CONFIG_PATH, encoding="utf-8", errors="replace") as fh:
            conf = json.load(fh) or {}
        return conf.get(key) if isinstance(conf, dict) else None
    except (OSError, ValueError):
        return None


def configured_roots():
    value = _conf(CONF_ROOTS, ENV_ROOTS)
    if isinstance(value, str):
        value = [p for p in value.split(":") if p]
    roots = value if isinstance(value, list) and value else DEFAULT_ROOTS
    return [r for r in roots if isinstance(r, str) and os.path.isdir(r)]


def own_paths():
    """JARVIS's own code and state: never scanned as an application."""
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    return [here, os.path.expanduser("~/.jarvis"), "/opt/jarvis", "/var/lib/jarvis"]


def _rel(path, project):
    return os.path.relpath(path, project) if path.startswith(project + "/") else path


def _listed(items):
    return "; ".join(items[:MAX_LISTED]) + (" ..." if len(items) > MAX_LISTED else "")


def _inventory(walk, roots):
    cb = set(walk["codebases"])
    out = []
    for path in walk["lockfiles"]:
        for eco, name, version in lockfiles.parse(path):
            out.append({"eco": eco, "name": name, "version": version, "path": path,
                        "project": discover.project_of(path, roots, cb)})
    for venv in walk["venvs"]:
        for eco, name, version in lockfiles.venv_packages(venv):
            out.append({"eco": eco, "name": name, "version": version, "path": venv,
                        "project": discover.project_of(venv, roots, cb)})
    return out


def _code(walk, roots, stop):
    cb = set(walk["codebases"])
    hits = {}                       # (project, rule) -> [(rel:line, tainted)]
    for path in walk["sources"]:
        if time.monotonic() > stop:
            walk["truncated"] = True
            break
        found = rules.scan_file(path)
        project = discover.project_of(path, roots, cb)
        for rid, line, tainted in found or ():
            hits.setdefault((project, rid), []).append((f"{_rel(path, project)}:{line}", tainted))
    out = []
    for (project, rid), places in sorted(hits.items()):
        tainted = [p for p, t in places if t]
        ordered = tainted + [p for p, t in places if not t]
        out.append(_f("medium" if tainted else "low",
                      f"{rules.title(rid)} in {os.path.basename(project) or project}",
                      f"{len(places)} places, {len(tainted)} on a line with request input: "
                      f"{_listed(ordered)}. A line-pattern match to review, not a confirmed flaw.",
                      project))
    return out


def _secrets(walk, roots, stop):
    cb = set(walk["codebases"])
    hits = {}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for path in walk["sources"] + walk["configs"]:
        if time.monotonic() > stop:
            walk["truncated"] = True
            break
        for kind, value, line, sev in credentials.scan_file(path, follow=False):
            project = discover.project_of(path, roots, cb)
            hits.setdefault(project, []).append(
                (CAP.get(sev, sev), f"{_rel(path, project)}:{line} {kind} "
                                    f"(fingerprint {credentials.fingerprint(value)})"))
    out = []
    for project, items in sorted(hits.items()):
        items.sort(key=lambda it: order.get(it[0], 9))
        out.append(_f(items[0][0], f"credentials in code of {os.path.basename(project) or project}",
                      f"{len(items)} found: " + _listed([d for _s, d in items]) + ". Move them to the environment or a "
                      "secret store and rotate any that were ever committed or deployed.", project))
    return out


def _writable(walk, roots):
    cb = set(walk["codebases"])
    by = {}
    for path in walk["writable"]:
        by.setdefault(discover.project_of(path, roots, cb), []).append(path)
    return [_f("medium", f"world-writable code in {os.path.basename(project) or project}",
               f"{len(items)} code files or folders any local account can change: "
               f"{_listed(items)}. Remove the write bit for others (chmod o-w).", project)
            for project, items in sorted(by.items())]


def _exposed(web_roots, max_depth=3):
    out = []
    for root in web_roots:
        base = root.rstrip("/").count("/")
        for dirpath, dirs, files in os.walk(root):
            if dirpath.count("/") - base >= max_depth:
                dirs[:] = []
            if ".git" in dirs:
                out.append(_f("high", ".git folder inside a web root",
                              f"{os.path.join(dirpath, '.git')}: if the server serves this folder, "
                              f"anyone can download the source and its history, credentials "
                              f"included. Deny dot-paths in the server or move it out.",
                              os.path.join(dirpath, ".git")))
            dirs[:] = [d for d in dirs if d not in discover.SKIP_DIRS]
            for name in files:
                if name == ".env" or name.startswith(".env."):
                    out.append(_f("high", ".env file inside a web root",
                                  f"{os.path.join(dirpath, name)}: if the server serves this "
                                  f"folder, anyone can download the application's settings. Move "
                                  f"it above the document root or deny dot-files.",
                                  os.path.join(dirpath, name)))
    return out


def _codebases(walk, roots):
    found = sorted(walk["codebases"])
    if not found:
        return []
    return [_f("ok", "codebases found",
               f"{len(found)}: {_listed(found) if len(found) <= MAX_LISTED else '; '.join(found[:40])}"
               + (f" and {len(found) - 40} more" if len(found) > 40 else "")
               + f" (in {', '.join(roots)})", ", ".join(roots))]


def _extra_roots(which, run):
    """Code folders named by services and containers, and whether containers were observed."""
    kw = {"run": run} if run else {"run": tools._run}
    mounts, observed = discover.container_paths(which=which, **kw)
    return discover.service_paths() + mounts, observed


def _under(path, roots):
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def audit(store=None, *, roots=None, web_roots=None, index=_UNSET, kev=None, now=None,
          which=shutil.which, run=None, state_dir=None, exclude=None, semgrep_rules=_UNSET,
          extra_roots=None, write_inventory=True, max_files=200_000, max_dirs=60_000,
          deadline_s=180.0):
    now = time.time() if now is None else now
    state_dir = state_dir or osvindex.ROOT
    roots = [r for r in (configured_roots() if roots is None else roots) if os.path.isdir(r)]
    containers_observed = None
    if extra_roots is None:
        extra_roots, containers_observed = _extra_roots(which, run)
    exclude = own_paths() if exclude is None else exclude
    roots += [r for r in dict.fromkeys(extra_roots)
              if os.path.isdir(r) and not _under(r, roots) and not _under(r, exclude)]
    if web_roots is None:
        web_roots = webroots.expand(sorted(webroots.roots_from_config()) + list(webroots.COMMON_ROOTS))
    out = []
    stop = time.monotonic() + deadline_s
    # The walk gets half the budget; the rules, secrets and tools share the rest.
    walk = discover.walk(roots, exclude, max_files=max_files, max_dirs=max_dirs,
                         deadline_s=deadline_s / 2)
    inventory = _inventory(walk, roots)
    if write_inventory:             # a hand scan of chosen paths must not replace the daemon's
        osvindex.write_json(osvindex.inventory_path(state_dir),
                            {"generated": int(now), "packages": inventory})
    if index is _UNSET:
        index = osvindex.load(osvindex.index_path(state_dir))
    if kev is None:
        kev = deps.kev_set(store) if store is not None else set()
    if inventory:
        out.extend(deps.judge(inventory, index, kev, now))
    out.extend(_code(walk, roots, stop))
    out.extend(_secrets(walk, roots, stop))
    out.extend(_writable(walk, roots))
    out.extend(_exposed(web_roots))
    out.extend(_codebases(walk, roots))
    if semgrep_rules is _UNSET:
        semgrep_rules = _conf(CONF_SEMGREP, ENV_SEMGREP)
    projects = sorted({discover.project_of(p, roots, set(walk["codebases"])) for p in walk["sources"]
                       if p.endswith(".py")} | {i["project"] for i in inventory})
    kw = {"run": run} if run else {}
    out.extend(tools.run(projects, which=which, semgrep_rules=semgrep_rules, stop=stop, **kw))
    if not roots:
        out.append(_f("low", "no application code roots found",
                      "none of the configured or default roots exists here; set `code_roots` in "
                      "the config to the folders your applications live in", "code_roots"))
    if containers_observed is False:
        out.append(_f("low", "container mounts not observed",
                      "a container runtime is installed but did not list its containers to this "
                      "account; code bind-mounted into containers is not scanned unless it lies "
                      "under the application roots", "docker"))
    if roots and walk["truncated"]:
        out.append(_f("low", "application code partly scanned",
                      f"the walk stopped at its budget after {walk['files']} files in "
                      f"{walk['dirs']} folders; what lies beyond is not observed. Narrow "
                      f"`code_roots` to the application folders.", ", ".join(roots)))
    if roots and not walk["truncated"] and not any(f["severity"] != "ok" for f in out):
        out.append(_f("ok", "no risky pattern in application code",
                      f"{len(walk['sources'])} source files, {len(walk['lockfiles'])} lockfiles "
                      f"and {len(walk['venvs'])} virtual environments in {', '.join(roots)}",
                      ", ".join(roots)))
    return out
