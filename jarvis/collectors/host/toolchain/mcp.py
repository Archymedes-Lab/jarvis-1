"""MCP servers — what an agent is allowed to call."""

import glob
import os
import re

from jarvis.platform import host as machine

from .common import PAYLOAD_RE, _diff, _finding, _hash, _home, _json, _short, repos

_M_MCP = "toolchain_mcp"

SHELL_CMD_RE = re.compile(
    r"^(/(usr/)?bin/)?(ba|z|k|da)?sh$|^cmd(\.exe)?$|^(powershell|pwsh)(\.exe)?$",
    re.I)

USER_MCP_FILES = (
    "~/.mcp.json", "~/.cursor/mcp.json", "~/.vscode/mcp.json",
    "~/.codeium/windsurf/mcp_config.json", "~/.antigravity/mcp_config.json",
    "~/.gemini/settings.json", "~/.config/mcp.json", "~/.aws/amazonq/mcp.json",
)

PROJECT_MCP_RELS = (
    ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".amazonq/mcp.json",
    ".gemini/settings.json", ".codeium/mcp_config.json",
    ".antigravity/mcp_config.json",
)


def _servers_in(doc):
    """Pull server definitions out of the several shapes vendors use."""
    if not isinstance(doc, dict):
        return {}
    for key in ("mcpServers", "mcp_servers", "servers"):
        node = doc.get(key)
        if isinstance(node, dict):
            return node
    mcp = doc.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


def _describe(spec):
    """Flatten a server definition to the command line it will actually run."""
    if not isinstance(spec, dict):
        return str(spec)[:200], ""
    url = spec.get("url") or spec.get("endpoint") or ""
    cmd = spec.get("command") or ""
    args = spec.get("args") or []
    if not isinstance(args, list):
        args = [str(args)]
    line = " ".join([str(cmd)] + [str(a) for a in args]).strip()
    return line[:400], str(url)[:200]


def _score_server(name, spec, source, scope, host):
    """One server entry -> at most one finding, severity from what it runs."""
    line, url = _describe(spec)
    where = _short(source)
    cmd = spec.get("command") if isinstance(spec, dict) else ""
    base = os.path.basename(str(cmd).split()[0]) if cmd else ""

    if line and PAYLOAD_RE.search(line):
        return _finding(
            "agent", "critical",
            f"MCP server '{name}' runs a downloaded or encoded payload",
            f"the editor launches this on startup, unattended, with your "
            f"credentials and your filesystem: {line}. A fetch-and-run or "
            f"encoded command in a config file is the exact shape of the 2026 "
            f"MCP auto-execution compromises — treat it as executing now, not "
            f"as a proposal.",
            where, host)

    if base and SHELL_CMD_RE.match(base):
        return _finding(
            "agent", "high" if scope == "user" else "critical",
            f"MCP server '{name}' is a shell command, not a program",
            f"`{line}` — the server field is being used to carry a command "
            f"string rather than name an executable. Whatever that string does "
            f"happens every time the editor starts."
            + ("" if scope == "user" else " This one is defined inside a "
               "repository, so it came from whoever wrote that repository."),
            where, host)

    if scope == "repo":
        return _finding(
            "agent", "high",
            f"repository-scoped MCP server '{name}'",
            f"{'runs ' + line if line else 'connects to ' + url} — this is "
            f"configured in the repo, not by you, so opening the folder is "
            f"enough to start it. Confirm you intended this server before the "
            f"next time you open the workspace.",
            where, host)

    detail = f"runs `{line}`" if line else f"connects to {url}"
    return _finding(
        "agent", "low", f"MCP server '{name}' is configured",
        f"{detail} — inventory, so that a change to it is visible next run",
        where, host)


def _mcp_sources(hosts):
    """(path, scope, host) for every MCP config worth reading."""
    out = []
    if "wsl" in hosts:
        for p in USER_MCP_FILES:
            path = os.path.expanduser(p)
            if os.path.isfile(path):
                out.append((path, "user", "wsl"))
        found, _ = repos()
        for repo in found:
            for rel in PROJECT_MCP_RELS:
                path = os.path.join(repo, rel)
                if os.path.isfile(path):
                    out.append((path, "repo", "wsl"))
    if "win" in hosts:
        for udir in _windows_profiles():
            for p in USER_MCP_FILES:
                path = os.path.join(udir, p.replace("~/", "").replace("/", os.sep))
                if os.path.isfile(path):
                    out.append((path, "user", "win"))
    return out


def _windows_profiles():
    """Real Windows user profiles, skipping the template accounts."""
    from jarvis.platform import mounts as _mounts
    # One gate for the whole Windows-profile traversal: on a stale drive every
    # glob and stat below fails with EIO, so skip the walk instead of
    # hammering a sick mount hourly. The coverage self-audit reports the
    # single stale-mount diagnosis; this side simply covers less until then.
    if _mounts.windows_drive() == _mounts.STALE:
        return []
    out = []
    users = machine.users_dir()
    for path in sorted(glob.glob(os.path.join(users, "*"))) if users else ():
        name = os.path.basename(path)
        if name.lower() in ("public", "default", "default user", "all users"):
            continue
        if os.path.isdir(path):
            out.append(path)
    return out[:8]


def check_mcp(store=None, hosts=("wsl", "win")):
    out, seen = [], {}
    sources = _mcp_sources(hosts)

    for path, scope, host in sources:
        doc = _json(path)
        if doc is None:
            if os.path.getsize(path) if os.path.exists(path) else 0:
                out.append(_finding(
                    "agent", "medium", f"unreadable MCP config: {_short(path)}",
                    "the file exists but does not parse, so its contents are "
                    "unaudited — this check cannot tell an empty config from a "
                    "malformed one that the editor still partially honours",
                    _short(path), host))
            continue
        servers = _servers_in(doc)
        for name, spec in servers.items():
            out.append(_score_server(name, spec, path, scope, host))
            line, url = _describe(spec)
            seen[f"{_short(path)}::{name}"] = _hash(line + "|" + url)

    # Claude Code keeps per-project server definitions inside one user-level
    # file, so they never appear as a repo-scoped path above. They still run
    # per project, and they are still the thing that changed if one changed.
    claude_json = os.path.join(_home(), ".claude.json")
    if "wsl" in hosts and os.path.isfile(claude_json):
        doc = _json(claude_json) or {}
        for name, spec in _servers_in(doc).items():
            out.append(_score_server(name, spec, claude_json, "user", "wsl"))
            line, url = _describe(spec)
            seen[f"~/.claude.json::{name}"] = _hash(line + "|" + url)
        projects = doc.get("projects")
        if isinstance(projects, dict):
            for proj, cfg in projects.items():
                for name, spec in _servers_in(cfg or {}).items():
                    out.append(_score_server(
                        name, spec, claude_json, "repo", "wsl"))
                    line, url = _describe(spec)
                    seen[f"{proj}::{name}"] = _hash(line + "|" + url)

    out.extend(_diff(store, _M_MCP, seen, "agent", "MCP server",
                     "a server definition that changed after you approved it "
                     "is the Cursor re-validation gap: approval is recorded "
                     "once and the command is read fresh at every launch"))
    if not seen:
        out.append(_finding(
            "agent", "ok", "no MCP servers configured",
            (f"{len(sources)} MCP config file(s) read, none defining a server"
             if sources else
             "no MCP config file exists at any of the user- or repo-scope "
             "locations checked")
            + " — nothing is auto-launched by an editor on this account",
            "MCP"))
    return out
