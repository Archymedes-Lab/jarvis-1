"""Agent hooks, instruction files and plugins."""

import glob
import hashlib
import os
import re
import subprocess

from .common import (
    MAX_REPOS,
    PAYLOAD_RE,
    _diff,
    _finding,
    _hash,
    _home,
    _json,
    _read,
    _short,
    repos,
)

_M_HOOKS = "toolchain_hooks"

INLINE_CODE_RE = re.compile(
    r"\bnode\s+-e\s|\bpython3?\s+-c\s|\bperl\s+-e\s|\bruby\s+-e\s"
    r"|\bdeno\s+eval\b|\bbun\s+-e\s",
    re.I)

INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")

AGENT_DOC_NAMES = (
    "CLAUDE.md", "AGENTS.md", "AGENT.md", ".cursorrules", "GEMINI.md",
    ".windsurfrules", ".clinerules", "copilot-instructions.md",
)

PROJECT_HOOK_RELS = (
    ".claude/settings.json", ".claude/settings.local.json",
    ".vscode/tasks.json",
)

# Reviewed against the official typesafe-ai/skills v0.5.7 commit on
# 2026-09-23. These hashes are content proof, not trust in a marketplace name.
# Any update, added plugin file, symlink, or changed skill returns to medium.
REVIEWED_TYPESAFE = {
    ".claude-plugin/marketplace.json": "7040ea575b7549d7db06cce21ebe479471930953eaede01d8cd9ed81511abd11",
    ".claude-plugin/plugin.json": "3d4e3433dc040fde349deaf773a4a4b070b3aa5ce34b3f321b170d2409a9fa5a",
    "LICENSE": "835f233f1d6ed84a9b9a351aba0689b47644a4137d6316911fc7957bde523b02",
    "README.md": "799ce1dc39dc1cb98977f930610bf693a26d1a78e5912b860014447d97390282",
    "skills/typesafe-ai/LICENSE": "835f233f1d6ed84a9b9a351aba0689b47644a4137d6316911fc7957bde523b02",
    "skills/typesafe-ai/SKILL.md": "71ea90d7906c6554c4f4c460ef7361b2d26f59116ccdae986dc6d997b9389f52",
}
REVIEWED_TYPESAFE_COMMIT = "65a39f393687675ce170e6094757de20370365b9"


def _walk_hooks(node, acc):
    """Collect every {"type": "command", "command": …} anywhere in a hooks tree.

    The shape differs between tools and between versions of the same tool, so
    matching on structure rather than on an expected path means a vendor
    reorganising their schema does not silently turn this check off.
    """
    if isinstance(node, dict):
        cmd = node.get("command")
        if cmd and (node.get("type") in (None, "command")) and isinstance(cmd, str):
            acc.append(cmd)
        for v in node.values():
            _walk_hooks(v, acc)
    elif isinstance(node, list):
        for v in node:
            _walk_hooks(v, acc)
    return acc


def _git(repo, *args):
    try:
        done = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                              errors="replace", timeout=10, check=False,
                              env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _github_login(home):
    """The account the GitHub CLI is signed in as. Reads only the `user:`
    line of hosts.yml; the token on other lines is never parsed or kept."""
    try:
        with open(os.path.join(home, ".config", "gh", "hosts.yml"), errors="replace") as fh:
            text = fh.read(20000)
    except OSError:
        return ""
    block = re.search(r"(?ms)^github\.com:\n(.*?)(?=^\S|\Z)", text)
    user = re.search(r"(?m)^\s+user:\s*([A-Za-z0-9-]+)\s*$", block.group(1)) if block else None
    return user.group(1) if user else ""


def _self_authored(path, home):
    """A repo hook the owner wrote: every commit to the file is by this
    machine's git identity, it has no uncommitted change, and `origin` belongs
    to the GitHub account signed in here. Anything unproven stays unverified."""
    repo = os.path.dirname(os.path.dirname(path))
    rel = os.path.relpath(path, repo)
    email = (_git(repo, "config", "user.email") or "").strip().casefold()
    authors = {a.strip().casefold() for a in
               (_git(repo, "log", "--format=%ae", "--", rel) or "").splitlines() if a.strip()}
    if not email or authors != {email}:
        return False
    if _git(repo, "status", "--porcelain", "--", rel) != "":
        return False
    origin = (_git(repo, "remote", "get-url", "origin") or "").strip()
    owner = re.match(r"^(?:https://github\.com/|git@github\.com:)([A-Za-z0-9-]+)/", origin)
    login = _github_login(home)
    return bool(owner and login and owner.group(1).casefold() == login.casefold())


def check_agent_hooks(store=None, hosts=("wsl", "win")):
    if "wsl" not in hosts:
        return []
    out, seen = [], {}
    home = _home()

    sources = [(os.path.join(home, ".claude", "settings.json"), "user"),
               (os.path.join(home, ".claude", "settings.local.json"), "user")]
    found, truncated = repos()
    for repo in found:
        for rel in PROJECT_HOOK_RELS:
            sources.append((os.path.join(repo, rel), "repo"))

    for path, scope in sources:
        if not os.path.isfile(path):
            continue
        doc = _json(path)
        if not isinstance(doc, dict):
            continue
        cmds = _walk_hooks(doc.get("hooks") or doc.get("tasks") or {}, [])
        for cmd in cmds:
            seen[f"{_short(path)}::{_hash(cmd)[:8]}"] = _hash(cmd)
            if PAYLOAD_RE.search(cmd):
                out.append(_finding(
                    "agent", "critical",
                    f"agent hook fetches and runs code ({_short(path)})",
                    f"`{cmd[:300]}` runs automatically on an agent or editor "
                    f"event. A hook is not a suggestion the tool shows you — it "
                    f"is a shell command the tool executes.",
                    _short(path)))
            elif scope == "repo" and _self_authored(path, home):
                out.append(_finding(
                    "agent", "low",
                    f"repository-supplied hook runs a command ({_short(path)})",
                    f"`{cmd[:300]}` — authored only by your git identity, with "
                    f"no uncommitted change, in a repository whose origin is "
                    f"your signed-in GitHub account. Inventory; a change to it "
                    f"is reported next run.",
                    _short(path)))
            elif scope == "repo":
                inline = INLINE_CODE_RE.search(cmd)
                out.append(_finding(
                    "agent", "high" if inline else "medium",
                    f"repository-supplied hook runs a command ({_short(path)})",
                    f"`{cmd[:300]}` — this hook ships with the repo, so cloning "
                    f"and opening it is enough to run it."
                    + (" The program is written inline in the config rather "
                       "than living in a reviewable file, which is common in "
                       "honest hooks and is also what makes a dishonest one "
                       "easy to miss in a diff." if inline else
                       " Verify it is yours."),
                    _short(path)))
            else:
                out.append(_finding(
                    "agent", "low", "agent hook configured",
                    f"`{cmd[:200]}` in your own settings — inventory, so a "
                    f"change to it is visible next run",
                    _short(path)))

    out.extend(_diff(store, _M_HOOKS, seen, "agent", "agent hook",
                     "a hook command that changed is a shell command that "
                     "changed, and it runs on the next tool event"))
    out.extend(_check_instruction_files(found))
    out.extend(_check_agent_plugins())
    if truncated:
        out.append(_finding(
            "visibility", "medium", "repository scan was truncated",
            f"stopped at {MAX_REPOS} repositories, so repo-scoped MCP servers, "
            f"hooks and git hooks below that cut-off are unaudited",
            "toolchain.repos"))
    if not seen:
        out.append(_finding(
            "agent", "ok", "no agent hooks configured",
            "no settings file defines a command hook, so no agent event "
            "currently executes a shell command", "~/.claude/settings.json"))
    return out


def _check_instruction_files(found_repos):
    """Agent instruction files carrying text hidden from the person reading them."""
    out, checked = [], 0
    candidates = []
    for name in AGENT_DOC_NAMES:
        candidates.append(os.path.join(_home(), name))
    for repo in found_repos:
        for name in AGENT_DOC_NAMES:
            candidates.append(os.path.join(repo, name))
            candidates.append(os.path.join(repo, ".github", name))
        candidates.extend(glob.glob(os.path.join(repo, ".cursor", "rules", "*")))
        candidates.extend(glob.glob(os.path.join(repo, ".claude", "*.md")))
        candidates.extend(glob.glob(
            os.path.join(repo, ".claude", "skills", "*", "*.md")))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        checked += 1
        text = _read(path, 200000)
        hits = INVISIBLE_RE.findall(text)
        if hits:
            line_no = 1
            for i, ch in enumerate(text):
                if INVISIBLE_RE.match(ch):
                    line_no = text.count("\n", 0, i) + 1
                    break
            out.append(_finding(
                "agent", "high",
                f"hidden characters in an agent instruction file: {_short(path)}",
                f"{len(hits)} zero-width or bidirectional-override characters, "
                f"first at line {line_no}. These render as nothing to you and "
                f"as text to the model, which is the documented way to put an "
                f"instruction in a file that a human reviewer cannot see.",
                _short(path)))
    if checked and not out:
        out.append(_finding(
            "agent", "ok", "agent instruction files carry no hidden text",
            f"{checked} instruction and skill files scanned for zero-width and "
            f"bidi-override characters; every one is legible as written",
            "agent instructions"))
    return out


def _check_agent_plugins():
    """Third-party agent plugins and the marketplaces they came from."""
    out = []
    base = os.path.join(_home(), ".claude", "plugins")
    installed = _json(os.path.join(base, "installed_plugins.json"))
    markets = _json(os.path.join(base, "known_marketplaces.json"))
    plugins = {}
    node = installed
    if isinstance(node, dict) and isinstance(node.get("plugins"), dict):
        node = node["plugins"]          # {"version": 2, "plugins": {...}}
    if isinstance(node, dict):
        for key, val in node.items():
            plugins[str(key)] = val
    elif isinstance(node, list):
        plugins = {str(x): None for x in node}

    market_names = []
    if isinstance(markets, dict):
        market_names = list(markets.keys())

    if plugins:
        reviewed = {name for name, records in plugins.items()
                    if _reviewed_typesafe_plugin(base, name, records, markets)}
        unreviewed = [name for name in plugins if name not in reviewed]
        if reviewed:
            out.append(_finding(
                "agent", "low", f"{len(reviewed)} reviewed agent plugin(s) installed",
                ", ".join(sorted(reviewed)) + " — every installed content file matches "
                "the reviewed official TypeSafe v0.5.7 commit; only documentation "
                "and a skill are installed. The skill can still influence the agent; "
                "a changed file or extra plugin file restores the warning.",
                "~/.claude/plugins"))
        if unreviewed:
            out.append(_finding(
                "agent", "medium" if market_names else "low",
                f"{len(unreviewed)} agent plugin(s) installed",
                "third-party plugins can influence an agent with tool access: "
                + ", ".join(unreviewed[:12])
                + (f" — marketplace(s): {', '.join(market_names[:6])}. "
                   "Verify the installed content and source before trusting it."
                   if market_names else ""),
                "~/.claude/plugins"))
    return out


def _reviewed_typesafe_plugin(base, name, records, markets):
    """True only for the six reviewed files at the exact official commit."""
    if name != "typesafe@typesafe-ai" or not isinstance(records, list) or len(records) != 1:
        return False
    record = records[0]
    market = (markets or {}).get("typesafe-ai") if isinstance(markets, dict) else None
    if not isinstance(record, dict) or not isinstance(market, dict):
        return False
    if market.get("source") != {"source": "github", "repo": "typesafe-ai/skills"}:
        return False
    root = os.path.join(base, "cache", "typesafe-ai", "typesafe", "0.5.7")
    if (record.get("version") != "0.5.7"
            or record.get("gitCommitSha") != REVIEWED_TYPESAFE_COMMIT
            or record.get("installPath") != root or not os.path.isdir(root)
            or os.path.islink(root)):
        return False
    seen = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        if any(os.path.islink(os.path.join(directory, entry)) for entry in dirs + files):
            return False
        for filename in files:
            path = os.path.join(directory, filename)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if rel.startswith(".in_use/") and rel[8:].isdigit():
                try:
                    if os.path.getsize(path) <= 128:
                        continue  # Claude's bounded, transient use markers
                except OSError:
                    return False
            wanted = REVIEWED_TYPESAFE.get(rel)
            if not wanted:
                return False
            try:
                with open(path, "rb") as handle:
                    actual = hashlib.sha256(handle.read(300000)).hexdigest()
                    if handle.read(1):
                        return False
            except OSError:
                return False
            if actual != wanted:
                return False
            seen.add(rel)
    return seen == set(REVIEWED_TYPESAFE)
