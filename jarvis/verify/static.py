"""Static rules for this product's own bug classes, shipped in the package.

    python -m jarvis.verify          runs them with the rest of the ladder
    static.run(root)                 -> {"ok", "applicable", "files", "rules", "violations"}

General linters (ruff, mypy) catch general mistakes. These rules catch the
mistakes this product has actually made, each born from a defect found in it
and each tied to an invariant in jarvis/verify/invariants.py:

    S1  V12  a collector launches a Windows program outside the interop gate
    S2  V14  an elevated shell is started on a script file (-File) rather than
             on inline code fixed at launch, so a same-user process can swap the
             file between staging and the UAC prompt (broker, posture, sensor
             installers; 2026-10-30)
    S3  V14  a command line is handed to a shell (shell=True, os.system, os.popen)
    S4  V14  a .cmd/.bat launcher starts PowerShell by bare name, which cmd
             resolves in the current folder first (Install.cmd, 2026-10-30)

There is no list of tolerated violations: a rule ships with the tree clean.
Rules are syntactic: S2 sees a -File argument written in the same function as
-Verb RunAs, not one passed in from elsewhere, and a literal split mid-token
("-Ve" "rb") would pass its fast exit. A copy with no sources
(the sourceless Linux release) is "not applicable", never a pass.
"""

import ast
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

Hits = list[tuple[int, str]]

# Folders of a tree that hold shipped code and launchers (the package itself is
# added by name, since the Argus build renames it).
ROOTS = ("scripts", "windows-sensor", "windows-sysmon", "desktop/scripts")
SUFFIXES = (".py", ".ps1", ".cmd", ".bat")
SKIP_DIRS = {"__pycache__", "node_modules", "target", ".git", "tests"}


@dataclass(frozen=True)
class Rule:
    id: str
    invariant: str
    summary: str
    suffixes: tuple[str, ...]
    check: Callable[[str, str], Hits]
    scope: Callable[[str, str], bool] = lambda path, package: True


# ---------------------------------------------------------------- S1 / V12 ----
LAUNCHERS = {"run", "Popen", "check_output", "check_call", "call"}
WINDOWS_HINTS = ("_ps", "powershell", "pwsh", ".exe", "interop_launcher")
# path below the package -> why this launch is deliberately ungated
# (docs/architecture/INTEROP-GATE.md).
UNGATED = {
    "collectors/host/posture/collect.py": "waits on the owner's elevation prompt",
    "collectors/host/inputwatch/helper.py": "restores the input hook (protection)",
}


@lru_cache(maxsize=4)
def _parse(source):
    """One parse per file for all rules (the engine runs every rule on a file in turn)."""
    return ast.parse(source)


def _below_package(path):
    return path.split("/", 1)[1] if "/" in path else path


def _ungated_windows_launches(path, source) -> Hits:
    if _below_package(path) in UNGATED or "subprocess" not in source:
        return []
    hits: Hits = []
    for node in ast.walk(_parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in LAUNCHERS and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"):
            continue
        text = ast.unparse(node)
        if any(h in text.lower() for h in WINDOWS_HINTS):
            hits.append((node.lineno, text[:120]))
    return hits


# ---------------------------------------------------------------- S2 / V14 ----
ELEVATE = re.compile(r"-Verb\s+['\"]?RunAs\b", re.I)
FILE_ARG = re.compile(r"-File\b(?!Path)", re.I)
COMPOUND = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.AsyncFor,
            ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match)


def _elevated_file_launch_py(source) -> Hits:
    """An elevated launch whose enclosing function (or module statement) also
    writes a -File argument: the argument list is often built a few lines
    before the Start-Process (broker.py), so one statement is too narrow."""
    if not re.search(r"-verb", source, re.I):              # necessary for any match: fast exit
        return []
    tree = _parse(source)
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    hits: Hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.stmt) and not isinstance(node, COMPOUND)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue                                      # a docstring mentions, it does not launch
        text = ast.unparse(node)
        if not ELEVATE.search(text):
            continue
        scope: ast.AST = node
        while scope in parent and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = parent[scope]
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = node                                  # module level: the statement itself
        if FILE_ARG.search(ast.unparse(scope)):
            hits.append((node.lineno, text[:120]))
    return hits


def _ps_statements(source):
    """(first line, text) of each logical PowerShell statement, comments removed
    and backtick continuations joined."""
    out, buf, start, in_block = [], [], 0, False
    for n, raw in enumerate(source.splitlines(), 1):
        line = raw
        if in_block:
            if "#>" not in line:
                continue
            line, in_block = line.split("#>", 1)[1], False
        if "<#" in line:
            line, in_block = line.split("<#", 1)[0], "#>" not in line.split("<#", 1)[1]
        if line.lstrip().startswith("#"):
            line = ""
        if not buf:
            start = n
        stripped = line.rstrip()
        buf.append(stripped[:-1] if stripped.endswith("`") else stripped)
        if not stripped.endswith("`"):
            out.append((start, " ".join(buf)))
            buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _elevated_file_launch(path, source) -> Hits:
    if path.endswith(".py"):
        return _elevated_file_launch_py(source)
    hits: Hits = []
    for line, text in _ps_statements(source):
        m = ELEVATE.search(text)
        if m and FILE_ARG.search(text[m.start():]):
            hits.append((line, text.strip()[:120]))
    return hits


# ---------------------------------------------------------------- S3 / V14 ----
SHELL_HINT = re.compile(r"shell\s*=\s*True|\bos\s*\.\s*(?:system|popen)\b")


def _shell_strings(path, source) -> Hits:
    if not SHELL_HINT.search(source):                     # necessary for any match: fast exit
        return []
    hits: Hits = []
    for node in ast.walk(_parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)):
            continue
        owner, attr = node.func.value.id, node.func.attr
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in node.keywords)
        if (owner == "subprocess" and attr in LAUNCHERS and shell) or \
                (owner == "os" and attr in ("system", "popen")):
            hits.append((node.lineno, ast.unparse(node)[:120]))
    return hits


# ---------------------------------------------------------------- S4 / V14 ----
BARE_POWERSHELL = re.compile(r"^(?:call\s+|start\s+(?:\"[^\"]*\"\s+)?)?(?:powershell|pwsh)(?:\.exe)?\b", re.I)


def _bare_powershell(path, source) -> Hits:
    hits: Hits = []
    for n, raw in enumerate(source.splitlines(), 1):
        line = raw.strip().lstrip("@").strip()
        if re.match(r"(rem\b|::)", line, re.I):
            continue
        if BARE_POWERSHELL.match(line):
            hits.append((n, line[:120]))
    return hits


def _in(*folders):
    def scope(path, package):
        below = _below_package(path) if path.startswith(package + "/") else None
        return below is not None and any(below.startswith(f + "/") for f in folders)
    return scope


def _code(path, package):
    return path.startswith(package + "/") or path.startswith("scripts/")


RULES = (
    Rule("S1", "V12", "Windows programs are launched only through the interop gate",
         (".py",), _ungated_windows_launches, _in("collectors", "service", "core")),
    Rule("S2", "V14", "an elevated shell runs inline code fixed at launch, never a script file",
         (".py", ".ps1"), _elevated_file_launch,
         lambda path, package: path.endswith(".ps1") or _code(path, package)),
    Rule("S3", "V14", "no command line is handed to a shell (shell=True, os.system, os.popen)",
         (".py",), _shell_strings, _code),
    Rule("S4", "V14", ".cmd/.bat launchers start PowerShell by full path",
         (".cmd", ".bat"), _bare_powershell),
)
RULES_BY_ID = {r.id: r for r in RULES}


def _files(tree, package):
    seen = set()
    tops = [tree / package] + [tree / r for r in ROOTS]
    for top in tops:
        if not top.is_dir():
            continue
        for p in sorted(top.rglob("*")):
            if p.suffix in SUFFIXES and p.is_file() and not SKIP_DIRS & set(p.relative_to(tree).parts):
                seen.add(p)
    for p in sorted(tree.glob("*")):
        if p.suffix in (".ps1", ".cmd", ".bat") and p.is_file():
            seen.add(p)
    return sorted(seen)


def run(root=None, package=None):
    """Every rule over every shipped source file of the tree at `root`."""
    here = Path(__file__).resolve()
    tree = Path(root) if root is not None else here.parents[2]
    package = package or here.parents[1].name
    files = _files(tree, package)
    violations, errors = [], []
    counts = {r.id: 0 for r in RULES}
    for p in files:
        rel = p.relative_to(tree).as_posix()
        try:
            source = p.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        for rule in RULES:
            if p.suffix not in rule.suffixes or not rule.scope(rel, package):
                continue
            try:
                found = rule.check(rel, source)
            except SyntaxError as exc:
                errors.append(f"{rel}: cannot parse ({exc.msg}, line {exc.lineno})")
                break
            for line, text in found:
                counts[rule.id] += 1
                violations.append({"rule": rule.id, "invariant": rule.invariant, "path": rel,
                                   "line": line, "text": text})
    return {"ok": not violations and not errors, "applicable": bool(files), "files": len(files),
            "rules": [{"id": r.id, "invariant": r.invariant, "summary": r.summary,
                       "violations": counts[r.id]} for r in RULES],
            "violations": violations, "errors": errors[:20]}
