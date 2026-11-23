#!/usr/bin/env python3
"""Fast test runner: parallel by module, and only what changed.

    python3 scripts/dev/fasttest.py            run the modules whose inputs changed
    python3 scripts/dev/fasttest.py --all      run every module (ignores the cache)
    python3 scripts/dev/fasttest.py --list     say what would run and why, run nothing
    python3 scripts/dev/fasttest.py -k broker  only modules whose name contains "broker"

Same tests as `python3 -m unittest discover -s tests`, run one module per process:
  * Parallel: --jobs workers (default: the CPU count), longest modules first
    (durations recorded from earlier runs). Modules that start PowerShell or use
    WSL interop run in their own lane, one at a time: run side by side they made
    the interop relay fail ("UtilAcceptVsock: accept4 failed") and the tests flake.
  * Cached: a module that passed is skipped while nothing it depends on changed:
    its own file, every jarvis/ or tests/ module it imports (transitively), every
    repository file its code names by path, the non-Python payloads under jarvis/
    (scripts, pages, rule data), and the Python version. Failures are never cached.
  * Isolated: each worker gets a scratch HOME/USERPROFILE, so no test reads or
    writes the owner's real ~/.jarvis (the phone registry incident of 2026-11-04).

The cache is an optimisation for iteration, not a gate: `--all` (or the plain
unittest discover command) still runs everything before a release is staged.
"""

import argparse
import ast
import concurrent.futures as cf
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
CACHE_DIR = Path(os.environ.get("FASTTEST_CACHE", Path.home() / ".cache" / "argus-fasttest"))
CACHE = CACHE_DIR / "results.json"
INTEROP = re.compile(r"powershell\.exe|pwsh|_powershell\(|\bwin\.run\(|\bwin\._ps|interop|/mnt/c/|cmd\.exe|wslpath")
ASSET_SUFFIXES = (".ps1", ".psm1", ".json", ".html", ".js", ".css", ".txt", ".toml", ".yml", ".yaml",
                  ".nsi", ".sh", ".xml", ".cs", ".sql", ".svelte", ".ts", ".rs")
LITERAL_PATH = re.compile(r"[\w./\\-]+\.(?:ps1|psm1|json|html|js|css|nsi|sh|xml|cs|toml|yml|yaml|svelte|ts|rs|md|py)\b")


def sha(data):
    return hashlib.sha256(data).hexdigest()


INDEX = CACHE_DIR / "index.json"
_index = {}            # rel path -> {"m": mtime_ns, "s": size, "h": sha256, "i": [imports], "n": [named files]}
_dirty = False
ROOT_S = str(ROOT) + os.sep
ALL_FILES = []         # rel paths (str)
BY_NAME = {}


def _entry(rel):
    """Hash, imports and named files of one repository file, re-read only when it changed."""
    global _dirty
    full = ROOT_S + rel
    try:
        st = os.stat(full)
    except OSError:
        return None
    e = _index.get(rel)
    if e and e["m"] == st.st_mtime_ns and e["s"] == st.st_size:
        return e
    data = open(full, "rb").read()
    e = {"m": st.st_mtime_ns, "s": st.st_size, "h": sha(data), "i": None, "n": None}
    _index[rel] = e
    _dirty = True
    return e


def module_rel(name):
    """jarvis.x.y / tests.z -> rel path of its file, or None (stdlib, third party)."""
    if name.split(".")[0] not in ("jarvis", "tests"):
        return None
    base = name.replace(".", "/")
    for rel in (base + ".py", base + "/__init__.py"):
        if os.path.isfile(ROOT_S + rel):
            return rel
    return None


def imports_of(rel):
    e = _entry(rel)
    if e is None:
        return []
    if e["i"] is None:
        global _dirty
        out = set()
        try:
            tree = ast.parse(open(ROOT_S + rel, "rb").read())
        except (SyntaxError, ValueError):
            tree = None
        pkg = rel[:-3].split("/")[:-1]
        for node in (ast.walk(tree) if tree else ()):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = pkg[:len(pkg) - node.level + 1] if node.level > 1 else pkg
                    mod = ".".join(base + ([node.module] if node.module else []))
                else:
                    mod = node.module or ""
                names = [mod] + [f"{mod}.{a.name}" for a in node.names]
            for n in names:
                parts = n.split(".")
                for i in range(len(parts), 0, -1):     # a.b.c, then its packages a.b, a
                    r = module_rel(".".join(parts[:i]))
                    if r:
                        out.add(r)
        e["i"] = sorted(out)
        _dirty = True
    return e["i"]


def named_of(rel):
    """Repository files this file names by path or file name in its text."""
    e = _entry(rel)
    if e is None:
        return []
    if e["n"] is None:
        global _dirty
        found = set()
        text = open(ROOT_S + rel, encoding="utf-8", errors="replace").read()
        for m in set(LITERAL_PATH.findall(text)):
            m = m.replace("\\", "/").lstrip("./")
            if os.path.isfile(ROOT_S + m):
                found.add(m)
            else:
                found.update(BY_NAME.get(m.rsplit("/", 1)[-1], ()))
        e["n"] = sorted(found)
        _dirty = True
    return e["n"]


_closures = {}


def closure(rel):
    if rel in _closures:
        return _closures[rel]
    seen, todo = set(), [rel]
    while todo:
        r = todo.pop()
        if r in seen:
            continue
        seen.add(r)
        todo.extend(x for x in imports_of(r) if x not in seen)
    _closures[rel] = seen
    return seen


def tracked_files():
    try:
        return subprocess.run(["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard"],
                              capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        return [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file()]


def payload_digest():
    """Every non-Python file under jarvis/: payloads the code loads by path at run time."""
    h = hashlib.sha256()
    for rel in sorted(f for f in ALL_FILES if f.startswith("jarvis/") and f.endswith(ASSET_SUFFIXES)):
        e = _entry(rel)
        h.update(rel.encode() + b"\0" + (e["h"] if e else "missing").encode())
    return h.hexdigest()


def module_key(test_rel, payloads):
    deps = closure(test_rel)
    files = set(deps)
    for d in deps:
        files.update(named_of(d))
    h = hashlib.sha256(f"py{sys.version_info[:3]}|{payloads}".encode())
    for rel in sorted(files):
        e = _entry(rel)
        h.update(rel.encode() + b"\0" + (e["h"] if e else "missing").encode())
    return h.hexdigest(), len(files)


def load_index():
    global _index
    try:
        _index = json.loads(INDEX.read_text())
    except (OSError, ValueError):
        _index = {}


def save_index():
    if _dirty:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = INDEX.with_suffix(".tmp")
        tmp.write_text(json.dumps(_index, separators=(",", ":")))
        os.replace(tmp, INDEX)


def load_cache():
    try:
        return json.loads(CACHE.read_text())
    except (OSError, ValueError):
        return {"passed": {}, "durations": {}}


def save_cache(cache):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=0, sort_keys=True))
    os.replace(tmp, CACHE)


def run_module(name, timeout):
    """One test module in its own process with a scratch home. -> (name, ok, seconds, tail)."""
    # Not under /tmp: release and provenance code refuse a world-writable ancestor.
    homes = CACHE_DIR / "homes"
    homes.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(homes, 0o700)
    with tempfile.TemporaryDirectory(prefix="home-", dir=homes) as home:
        # The usual home layout: some tests create temporary files under ~/.cache.
        for sub in (".cache", ".config", ".local/share"):
            os.makedirs(os.path.join(home, sub), exist_ok=True)
        env = dict(os.environ, HOME=home, USERPROFILE=home, PYTHONDONTWRITEBYTECODE="1")
        start = time.monotonic()
        try:
            r = subprocess.run([sys.executable, "-m", "unittest", f"tests.{name}"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=timeout)
            ok, out = r.returncode == 0, (r.stdout + r.stderr)
        except subprocess.TimeoutExpired as exc:
            ok, out = False, f"TIMEOUT after {timeout}s\n" + str(exc.stdout or "")[-2000:]
        return name, ok, time.monotonic() - start, out


def summary_line(out):
    m = re.findall(r"^(Ran \d+ tests? in [\d.]+s)$", out, re.M)
    r = re.findall(r"^(OK.*|FAILED.*)$", out, re.M)
    return f"{m[-1] if m else '?'} {r[-1] if r else ''}".strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--all", action="store_true", help="run every module, ignore the cache")
    ap.add_argument("--list", action="store_true", help="show what would run, run nothing")
    ap.add_argument("-k", dest="match", default="", help="only modules whose name contains this")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--timeout", type=int, default=900, help="seconds per module")
    args = ap.parse_args(argv)

    started = time.monotonic()
    load_index()
    ALL_FILES.extend(f for f in tracked_files() if os.path.isfile(ROOT_S + f))
    for f in ALL_FILES:
        BY_NAME.setdefault(f.rsplit("/", 1)[-1], set()).add(f)
    payloads = payload_digest()
    cache = load_cache()
    modules = sorted(p.stem for p in TESTS.glob("test_*.py") if args.match in p.stem)
    plan, skipped = [], 0
    keys = {}
    for m in modules:
        key, nfiles = module_key(f"tests/{m}.py", payloads)
        keys[m] = key
        if not args.all and cache["passed"].get(m) == key:
            skipped += 1
            continue
        plan.append(m)
    save_index()
    durations = cache.get("durations", {})
    interop = {m for m in plan if INTEROP.search((TESTS / f"{m}.py").read_text(encoding="utf-8", errors="replace"))}
    plan.sort(key=lambda m: -durations.get(m, 30.0))
    est = sum(durations.get(m, 30.0) for m in plan)
    print(f"{len(modules)} modules: {skipped} unchanged since they passed (skipped), {len(plan)} to run "
          f"({len(interop)} in the one-at-a-time interop lane); planning took {time.monotonic() - started:.1f}s")
    if args.list:
        for m in plan:
            print(f"  {m}{'  [interop lane]' if m in interop else ''}  ~{durations.get(m, 30.0):.0f}s")
        return 0
    if not plan:
        print("nothing changed since the last passing run")
        return 0
    print(f"serial estimate ~{est / 60:.1f} min; running on {args.jobs} workers")

    failures, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool, \
            cf.ThreadPoolExecutor(max_workers=1) as lane:
        futs = [(lane if m in interop else pool).submit(run_module, m, args.timeout) for m in plan]
        for fut in cf.as_completed(futs):
            name, ok, secs, out = fut.result()
            done += 1
            durations[name] = round(secs, 1)
            if ok:
                cache["passed"][name] = keys[name]
            else:
                cache["passed"].pop(name, None)
                failures.append((name, out))
            print(f"[{done}/{len(plan)}] {'ok  ' if ok else 'FAIL'} {name} ({secs:.1f}s) {summary_line(out)}",
                  flush=True)
            cache["durations"] = durations
            save_cache(cache)                     # progress survives an interrupted run
    wall = time.monotonic() - started
    print(f"\n{len(plan) - len(failures)} passed, {len(failures)} failed, {skipped} skipped as unchanged; "
          f"{wall / 60:.1f} min wall (serial ~{est / 60:.1f} min)")
    for name, out in failures:
        print(f"\n===== {name} =====")
        print("\n".join(out.strip().splitlines()[-25:]))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
