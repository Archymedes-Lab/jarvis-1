"""Finding every codebase on the server, in a bounded walk.

A codebase is a folder holding a .git directory or a project manifest
(MANIFESTS). The walk starts from the application roots and from the folders
the server's own services and containers run code from (service_paths,
container_paths), so a codebase outside the usual places is still found.

Collects what the scanners read (lockfiles, virtual environments, source and
config files) and what it can judge from the walk itself (world-writable code).
Symlinks are never followed, dependency and build trees are skipped (their
lockfile at the project root already names them), and the walk stops at a file
count, a directory count and a deadline. Stopping is reported by the caller as
"partly scanned", never as clean.
"""

import glob
import json
import os
import re
import stat
import time

from . import lockfiles

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "bower_components", "__pycache__",
    ".cache", ".npm", ".yarn", ".pnpm-store", ".cargo", ".rustup", ".gradle", ".m2",
    "site-packages", "dist-packages", ".tox", ".nox", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "dist", "build", ".next", ".nuxt", "target", "coverage",
    "tests", "test", "__tests__", "spec", "testdata", "fixtures", "examples",
    ".idea", ".vscode", ".local", ".config", ".mozilla", ".vscode-server", "snap",
    "__mocks__", "mocks", "e2e", "third_party", "third-party",
    # Vendored copies and SDK installs: third-party code that arrives and updates
    # with its tool, not the owner's code (2026-10-29: 276 of 367 "codebases"
    # here were Go module-cache entries, plus vendored boto and NDK packages).
    "vendored", "_vendor", "google-cloud-sdk",
}
# A Go module-cache entry is named module@version (e.g. grpc@v1.83.2); so is
# every directory inside GOPATH/pkg/mod. No project folder has that shape.
MODULE_CACHE = re.compile(r"@v\d")


def _dependency_store(dirpath, name):
    """A dependency or SDK store under dirpath: Go's module cache (pkg/mod and
    module@version entries), the Android SDK."""
    parent = os.path.basename(dirpath)
    return (MODULE_CACHE.search(name) is not None
            or (parent == "pkg" and name in ("mod", "sumdb"))
            or (parent == "Android" and name == "Sdk"))
# A bundled interpreter's standard library (lib/python3.11 inside an SDK).
BUNDLED = re.compile(r"^python\d")
# Test code is full of deliberate fakes (keys, eval, shell calls) and is not served.
TEST_FILE = re.compile(r"^test_.*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[cm]?[jt]sx?$|Tests?\.(?:java|kt)$")
SOURCE_EXT = {".py", ".php", ".phtml", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
              ".rb", ".go", ".java", ".kt"}
CONFIG_EXT = {".env", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".json"}
MAX_SOURCE_BYTES = 512 * 1024
MANIFESTS = {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "go.mod", "Cargo.toml",
             "composer.json", "Gemfile", "pom.xml", "build.gradle", "build.gradle.kts"}
UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system",
             "/usr/lib/systemd/system", "/home/*/.config/systemd/user")
# Where the distribution's own programs live: a service running one names no codebase.
SYSTEM_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/",
                   "/usr/libexec/", "/lib64/", "/usr/share/")
NOT_CODE = ("/", "/proc", "/sys", "/dev", "/run", "/etc", "/boot")
MAX_CONTAINERS = 200


def _is_config(name):
    low = name.lower()
    return low == ".env" or low.startswith(".env.") or os.path.splitext(low)[1] in CONFIG_EXT


def _world_writable(mode):
    return bool(mode & stat.S_IWOTH) and not mode & stat.S_ISVTX


def walk(roots, exclude=(), max_files=200_000, max_dirs=60_000, deadline_s=240.0,
         clock=time.monotonic):
    """What the scanners need from `roots`, within the bounds given."""
    out = {"codebases": [], "lockfiles": [], "venvs": [], "sources": [], "configs": [], "writable": [],
           "files": 0, "dirs": 0, "truncated": False, "unreadable": 0}
    skip = {os.path.realpath(p) for p in exclude}
    stop = clock() + deadline_s

    def onerror(_exc):
        out["unreadable"] += 1

    for root in roots:
        if out["truncated"]:
            break
        for dirpath, dirs, files in os.walk(root, onerror=onerror):
            out["dirs"] += 1
            if out["dirs"] > max_dirs or out["files"] > max_files or clock() > stop:
                out["truncated"] = True
                break
            if ".git" in dirs or any(f in MANIFESTS or lockfiles.is_lockfile(f) for f in files):
                out["codebases"].append(dirpath)
            if "pyvenv.cfg" in files:
                out["venvs"].append(dirpath)
                dirs[:] = []
                continue
            # Hidden folders below a root are tool installs and caches (editor
            # servers, version managers), not applications; a hidden root is still walked.
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")
                             and not BUNDLED.match(d) and not _dependency_store(dirpath, d)
                             and os.path.realpath(os.path.join(dirpath, d)) not in skip)
            try:
                if _world_writable(os.lstat(dirpath).st_mode):
                    out["writable"].append(dirpath)
            except OSError:
                pass
            for name in sorted(files):
                out["files"] += 1
                if out["files"] > max_files:
                    out["truncated"] = True
                    break
                path = os.path.join(dirpath, name)
                ext = os.path.splitext(name)[1].lower()
                lock = lockfiles.is_lockfile(name)
                code = ext in SOURCE_EXT and not TEST_FILE.search(name)
                if not (lock or code or _is_config(name)):
                    continue
                try:
                    st = os.lstat(path)
                except OSError:
                    out["unreadable"] += 1
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue                    # symlinks, sockets, devices
                if lock:
                    out["lockfiles"].append(path)
                    continue
                if st.st_size > MAX_SOURCE_BYTES:
                    continue
                if code:
                    out["sources"].append(path)
                    if _world_writable(st.st_mode):
                        out["writable"].append(path)
                else:
                    out["configs"].append(path)
    return out


def project_of(path, roots, codebases=()):
    """The codebase a path belongs to: the nearest enclosing one found by the
    walk, else the first folder under its root."""
    if codebases:
        known = codebases if isinstance(codebases, (set, frozenset)) else set(codebases)
        d = path if path in known else os.path.dirname(path)
        while d and d != "/":
            if d in known:
                return d
            d = os.path.dirname(d)
    best = None
    for root in roots:
        r = root.rstrip("/") or "/"
        if path == r or path.startswith(r + "/") or r == "/":
            if best is None or len(r) > len(best):
                best = r
    if best is None:
        return os.path.dirname(path)
    rel = os.path.relpath(path, best)
    first = rel.split(os.sep, 1)[0]
    if first in (".", "") or os.sep not in rel:
        return best
    return os.path.join(best, first)


def _code_dir(path):
    path = os.path.normpath(path)
    if path in NOT_CODE or any(path.startswith(p + "/") for p in NOT_CODE[1:]):
        return None
    if path.startswith(SYSTEM_PREFIXES) or not os.path.isabs(path):
        return None
    if os.path.isfile(path):
        path = os.path.dirname(path)
    return path if os.path.isdir(path) and path != "/" else None


def service_paths(unit_dirs=UNIT_DIRS):
    """Folders systemd services run code from: WorkingDirectory= and the
    absolute paths in ExecStart= that are not the distribution's programs."""
    found = set()
    files = []
    for d in unit_dirs:
        for unit_dir in (glob.glob(d) if "*" in d else [d]):
            files += glob.glob(os.path.join(unit_dir, "*.service"))
    for path in sorted(files)[:5000]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read(256 * 1024)
        except OSError:
            continue
        for line in text.splitlines():
            key, sep, value = line.strip().partition("=")
            if not sep:
                continue
            if key == "WorkingDirectory":
                candidates = [value.strip().lstrip("-!~")]
            elif key in ("ExecStart", "ExecStartPre"):
                candidates = [t.lstrip("-@:+!") for t in value.split() if "/" in t]
            else:
                continue
            for c in candidates:
                d = _code_dir(c)
                if d:
                    found.add(d)
    return sorted(found)


def container_paths(which, run):
    """(host folders bind-mounted into running containers, observed). observed
    is None when no container runtime is installed, False when it would not answer."""
    exe = which("docker") or which("podman")
    if not exe:
        return [], None
    code, out = run([exe, "ps", "-q"], timeout=30)
    if code != 0:
        return [], False
    ids = out.split()[:MAX_CONTAINERS]
    if not ids:
        return [], True
    code, out = run([exe, "inspect", *ids], timeout=60)
    try:
        docs = json.loads(out) if code == 0 else None
    except ValueError:
        docs = None
    if not isinstance(docs, list):
        return [], False
    found = set()
    for doc in docs:
        for m in (doc or {}).get("Mounts") or ():
            if m.get("Type") == "bind" and m.get("Source"):
                d = _code_dir(m["Source"])
                if d:
                    found.add(d)
    return sorted(found), True
