"""Where to look for credentials, and the audit that ties matching to exposure."""

import os
import re
import stat

from jarvis.core import fsperm
from jarvis.core.finding import finding as _finding

from .exposure import _git_tracked, _other_humans, _private_project_env, _world_readable
from .patterns import _mask, fingerprint, scan_file

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


CAT_ORDER = {"reachable": 0, "tracked": 1, "present": 2, "visibility": 3}


# Directories that hold other people's code, build output, or caches. Scanning
# them finds thousands of test fixtures and no real secrets.
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", "target", ".next", ".nuxt", ".cache",
    ".gradle", ".m2", ".cargo", ".rustup", ".npm", ".pnpm-store", ".yarn",
    "vendor", "site-packages", ".tox", ".terraform", "Pods", ".idea",
    ".vscode-server", ".cursor-server", ".antigravity-server", "snap",
    ".local/share/Trash", "AppData", "Windows", "Program Files",
}


# Path fragments that mean "this file is a cache, a vendored dependency, or
# someone else's source". The first live run drowned six real credentials —
# an OAuth token, a Cursor auth file, a project .env — under hundreds of hits
# inside WebKit caches and package stores. A scanner nobody reads because it
# cries wolf is worse than no scanner.
SKIP_PATH_PARTS = (
    "webkitcache", "/cache/", "gpucache", "code cache", "blob_storage",
    "indexeddb", "service worker", "local storage", "session storage",
    "/pkg/mod/", "/pnpm/store/", "/share/uv/", "-server/bin/", "/.git/",
    "/dist/", "/coverage/", "/.next/", "/testdata/", "/fixtures/",
    "/node_modules/", "/site-packages/", "/.trash/", "/logs/",
    # Manual pages and bundled documentation quote example keys to show their
    # format (npm's config.7 carries a sample private key block).
    "/share/man/", "/share/doc/",
    # AI tool working state: conversation caches, file-history snapshots and
    # plugin sources. These mirror content that already exists elsewhere, so
    # reporting them doubles every finding and points at a path the user
    # cannot act on.
    "/.claude/file-history/", "/.claude/todos/", "/.claude/projects/",
    "/.claude/paste-cache/", "/.claude/plugins/",
    "/.codex/.tmp/", "/.codex/sessions/", "/.cursor/projects/",
    "/.gemini/tmp/", "/.gemini/antigravity/", "/.antigravity", "/.aider",
    "/.continue/sessions/",
)


# Files whose entire purpose is to show the *shape* of a credential.
EXAMPLE_FILES = re.compile(
    r"(\.env\.(example|sample|template|dist)$|\.example$|\.sample$|"
    r"(^|/)(example|sample|template|test)[._-]|[-_]test\.|\.test\.|\.spec\.)", re.I)


SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
    ".zip", ".gz", ".tar", ".xz", ".7z", ".rar", ".jar", ".war",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".ttf", ".woff",
    ".woff2", ".eot", ".so", ".dll", ".dylib", ".exe", ".bin", ".o",
    ".pyc", ".pyo", ".class", ".wasm", ".db", ".sqlite", ".sqlite3",
    ".lock", ".map", ".min.js", ".pack",
}


# Files whose whole purpose is holding a credential. Their existence is not the
# finding; their permissions and whether git can see them are.
CREDENTIAL_FILES = (
    ".npmrc", ".git-credentials", ".pypirc", ".netrc",
    ".aws/credentials", ".config/gh/hosts.yml", ".docker/config.json",
    ".kube/config", ".config/gcloud/credentials.db",
    ".config/.wrangler/config/default.toml",
)


def walk(roots, max_files=60000):
    seen = 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and not d.startswith(".cache")]
            # Trailing slash: every entry in SKIP_PATH_PARTS is written as a
            # whole path component ("/.claude/paste-cache/"), which the
            # directory itself only contains once its own name is closed off.
            # Without it the directory named by an entry was still scanned.
            low_dir = dirpath.lower() + "/"
            if any(part in low_dir for part in SKIP_PATH_PARTS):
                dirnames[:] = []
                continue
            for fn in filenames:
                seen += 1
                if seen > max_files:
                    return
                ext = os.path.splitext(fn)[1].lower()
                if ext in SKIP_EXT:
                    continue
                yield os.path.join(dirpath, fn)


def default_roots():
    """Where credentials actually live.

    Scanning all of $HOME sounds thorough and is mostly theatre: the first
    attempt spent fifteen minutes inside dependency trees and package caches
    without finishing, and the real findings it had already surfaced were all
    in config directories and project checkouts. So the default is the places
    a credential is plausibly stored — tool config, documents, and the top
    level of each git repository — and `--deep` is there for the rare case
    where the whole tree really is wanted.
    """
    home = os.path.expanduser("~")
    roots = []
    for rel in (".config", ".aws", ".azure", ".docker", ".kube", ".gemini",
                ".fly", ".ssh", ".gnupg", ".claude", ".codex", ".cursor",
                ".convex", ".nova", ".vscode", "Documents", "Desktop",
                "Downloads"):
        p = os.path.join(home, rel)
        if os.path.isdir(p):
            roots.append(p)

    # Git checkouts near the top of home: that is where .env files live.
    try:
        for name in sorted(os.listdir(home)):
            p = os.path.join(home, name)
            if not os.path.isdir(p) or name in SKIP_DIRS:
                continue
            if os.path.isdir(os.path.join(p, ".git")):
                roots.append(p)
    except OSError:
        pass
    return roots


# Files that exist to hold one tool's own login, relative to $HOME. Their
# owner-only, untracked copies are advisory inventory. A value copied outside
# its tool store remains actionable, as do loose or shared files.
DESIGNATED_STORES = {
    ".claude/.credentials.json": "Claude Code",
    ".config/gh/hosts.yml": "GitHub CLI",
    ".config/cursor/auth.json": "Cursor",
    ".config/.wrangler/config/default.toml": "Wrangler",
    # The owner's own app keeps its API key in its XDG config (2026-09-23).
    ".config/archymedes/settings.json": "archymedes",
}


def _designated_store(path, home):
    """The tool that owns `path` as its credential store, or None. Requires a
    regular file (not a link) owned by this user with no group/other bits."""
    rel = os.path.relpath(path, home)
    tool = DESIGNATED_STORES.get(rel)
    if not tool:
        return None
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or not fsperm.owner_only(st):
        return None
    return tool


LOOSE_FILES = (".bash_history", ".zsh_history", ".npmrc", ".netrc",
               ".pypirc", ".git-credentials", ".env", ".env.local",
               ".my.cnf", ".pgpass", ".rediscli_history", ".psql_history")


def audit(roots=None, hosts=("wsl",), deep=False):
    home = os.path.expanduser("~")
    if roots:
        roots = list(roots)
    elif deep:
        roots = [home]
    else:
        roots = default_roots()
    out = []
    found = {}          # fingerprint -> list of (path, kind, line)
    scanned = 0

    targets = list(walk(roots))
    if not deep:
        for rel in LOOSE_FILES:
            p = os.path.join(home, rel)
            if os.path.isfile(p):
                targets.append(p)

    others = _other_humans()

    for path in targets:
        scanned += 1
        if EXAMPLE_FILES.search(os.path.basename(path)):
            continue        # a file that exists to show the shape of a secret
        for kind, secret, lineno, sev in scan_file(path):
            fp = fingerprint(secret)
            found.setdefault(fp, {"kind": kind, "sev": sev,
                                  "mask": "[private key]" if kind.startswith("private key block") else _mask(secret), "hits": []})
            if (path, lineno) not in found[fp]["hits"]:
                found[fp]["hits"].append((path, lineno))

    for fp, info in found.items():
        paths = info["hits"]
        first_path, first_line = paths[0]
        reachable = [p for p, _ in paths if _world_readable(p)]
        tracked = []
        for p, _ in paths:
            is_tracked, remote = _git_tracked(p)
            if is_tracked:
                tracked.append((p, remote))

        sev = info["sev"]
        cat = "present"
        extra = ""
        if tracked:
            cat = "tracked"
            sev = "critical"
            remote = next((r for _, r in tracked if r), "")
            extra = ("  git is tracking this file"
                     + (f" and its remote is {remote}" if remote else "")
                     + " — the credential is one push from being published")
        elif reachable and others:
            cat = "reachable"
            sev = "critical" if sev in ("critical", "high") else "high"
            extra = ("  the file is readable by other accounts on this system ("
                     + ", ".join(others[:3]) + ")")
        locations = {
            _designated_store(p, home)
            or ("project environment file" if _private_project_env(p, home) else None)
            for p, _ in paths
        }
        protected = next(iter(locations)) if len(locations) == 1 else None
        if cat == "present" and protected and not others:
            sev = "low"
            extra = ("  Expected local software credential in an owner-only, "
                     "untracked store. Any process running as you can still read "
                     "it; review access and rotate if it was exposed elsewhere.")

        where = f"{first_path}:{first_line}"
        more = (f" (+{len(paths) - 1} more location"
                f"{'s' if len(paths) > 2 else ''})" if len(paths) > 1 else "")
        description = "stored locally" if info['kind'].startswith("private key block") else "in plaintext"
        if cat == "present" and protected and not others:
            description = ("in a private project environment file"
                           if protected == "project environment file" else
                           f"in {protected}'s credential store")
        context = "Volume encryption has not been verified for this file; credential validity and external exposure were not checked."
        if info['kind'] == "AWS access key id":
            context += " An access key ID alone cannot authenticate; the matching secret access key is required."
        out.append(_finding(
            cat, sev, f"{info['kind']} {description}{more}",
            f"{info['mask']}  fingerprint {fp} — {context}{extra}",
            where))

    for rel in CREDENTIAL_FILES:
        p = os.path.join(home, rel)
        if not os.path.exists(p):
            continue
        if _world_readable(p):
            try:
                mode = oct(os.stat(p).st_mode & 0o777)
            except OSError:
                mode = "?"
            out.append(_finding(
                "reachable", "high",
                f"credential file is readable by others: {rel}",
                f"mode {mode} — this file exists to hold a credential, so its "
                f"permissions are the only thing protecting it",
                p))

    out.append(_finding(
        "visibility", "ok", f"scanned {scanned} files for credentials",
        f"{len(found)} distinct secret{'s' if len(found) != 1 else ''} found. "
        f"Values are never stored or printed — only a masked preview and a "
        f"truncated fingerprint, so this report is not itself a leak.",
        ", ".join(roots)))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
