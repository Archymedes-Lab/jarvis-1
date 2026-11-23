"""Who else could read a found credential: other accounts, world-readable files,
and whether git would publish it."""

import os
import re
import stat
import subprocess

from jarvis.core import fsperm


def _other_humans():
    """Real login accounts other than this one.

    "Readable by other accounts" is only a finding if other accounts exist.
    WSL's default umask writes 0644, so on a single-user machine that
    condition is true for essentially every file — the first run escalated
    200 findings to critical on exactly this mistake. Where nobody else can
    log in, permissions are not the control that matters; the unencrypted
    disk is.
    """
    try:
        import pwd
    except ImportError:
        # Native Windows: no passwd database, and mode bits decide nothing
        # there, so "readable by another account" cannot be argued from them.
        return []
    me = os.getuid()
    try:
        return [p.pw_name for p in pwd.getpwall()
                if p.pw_uid >= 1000 and p.pw_uid != me
                and p.pw_shell and "nologin" not in p.pw_shell
                and "false" not in p.pw_shell]
    except Exception:
        return []


def _world_readable(path):
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH))


# Two git subprocesses per finding is fine for ten findings and unusable for a
# few hundred — the first full run had not finished after ten minutes. The
# remote lookup is per repository, not per file, so it is cached.
_repo_cache: dict = {}


def _repo_of(directory):
    """(repo_root, origin_url) for a directory, or (None, "")."""
    if directory in _repo_cache:
        return _repo_cache[directory]
    try:
        r = subprocess.run(["git", "-C", directory, "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, errors="replace", timeout=8)
        if r.returncode != 0:
            result = (None, "")
        else:
            root = r.stdout.strip()
            rem = subprocess.run(["git", "-C", root, "remote", "get-url", "origin"],
                                 capture_output=True, text=True, errors="replace", timeout=8)
            result = (root, rem.stdout.strip() if rem.returncode == 0 else "")
    except (OSError, subprocess.SubprocessError):
        result = (None, "")
    _repo_cache[directory] = result
    return result


def _git_tracked(path):
    """Is this file tracked by git, and does its repo have a remote?"""
    d = os.path.dirname(path) or "."
    root, remote = _repo_of(d)
    if not root:
        return False, ""
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch",
                            "--", path], capture_output=True, text=True, errors="replace", timeout=8)
        return (r.returncode == 0), remote
    except (OSError, subprocess.SubprocessError):
        return False, ""


def _private_project_env(path, home):
    """A private development env in an ignored repo or a local app without Git."""
    if not re.fullmatch(r"\.env(?:\.[a-z0-9_-]+)?", os.path.basename(path), re.I):
        return False
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or not fsperm.owner_only(st):
            return False
        root, _remote = _repo_of(os.path.dirname(path))
        if not root:
            project = os.path.dirname(path)
            if os.path.realpath(os.path.dirname(project)) != os.path.realpath(home):
                return False
            marker = os.path.join(project, ".git")
            if os.path.lexists(marker):
                if not os.path.isdir(marker) or os.listdir(marker):
                    return False
            return any(os.path.isfile(os.path.join(project, name)) for name in
                       ("package.json", "pyproject.toml", "requirements.txt"))
        if os.path.realpath(root) == os.path.realpath(home):
            return False
        rel = os.path.relpath(os.path.realpath(path), os.path.realpath(root))
        if rel.startswith(("../", ".git/")) or rel in ("..", ".git"):
            return False
        result = subprocess.run(
            ["git", "-C", root, "check-ignore", "--quiet", "--", path],
            capture_output=True, timeout=8)
        return result.returncode == 0
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
