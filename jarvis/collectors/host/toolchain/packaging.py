"""Git hooks, package manager configuration and .pth shims."""

import glob
import os
import re

from .common import PAYLOAD_RE, _finding, _home, _read, _short, repos

_PTH_SHIMS = (
    (re.compile(r"^distutils-precedence\.pth$"),
     re.compile(r"_distutils_hack")),
    (re.compile(r"-nspkg\.pth$"),
     re.compile(r"sys\._getframe\(1\)\.f_locals\['sitedir'\]")),
    (re.compile(r"^__editable__.*\.pth$"),
     re.compile(r"__editable___|__editable__")),
    (re.compile(r"^_virtualenv\.pth$"), re.compile(r"_virtualenv")),
    (re.compile(r"^(setuptools|pkg_resources)[-.].*\.pth$"),
     re.compile(r"setuptools|pkg_resources")),
)


def _record_owner(path):
    """The distribution whose install RECORD lists this file with the same
    SHA-256, or "". RECORD hashes are urlsafe base64 without padding."""
    import base64
    import hashlib
    site, name = os.path.dirname(path), os.path.basename(path)
    try:
        with open(path, "rb") as fh:
            digest = base64.urlsafe_b64encode(hashlib.sha256(fh.read()).digest())
        digest = digest.rstrip(b"=").decode()
    except OSError:
        return ""
    for record in glob.glob(os.path.join(site, "*.dist-info", "RECORD")):
        for row in _read(record, 2_000_000).splitlines():
            parts = row.rsplit(",", 2)
            if len(parts) == 3 and parts[0] == name and parts[1] == f"sha256={digest}":
                return os.path.basename(os.path.dirname(record)).rsplit(".dist-info", 1)[0]
    return ""


def check_git_hooks(hosts=("wsl", "win")):
    """Scripts `git` runs for you, and redirections of where it looks for them."""
    if "wsl" not in hosts:
        return []
    out = []
    found, _ = repos()
    checked = 0

    global_cfg = _read(os.path.join(_home(), ".gitconfig"))
    m = re.search(r"^\s*hooksPath\s*=\s*(.+)$", global_cfg, re.M)
    if m:
        out.append(_finding(
            "vcs", "high", "git hooks are redirected globally",
            f"core.hooksPath = {m.group(1).strip()} in ~/.gitconfig — every "
            f"repository on this account runs scripts from that directory "
            f"instead of its own .git/hooks, including repositories that have "
            f"no hooks of their own",
            "~/.gitconfig"))

    for repo in found:
        cfg = _read(os.path.join(repo, ".git", "config"))
        m = re.search(r"^\s*hooksPath\s*=\s*(.+)$", cfg, re.M)
        if m:
            out.append(_finding(
                "vcs", "medium",
                f"git hooks redirected in {_short(repo)}",
                f"core.hooksPath = {m.group(1).strip()} — hook scripts come "
                f"from a path the repository chose", _short(repo)))
        hookdir = os.path.join(repo, ".git", "hooks")
        try:
            hooks = os.listdir(hookdir)
        except OSError:
            continue
        for h in sorted(hooks):
            if h.endswith(".sample"):
                continue
            path = os.path.join(hookdir, h)
            if not os.access(path, os.X_OK):
                continue
            checked += 1
            body = _read(path, 40000)
            if PAYLOAD_RE.search(body):
                line = next((ln.strip() for ln in body.splitlines()
                             if PAYLOAD_RE.search(ln)), "")
                out.append(_finding(
                    "vcs", "critical", f"git hook fetches and runs code: {h}",
                    f"in {_short(repo)}: {line[:240]} — this runs on the "
                    f"matching git operation, with no prompt",
                    _short(path)))
            else:
                out.append(_finding(
                    "vcs", "low", f"active git hook: {h}",
                    f"{_short(repo)} runs this script on `git {h.replace('-', ' ')}`; "
                    f"usually a formatter or a linter, listed because a hook is "
                    f"executable content that arrives with a clone",
                    _short(path)))
    if found and not checked and not out:
        out.append(_finding(
            "vcs", "ok", "no active git hooks",
            f"{len(found)} repositories checked; only the unmodified .sample "
            f"templates are present and core.hooksPath is not redirected",
            "git hooks"))
    return out


def registry_redirects(home=None):
    """npm and pip configured to install from somewhere other than their default.

    `home` points the check at another home directory (the coverage map's
    probe uses a temporary one)."""
    out = []
    home = _home() if home is None else home

    # Registry redirection: the quiet half of a supply-chain compromise. A
    # poisoned mirror needs no malicious package name — the names stay right and
    # the contents change.
    npmrc = _read(os.path.join(home, ".npmrc"))
    for m in re.finditer(r"^\s*(?:[^=\s]*:)?registry\s*=\s*(\S+)", npmrc, re.M):
        url = m.group(1)
        if not re.match(r"https://registry\.npmjs\.org/?$", url):
            out.append(_finding(
                "packages", "high", "npm installs from a non-default registry",
                f"registry = {url} in ~/.npmrc — every `npm install` on this "
                f"account resolves through that host, so its contents are as "
                f"trusted as npmjs.org is. Expected for a company proxy, and a "
                f"complete supply-chain takeover if it is not one you set.",
                "~/.npmrc"))

    for cfg in ("~/.pip/pip.conf", "~/.config/pip/pip.conf", "~/.pydistutils.cfg"):
        text = _read(os.path.join(home, cfg[2:]))
        for m in re.finditer(r"^\s*(?:extra-)?index-url\s*=\s*(\S+)", text, re.M):
            url = m.group(1)
            if "pypi.org" not in url:
                out.append(_finding(
                    "packages", "high", "pip installs from a non-default index",
                    f"index-url = {url} in {cfg}. An extra-index-url is worse "
                    f"than a replacement: pip will take whichever index offers "
                    f"the higher version, which is dependency confusion by "
                    f"configuration.",
                    cfg))
    return out


def check_package_config(hosts=("wsl", "win")):
    """Where packages come from, and what they are allowed to run on install."""
    if "wsl" not in hosts:
        return []
    out = registry_redirects()

    out.extend(_check_pth_files())
    if not out:
        out.append(_finding(
            "packages", "ok", "package sources and startup hooks are clean",
            "npm and pip resolve to their default registries and no site "
            "directory contains an executable .pth line",
            "package config"))
    return out


def _is_packaging_shim(filename, line):
    return any(name_re.search(filename) and body_re.search(line)
               for name_re, body_re in _PTH_SHIMS)


def _check_pth_files():
    """`.pth` lines beginning with `import` run on every interpreter start.

    This is a documented CPython feature and one of the quietest persistence
    mechanisms available on a developer machine: no service, no autostart entry,
    no process of its own, and it executes inside every Python that imports
    site — which on this box includes jarvis itself.
    """
    out, hits = [], {}
    dirs = []
    try:
        import site
        import sysconfig
        for fn in (site.getsitepackages, site.getusersitepackages):
            try:
                val = fn()
            except Exception:
                continue
            dirs.extend(val if isinstance(val, (list, tuple)) else [val])
        for key in ("purelib", "platlib"):
            try:
                dirs.append(sysconfig.get_paths()[key])
            except Exception:
                pass
    except Exception:
        return out

    found, _ = repos()
    for repo in found[:60]:
        dirs.extend(glob.glob(os.path.join(repo, ".venv", "lib", "python*",
                                           "site-packages")))
        dirs.extend(glob.glob(os.path.join(repo, "venv", "lib", "python*",
                                           "site-packages")))

    for d in dict.fromkeys(dirs):
        if not d or not os.path.isdir(d):
            continue
        for path in sorted(glob.glob(os.path.join(d, "*.pth"))):
            for line in _read(path, 60000).splitlines():
                s = line.strip()
                if not s.startswith(("import ", "import\t")):
                    continue
                if _is_packaging_shim(os.path.basename(path), s):
                    continue
                key = (os.path.basename(path), s)
                hits.setdefault(key, []).append(path)

    for (fname, line), full_paths in hits.items():
        paths = [_short(x) for x in full_paths]
        payload = bool(PAYLOAD_RE.search(line))
        owners = [_record_owner(x) for x in full_paths]
        if not payload and all(owners):
            out.append(_finding(
                "packages", "low", f"executable .pth line in {fname}",
                f"`{line[:240]}` — shipped by {', '.join(sorted(set(owners)))}: "
                f"the file's SHA-256 matches that package's install RECORD, so "
                f"it is what the package installed, not a later edit.",
                paths[0]))
            continue
        extra = (f" Seen in {len(paths)} environments." if len(paths) > 1
                 else "")
        out.append(_finding(
            "packages", "critical" if payload else "medium",
            f"executable .pth line in {fname}",
            f"`{line[:240]}` — Python runs this on every interpreter start "
            f"that imports site. It owns no process, creates no service and "
            f"appears in no autostart list."
            + (" The line fetches or decodes what it runs, which no packaging "
               "shim does." if payload else
               " Most likely a packaging or coverage shim; listed because this "
               "is the quietest code-on-startup mechanism a Python machine "
               "has, and an inventory is what makes a new entry visible.")
            + extra,
            paths[0]))
    return out
