"""Argus guarding itself: tamper evidence that holds even when the source is public.

The source of Argus leaked (2026.10.22-2026.10.30). Anything that depends on
an attacker not knowing a path, a name list or a threshold is now evadable
(docs/architecture/DETECTION-CONTENT.md). These checks depend on none of that:
each states an invariant that an attacker must break to do the thing it
guards, so knowing the check does not help them avoid it.

    hooks     Python startup hooks: executable `.pth` lines, sitecustomize and
              usercustomize in the system and user site directories. Every
              Python process (Argus included) runs them; the LiteLLM 1.107.0
              compromise (2026-10) used exactly this. Unlike the toolchain
              inventory, nothing here is allowlisted by file name: the set and
              the content of the hooks are learned once, and any later
              addition or change is reported, lowered (never hidden) only when
              the file matches its own package's install RECORD hash. A system
              site directory writable by a non-root account is an invariant
              break in itself (T1546.016-like persistence; ATT&CK T1546).
    code      Argus's own installed code against its release manifest
              (RELEASE.json): every listed file's SHA-256, any extra code file
              in the tree, and any item a non-root account can write.
              Changing Argus means changing these bytes (T1562.001, T1554).
    units     Argus's own service and timer units and their drop-in
              directories: learned once; an edit, a new drop-in or a removal is
              reported. A drop-in can replace ExecStart without touching the
              unit (T1543.002, T1562.001).
    state     Argus's own state directory: only Argus's account writes it. An
              entry owned by another account, a symlink leading out of it, or
              an entry another account can reach and write breaks that.
    rules     the signed rule-pack channel (core/rulepack.py): a pack that
              vanished after acceptance, was rolled back, expired or failed
              verification, and pack rules suspended for slow matching.

Invariants (tests/test_selfguard.py holds each):
    G1  what cannot be read is reported as not observed, never as clean
    G2  the first run learns and reports what it learned only as low
        inventory; drift is reported from the second run on
    G3  a package RECORD match lowers a hook change's severity; it never hides it
    G4  bounded: file counts, bytes hashed and findings all have ceilings
    G5  read-only: nothing is changed, loaded or executed (hooks are read as
        text, never imported)
"""

import glob
import hashlib
import json
import os
import stat
import time

from jarvis.core.finding import finding as _finding

STATE_META = "selfguard_state_v1"   # {"hooks": {path: sha}, "units": {path: sha}, "learned_at"}
HASH_LIMIT = 1024 * 1024
MAX_HOOK_FILES = 400
MAX_UNIT_FILES = 100
MAX_CODE_FILES = 6000
MAX_CODE_BYTES = 256 * 1024 * 1024
MAX_STATE_ENTRIES = 20000
MAX_LISTED = 8
CATEGORY = "self-protection"

SYSTEM_SITE_GLOBS = ("/usr/lib/python3*/dist-packages", "/usr/lib/python3*/site-packages",
                     "/usr/local/lib/python3*/dist-packages", "/usr/local/lib/python3*/site-packages",
                     "/usr/lib64/python3*/site-packages")
USER_SITE_GLOBS = ("~/.local/lib/python3*/site-packages",)
HOOK_MODULES = ("sitecustomize.py", "usercustomize.py", "sitecustomize/__init__.py",
                "usercustomize/__init__.py")
UNIT_GLOBS = ("/etc/systemd/system/argus*.service", "/etc/systemd/system/argus*.timer",
              "/etc/systemd/system/jarvis*.service", "/etc/systemd/system/jarvis*.timer",
              "/etc/systemd/system/argus*.d/*.conf", "/etc/systemd/system/jarvis*.d/*.conf",
              "/lib/systemd/system/argus*.service", "/lib/systemd/system/argus*.timer",
              "/usr/lib/systemd/system/argus*.service", "/usr/lib/systemd/system/argus*.timer",
              "~/.config/systemd/user/jarvis*.service", "~/.config/systemd/user/jarvis*.timer",
              "~/.config/systemd/user/jarvis*.d/*.conf",
              "~/.config/systemd/user/argus*.service", "~/.config/systemd/user/argus*.timer")
CODE_SUFFIXES = (".py", ".pth", ".so", ".pyc", ".sh", ".ps1", ".js", ".html")


def _p(root, path):
    path = os.path.expanduser(path)
    return os.path.join(root, path.lstrip("/")) if root != "/" else path


def _sha(path, limit=HASH_LIMIT):
    """(hex digest, problem). Reads at most `limit` bytes; larger is a problem."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        return None, exc.strerror or str(exc)
    if len(data) > limit:
        return None, f"over {limit} bytes"
    return hashlib.sha256(data).hexdigest(), ""


# -- hooks ------------------------------------------------------------------------

def _executable_pth(path):
    """True when a .pth file has a line CPython executes (starts with `import`)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(HASH_LIMIT)
    except OSError:
        return True             # unreadable: treat as a hook so it is reported, not skipped
    return any(line.startswith(("import ", "import\t")) for line in text.splitlines())


def site_dirs(root="/"):
    """[(directory, scope)] with scope "system" or "user"; deduplicated by realpath."""
    out, seen = [], set()
    for scope, globs in (("system", SYSTEM_SITE_GLOBS), ("user", USER_SITE_GLOBS)):
        for g in globs:
            for d in sorted(glob.glob(_p(root, g))):
                real = os.path.realpath(d)
                if os.path.isdir(d) and real not in seen:
                    seen.add(real)
                    out.append((d, scope))
    return out


def hook_files(root="/"):
    """{path: scope} of every startup hook found, and whether the list was capped."""
    found, capped = {}, False
    for d, scope in site_dirs(root):
        candidates = [p for p in sorted(glob.glob(os.path.join(d, "*.pth"))) if _executable_pth(p)]
        candidates += [os.path.join(d, m) for m in HOOK_MODULES if os.path.isfile(os.path.join(d, m))]
        for p in candidates:
            if len(found) >= MAX_HOOK_FILES:
                capped = True
                break
            found[p] = scope
    return found, capped


def _record_owner(path, digest_hex):
    """The distribution whose install RECORD lists this file with this SHA-256, or ""."""
    import base64
    site, name = os.path.dirname(path), os.path.basename(path)
    want = "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(digest_hex)).rstrip(b"=").decode()
    for record in glob.glob(os.path.join(site, "*.dist-info", "RECORD"))[:2000]:
        try:
            with open(record, encoding="utf-8", errors="replace") as fh:
                rows = fh.read(2_000_000).splitlines()
        except OSError:
            continue
        for row in rows:
            parts = row.rsplit(",", 2)
            if len(parts) == 3 and parts[0] == name and parts[1] == want:
                return os.path.basename(os.path.dirname(record)).rsplit(".dist-info", 1)[0]
    return ""


def _writable_by_others(st):
    return st.st_uid != 0 or bool(st.st_mode & 0o022)


def hook_findings(learned, root="/"):
    """(findings, new learned map, problems)."""
    out, problems = [], []
    files, capped = hook_files(root)
    if capped:
        problems.append(f"more than {MAX_HOOK_FILES} startup hooks; the rest were not read")
    current = {}
    for path, scope in files.items():
        digest, problem = _sha(path)
        if digest is None:
            problems.append(f"{path}: {problem}")
            continue
        current[path] = digest
    for d, scope in site_dirs(root):
        if scope != "system":
            continue
        try:
            st = os.stat(d)
        except OSError as exc:
            problems.append(f"{d}: {exc.strerror or exc}")
            continue
        if _writable_by_others(st):
            out.append(_finding(
                CATEGORY, "high", "system Python site directory writable by a non-root account",
                f"{d} (owner uid {st.st_uid}, mode {stat.S_IMODE(st.st_mode):o}): any account that can "
                "write here can add a startup hook every Python program on this machine, Argus "
                "included, runs at start (T1546). It should be root-owned and not group or world "
                "writable.", d))
    if learned is None:
        if current:
            out.append(_finding(
                CATEGORY, "low", f"{len(current)} Python startup hook(s) present at first observation",
                "Learned as the baseline; any later addition or change is reported: "
                + ", ".join(sorted(current)[:MAX_LISTED]), "python-startup-hooks"))
        return out, current, problems
    for path, digest in sorted(current.items()):
        old = learned.get(path)
        if old == digest:
            continue
        scope = files[path]
        owner = _record_owner(path, digest)
        what = "added" if old is None else "changed"
        if owner:
            sev = "low"
            why = (f"its SHA-256 matches the install RECORD of {owner}, so it is what that package "
                   "installed; confirm you installed or upgraded it")
        else:
            sev = "high" if scope == "system" else "medium"
            why = ("no package RECORD vouches for these bytes. Python runs this on every interpreter "
                   "start (Argus included); this is how the LiteLLM 1.107.0 compromise persisted")
        out.append(_finding(CATEGORY, sev, f"Python startup hook {what}: {os.path.basename(path)}",
                            f"{path} ({scope} site directory) was {what} since it was learned: {why}.",
                            path))
    for path in sorted(set(learned) - set(current)):
        out.append(_finding(CATEGORY, "low", f"Python startup hook removed: {os.path.basename(path)}",
                            f"{path} was a learned startup hook and is gone (an uninstall, or "
                            "cleanup after use).", path))
    return out, current, problems


# -- own code ---------------------------------------------------------------------

def code_findings(release_root):
    """Argus's installed tree against its RELEASE.json. (findings, problems)."""
    out, problems = [], []
    manifest_path = os.path.join(release_root, "RELEASE.json")
    try:
        with open(manifest_path, encoding="utf-8", errors="replace") as fh:
            files = json.load(fh).get("files")
        if not isinstance(files, dict) or not files:
            raise ValueError
    except FileNotFoundError:
        return out, [f"no release manifest at {manifest_path}: running from a development "
                     "checkout, so Argus's own code is not checked"]
    except (OSError, ValueError, AttributeError):
        return [_finding(CATEGORY, "high", "Argus release manifest unreadable or malformed",
                         f"{manifest_path} cannot be parsed: Argus cannot check its own code. "
                         "A sealed release always carries a valid manifest.", manifest_path)], []
    if len(files) > MAX_CODE_FILES:
        problems.append(f"manifest lists {len(files)} files; only {MAX_CODE_FILES} checked")
    changed, missing, budget = [], [], MAX_CODE_BYTES
    for rel in sorted(files)[:MAX_CODE_FILES]:
        if not isinstance(rel, str) or rel.startswith("/") or ".." in rel.split("/"):
            changed.append(str(rel))
            continue
        full = os.path.join(release_root, rel)
        try:
            size = os.path.getsize(full)
        except FileNotFoundError:
            missing.append(rel)
            continue
        except OSError as exc:
            problems.append(f"{rel}: {exc.strerror or exc}")
            continue
        if size > budget:
            problems.append(f"hash budget exhausted at {rel}")
            break
        budget -= size
        digest, problem = _sha(full, limit=max(size, 1))
        if digest is None:
            problems.append(f"{rel}: {problem}")
        elif digest != files[rel]:
            changed.append(rel)
    extra, writable = [], []
    listed = set(files)
    stems = {r[:-3] for r in listed if r.endswith(".py")}
    for dirpath, dirnames, filenames in os.walk(release_root):
        dirnames.sort()
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, release_root)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if _writable_by_others(st) and not stat.S_ISLNK(st.st_mode):
                writable.append(rel)
            if name not in filenames or rel in listed or rel == "RELEASE.json":
                continue
            if stat.S_ISLNK(st.st_mode):
                extra.append(rel)
            elif name.endswith(CODE_SUFFIXES):
                parent = os.path.dirname(rel)
                if os.path.basename(parent) == "__pycache__" and name.endswith(".pyc") and \
                        os.path.join(os.path.dirname(parent), name.split(".", 1)[0]) in stems:
                    continue         # bytecode of a listed module; root-ownership is checked above
                extra.append(rel)
    for items, sev, title, why in (
            (changed, "critical", "Argus code differs from its release manifest",
             "these files' SHA-256 no longer matches RELEASE.json"),
            (missing, "high", "Argus code missing from its release",
             "these files are listed in RELEASE.json and absent"),
            (extra, "high", "unlisted code inside the Argus release",
             "code files or links that RELEASE.json does not list (a planted module is imported "
             "like any other)"),
            (writable, "high", "Argus release writable by a non-root account",
             "a sealed release is root-owned and not group or world writable")):
        if items:
            out.append(_finding(CATEGORY, sev, title,
                                f"{len(items)} item(s) in {release_root}: {why}: "
                                + ", ".join(items[:MAX_LISTED]), release_root))
    return out, problems


# -- units ------------------------------------------------------------------------

def unit_files(root="/"):
    out = []
    for g in UNIT_GLOBS:
        for p in sorted(glob.glob(_p(root, g))):
            if os.path.isfile(p) and p not in out:
                out.append(p)
    return out[:MAX_UNIT_FILES]


def unit_findings(learned, root="/"):
    out, problems, current = [], [], {}
    for p in unit_files(root):
        digest, problem = _sha(p)
        if digest is None:
            problems.append(f"{p}: {problem}")
        else:
            current[p] = digest
    if learned is None:
        return out, current, problems
    for p in sorted(current):
        if learned.get(p) == current[p]:
            continue
        dropin = p.endswith(".conf") and ".d/" in p
        what = "added" if p not in learned else "edited"
        out.append(_finding(
            CATEGORY, "high", f"Argus service unit {what}: {os.path.basename(p)}",
            f"{p} was {what} since it was learned"
            + (": a drop-in can replace ExecStart or switch the service off without touching the "
               "unit itself" if dropin else "")
            + ". Expected only during an Argus install or upgrade you ran.", p))
    for p in sorted(set(learned) - set(current)):
        out.append(_finding(CATEGORY, "high", f"Argus service unit removed: {os.path.basename(p)}",
                            f"{p} was learned and is gone: Argus or its self-check may no longer "
                            "start. Expected only during an uninstall you ran.", p))
    return out, current, problems


# -- state directory ---------------------------------------------------------------

def _private_group(gid, uid):
    try:
        import grp
        import pwd  # POSIX only: imported where used (native Windows imports this module)
        g = grp.getgrgid(gid)
        return not g.gr_mem and pwd.getpwuid(uid).pw_gid == gid
    except (ImportError, KeyError, OSError):
        return False


def state_findings(state_root, uid=None):
    """Entries in Argus's own state directory that another account wrote or can write."""
    uid = os.geteuid() if uid is None else uid
    out, problems = [], []
    try:
        top = os.lstat(state_root)
    except FileNotFoundError:
        return out, [f"{state_root} does not exist"]
    except OSError as exc:
        return out, [f"{state_root}: {exc.strerror or exc}"]
    foreign, rooted, escapes, exposed, seen = [], [], [], [], 0
    real_root = os.path.realpath(state_root)
    # (directory, reachable by group, reachable by others): an entry is writable
    # by another account only if that account can also traverse every directory
    # above it, so a 0700 state root makes inner modes moot (measured live
    # 2026-10-30: event-log segments are 0664 inside a 0700 root).
    stack = [(state_root, bool(top.st_mode & 0o010), bool(top.st_mode & 0o001))]
    if stat.S_ISLNK(top.st_mode):
        escapes.append(state_root)
        stack = []
    if top.st_uid != uid:
        (rooted if top.st_uid == 0 else foreign).append(state_root)
    while stack:
        d, g_ok, o_ok = stack.pop()
        try:
            names = sorted(os.listdir(d))
        except OSError as exc:
            problems.append(f"{d}: {exc.strerror or exc}")
            continue
        for name in names:
            seen += 1
            if seen > MAX_STATE_ENTRIES:
                problems.append(f"over {MAX_STATE_ENTRIES} entries; the rest were not checked")
                stack = []
                break
            full = os.path.join(d, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_uid != uid:
                (rooted if st.st_uid == 0 else foreign).append(full)
            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(full)
                if target != real_root and not target.startswith(real_root + os.sep):
                    escapes.append(full)
                continue
            mode = st.st_mode
            if (o_ok and mode & 0o002) or (g_ok and mode & 0o020 and not _private_group(st.st_gid, uid)):
                exposed.append(full)
            if stat.S_ISDIR(mode):
                stack.append((full, g_ok and bool(mode & 0o010), o_ok and bool(mode & 0o001)))
    for items, sev, title, why in (
            (foreign, "high", "Argus state written by another account",
             "only Argus's own account writes its state; these belong to someone else"),
            (rooted, "medium", "Argus state written by root",
             "usually a command run with sudo by mistake; otherwise something with root wrote "
             "into Argus's evidence"),
            (escapes, "high", "link out of Argus's state directory",
             "a symlink here redirects Argus's own writes or reads to somewhere else"),
            (exposed, "high", "Argus state writable by another account",
             "another account can reach and change these entries")):
        if items:
            out.append(_finding(CATEGORY, sev, title, f"{len(items)} item(s): {why}: "
                                + ", ".join(items[:MAX_LISTED]), state_root))
    return out, problems


# -- rule pack ---------------------------------------------------------------------

RULE_STATUS = {
    "missing": ("high", "accepted rule pack has disappeared",
                "falling back to built-in rules only. Removing the pack is how someone with this "
                "account's access would quietly drop newer detections"),
    "rollback": ("high", "rule pack rolled back to an older version",
                 "the older pack is refused and built-in rules run; an older pack is how someone "
                 "would reinstate detections they already evade"),
    "rejected": ("high", "installed rule pack failed verification",
                 "it is not used; built-in rules run"),
    "expired": ("medium", "rule pack expired",
                "its rules stopped matching; built-in rules run. A feed that stops updating "
                "(blocked fetch, frozen mirror) ends here instead of going stale silently"),
    "no-signers": ("medium", "rule pack installed but no rule-pack key is pinned",
                   "this program trusts no rule-pack key yet, so the pack is not used"),
}


def floor_findings(result, recorded):
    """The rule pack's accepted-version floor kept twice: rulepack's state.json
    and this collector's state in the daemon database. Resetting one to reopen
    rollback leaves the other (Jev 2026-10-30 ranked the single, account-writable
    floor the top remaining risk at 0.82). -> (findings, floor to record)."""
    seen = (result or {}).get("version") or 0
    if not isinstance(seen, int):
        seen = 0
    if recorded and seen < recorded:
        return [_finding(CATEGORY, "high", "rule-pack acceptance record reset",
                         f"version {recorded} was accepted here earlier, but the rule-pack state now "
                         f"records {seen or 'none'}: the record that refuses older packs was removed or "
                         "rewound. Older packs would be accepted again.", "rulepack")], recorded
    return [], max(seen, recorded or 0)


def rule_findings(result, suspended):
    out = []
    status = (result or {}).get("status", "builtin")
    if status in RULE_STATUS:
        sev, title, why = RULE_STATUS[status]
        problem = (result or {}).get("problem") or ""
        out.append(_finding(CATEGORY, sev, title, f"{problem}. {why}." if problem else f"{why}.",
                            "rulepack"))
    if suspended:
        out.append(_finding(
            CATEGORY, "medium", "rule-pack rules suspended for slow matching",
            f"{len(suspended)} rule(s) took over the matching limit once and were switched off for "
            "this pack: a bad pattern, or a command line built to stall the matcher: "
            + ", ".join(f"{k} {v} ms" for k, v in sorted(suspended.items())[:MAX_LISTED]), "rulepack"))
    return out


# -- audit -------------------------------------------------------------------------

def audit(store, hosts=None, now=None, root="/", release_root=None, state_root=None,
          rules=None, suspended=None):
    now = time.time() if now is None else now
    if release_root is None:
        from jarvis.core.paths import REPO_ROOT
        release_root = str(REPO_ROOT)
    state_root = state_root or _p(root, "~/.jarvis")
    problems = []
    try:
        state = json.loads(store.get_meta(STATE_META, "") or "{}")
        if not isinstance(state, dict):
            raise ValueError
    except (ValueError, TypeError):
        state = {}
        problems.append("stored self-protection state could not be read; learning again, so "
                        "changes since the last good run are not reported")
    out = []
    f, hooks, p = hook_findings(state.get("hooks"), root)
    out += f
    problems += p
    f, p = code_findings(release_root)
    out += f
    problems += p
    f, units, p = unit_findings(state.get("units"), root)
    out += f
    problems += p
    f, p = state_findings(state_root)
    out += f
    problems += p
    # `suspended` (pack rules the technique matcher switched off) is handed in by
    # the service layer: collector domains do not import each other.
    suspended = suspended or {}
    if rules is None:
        try:
            from jarvis.core import rulepack
            rules = rulepack.current()
        except Exception as exc:
            problems.append(f"rule-pack state unreadable: {type(exc).__name__}")
            rules = {}
    out += rule_findings(rules, suspended)
    f, floor = floor_findings(rules, state.get("rule_floor") if type(state.get("rule_floor")) is int else 0)
    out += f
    store.set_meta(STATE_META, json.dumps({"hooks": hooks, "units": units, "rule_floor": floor,
                                           "learned_at": state.get("learned_at") or int(now)}))
    if problems:
        out.append(_finding("visibility", "low", "Argus self-protection not fully observed",
                            "; ".join(problems[:MAX_LISTED])[:1500], "selfguard"))
    return out
