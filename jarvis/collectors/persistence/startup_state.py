"""Bounded startup-path and history-link observations, without retaining source.

Literal invocation under temporary staging directories is advisory evidence, not
proof of an unauthorized change. Variable expansion and arbitrary shell grammars
are not interpreted. No history contents, source lines or arguments are emitted.
"""
import hashlib
import os
import re
import shlex
import stat
import time

from jarvis.core import collection, safe_files
from jarvis.core.finding import file_finding, finding

MAX_FILES = 512
MAX_ENTRIES = 2048
MAX_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024
MAX_SECONDS = 10.0
MAX_HOMES = 64
MAX_LINE = 4096
MAX_TOKENS = 512
STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")
PROFILE_NAMES = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_login", ".bash_logout")
HISTORY_NAMES = (".bash_history", ".zsh_history", ".sh_history")
PROFILE_FILES = ("/etc/profile",)
PROFILE_DIRS = ("/etc/profile.d",)
BOOT_FILES = ("/etc/rc.local", "/etc/rc.d/rc.local")
CRON_FILES = ("/etc/crontab",)
CRON_DIRS = (("/etc/cron.d", True), ("/var/spool/cron/crontabs", False), ("/var/spool/cron", False))
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
_SCHEDULE = re.compile(r"^[A-Za-z0-9*/?,\-]+$")
_CONTROL = frozenset({"then", "else", "elif", "do", "while", "until", "if", "!"})
_WRAPPERS = frozenset({"env", "exec", "command", "nohup", "setsid"})
_INTERPRETERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "node"})


def staging_program(token):
    if not token.startswith("/") or any(c in token for c in ("$", "`", "\n", "\r", "\x00")):
        return None
    normalized = os.path.normpath(token)
    return normalized if normalized.startswith(STAGING) else None


def invocation(line):
    """First literal staging-path command or interpreter script; no execution."""
    if len(line) > MAX_LINE:
        raise ValueError("startup line exceeds budget")
    lexer = shlex.shlex(line, posix=True, punctuation_chars="();|&{}")
    lexer.whitespace_split = True
    need_command, script, skip_loop = True, False, False
    for index, token in enumerate(lexer):
        if index >= MAX_TOKENS:
            raise ValueError("startup tokens exceed budget")
        if need_command and token == "for":
            skip_loop = True
        if skip_loop:
            if token == "do":
                skip_loop, need_command = False, True
            continue
        if all(c in ";|&(){}" for c in token):
            if token not in (")", "}"):
                need_command, script = True, False
            continue
        if need_command and token in _CONTROL:
            need_command, script = True, False
            continue
        if need_command:
            if _ASSIGN.match(token):
                continue
            if token in _WRAPPERS or os.path.basename(token) in _WRAPPERS:
                continue
            if token.startswith("-"):
                continue
            target = staging_program(token)
            if target:
                return target
            base = os.path.basename(token)
            script = base in _INTERPRETERS or token in (".", "source")
            need_command = False
        elif script:
            if token.startswith("-"):
                if token in ("-c", "-m", "-e", "-r") or "c" in token[1:]:
                    script = False
                continue
            # Command strings and variable expansion are not modeled.
            target = staging_program(token)
            if target:
                return target
            script = False
    return None


def cron_command(line, system=False):
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or _ASSIGN.match(stripped):
        return None
    parts = stripped.split(None, 7 if system else 6)
    if parts[0].startswith("@"):
        count = 2 if system else 1
        if len(parts) <= count:
            return None
        return stripped.split(None, count)[count]
    count = 6 if system else 5
    if len(parts) <= count or not all(_SCHEDULE.fullmatch(p) for p in parts[:5]):
        return None
    return stripped.split(None, count)[count]


class Pass:
    def __init__(self, clock):
        self.clock, self.started = clock, clock()
        self.entries = self.files = self.bytes = self.gaps = 0
        self.cut = False
        self.out = []

    def step(self):
        if self.entries >= MAX_ENTRIES or self.clock() - self.started >= MAX_SECONDS:
            self.cut = True
            return False
        self.entries += 1
        return True

    def metadata(self, path):
        if not self.step():
            return None
        try:
            parent = safe_files.open_safe(os.path.dirname(path), directory=True)
            try:
                return os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
        except FileNotFoundError:
            return None
        except OSError:
            self.gaps += 1
            return None

    def read(self, path):
        meta = self.metadata(path)
        if meta is None:
            return None
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_FILE_BYTES:
            self.gaps += 1
            return None
        if self.files >= MAX_FILES or self.bytes + meta.st_size > MAX_BYTES:
            self.cut = True
            return None
        data = safe_files.read_start(path, limit=meta.st_size + 1, expected=safe_files.identity(meta))
        if data is None or len(data) != meta.st_size:
            self.gaps += 1
            return None
        self.files += 1
        self.bytes += len(data)
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            self.gaps += 1
            return None
        return meta, text, hashlib.sha256(data).hexdigest()

    def paths(self, directory, suffix=None):
        if not self.step():
            return
        try:
            fd = safe_files.open_safe(directory, directory=True)
        except FileNotFoundError:
            return
        except OSError:
            self.gaps += 1
            return
        try:
            with os.scandir(fd) as rows:
                for row in rows:
                    if not self.step():
                        break
                    if row.name.startswith(".") or (suffix and not row.name.endswith(suffix)):
                        continue
                    if row.is_dir(follow_symlinks=False):
                        continue
                    yield os.path.join(directory, row.name)
        except OSError:
            self.gaps += 1
        finally:
            os.close(fd)

    def script(self, path, kind, system=False, executable=False):
        result = self.read(path)
        if result is None:
            return
        meta, text, digest = result
        if executable and not meta.st_mode & 0o111:
            return
        for number, line in enumerate(text.splitlines(), 1):
            try:
                command = cron_command(line, system) if kind == "cron" else line
                target = invocation(command) if command else None
            except ValueError:
                self.gaps += 1
                continue
            if target:
                self.out.append(file_finding(
                    "persistence", "medium", f"{kind} startup invokes a temporary-path program",
                    f"SHA-256 {digest}; line {number}; program {target[:300]}. "
                    "Temporary directories can hold replaceable artifacts. Confirm whether this startup "
                    "entry belongs here; source and arguments are withheld. Boot activation is not verified.", path))
                break  # fold within the source, never quote or retain command text

    def history(self, path):
        meta = self.metadata(path)
        if meta is None or not stat.S_ISLNK(meta.st_mode):
            return
        try:
            parent = safe_files.open_safe(os.path.dirname(path), directory=True)
            try:
                target = os.readlink(os.path.basename(path), dir_fd=parent)
                after = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
        except OSError:
            self.gaps += 1
            return
        if safe_files.identity(meta) != safe_files.identity(after):
            self.gaps += 1
            return
        absolute = os.path.normpath(target if os.path.isabs(target) else os.path.join(os.path.dirname(path), target))
        if absolute in ("/dev/null", "/dev/zero", "/dev/full"):
            self.out.append(file_finding(
                "persistence", "medium", "Shell history is redirected to a non-persistent device",
                f"The history pathname is a link to {absolute}. Future history writes may be discarded "
                "or fail. This can be deliberate privacy configuration; confirm its purpose. "
                "No history contents were read.", path))


def audit(home_dirs, *, profile_files=PROFILE_FILES, profile_dirs=PROFILE_DIRS,
          boot_files=BOOT_FILES, cron_files=CRON_FILES, cron_dirs=CRON_DIRS, clock=time.monotonic):
    scan = Pass(clock)
    for path in profile_files:
        scan.script(path, "profile")
    for directory in profile_dirs:
        for path in scan.paths(directory, ".sh"):
            scan.script(path, "profile")
    for path in boot_files:
        scan.script(path, "legacy boot", executable=True)
    for path in cron_files:
        scan.script(path, "cron", system=True)
    for directory, system in cron_dirs:
        for path in scan.paths(directory):
            scan.script(path, "cron", system=system)
    for index, (_user, home, _uid) in enumerate(home_dirs):
        if index >= MAX_HOMES:
            scan.cut = True
            break
        if scan.cut:
            break
        for name in PROFILE_NAMES:
            scan.script(os.path.join(home, name), "profile")
        for name in HISTORY_NAMES:
            scan.history(os.path.join(home, name))
    if scan.gaps or scan.cut:
        collection.failed("startup-state", "startup evidence incomplete")
        scan.out.append(finding(
            "visibility", "low", "Startup state was not completely checked",
            f"{scan.files} files read, {scan.bytes} bytes, {scan.gaps} unreadable/changed/unsupported sources; "
            f"limit reached: {scan.cut}. Limits: {MAX_ENTRIES} entries, {MAX_FILES} files, "
            f"{MAX_BYTES} bytes, {int(MAX_SECONDS)} seconds. Missing evidence is not clean state.", "startup state"))
    else:
        collection.succeeded("startup-state")
    return scan.out
