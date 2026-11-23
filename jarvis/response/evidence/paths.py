"""Persistent locations for collected evidence and optional forensic tooling.

Everything an investigation produces belongs under the state root, never under
a temporary directory. A WSL restart or a tmpfiles sweep destroys /tmp without
warning, and evidence that vanishes mid-investigation is worse than evidence
that was never collected: the case notes still reference it.
"""

import os

STATE_ROOT = os.path.expanduser("~/.jarvis")

# Collected artefacts, one directory per case.
EVIDENCE_ROOT = os.path.join(STATE_ROOT, "evidence")

# Optional third-party parsers (python-evtx and friends). JARVIS itself is
# stdlib-only; these are installed on demand and are not import-time
# requirements, so a missing tool degrades one scan rather than the service.
TOOLS_ROOT = os.path.join(STATE_ROOT, "tools")

# Evidence can contain credentials, private keys and command history, so the
# directories are owner-only and the files inside them are owner-read.
DIR_MODE = 0o700
FILE_MODE = 0o600


def secure_dir(path):
    """Create `path` (and parents) owner-only, and return it.

    chmod is applied even when the directory already exists: a case directory
    created before this convention, or by a differently-umasked process, must
    not silently stay group-readable.
    """
    os.makedirs(path, mode=DIR_MODE, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        # A directory on a filesystem without POSIX modes (DrvFS) cannot be
        # tightened. Collection still works; the caller is told by list_cases.
        pass
    return path


def secure_file(path):
    try:
        os.chmod(path, FILE_MODE)
    except OSError:
        pass
    return path


def evidence_root():
    return secure_dir(EVIDENCE_ROOT)


def tools_root():
    return secure_dir(TOOLS_ROOT)


def case_dir(case, create=True):
    """Directory holding one investigation's artefacts."""
    path = os.path.join(EVIDENCE_ROOT, safe_name(case))
    return secure_dir(path) if create else path


def safe_name(name):
    """Reduce a case name to one path segment.

    Case names reach this from CLI arguments and from alert titles, so a name
    is never allowed to traverse out of the evidence root or to name a hidden
    file.
    """
    out = "".join(c if (c.isalnum() or c in "-_.") else "-"
                  for c in (name or "").strip())
    out = out.strip(".-") or "case"
    return out[:96]
