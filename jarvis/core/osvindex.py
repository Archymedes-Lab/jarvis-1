"""Which application dependency versions the public OSV data says are vulnerable.

The read side of intel/osv.py, in core so that collectors (a lower layer than
intel) can read what the daily `osv` job writes, and the job can read the
inventory the `appcode` collector writes:

    inventory.json  {"generated", "packages": [{eco, name, version, path, project}]}
    index.json      {"ecosystems": {eco: {"fetched_at", "source",
                                          "packages": {name: [entry, ...]}}}}

    entry = {"id", "aliases", "severity", "summary", "malicious",
             "ranges": [[introduced, fixed, last_affected], ...],
             "versions": [...]}

Both live under ~/.jarvis/osv, owner-only. Nothing in them leaves the machine:
the job downloads public per-ecosystem dumps and matches locally.

Versions are compared by one ordering that is right for the common cases of
every ecosystem OSV covers here (PEP 440, SemVer, Maven, RubyGems, Go): numeric
fields numerically, pre-releases (dev, alpha, beta, milestone, rc, snapshot)
below the release, post-releases (post, sp, patch) above it and below the next
number, build metadata ignored. An exotic scheme can still be misordered; the
explicit `versions` list OSV publishes for most entries is checked first.
"""

import json
import os
import re

ROOT = os.path.expanduser("~/.jarvis/osv")
ECOSYSTEMS = ("PyPI", "npm", "Go", "crates.io", "Packagist", "RubyGems", "Maven")


def index_path(root=ROOT):
    return os.path.join(root, "index.json")


def inventory_path(root=ROOT):
    return os.path.join(root, "inventory.json")


def normalise(eco, name):
    """The key a package is matched by: PEP 503 names for PyPI, lower case
    where the registry is case-insensitive, exact elsewhere."""
    name = (name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco in ("npm", "Packagist", "RubyGems"):
        return name.lower()
    return name


# --- version order -------------------------------------------------------------

_PRE = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "m": 3, "milestone": 3,
        "c": 4, "rc": 4, "cr": 4, "pre": 4, "preview": 4, "snapshot": 5}
_RELEASE = {"release", "final", "ga"}
_POST = {"post": 7, "sp": 7, "p": 7, "pl": 7, "patch": 7, "r": 7, "rev": 7}
_TOKEN = re.compile(r"\d+|[a-z]+")


def _tokens(version):
    v = str(version or "").strip().lower()
    if v.startswith("v"):
        v = v[1:]
    v = v.split("+", 1)[0]
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall(v[:200]) if t not in _RELEASE]


def _word_key(word):
    if word in _PRE:
        return (_PRE[word], "")
    if word in _POST:
        return (_POST[word], "")
    return (4.5, word)          # unknown qualifier: a pre-release, ordered by name


def _tail(rest):
    """Order of the extra tokens one version has over another: -1, 0 or 1."""
    for t in rest:
        if isinstance(t, int):
            if t:
                return 1
            continue
        return 1 if t in _POST else -1
    return 0


def compare(a, b):
    """-1, 0 or 1 as version a sorts before, equal to or after version b."""
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return 1                # a number sorts after any qualifier
        if isinstance(y, int):
            return -1
        kx, ky = _word_key(x), _word_key(y)
        if kx != ky:
            return -1 if kx < ky else 1
    n = min(len(ta), len(tb))
    if len(ta) > n:
        return _tail(ta[n:])
    if len(tb) > n:
        return -_tail(tb[n:])
    return 0


def affected(version, entry):
    """Whether `version` falls inside an OSV entry's affected versions."""
    for listed in entry.get("versions") or ():
        if compare(version, listed) == 0:
            return True
    for introduced, fixed, last in entry.get("ranges") or ():
        if introduced not in (None, "", "0") and compare(version, introduced) < 0:
            continue
        if fixed and compare(version, fixed) >= 0:
            continue
        if last and compare(version, last) > 0:
            continue
        return True
    return False


# --- files --------------------------------------------------------------------

def load(path):
    """A stored JSON document, or None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def write_json(path, doc):
    """Atomic, owner-only: the inventory names what this server runs."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
