"""Installed dependency versions, read from lockfiles and virtual environments.

parse(path) -> [(ecosystem, normalised name, version)] for the exact versions a
lockfile pins. Ranges (`requests>=2`) name no installed version and are left
out; so are Maven versions given through ${properties}. Each file is read under
a byte cap and a malformed one yields nothing rather than an error: a hostile
lockfile must not stop the scan.
"""

import glob
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET

from jarvis.core import safeio
from jarvis.core.osvindex import normalise

MAX_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 20_000

EXACT = {"poetry.lock": "poetry", "uv.lock": "poetry", "Pipfile.lock": "pipfile",
         "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn",
         "pnpm-lock.yaml": "pnpm", "go.mod": "gomod", "Cargo.lock": "cargo",
         "composer.lock": "composer", "Gemfile.lock": "gemfile", "pom.xml": "pom"}
_REQ_FILE = re.compile(r"^requirements[\w.-]*\.txt$")


def is_lockfile(name):
    return name in EXACT or bool(_REQ_FILE.match(name))


def _read(path):
    # Not a link, FIFO or device swapped in after the walk; never past MAX_BYTES.
    try:
        return safeio.read_text(path, MAX_BYTES, follow=False)
    except OSError:
        return None


_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)")


def _requirements(text):
    for line in text.splitlines():
        m = _REQ.match(line.strip())
        if m:
            yield "PyPI", m.group(1), m.group(2)


def _npm(text):
    doc = json.loads(text)
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            if meta.get("version"):
                yield "npm", key.rsplit("node_modules/", 1)[1], meta["version"]
        return
    stack = [doc.get("dependencies") or {}]
    while stack:
        deps = stack.pop()
        for name, meta in deps.items() if isinstance(deps, dict) else ():
            if isinstance(meta, dict):
                if meta.get("version"):
                    yield "npm", name, meta["version"]
                stack.append(meta.get("dependencies") or {})


def _spec_name(spec):
    spec = spec.strip().strip('"').strip("'")
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def _yarn(text):
    names = []
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            names = [_spec_name(s) for s in line.rstrip()[:-1].split(",")]
            names = [n for n in names if n and n != "__metadata"]
        elif names:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
            if m:
                for n in set(names):
                    yield "npm", n, m.group(1)
                names = []


def _pnpm(text):
    section = False
    for line in text.splitlines():
        if not line.startswith(" "):
            section = line.rstrip() in ("packages:", "snapshots:")
            continue
        if not section or not re.match(r"^  \S.*:\s*$", line):
            continue
        key = line.strip()[:-1].strip("'\"").lstrip("/").split("(", 1)[0]
        at = key.rfind("@")
        if at > 0:
            yield "npm", key[:at], key[at + 1:]
        elif key.count("/") >= 1:
            name, _, version = key.rpartition("/")
            yield "npm", name, version


def _toml_packages(text, eco):
    for p in tomllib.loads(text).get("package") or ():
        if isinstance(p, dict) and p.get("name") and p.get("version"):
            yield eco, str(p["name"]), str(p["version"])


def _pipfile(text):
    doc = json.loads(text)
    for section in ("default", "develop"):
        for name, meta in (doc.get(section) or {}).items():
            version = str((meta or {}).get("version") or "")
            if version.startswith("=="):
                yield "PyPI", name, version[2:]


def _composer(text):
    doc = json.loads(text)
    for section in ("packages", "packages-dev"):
        for p in doc.get(section) or ():
            if isinstance(p, dict) and p.get("name") and p.get("version"):
                yield "Packagist", p["name"], str(p["version"]).lstrip("v")


def _gemfile(text):
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line[0].isspace():
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", line) if in_specs else None
        if m:
            yield "RubyGems", m.group(1), m.group(2).split("-", 1)[0]


def _gomod(text):
    block = False
    for line in text.splitlines():
        line = line.split("//", 1)[0].strip()
        if line.startswith("require ("):
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        parts = line.split()
        if line.startswith("require ") and len(parts) == 3:
            parts = parts[1:]
        elif not block or len(parts) != 2:
            continue
        version = parts[1].lstrip("v").replace("+incompatible", "")
        yield "Go", parts[0], version


def _pom(text):
    root = ET.fromstring(text)
    for el in root.iter():
        if not el.tag.endswith("dependency"):
            continue
        fields = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in el}
        version = fields.get("version", "")
        if fields.get("groupId") and fields.get("artifactId") and version and "${" not in version:
            yield "Maven", f"{fields['groupId']}:{fields['artifactId']}", version


_PARSERS = {"npm": _npm, "yarn": _yarn, "pnpm": _pnpm, "pipfile": _pipfile,
            "composer": _composer, "gemfile": _gemfile, "gomod": _gomod, "pom": _pom,
            "poetry": lambda t: _toml_packages(t, "PyPI"),
            "cargo": lambda t: _toml_packages(t, "crates.io")}


def parse(path):
    """[(ecosystem, name, version)] pinned by one lockfile; [] when unreadable."""
    name = os.path.basename(path)
    kind = EXACT.get(name) or ("requirements" if _REQ_FILE.match(name) else None)
    text = _read(path) if kind else None
    if text is None or len(text) > MAX_BYTES:
        return []
    fn = _requirements if kind == "requirements" else _PARSERS[kind]
    out = set()
    try:
        for eco, pkg, version in fn(text):
            if pkg and version:
                out.add((eco, normalise(eco, pkg), str(version).strip()))
            if len(out) >= MAX_PACKAGES:
                break
    except (ValueError, TypeError, AttributeError, KeyError, ET.ParseError, tomllib.TOMLDecodeError,
            RecursionError):
        # RecursionError: "[[[[..." nested past the parser's depth. One hostile
        # lockfile used to abort the whole appcode run for every project.
        return []
    return sorted(out)


def venv_packages(venv):
    """[(PyPI, name, version)] from a virtual environment's *.dist-info folders."""
    out = set()
    for pattern in ("lib/python3*/site-packages/*.dist-info", "lib64/python3*/site-packages/*.dist-info"):
        for d in glob.glob(os.path.join(venv, pattern))[:MAX_PACKAGES]:
            stem = os.path.basename(d)[:-len(".dist-info")]
            name, sep, version = stem.rpartition("-")
            if sep and name and version:
                out.add(("PyPI", normalise("PyPI", name), version))
    return sorted(out)
