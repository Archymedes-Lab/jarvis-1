"""Measured facts about the computer ARGUS-INSTINCT runs on (docs/architecture/AGNOSTIC-DEPLOYMENT.md).

One binary must run on many kinds of computer: Ubuntu and Debian, the RHEL
family, Alpine, containers, virtual machines, WSL and Windows, later macOS.
What applies on a host is derived from what this module measures there, never
from a machine name, a user name or a path that only the developer's machine has.

Invariants (tests/test_facts.py):
- Read-only and bounded: only file reads under the given root, existence checks
  and a PATH lookup; no subprocess, no network, no write, no privilege. A read
  is capped at MAX_READ bytes.
- Unknown stays unknown: a fact that cannot be read is None (or absent from a
  set), never guessed. A requirement that depends on it is then unmet, which
  reports the collector as not applicable with the reason; it never fails or
  reads as healthy.
- Deterministic: the same filesystem gives the same facts (sets are sorted).
- Pure parsers: parse_os_release, container_kind, libc_kind and family_of take
  text or paths and return values, so every host shape is testable from fixtures.
"""

import os
import shutil
import sys

MAX_READ = 64 * 1024
FAMILIES = {          # os-release ID or ID_LIKE word -> family
    "debian": "debian", "ubuntu": "debian", "raspbian": "debian", "linuxmint": "debian",
    "rhel": "rhel", "fedora": "rhel", "centos": "rhel", "rocky": "rhel", "almalinux": "rhel", "amzn": "rhel", "ol": "rhel",
    "suse": "suse", "opensuse": "suse", "sles": "suse",
    "alpine": "alpine", "arch": "arch", "manjaro": "arch",
}
PACKAGE_DBS = {"dpkg": "var/lib/dpkg/status", "rpm": "var/lib/rpm", "apk": "lib/apk/db/installed",
               "pacman": "var/lib/pacman/local"}
ENGINE_SOCKETS = {"docker": ("var/run/docker.sock", "run/docker.sock"),
                  "podman": ("run/podman/podman.sock",)}


def _p(root, rel):
    return os.path.join(root, rel.lstrip("/"))


def _read(root, rel):
    try:
        with open(_p(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_READ)
    except OSError:
        return None


def _exists(root, rel):
    return os.path.lexists(_p(root, rel))


def parse_os_release(text):
    """{'id', 'id_like': [...], 'version_id', 'codename', 'name'} from os-release text, or {}."""
    if not text:
        return {}
    kv = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            kv[key] = value.strip().strip('"').strip("'")
    if not kv:
        return {}
    return {"id": kv.get("ID", "").lower() or None, "id_like": sorted(kv.get("ID_LIKE", "").lower().split()),
            "version_id": kv.get("VERSION_ID") or None, "codename": kv.get("VERSION_CODENAME") or None,
            "name": kv.get("PRETTY_NAME") or kv.get("NAME") or None}


def family_of(distro):
    """The package family of a parsed os-release, or None when unknown."""
    for word in [distro.get("id") or ""] + list(distro.get("id_like") or []):
        if word in FAMILIES:
            return FAMILIES[word]
    return None


def container_kind(root="/", environ=None, cgroup=None):
    """The container runtime this process runs in, or None. Evidence only, no guess."""
    env = os.environ if environ is None else environ
    if _exists(root, "/.dockerenv"):
        return "docker"
    if _exists(root, "/run/.containerenv"):
        return "podman"
    if env.get("KUBERNETES_SERVICE_HOST"):
        return "kubernetes"
    marker = (env.get("container") or "").lower()
    if marker in ("docker", "podman", "lxc", "systemd-nspawn", "oci"):
        return marker
    text = _read(root, "/proc/1/cgroup") if cgroup is None else cgroup
    for word in ("kubepods", "docker", "libpod", "lxc"):
        if text and word in text:
            return {"kubepods": "kubernetes", "libpod": "podman"}.get(word, word)
    return None


def libc_kind(root="/"):
    """'musl', 'glibc' or None (by the dynamic loader present)."""
    for d in ("lib", "usr/lib"):
        try:
            names = os.listdir(_p(root, d))
        except OSError:
            continue
        if any(n.startswith("ld-musl-") for n in names):
            return "musl"
    for rel in ("lib64/ld-linux-x86-64.so.2", "lib/ld-linux-aarch64.so.1", "lib/x86_64-linux-gnu/libc.so.6",
                "lib/aarch64-linux-gnu/libc.so.6", "usr/lib64/libc.so.6", "lib/ld-linux-armhf.so.3"):
        if _exists(root, rel):
            return "glibc"
    return None


def _os_name(platform):
    if platform.startswith("linux"):
        return "linux"
    if platform in ("win32", "cygwin"):
        return "windows"
    if platform == "darwin":
        return "macos"
    return "other"


def probe(root="/", platform=None, environ=None, which=shutil.which):
    """The facts of this host as a plain, JSON-ready dict."""
    os_name = _os_name(sys.platform if platform is None else platform)
    facts = {"os": os_name, "arch": (os.uname().machine if hasattr(os, "uname") else None)}
    if os_name != "linux":
        facts.update({"supported": os_name == "windows", "init": "windows-scm" if os_name == "windows" else None})
        return facts
    osrelease = (_read(root, "/proc/sys/kernel/osrelease") or "").strip() or None
    distro = parse_os_release(_read(root, "/etc/os-release") or _read(root, "/usr/lib/os-release"))
    container = container_kind(root, environ)
    if _exists(root, "/run/systemd/system"):
        init = "systemd"
    elif _exists(root, "/run/openrc") or _exists(root, "/sbin/openrc"):
        init = "openrc"
    else:
        init = None
    engines = sorted(e for e, socks in ENGINE_SOCKETS.items()
                     if any(_exists(root, s) for s in socks) or (root == "/" and which(e)))
    facts.update({
        "supported": True,
        "kernel": osrelease,
        "wsl": bool(osrelease and "microsoft" in osrelease.lower()),
        "distro": distro.get("id"), "distro_like": distro.get("id_like", []),
        "version_id": distro.get("version_id"), "codename": distro.get("codename"),
        "family": family_of(distro) if distro else None,
        "init": init,
        "journald": _exists(root, "/run/systemd/journal"),
        "container": container,
        "libc": libc_kind(root),
        "package_dbs": sorted(k for k, rel in PACKAGE_DBS.items() if _exists(root, rel)),
        "container_engines": engines,
        "btf": _exists(root, "/sys/kernel/btf/vmlinux"),
        "input_devices": _exists(root, "/dev/input"),
        "root": (os.geteuid() == 0) if root == "/" and hasattr(os, "geteuid") else None,
    })
    return facts


_CACHE = {}


def current():
    """This host's facts, probed once per process."""
    if "facts" not in _CACHE:
        _CACHE["facts"] = probe()
    return _CACHE["facts"]
