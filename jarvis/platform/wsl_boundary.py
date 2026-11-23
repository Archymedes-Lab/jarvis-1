"""Bounded read of the WSL trust boundary: config, DrvFs mounts, interop, sockets.

Reads configuration and metadata only. No file contents beyond the two WSL
config files, no environment values, no command lines. Every source reports
its own status; an unreadable source is unknown, never "unchanged". This
module never changes host policy.
"""

import os

WSL_CONF = "/etc/wsl.conf"
WINDOWS_CONFIG = "wslconfig"
MOUNTINFO = "/proc/self/mountinfo"
INTEROP = "/proc/sys/fs/binfmt_misc/WSLInterop"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
KERNEL_RELEASE = "/proc/sys/kernel/osrelease"
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
MAX_BYTES = 65536
MAX_MOUNTS = 256
MAX_VALUE = 200
# Only these are retained; anything else in a config file is ignored.
WSL_CONF_KEYS = {
    "boot": {"systemd", "command"},
    "automount": {"enabled", "root", "options", "mountfstab"},
    "interop": {"enabled", "appendwindowspath"},
    "network": {"generatehosts", "generateresolvconf", "hostname"},
    "user": {"default"},
}
WSLCONFIG_KEYS = {
    "wsl2": {"kernel", "kernelcommandline", "kernelmodules", "networkingmode",
             "firewall", "dnstunneling", "autoproxy", "nestedvirtualization",
             "guiapplications", "localhostforwarding", "memory", "processors",
             "swap", "vmidletimeout", "safemode"},
    "experimental": {"automemoryreclaim", "sparsevhd", "hostaddressloopback",
                     "bestefforddnsparsing", "dnstunneling"},
    "interop": {"enabled", "appendwindowspath"},
}


def _read(path):
    with open(path, "rb") as fh:
        return fh.read(MAX_BYTES).decode("utf-8", "replace")


def parse_ini(text, allowed):
    """Section/key pairs from an allowlist; keys case-folded, values bounded."""
    facts, section = {}, None
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if sep and section in allowed and key in allowed[section]:
            facts[f"{section}.{key}"] = value.strip().strip('"')[:MAX_VALUE]
    return facts


def _source(reader, path, allowed, prefix):
    try:
        return {"status": "current", "facts": {
            f"{prefix}.{k}": v for k, v in parse_ini(reader(path), allowed).items()}}
    except FileNotFoundError:
        # An absent config file is a defined state (defaults apply), not unknown.
        return {"status": "absent", "facts": {}}
    except OSError as exc:
        return {"status": "unavailable", "facts": {}, "reason": type(exc).__name__}


def _mounts(path):
    rows = []
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BYTES * 4).decode("utf-8", "replace")
    for line in raw.splitlines():
        left, sep, right = line.partition(" - ")
        parts, tail = left.split(), right.split()
        if not sep or len(parts) < 6 or len(tail) < 3:
            continue
        opts = tail[2].split(",")
        if tail[0] != "9p" or not any(o.startswith("aname=drvfs") for o in opts):
            continue
        rows.append((parts[4], "ro" if parts[5].split(",")[0] == "ro" else "rw"))
    return sorted(rows)[:MAX_MOUNTS]


def snapshot(*, wsl_conf=WSL_CONF, windows_config=None, mountinfo=MOUNTINFO,
             interop=INTEROP, boot_id=BOOT_ID, kernel=KERNEL_RELEASE,
             sockets=DOCKER_SOCKETS, path_env=None):
    """Return {'boot_id', 'sources': {name: {status, facts}}, 'facts': flat}."""
    sources = {"wsl_conf": _source(_read, wsl_conf, WSL_CONF_KEYS, "wsl_conf")}
    if windows_config:
        sources["windows_wslconfig"] = _source(_read, windows_config,
                                               WSLCONFIG_KEYS, "wslconfig")
    else:
        sources["windows_wslconfig"] = {"status": "unavailable", "facts": {},
                                        "reason": "path not supplied"}
    try:
        mounts = _mounts(mountinfo)
        sources["drvfs"] = {"status": "current", "facts": {
            f"drvfs.mount[{mp}]": mode for mp, mode in mounts}}
    except OSError as exc:
        sources["drvfs"] = {"status": "unavailable", "facts": {},
                            "reason": type(exc).__name__}
    try:
        state = _read(interop).split("\n", 1)[0].strip()
        sources["interop"] = {"status": "current",
                              "facts": {"interop.binfmt": state}}
    except FileNotFoundError:
        sources["interop"] = {"status": "current",
                              "facts": {"interop.binfmt": "not_registered"}}
    except OSError as exc:
        sources["interop"] = {"status": "unavailable", "facts": {},
                              "reason": type(exc).__name__}
    path_env = os.environ.get("PATH", "") if path_env is None else path_env
    windows_dirs = sum(1 for p in path_env.split(":") if p.startswith("/mnt/"))
    sources["path"] = {"status": "current",
                       "facts": {"path.windows_dirs": str(windows_dirs)}}
    present = []
    for sock in sockets:
        try:
            st = os.stat(sock)
            present.append(f"{sock}:{st.st_mode & 0o7777:o}")
        except OSError:
            continue
    sources["docker_socket"] = {"status": "current", "facts": {
        "docker.socket": ",".join(present) or "absent"}}
    try:
        release = _read(kernel).strip()[:MAX_VALUE]
        sources["kernel"] = {"status": "current",
                             "facts": {"kernel.release": release}}
    except OSError as exc:
        sources["kernel"] = {"status": "unavailable", "facts": {},
                             "reason": type(exc).__name__}
    try:
        boot = _read(boot_id).strip() or None
    except OSError:
        boot = None
    facts = {k: v for s in sources.values() for k, v in s["facts"].items()}
    return {"boot_id": boot, "sources": sources, "facts": facts}
