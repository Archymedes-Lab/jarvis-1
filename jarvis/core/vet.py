"""The gate between what the internet says and what this machine acts on.

Threat intelligence arrives as prose written by strangers and is summarised by
a language model. Both halves of that pipeline are wrong sometimes, and they
are wrong in a specific, dangerous direction: they produce indicators that look
exactly like real ones.

A single observed extraction returned `evil.com`, `192.168.1.100`, `gdb`,
`strace`, bare `/tmp/`, and two "SHA-256" values that are the digests of the
empty string. Every one of those is syntactically perfect. Loaded into a
detection engine on a developer's workstation, that one article would flag the
debugger on every use and pin a permanent alert on a directory that is supposed
to be full of files.

So nothing extracted is trusted. Every candidate passes through here first, and
this module is deliberately the least clever code in the project: no network,
no model, no heuristics that "learn". Just explicit rules about what cannot
possibly be a useful indicator on this machine.

Two invariants hold everywhere downstream:

  * Intel may only ever ADD suspicion. No fetched content can approve a
    process, clear a finding, or lower a severity. The worst a poisoned feed
    can do is waste your attention; it can never create a blind spot.
  * Nothing fetched is ever executed, interpolated into a shell, or used as a
    path to open. Indicators are compared as data and only as data.
"""

import ipaddress
import re

from .vet_lists import (
    ATTACK_ID,
    CARVEOUT_DIRS,
    CLOUDFLARE_IPV4,
    CVE_ID,
    DOMAIN_DENY,
    DOMAIN_DENY_TLD,
    DOMAIN_RE,
    DUAL_USE_DOMAINS,
    FILENAME_RE,
    GENERIC_PROCESS,
    GITHUB_SHARED_IPV4,
    HEX64,
    JUNK_DIGESTS,
    KERNEL_SYM,
    LIBRARY_DENY,
    PACKAGE_INFRA,
    PATH_DENY_PREFIX,
    PATH_DENY_TRUSTED,
    PAYLOAD_EXT,
    PLACEHOLDER_MARKS,
    PROCESS_DENY,
    PUBLIC_INFRA_IPS,
    SHARED_HOSTING,
    SYSCALL_WORDS,
    WINDOWS_SYSTEM_BIN,
)

_DUAL_USE_REASON = "public IP-lookup or connectivity-check service, used by benign software too"


def refang(value: str) -> str:
    """Undo the defanging conventions writeups use so links are not clickable."""
    v = value.strip().strip('.,;:"\'()[]<>')
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[/]", "/").replace("[@]", "@")
    v = re.sub(r"^h(xx|XX)p", "http", v)
    v = re.sub(r"^(https?)\[:\]//", r"\1://", v)
    return v.strip()


def _has_placeholder(value: str) -> bool:
    low = value.lower()
    return any(mark in low for mark in PLACEHOLDER_MARKS)


def vet_sha256(value: str):
    v = refang(value).lower()
    if not HEX64.match(v):
        return None, "not a 64-character hex digest"
    if v in JUNK_DIGESTS:
        return None, "digest of empty input"
    if len(set(v)) < 6:
        return None, "degenerate digest"
    return v, ""


def vet_ipv4(value: str):
    v = refang(value)
    # Strip anything that is plainly a URL rather than a bare address.
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return None, "not an IP address"
    if not addr.is_global:
        # Private, loopback, link-local, multicast and reserved ranges are
        # either lab artefacts or this machine's own network.
        return None, "not a public address"
    if str(addr) in PUBLIC_INFRA_IPS:
        return None, "public DNS or shared infrastructure"
    if any(addr in network for network in CLOUDFLARE_IPV4):
        return None, "shared Cloudflare anycast address"
    if any(addr in network for network in GITHUB_SHARED_IPV4):
        return None, "shared GitHub Pages / raw content address"
    return str(addr), ""


def vet_domain(value: str):
    v = refang(value).lower()
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0].rstrip(".")
    if _has_placeholder(v):
        return None, "placeholder value"
    if not DOMAIN_RE.match(v):
        return None, "not a well-formed domain"
    tld = v.rsplit(".", 1)[-1]
    if tld in DOMAIN_DENY_TLD:
        return None, "reserved example TLD"
    if v in DOMAIN_DENY:
        return None, "publisher or example domain"
    if v in SHARED_HOSTING:
        return None, "shared hosting root, not a specific host"
    parts_pi = v.split(".")
    for i in range(len(parts_pi) - 1):
        if ".".join(parts_pi[i:]) in PACKAGE_INFRA:
            return None, "package registry or its CDN, used by everyone"
    if v in DUAL_USE_DOMAINS:
        return None, _DUAL_USE_REASON
    parts_du = v.split(".")
    for i in range(len(parts_du) - 1):
        if ".".join(parts_du[i:]) in DUAL_USE_DOMAINS:
            return None, _DUAL_USE_REASON
    # Also reject any subdomain of a denied registrable domain. SHARED_HOSTING
    # is deliberately excluded here: its subdomains are exactly what we want.
    parts = v.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in DOMAIN_DENY:
            return None, "publisher or example domain"
    return v, ""


def vet_cidr(value: str):
    """A network range, for feeds that publish blocks rather than addresses."""
    v = refang(value)
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None, "not a network range"
    if not net.is_global:
        return None, "not a public range"
    if net.prefixlen < 8:
        return None, "range too broad to be actionable"
    return str(net), ""


def vet_path(value: str):
    v = refang(value)
    if _has_placeholder(v):
        return None, "placeholder value"
    norm = v.replace("\\", "/").lower()
    if "/" not in norm:
        return None, "bare filename, not a path"
    if norm.endswith("/"):
        return None, "directory, not a file"
    base = norm.rsplit("/", 1)[-1]
    if len(base) < 3:
        return None, "no usable filename"
    # A single-component absolute path is almost always a fragment of a longer
    # one that the extraction clipped — "/tmp", "/proc", "/modules". Those name
    # directories that exist on every machine, so keeping them would guarantee
    # a false positive on the first hunt.
    comps = [c for c in norm.split("/") if c]
    if len(comps) < 2 and not norm.endswith(PAYLOAD_EXT):
        return None, "too shallow to identify a file"
    if norm.startswith(PATH_DENY_PREFIX):
        return None, "kernel or pseudo-filesystem path"
    if norm.startswith(PATH_DENY_TRUSTED) and not (
            norm.startswith(CARVEOUT_DIRS) and norm.endswith(PAYLOAD_EXT)):
        # Inside an installed-software directory and not one of the few places
        # a dropped payload has to live: this is a system file's own path.
        return None, "path owned by installed software"
    if len(norm) > 260:
        return None, "implausibly long path"
    return v, ""


def vet_process(value: str):
    v = refang(value).lower()
    if _has_placeholder(v):
        return None, "placeholder value"
    if "/" in v or "\\" in v:
        v = v.replace("\\", "/").rsplit("/", 1)[-1]
    if v.endswith((".so", ".ko", ".dll", ".dylib")) or ".so." in v:
        # A shared object or kernel module is a file, not a process name;
        # matching it against the process table can only ever misfire.
        return None, "shared library or module, not a process"
    if not FILENAME_RE.match(v):
        return None, "not a plausible process name"
    if len(v) < 4:
        return None, "too short to match unambiguously"
    if KERNEL_SYM.search(v) or v in SYSCALL_WORDS:
        return None, "kernel symbol or syscall name"
    stem = v.rsplit(".", 1)[0]
    for form in (v, stem, stem + ".exe"):
        if form in PROCESS_DENY or form in WINDOWS_SYSTEM_BIN:
            return None, "legitimate system or developer tool"
        if form in GENERIC_PROCESS:
            return None, "name too generic to identify anything"
    return v, ""


def vet_filename(value: str):
    """A bare filename, kept only when it is specific enough to hunt for.

    This exists for the artefact class that has no path in the writeup but is
    still worth finding: a PAM module, a preloaded object, a dropped kernel
    module. hunt.py looks for these only in the handful of directories where
    such a payload has to live to work, never across the whole filesystem.
    """
    v = refang(value).lower()
    if _has_placeholder(v):
        return None, "placeholder value"
    if "/" in v or "\\" in v:
        v = v.replace("\\", "/").rsplit("/", 1)[-1]
    if not FILENAME_RE.match(v):
        return None, "not a plausible filename"
    if len(v) < 5:
        return None, "too short to match unambiguously"
    if v in LIBRARY_DENY or v in PROCESS_DENY:
        return None, "stock system component"
    if KERNEL_SYM.search(v) or v in SYSCALL_WORDS:
        return None, "kernel symbol or syscall name"
    if "." not in v:
        return None, "no extension, too generic to hunt by name"
    return v, ""


def vet_regkey(value: str):
    v = refang(value)
    if _has_placeholder(v):
        return None, "placeholder value"
    norm = v.replace("/", "\\").upper()
    if not norm.startswith(("HKLM", "HKCU", "HKCR", "HKU", "HKEY_")):
        return None, "not a registry path"
    if norm.count("\\") < 2:
        return None, "too shallow to be specific"
    return v, ""


def vet_attack(value: str):
    v = refang(value).upper()
    if not ATTACK_ID.match(v):
        return None, "not an ATT&CK technique id"
    return v, ""


def vet_cve(value: str):
    v = refang(value).upper()
    if not CVE_ID.match(v):
        return None, "not a CVE identifier"
    return v, ""


VETTERS = {
    "sha256": vet_sha256,
    "ipv4": vet_ipv4,
    "domain": vet_domain,
    "path": vet_path,
    "process": vet_process,
    "filename": vet_filename,
    "cidr": vet_cidr,
    "regkey": vet_regkey,
    "attack": vet_attack,
    "cve": vet_cve,
}


def vet(kind: str, value: str):
    """Return (normalised_value, "") if usable, else (None, reason_rejected)."""
    fn = VETTERS.get(kind)
    if not fn:
        return None, f"unknown indicator kind: {kind}"
    if not isinstance(value, str) or not value.strip():
        return None, "empty value"
    if len(value) > 512:
        return None, "implausibly long value"
    try:
        return fn(value)
    except Exception as exc:            # a bad candidate must never crash a refresh
        return None, f"vetting error: {exc}"
