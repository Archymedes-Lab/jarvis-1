"""Linux boot chain and kernel attack surface (Exa threat research 2026-10-29,
~/.cache/argus-research/exa-threats-2026-10-29.json).

Two things current Linux research keeps pointing at that no other collector
watches:

    boot      persistence that survives reinstalling userspace packages: the
              GRUB configuration and its generator scripts (/etc/grub.d), the
              initramfs build hooks and dracut modules, and the kernel and
              initramfs images themselves (Elastic Security Labs, Linux
              persistence series 2025). A file is learned once; a change later
              is weighed against package-manager activity around its ctime: a
              kernel or initramfs update explains a new image (low), nothing
              explains it (high for images and hooks, medium for the GRUB
              configuration an administrator may edit by hand). A hook or
              generator script no package owns is reported from the first run.
    taint     /proc/sys/kernel/tainted against its value at the first run of
              each boot: a forced or unsigned module or an oops appearing later
              in the boot is high, other new taint medium
    udev      rules that run a program from outside the system directories
              on a device event (persistence trigger), from the first run
    kernel    the settings that decide how far an unprivileged process gets
              with a kernel bug or a rootkit: unprivileged BPF (eBPF rootkits),
              unprivileged user namespaces (the 2026 page-cache exploits, Copy
              Fail and DirtyFrag, need them), kptr/dmesg restriction, ptrace
              scope, module signature enforcement, lockdown, and the loaded
              modules those exploits reach (algif_aead, esp4/esp6, rxrpc).

Invariants (tests/test_bootchain.py holds each):
    I1  a file or setting that cannot be read is reported as not observed,
        never as clean
    I2  the first run learns; drift is reported from the second run on (an
        unowned hook is reported at once: it is risky in itself)
    I3  package activity can lower a change's severity, never hide it
    I4  bounded: large images are fingerprinted by size, inode and ctime (a
        userspace process cannot set ctime, so a backdated mtime does not hide
        a change), small files are hashed, and files, log bytes and findings
        all have ceilings
    I5  read-only: nothing is loaded, written or changed
"""

import glob
import hashlib
import json
import os
import re
import time

from jarvis.core.finding import finding as _finding

STATE_META = "bootchain_state_v1"     # {"learned_at", "files": {path: signature}, "events": [...]}
MAX_FILES = 400
HASH_LIMIT = 1024 * 1024              # hash files up to 1 MiB; larger ones by stat signature
LOG_TAIL = 2 * 1024 * 1024
PKG_WINDOW_S = 20 * 60                # a boot-related package operation this close explains a change
# Only operations on packages that write the boot chain (kernel, bootloader,
# initramfs builders and what they pull in) explain a change: an unrelated
# upgrade must not open a window to hide in (Jev 2026-10-29: 0.28 "too wide").
BOOT_PKG = re.compile(r"linux-(image|modules|headers|firmware)|\bkernel|grub|shim|initramfs|dracut|mkinitcpio"
                      r"|microcode|systemd-boot|dkms|\bzfs|nvidia|cryptsetup|lvm2|mdadm|plymouth|busybox|kmod",
                      re.I)
KEEP_S = 7 * 24 * 3600
MAX_EVENTS = 200
MAX_LISTED = 8

# (glob, kind). kind decides severity when nothing explains a change.
WATCHED = (
    ("/boot/vmlinuz*", "image"),
    ("/boot/initrd.img*", "image"),
    ("/boot/initramfs-*.img", "image"),
    ("/boot/grub/grub.cfg", "config"),
    ("/boot/grub2/grub.cfg", "config"),
    ("/etc/default/grub", "config"),
    ("/etc/default/grub.d/*", "config"),
    ("/etc/grub.d/*", "hook"),
    ("/etc/initramfs-tools/hooks/*", "hook"),
    ("/etc/initramfs-tools/scripts/*/*", "hook"),
    ("/etc/initramfs-tools/conf.d/*", "config"),
    ("/etc/dracut.conf", "config"),
    ("/etc/dracut.conf.d/*", "config"),
    ("/usr/lib/dracut/modules.d/*/*", "hook"),
    ("/etc/modprobe.d/*", "config"),
    ("/etc/modules-load.d/*", "config"),
    ("/etc/modules", "config"),
    ("/etc/udev/rules.d/*", "udev"),
)
UNEXPLAINED = {"image": "high", "hook": "high", "config": "medium", "udev": "medium"}
# A udev rule that runs a program on a device event is a persistence trigger
# (Elastic Linux persistence 2025): RUN+= or PROGRAM= naming anything outside the
# system directories. Administrators write udev rules too, so only those count.
UDEV_EXEC = re.compile(r"\b(?:RUN|PROGRAM|IMPORT\{program\})\s*\+?=\s*\"([^\"]+)\"")
SYSTEM_BIN = ("/usr/", "/lib/", "/bin/", "/sbin/")
PKG_LOGS = ("/var/log/dpkg.log", "/var/log/dnf.rpm.log", "/var/log/zypp/history", "/var/log/pacman.log")
PKG_LINE_TS = (
    (re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:install|upgrade|configure|trigproc|remove) "),
     "%Y-%m-%d %H:%M:%S"),                                                   # dpkg
    (re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S* (?:SUBDEBUG|INFO) (?:Installed|Upgrade|Upgraded)"),
     "%Y-%m-%dT%H:%M:%S"),                                                   # dnf
    (re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\|install\|"), "%Y-%m-%d %H:%M:%S"),  # zypper
    (re.compile(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\] \[ALPM\] (?:installed|upgraded)"),
     "%Y-%m-%dT%H:%M:%S"),                                                   # pacman
)

# sysctl or sysfs path -> (bad value test, severity, title, why)
KERNEL = (
    ("/proc/sys/kernel/unprivileged_bpf_disabled", lambda v: v == "0", "medium",
     "any user can load BPF programs",
     "kernel.unprivileged_bpf_disabled = 0: unprivileged eBPF is how BPF rootkits and several kernel "
     "exploits start; set it to 1 or 2"),
    ("/proc/sys/kernel/kptr_restrict", lambda v: v == "0", "low",
     "kernel addresses are visible to every user",
     "kernel.kptr_restrict = 0 hands exploits the addresses KASLR hides; set 1"),
    ("/proc/sys/kernel/dmesg_restrict", lambda v: v == "0", "low",
     "every user can read the kernel log", "kernel.dmesg_restrict = 0; set 1"),
    ("/proc/sys/kernel/yama/ptrace_scope", lambda v: v == "0", "low",
     "any process can trace any other of the same user",
     "kernel.yama.ptrace_scope = 0 lets malware read another program's memory (browsers, SSH agents); set 1"),
)
# /proc/sys/kernel/tainted bits worth naming (Documentation/admin-guide/tainted-kernels).
TAINT_BITS = {0: "proprietary module", 1: "module force-loaded", 7: "kernel died recently (OOPS)",
              9: "kernel warning", 12: "out-of-tree module", 13: "unsigned module", 15: "live patch"}
TAINT_ALARM = {1, 7, 13}            # appearing during a boot: forced or unsigned module, an oops
# Modules the 2026 page-cache exploits reach (Elastic, Copy Fail / DirtyFrag):
# loaded and unused, they are attack surface; blacklist them if nothing needs them.
EXPLOIT_MODULES = ("algif_aead", "esp4", "esp6", "rxrpc")


def _read(path, limit=65536):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace"), ""
    except FileNotFoundError:
        return "", "missing"
    except OSError as exc:
        return "", exc.strerror or str(exc)


# ── boot chain ───────────────────────────────────────────────────────────

def watched_files(root="/"):
    def r(p):
        return os.path.join(root, p.lstrip("/")) if root != "/" else p
    out, truncated = [], 0
    for pattern, kind in WATCHED:
        for p in sorted(glob.glob(r(pattern))):
            if os.path.isfile(p) and not os.path.islink(p):
                if len(out) >= MAX_FILES:
                    truncated += 1
                    continue
                out.append((p, kind, pattern))
    return out, truncated


def signature(path):
    """(signature, problem). Small files by content hash, large ones by stat."""
    try:
        st = os.stat(path)
    except OSError as exc:
        return None, exc.strerror or str(exc)
    sig = {"size": st.st_size, "ino": st.st_ino, "ctime": int(st.st_ctime), "mode": st.st_mode & 0o7777,
           "uid": st.st_uid}
    if st.st_size <= HASH_LIMIT:
        try:
            with open(path, "rb") as fh:
                sig["sha256"] = hashlib.sha256(fh.read(HASH_LIMIT + 1)).hexdigest()
        except OSError as exc:
            return None, exc.strerror or str(exc)
    return sig, ""


def changed(old, new):
    if "sha256" in old and "sha256" in new:
        return old["sha256"] != new["sha256"] or old["mode"] != new["mode"] or old["uid"] != new["uid"]
    return any(old.get(k) != new.get(k) for k in ("size", "ino", "ctime", "mode", "uid"))


def package_times(root="/"):
    """Epoch seconds of boot-related package operations from the package
    manager logs (tail only)."""
    times = []
    for log in PKG_LOGS:
        p = os.path.join(root, log.lstrip("/")) if root != "/" else log
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as fh:
                fh.seek(max(0, size - LOG_TAIL))
                text = fh.read(LOG_TAIL).decode("utf-8", "replace")
        except OSError:
            continue
        for line in text.splitlines():
            if not BOOT_PKG.search(line):
                continue
            for rx, fmt in PKG_LINE_TS:
                m = rx.match(line)
                if m:
                    try:
                        times.append(time.mktime(time.strptime(m.group(1), fmt)))
                    except ValueError:
                        pass
                    break
    return sorted(times)


def explained(ctime, times):
    return any(abs(t - ctime) <= PKG_WINDOW_S for t in times)


def package_owner(path):
    """True/False from dpkg or rpm, None when neither is installed. dpkg_owns
    answers False when no package manager answers, which must read as
    "unknown" here, never as "no package installed this" (I1)."""
    import shutil

    from jarvis.core.util import dpkg_owns, package_manager
    manager = package_manager()
    if not shutil.which("rpm" if manager == "rpm" else "dpkg"):
        return None
    return dpkg_owns(path, manager)


def boot_findings(state, now, root="/", owner=None):
    """(findings, events, state, problems)."""
    owner = owner or package_owner
    files, truncated = watched_files(root)
    problems = []
    if truncated:
        problems.append(f"{truncated} boot files over the {MAX_FILES}-file limit were not checked")
    learning = not state.get("learned_at")
    old = state.get("files") or {}
    # A pattern a later release starts watching is learned, not "added": the
    # snap udev rule from August read as new the day udev rules were added to
    # WATCHED (2026-10-29). States from before this have no list: their known
    # patterns are those of their files' kinds at the time, so assume all but udev.
    known = set(state.get("patterns") or [p for p, k in WATCHED if k != "udev"])
    new, events, out = {}, [], []
    times = None
    for path, kind, pattern in files:
        sig, problem = signature(path)
        if sig is None:
            problems.append(f"{path}: {problem}")
            continue
        sig["kind"] = kind
        new[path] = sig
        specific = False                 # a sharper finding below covers this file
        if kind == "udev" and path not in old:
            odd = udev_programs(path)
            if odd:
                specific = True
                out.append(_finding("persistence", "high", f"udev rule runs a program from outside the system: "
                                    f"{os.path.basename(path)}",
                                    f"{path} runs {', '.join(odd[:3])} on a device event", path))
        if kind == "hook" and path not in old:
            try:
                owned = owner(path)
            except Exception:
                owned = None
            if owned is False:
                specific = True
                out.append(_finding("persistence", "high", f"boot hook no package installed: {os.path.basename(path)}",
                                    f"{path} runs when the initramfs or GRUB configuration is built; no package "
                                    "owns it. Confirm you added it.", path))
        if learning or pattern not in known:
            continue
        if (path not in old and not specific) or (path in old and changed(old[path], sig)):
            if times is None:
                times = package_times(root)
            how = "added" if path not in old else "changed"
            sev = "low" if explained(sig["ctime"], times) else UNEXPLAINED[kind]
            events.append({"ts": now, "path": path, "kind": kind, "how": how, "sev": sev,
                           "ctime": sig["ctime"]})
    if not learning:
        for path, sig in old.items():
            if path not in new:
                if times is None:
                    times = package_times(root)
                sev = "low" if explained(now, times) else UNEXPLAINED.get(sig.get("kind"), "medium")
                events.append({"ts": now, "path": path, "kind": sig.get("kind", "config"), "how": "removed",
                               "sev": sev, "ctime": int(now)})
    state = {"learned_at": state.get("learned_at") or now, "files": new,
             "patterns": [p for p, _k in WATCHED]}
    return out, events, state, problems


def udev_programs(path):
    """Programs a udev rule file runs that live outside the system directories."""
    text, _p = _read(path, HASH_LIMIT)
    out = []
    for m in UDEV_EXEC.finditer(text):
        cmd = m.group(1).strip().split()
        prog = cmd[0] if cmd else ""
        if prog.startswith("/") and not prog.startswith(SYSTEM_BIN):
            out.append(prog)
        elif prog in ("sh", "bash", "/bin/sh", "/bin/bash") or prog.endswith(("/sh", "/bash")):
            out.extend(a for a in cmd[1:] if a.startswith("/") and not a.startswith(SYSTEM_BIN))
    return out


EVENT_WHY = {"image": "the kernel or initramfs that boots next",
             "hook": "a script that runs when the initramfs or GRUB configuration is built",
             "config": "boot or module-loading configuration",
             "udev": "a udev rule (it can run programs on device events)"}


def event_findings(events, now):
    out = {}
    for e in events:
        if now - e.get("ts", 0) > KEEP_S:
            continue
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(e["ctime"]))
        reason = ("during a package update" if e["sev"] == "low"
                  else "with no package update around that time")
        f = _finding("persistence", e["sev"], f"boot file {e['how']}: {e['path']}",
                     f"{EVENT_WHY.get(e['kind'], '')} was {e['how']} at {when}, {reason}", e["path"])
        out[(f["title"], f["where"])] = f
    return list(out.values())


# ── kernel attack surface ────────────────────────────────────────────────

def kernel_findings(root="/"):
    def r(p):
        return os.path.join(root, p.lstrip("/")) if root != "/" else p
    out, loose, problems = [], [], []
    for path, bad, sev, title, why in KERNEL:
        text, problem = _read(r(path), 64)
        if problem == "missing":
            continue                      # not built into this kernel
        if problem:
            problems.append(f"{path}: {problem}")
            continue
        value = text.strip()
        if bad(value):
            if sev == "low":
                loose.append(why)
            else:
                out.append(_finding("posture", sev, title, why, path))
    userns, _p = _read(r("/proc/sys/kernel/unprivileged_userns_clone"), 64)
    maxns, _p2 = _read(r("/proc/sys/user/max_user_namespaces"), 64)
    restrict, _p3 = _read(r("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"), 64)
    if userns.strip() != "0" and maxns.strip() not in ("", "0") and restrict.strip() != "1":
        loose.append("unprivileged user namespaces are open (kernel.unprivileged_userns_clone / "
                     "user.max_user_namespaces): the 2026 page-cache exploits need them; restrict them "
                     "where no container or browser sandbox needs them")
    sig_enforce, _p = _read(r("/sys/module/module/parameters/sig_enforce"), 16)
    lockdown, lp = _read(r("/sys/kernel/security/lockdown"), 256)
    if sig_enforce.strip() == "N" and (lp or "[none]" in lockdown):
        loose.append("unsigned kernel modules can be loaded (module.sig_enforce=N, no lockdown): a rootkit "
                     "module needs only root")
    modules, mp = _read(r("/proc/modules"), 1024 * 1024)
    if mp and mp != "missing":
        problems.append(f"/proc/modules: {mp}")
    loaded = {line.split()[0] for line in modules.splitlines() if line.strip()}
    hit = [m for m in EXPLOIT_MODULES if m in loaded]
    if hit:
        loose.append(f"loaded kernel modules that the 2026 page-cache exploits reach: {', '.join(hit)}; "
                     "blacklist them in /etc/modprobe.d if nothing here needs them")
    if loose:
        out.append(_finding("posture", "low", f"kernel attack surface: {len(loose)} setting(s) looser than "
                            "recommended", "; ".join(loose[:MAX_LISTED]), "kernel"))
    return out, problems


def taint_findings(state, root="/"):
    """(findings, taint state, problems). The bits a kernel has at the first run
    of a boot are its baseline (DKMS drivers set O and E at boot); bits that
    appear later in the same boot mean a module was loaded or the kernel warned."""
    def r(p):
        return os.path.join(root, p.lstrip("/")) if root != "/" else p
    text, problem = _read(r("/proc/sys/kernel/tainted"), 64)
    boot, _bp = _read(r("/proc/sys/kernel/random/boot_id"), 64)
    if problem == "missing":
        return [], state, []
    if problem:
        return [], state, [f"/proc/sys/kernel/tainted: {problem}"]
    try:
        value = int(text.strip() or "0")
    except ValueError:
        return [], state, ["/proc/sys/kernel/tainted is not a number"]
    boot = boot.strip() or "unknown"
    base = state if state.get("boot") == boot else {"boot": boot, "baseline": value, "reported": 0}
    new_bits = value & ~base["baseline"] & ~base.get("reported", 0)
    out = []
    names = [TAINT_BITS.get(b, f"bit {b}") for b in range(32) if new_bits >> b & 1]
    if new_bits:
        sev = "high" if any(new_bits >> b & 1 for b in TAINT_ALARM) else "medium"
        out.append(_finding("integrity", sev, "kernel taint changed since boot",
                            f"now {value} (boot baseline {base['baseline']}): {', '.join(names)}. A module loaded "
                            "after boot without a signature or by force is how a kernel rootkit arrives; check "
                            "`dmesg` and `lsmod`", "/proc/sys/kernel/tainted"))
        base = {**base, "reported": base.get("reported", 0) | new_bits}
    return out, base, []


def audit(store, hosts=None, now=None, root="/", owner=None):
    now = time.time() if now is None else now
    problems = []
    try:
        state = json.loads(store.get_meta(STATE_META, "") or "{}")
        if not isinstance(state, dict):
            raise ValueError
    except (ValueError, TypeError):
        state = {}
        problems.append("stored boot state could not be read; learning again, so changes since the last "
                        "good run are not reported")
    out, events, new_state, p = boot_findings(state, now, root, owner)
    problems += p
    kept = [e for e in state.get("events", []) if isinstance(e, dict) and now - e.get("ts", 0) <= KEEP_S
            # Events a state from before the pattern list raised for a then
            # newly watched class (udev) were the false "added" ones: drop them.
            and (state.get("patterns") is not None or e.get("kind") != "udev")]
    kept = (kept + events)[-MAX_EVENTS:]
    new_state["events"] = kept
    t, new_state["taint"], p = taint_findings(state.get("taint") or {}, root)
    out += t
    problems += p
    store.set_meta(STATE_META, json.dumps(new_state))
    out += event_findings(kept, now)
    k, p = kernel_findings(root)
    out += k
    problems += p
    if problems:
        out.append(_finding("visibility", "medium", "boot chain not fully observed",
                            "; ".join(problems[:MAX_LISTED])[:1500], "bootchain"))
    return out
