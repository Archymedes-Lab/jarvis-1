"""Storage governor: keep the only disk from filling again.

See docs/architecture/STORAGE-GOVERNOR.md. Twice (2026-10-11, 2026-10-23)
the Windows system drive hit 0.1 GB free; the WSL disk image and the page
file could not grow, guest writes failed and WSL relaunched the VM with
JARVIS, Docker and Sysmon inside it.

What this does, every run:
  * reads the host side in one PowerShell call (system drive free, WSL image
    size, swap, page-file policy, ballast file);
  * reads the guest side cheaply (statvfs, bounded walks of the known
    reclaimable caches at most every 6 h while headroom is fine, Docker's
    own accounting, JARVIS's own stores);
  * keeps a bounded history of free space and estimates the growth rate, so
    the owner is warned in days, not at the line;
  * removes JARVIS-made release stages beyond the newest three when they are
    neither deployed nor the live base (JARVIS created them to be consumed);
  * releases the ballast file when the drive is below the critical line and
    the file exists: the one automatic act, recorded and paged.

What it never does: delete anything the owner made, touch the store or the
sealed history, recreate the ballast, or run anything when a measurement is
missing (that is a visibility finding).
"""
import json
import math
import os
import time
from pathlib import Path

from jarvis.core.paths import load_win_script
from jarvis.platform import host as machine
from jarvis.platform.windows import ps_json

PS_STORAGE = load_win_script("storage.ps1")

GIB = 1024 ** 3
# Headroom lines. Below CRITICAL the page file and the image have already
# failed to grow on this machine; HIGH gives one bad hour of warning.
CRITICAL_FREE = 2 * GIB
HIGH_FREE = 8 * GIB
# Image larger than what the guest holds by this much: compaction is due.
OVERHANG_HIGH = 20 * GIB
# Free-space history for the growth estimate: samples kept, window used.
HISTORY_MAX = 200
GROWTH_WINDOW_S = 24 * 3600
GROWTH_MIN_SPAN_S = 2 * 3600
DAYS_WARN = 7.0
# Known reclaimables in the owner's home: (label, relative path, command).
RECLAIMABLES = (
    ("uv package cache", ".cache/uv", "uv cache clean"),
    ("Go build cache", ".cache/go-build", "go clean -cache"),
    ("Playwright browsers", ".cache/ms-playwright", "rm -rf ~/.cache/ms-playwright"),
    ("Puppeteer browsers", ".cache/puppeteer", "rm -rf ~/.cache/puppeteer"),
    ("npm cache", ".npm/_cacache", "npm cache clean --force"),
    ("pip cache", ".cache/pip", "pip cache purge"),
    ("Cargo registry cache", ".cargo/registry", "cargo cache -a (cargo-cache crate)"),
    ("Gradle caches", ".gradle/caches", "rm -rf ~/.gradle/caches"),
    ("Bun install cache", ".bun/install/cache", "bun pm cache rm"),
)
# System-owned growth that duplicates what JARVIS already keeps: rsyslog
# copies every Sysmon-for-Linux event into /var/log/syslog although JARVIS
# reads them from the journal (measured 2026-10-23: 9.2 GB of syslog copies).
SYSLOG_DIR = "/var/log"
SYSLOG_FIX = ("sudo install -Dm644 systemd/rsyslog-sysmon.conf /etc/rsyslog.d/10-jarvis-sysmon.conf "
              "&& sudo systemctl restart rsyslog && sudo rm -f /var/log/syslog.[0-9]*")
STAGING = Path(os.path.expanduser("~/.cache/jarvis-release-staging"))
STAGES_KEEP = 3
WALK_BUDGET_S = 20.0
HISTORY_META = "storage_free_history_v1"
# The reclaim walks are hints, not evidence, and the costliest part of this
# job: measured 2026-11-04 on the owner's laptop, about 19 s CPU and 76 s of
# metadata reads every 30 minutes (uv, npm, Gradle and Bun caches; Gradle and
# Bun hit the 20 s budget every time). A walk's sizes are reused for at most
# RECLAIM_MAX_AGE_S while the system drive has headroom; once free space is
# below HIGH_FREE, or has dropped by RECLAIM_FREE_DROP since the walk, every
# run walks again, because that is when the owner acts on the hints.
RECLAIM_META = "storage_reclaim_walk_v1"
RECLAIM_MAX_AGE_S = 6 * 3600
RECLAIM_FREE_DROP = 2 * GIB
BALLAST_META = "storage_ballast_releases_v1"
LIVE_RELEASE = Path("/opt/jarvis/current")


def _finding(severity, title, detail, where="storage", host="win", category="storage"):
    return dict(host=host, severity=severity, title=title, detail=detail,
                category=category, where=where)


def _gib(n):
    return f"{n / GIB:.1f} GiB"


def tree_bytes(path, budget_s=WALK_BUDGET_S, clock=time.monotonic):
    """(bytes, complete) under `path`, giving up when the budget is spent.

    A partial figure is still a lower bound, which is all a reclaim hint needs;
    `complete` is False so the finding says "at least"."""
    total, complete = 0, True
    start = clock()
    try:
        for root, dirs, files in os.walk(path, onerror=lambda e: None):
            if clock() - start > budget_s:
                complete = False
                break
            for name in files:
                try:
                    st = os.lstat(os.path.join(root, name))
                except OSError:
                    continue
                total += st.st_blocks * 512 if hasattr(st, "st_blocks") else st.st_size
    except OSError:
        return 0, False
    return total, complete


def walk_reclaimables(home=None, walk=None):
    """[(label, bytes, complete, command)] for the known caches that exist."""
    home = Path(os.path.expanduser("~")) if home is None else Path(home)
    walk = walk or tree_bytes
    out = []
    for label, rel, cmd in RECLAIMABLES:
        p = home / rel
        if p.is_dir():
            size, complete = walk(p)
            out.append((label, size, complete, cmd))
    return out


def reclaim_sizes(store, now, free, walk_all=None):
    """The reclaim hints: a fresh walk, or the last one while it may stand.

    Reused only when the last walk is younger than RECLAIM_MAX_AGE_S (and not
    from the future), the drive is measured above HIGH_FREE, and free space
    has not fallen by RECLAIM_FREE_DROP since. Anything unreadable walks."""
    walk_all = walk_all or walk_reclaimables
    measured = isinstance(free, (int, float)) and math.isfinite(free)
    try:
        last = json.loads(store.get_meta(RECLAIM_META, "") or "null")
    except (ValueError, TypeError, AttributeError):
        last = None
    if (measured and free >= HIGH_FREE and isinstance(last, dict)
            and isinstance(last.get("at"), (int, float)) and 0 <= now - last["at"] < RECLAIM_MAX_AGE_S
            and isinstance(last.get("free"), (int, float)) and last["free"] - free < RECLAIM_FREE_DROP
            and isinstance(last.get("sizes"), list)):
        try:
            return [(str(a), int(b), bool(c), str(d)) for a, b, c, d in last["sizes"]]
        except (TypeError, ValueError):
            pass
    sizes = walk_all()
    try:
        store.set_meta(RECLAIM_META, json.dumps({
            "at": now, "free": free if measured else None,
            "sizes": [list(x) for x in sizes]}))
    except Exception:
        pass
    return sizes


def guest_usage(root="/"):
    """(used, total) bytes of the guest root filesystem from statvfs, or None."""
    try:
        st = os.statvfs(root)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    return total - st.f_bfree * st.f_frsize, total


def docker_reclaimable(run=None):
    """Docker's own accounting of reclaimable bytes, or None when it does not answer."""
    import subprocess
    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True,
                                               errors="replace", timeout=15))
    try:
        proc = run(["docker", "system", "df", "--format", "{{json .}}"])
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    total = 0
    for line in (proc.stdout or "").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        total += _parse_size(str(row.get("Reclaimable", "")).split(" ")[0])
    return total


def _parse_size(text):
    """Docker's '4.323GB' / '623.7MB' / '1.115kB' -> bytes; unknown -> 0."""
    units = {"B": 1, "kB": 1000, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4}
    text = (text or "").strip()
    for unit in sorted(units, key=len, reverse=True):
        if text.endswith(unit):
            try:
                return float(text[: -len(unit)]) * units[unit]
            except ValueError:
                return 0
    return 0


def stale_stages(staging=STAGING, keep=STAGES_KEEP, live=LIVE_RELEASE, now=None):
    """Stage directories JARVIS may remove: beyond the newest `keep`, not the
    live release's source and not the live base. Returns [(path, bytes)]."""
    try:
        entries = [p for p in staging.iterdir() if p.is_dir() and (staging / (p.name + ".stage.json")).exists()]
    except OSError:
        return []
    entries.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    protected = set()
    try:
        manifest = json.loads((live / "RELEASE.json").read_text())
        protected.add(str(manifest.get("source", "")).rstrip("/"))
    except (OSError, ValueError):
        pass
    out = []
    for p in entries[keep:]:
        if str(p) in protected:
            continue
        size, _ = tree_bytes(p, budget_s=5.0)
        out.append((p, size))
    return out


def growth(history, now, window_s=GROWTH_WINDOW_S, min_span_s=GROWTH_MIN_SPAN_S):
    """Bytes of free space lost per day over `window_s`, from (ts, free) pairs;
    None when the span is too short to say."""
    recent = [(t, f) for t, f in history if now - t <= window_s]
    if len(recent) < 2:
        return None
    t0, f0 = recent[0]
    t1, f1 = recent[-1]
    if t1 - t0 < min_span_s:
        return None
    return (f0 - f1) / (t1 - t0) * 86400.0


def judge(host, guest, now, history=(), reclaim=(), docker=None, stages=(), ballast_released=False,
          syslog=None):
    """Findings from measured values. Pure; `host` is the PowerShell dict or
    None, `guest` is (used, total) or None."""
    out = []
    if not host:
        out.append(_finding("high", "storage headroom is unmeasured on the Windows side",
                            "the host read returned nothing, so the system drive, the WSL image "
                            "and the page file are not being watched this run", category="visibility"))
    else:
        for err in host.get("errors") or []:
            out.append(_finding("medium", "storage measurement incomplete", err, category="visibility"))
        free = host.get("sys_free")
        if isinstance(free, (int, float)) and math.isfinite(free):
            per_day = growth(list(history) + [(now, free)], now)
            days = (free - CRITICAL_FREE) / per_day if per_day and per_day > 0 else None
            if free < CRITICAL_FREE:
                out.append(_finding(
                    "critical", "system drive below the critical headroom line",
                    f"{host.get('sys_drive', 'C:')} has {_gib(free)} free. At this level the WSL "
                    f"image and the page file cannot grow; both disk-full crashes of the VM "
                    f"(2026-10-11, 2026-10-23) happened here."
                    + (" The ballast file was released this run to buy time." if ballast_released else
                       " No ballast file was available to release.")
                    + " Free space now: the reclaim commands are in the low findings below."))
            elif free < HIGH_FREE:
                out.append(_finding(
                    "high", "system drive headroom is low",
                    f"{host.get('sys_drive', 'C:')} has {_gib(free)} free; below {_gib(CRITICAL_FREE)} "
                    f"the VM has died twice. Reclaim before it gets there."))
            if days is not None and days < DAYS_WARN:
                out.append(_finding(
                    "high" if days < 2 else "medium", "system drive will reach the critical line soon",
                    f"losing {_gib(per_day)} per day over the last day; about {days:.1f} day(s) of "
                    f"headroom left at this rate ({_gib(free)} free now)."))
            elif per_day is not None:
                out.append(_finding(
                    "low", "system drive growth rate",
                    f"{'losing' if per_day > 0 else 'gaining'} {_gib(abs(per_day))} per day; "
                    f"{_gib(free)} free now."))
        vhdx = host.get("vhdx_bytes")
        if isinstance(vhdx, (int, float)) and guest:
            used, _total = guest
            overhang = vhdx - used
            if overhang > OVERHANG_HIGH:
                out.append(_finding(
                    "high", "WSL disk image holds far less than its size on Windows",
                    f"ext4.vhdx is {_gib(vhdx)} on the system drive but the guest uses "
                    f"{_gib(used)}: {_gib(overhang)} of freed blocks never went back to Windows. "
                    f"Either enable sparse mode once (`wsl --shutdown`, `wsl --manage "
                    f"{host.get('distro') or 'Ubuntu'} --set-sparse true`, then `sudo fstrim -av`) "
                    f"or compact the image with diskpart while WSL is stopped."))
            else:
                out.append(_finding("low", "WSL disk image size",
                                    f"ext4.vhdx {_gib(vhdx)} on the system drive, {_gib(used)} used inside."))
        if host.get("pagefile_automatic") is True:
            alloc = sum(int(p.get("allocated_mb") or 0) for p in host.get("pagefile") or [])
            out.append(_finding(
                "medium", "page file is system-managed",
                f"Windows grows the page file on demand ({alloc} MB allocated now); on a nearly full "
                f"drive that growth fails and the host runs out of commit. A fixed size (initial = "
                f"maximum, 8192 MB) removes one of the two growth paths."))
        ballast = host.get("ballast_bytes")
        if not ballast:
            out.append(_finding(
                "medium", "no ballast file reserved",
                f"create {host.get('ballast_path') or '%LOCALAPPDATA%\\Jarvis\\ballast.bin'} with "
                f"`fsutil file createnew <path> 4294967296` (4 GB, no administrator needed). JARVIS "
                f"deletes it only when the drive drops below {_gib(CRITICAL_FREE)} free, and pages you."))
        else:
            out.append(_finding("low", "ballast reserved", f"{_gib(ballast)} held for an emergency release."))
    if guest is None:
        out.append(_finding("medium", "guest filesystem usage unreadable", "statvfs failed",
                            host="wsl", category="visibility"))
    total_reclaim = 0
    for label, size, complete, cmd in reclaim:
        if size >= GIB:
            total_reclaim += size
            out.append(_finding(
                "low", f"reclaimable: {label}",
                f"{'at least ' if not complete else ''}{_gib(size)}; `{cmd}`. Your data, your "
                f"call; JARVIS does not delete it.", host="wsl"))
    if syslog and syslog >= GIB:
        total_reclaim += syslog
        out.append(_finding(
            "medium" if syslog >= 4 * GIB else "low", "reclaimable: syslog copies of the Sysmon journal",
            f"{_gib(syslog)} under {SYSLOG_DIR}; rsyslog writes every Sysmon-for-Linux event to "
            f"/var/log/syslog although JARVIS reads them from the journal, so this is a second copy "
            f"of evidence that already exists. Stop the copy and drop the rotated files: `{SYSLOG_FIX}`.",
            host="wsl"))
    if docker:
        total_reclaim += docker
        out.append(_finding("low", "reclaimable: Docker images, stopped containers and build cache",
                            f"{_gib(docker)} by Docker's own accounting; `docker system prune` "
                            f"(add `-a` to drop unused images too).", host="wsl"))
    if total_reclaim:
        out.append(_finding("low", "reclaimable total inside WSL",
                            f"{_gib(total_reclaim)}; freed blocks return to Windows only with "
                            f"sparse mode or a compaction.", host="wsl"))
    for path, size in stages:
        out.append(_finding("low", "superseded release stage removed",
                            f"{path} ({_gib(size)}): beyond the newest {STAGES_KEEP}, not deployed.",
                            host="wsl"))
    out.append(_finding(
        "low", "storage governor boundaries",
        "Measures the system drive, the WSL image, swap, page-file policy and the ballast "
        "every run, and the known caches at least every 6 hours (every run once headroom "
        "is low). Deletes only JARVIS-made superseded release stages and, "
        "below the critical line, the ballast file it was told to hold. Never touches your "
        "data, the store or the sealed history.", category="limits"))
    return out


def _history(store, now, free):
    try:
        hist = json.loads(store.get_meta(HISTORY_META, "[]")) or []
    except (ValueError, TypeError):
        hist = []
    hist = [(float(t), float(f)) for t, f in hist if isinstance(t, (int, float))]
    if isinstance(free, (int, float)) and math.isfinite(free):
        hist.append((now, float(free)))
    hist = hist[-HISTORY_MAX:]
    store.set_meta(HISTORY_META, json.dumps(hist))
    return hist[:-1] if isinstance(free, (int, float)) else hist


# -- plain Linux servers (ARGUS-SERVER.md W1) --------------------------------
# A server has no Windows drive or WSL image; what fills is its own mounts.
# Real, writable filesystems only: pseudo filesystems, squashfs snaps and
# read-only mounts cannot fill from the workload.
LINUX_REAL_FS = frozenset(("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs",
                           "reiserfs", "bcachefs", "nilfs2", "vfat", "exfat"))
LINUX_CRITICAL_PCT = 3.0       # below this share free, writes fail within hours
LINUX_CRITICAL_FREE = 1 * GIB  # or below this absolute free space
LINUX_HIGH_PCT = 10.0
LINUX_INODE_CRITICAL_PCT = 2.0
LINUX_INODE_HIGH_PCT = 10.0
LINUX_MAX_MOUNTS = 32
LINUX_HISTORY_META = "storage_linux_free_history_v1"


def linux_mounts(mounts_text=None, statvfs=None, stat=os.stat):
    """[(mountpoint, fstype, free, total, ifree, itotal)] for real writable mounts,
    one per device; (mounts, unreadable) with the mountpoints statvfs refused."""
    # Looked up here, not as a default: Windows Python has no os.statvfs, and a
    # default is evaluated at import, which broke every Windows install of the
    # 2026-10-25 and 2026-10-27 builds (tests/test_windows_import.py).
    statvfs = statvfs or os.statvfs
    if mounts_text is None:
        try:
            with open("/proc/self/mounts", errors="replace") as fh:
                mounts_text = fh.read()
        except OSError:
            return None, ["/proc/self/mounts"]
    out, unreadable, seen = [], [], set()
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] not in LINUX_REAL_FS:
            continue
        mnt = parts[1].replace("\\040", " ")
        if "ro" in parts[3].split(","):
            continue
        try:
            dev = stat(mnt).st_dev
            if dev in seen:
                continue
            st = statvfs(mnt)
        except OSError:
            unreadable.append(mnt)
            continue
        seen.add(dev)
        out.append((mnt, parts[2], st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize,
                    st.f_favail, st.f_files))
        if len(out) >= LINUX_MAX_MOUNTS:
            break
    return out, unreadable


def judge_linux(mounts, unreadable, now, history=None):
    """Findings for a plain Linux server's mounts. `history` maps mountpoint to
    [(ts, free)] samples before this one."""
    history = history or {}
    out = []
    if mounts is None:
        return [_finding("medium", "disk space not observed", "cannot read /proc/self/mounts",
                         host="wsl", category="visibility")]
    if not mounts:
        out.append(_finding("medium", "disk space not observed",
                            "no real writable filesystem was found in /proc/self/mounts",
                            host="wsl", category="visibility"))
    for mnt in unreadable:
        out.append(_finding("medium", f"disk space not observed on {mnt}",
                            "statvfs was refused; its headroom is unknown", where=mnt,
                            host="wsl", category="visibility"))
    for mnt, fstype, free, total, ifree, itotal in mounts:
        if total <= 0:
            continue
        pct = free * 100.0 / total
        detail = f"{_gib(free)} free of {_gib(total)} ({pct:.1f} %), {fstype}"
        if pct < LINUX_CRITICAL_PCT or free < LINUX_CRITICAL_FREE:
            out.append(_finding("critical", f"{mnt} is nearly full", detail
                                + "; writes (logs, databases, package updates) are about to fail",
                                where=mnt, host="wsl"))
        elif pct < LINUX_HIGH_PCT:
            out.append(_finding("high", f"{mnt} is low on space", detail, where=mnt, host="wsl"))
        else:
            rate = growth(list(history.get(mnt, ())) + [(now, free)], now)
            if rate and rate > 0 and free / rate < DAYS_WARN:
                out.append(_finding("high", f"{mnt} fills in {free / rate:.1f} days",
                                    f"{detail}; losing {_gib(rate)} per day over the last day",
                                    where=mnt, host="wsl"))
        # btrfs and some others report no inode limit (f_files == 0).
        if itotal > 0:
            ipct = ifree * 100.0 / itotal
            if ipct < LINUX_INODE_CRITICAL_PCT:
                out.append(_finding("critical", f"{mnt} is out of inodes",
                                    f"{ifree} of {itotal} inodes free ({ipct:.1f} %); new files "
                                    "cannot be created whatever the free space", where=mnt, host="wsl"))
            elif ipct < LINUX_INODE_HIGH_PCT:
                out.append(_finding("high", f"{mnt} is low on inodes",
                                    f"{ifree} of {itotal} inodes free ({ipct:.1f} %)",
                                    where=mnt, host="wsl"))
    return out


def _linux_history(store, now, mounts):
    """Record this sample per mount; return the history before it."""
    try:
        hist = json.loads(store.get_meta(LINUX_HISTORY_META, "{}") or "{}")
    except (ValueError, TypeError):
        hist = {}
    if not isinstance(hist, dict):
        hist = {}
    before = {k: [(float(t), float(f)) for t, f in v] for k, v in hist.items()
              if isinstance(v, list)}
    # Only mounts present now are kept, so the history stays bounded by
    # LINUX_MAX_MOUNTS x HISTORY_MAX samples.
    after = {m[0]: (before.get(m[0], []) + [(now, float(m[2]))])[-HISTORY_MAX:]
             for m in mounts or ()}
    store.set_meta(LINUX_HISTORY_META, json.dumps(after))
    return before


def audit_linux(store, now=None, mounts_text=None, statvfs=None, stat=os.stat):
    now = time.time() if now is None else now
    mounts, unreadable = linux_mounts(mounts_text, statvfs=statvfs, stat=stat)
    history = _linux_history(store, now, mounts)
    return judge_linux(mounts, unreadable, now, history)


def release_ballast(path, run=None):
    """Delete the ballast file on the Windows side. Returns (released, detail)."""
    from jarvis.platform.windows import ps_json as _ps
    run = run or _ps
    if not path:
        return False, "no ballast path"
    safe = str(path).replace("'", "''")
    script = (f"$p='{safe}'; if (-not (Test-Path -LiteralPath $p)) {{ $r=@{{ok=$false;why='absent'}} }} "
              f"else {{ try {{ Remove-Item -LiteralPath $p -Force -ErrorAction Stop; $r=@{{ok=$true}} }} "
              f"catch {{ $r=@{{ok=$false;why=[string]$_.Exception.Message}} }} }}; "
              f"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($r | ConvertTo-Json -Compress)))")
    try:
        result = run(script, timeout=30)
    except Exception as exc:  # noqa: BLE001 - the act must never raise into the scheduler
        return False, f"release failed: {type(exc).__name__}"
    if not result:
        return False, "release returned nothing"
    return bool(result.get("ok")), str(result.get("why") or "released")


def audit(store, hosts=("wsl", "win"), now=None, host=None, guest=None, reclaim=None,
          docker=None, stages=None, release=None, syslog=None):
    now = time.time() if now is None else now
    if "win" not in hosts and machine.kind() == "linux":
        return audit_linux(store, now=now)
    if "win" not in hosts:
        return [_finding("medium", "storage is not watched on the Windows side",
                         "Windows collection is disabled.", category="visibility")]
    if host is None:
        host = ps_json(PS_STORAGE, timeout=40) or None
    if guest is None:
        guest = guest_usage()
    if reclaim is None:
        reclaim = reclaim_sizes(store, now, (host or {}).get("sys_free"))
    if docker is None:
        docker = docker_reclaimable()
    if syslog is None:
        syslog, _ = tree_bytes(SYSLOG_DIR, budget_s=5.0)
    free = (host or {}).get("sys_free")
    history = _history(store, now, free)
    # The one automatic act: below the critical line, give back the ballast.
    released = False
    if host and isinstance(free, (int, float)) and free < CRITICAL_FREE and host.get("ballast_bytes"):
        released, why = (release or release_ballast)(host.get("ballast_path"))
        try:
            log = json.loads(store.get_meta(BALLAST_META, "[]")) or []
        except (ValueError, TypeError):
            log = []
        log.append({"at": now, "free": free, "bytes": host.get("ballast_bytes"),
                    "released": released, "detail": why})
        store.set_meta(BALLAST_META, json.dumps(log[-50:]))
    removed = []
    for path, size in (stale_stages() if stages is None else stages):
        try:
            import shutil
            shutil.rmtree(path)
            meta = path.parent / (path.name + ".stage.json")
            if meta.exists():
                meta.unlink()
            removed.append((path, size))
        except OSError:
            continue
    return judge(host, guest, now, history=history, reclaim=reclaim, docker=docker,
                 stages=removed, ballast_released=released, syslog=syslog)
