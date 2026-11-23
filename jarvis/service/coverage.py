"""Audit the monitor itself: where is it blind, degraded, or silently failing?

Every other module answers "what is wrong with the machine?". This one answers
"what can this system not see, and is it actually running?" — which is the
question that decides how much the others' silence is worth.

The failure mode this exists to prevent has already happened once here. The
daemon ran for hours reporting every Windows collector as healthy while the
interop socket was dead: each job had a timestamp, each timestamp was recent,
and every one of them was a stale snapshot being re-read. A clean report and no
report look identical unless something is specifically checking.

So the rules are:

  * A collector that has never produced a result is not "clean", it is missing.
  * A result older than its own interval is stale, and stale is a failure.
  * A check that could not run must say so where the result would have gone.
  * Degraded coverage is named with what specifically is invisible because of
    it, not as a generic warning.
"""

import json
import os
import shutil
import subprocess
import time

from jarvis.collectors.process import hidden
from jarvis.core.finding import finding as _finding
from jarvis.core.paths import REPO_ROOT
from jarvis.core.store import DEFAULT_DB, Store
from jarvis.platform import host
from jarvis.platform import windows as collect_windows
from jarvis.service.schedule import JOBS, NOT_APPLICABLE


def _cmd(args, timeout=10):
    # Notification authority belongs to the daemon's main PID.  systemctl is
    # linked to libsystemd and may use an inherited NOTIFY_SOCKET, which makes
    # the manager reject its message as an unauthorized child notification.
    env = os.environ.copy()
    for key in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"):
        env.pop(key, None)
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout,
                           text=True, errors="replace", env=env)
        return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def job_health(db_path=DEFAULT_DB):
    """Is every collector actually producing fresh results?"""
    out = []
    try:
        store = Store(db_path)
    except Exception as exc:
        return [_finding("collectors", "critical", "cannot open the database",
                         f"{exc} — nothing is being recorded", db_path)]
    try:
        snaps = store.get_snapshots()
        retries = {name: store.get_meta("collector_retry_" + name, "") for name in JOBS}
    finally:
        store.close()

    now = time.time()
    stale, broken, missing = [], [], []
    for name, (interval, label) in JOBS.items():
        # This audit cannot observe its own result: the scheduler writes a
        # snapshot only after the job returns, so on every run our own entry is
        # either absent or one interval old. Reporting that would be a permanent
        # false positive about the one collector that is provably running.
        if name in ("coverage", "report"):
            continue
        s = snaps.get(name)
        if not s or not s.get("ts"):
            missing.append(name)
            continue
        age = now - s["ts"]
        if s.get("error"):
            broken.append((name, s["error"]))
        # Two intervals of slack: jobs run one at a time, so a long Windows
        # audit legitimately delays the one queued behind it.
        elif age > max(interval * 2, interval + 300):
            stale.append((name, age, interval))

    for name in missing:
        out.append(_finding(
            "collectors", "critical", f"collector '{name}' has never produced a result",
            "there is no snapshot for it at all, so its entire subject area is "
            "unmonitored — this is not a clean result, it is no result",
            "jarvis serve") | {"about_collector": name})
    for name, err in broken:
        out.append(_finding(
            "collectors", "high", f"collector '{name}' is failing",
            f"last run raised: {err.strip().splitlines()[-1][:160] if err.strip() else 'unknown error'}",
            "jarvis serve") | {"about_collector": name})
    for name, age, interval in stale:
        out.append(_finding(
            "collectors", "high", f"collector '{name}' is stale",
            f"last result is {int(age // 60)} min old but it is supposed to run "
            f"every {interval // 60 or 1} min — you are reading history, not status",
            "jarvis serve") | {"about_collector": name})
    # Held retries: the scheduler kept a still-fresh good result after a
    # failed run. Shown so the smoothing is visible, never silent.
    for name, raw in sorted(retries.items()):
        try:
            note = json.loads(raw) if raw else None
        except ValueError:
            note = None
        if not isinstance(note, dict) or now - float(note.get("at") or 0) > 900:
            continue
        age = int((now - float(note.get("last_good") or now)) // 60)
        out.append(_finding(
            "collectors", "low", f"collector '{name}' is retrying",
            f"its last run failed ({str(note.get('error') or '?')[:120]}); the "
            f"previous result, {age} min old and still within its freshness "
            f"budget, stays in use until a retry succeeds",
            "jarvis serve") | {"about_collector": name})
    if not (missing or broken or stale):
        out.append(_finding(
            "collectors", "ok", "all collectors are current",
            f"{len(JOBS) - 2} collectors checked (coverage and the email report "
            f"excluded), every one fresh and error-free",
            db_path))
    return out


def daemon_health():
    """Is the 24/7 chain intact — service, linger, and the Windows logon task?"""
    if host.native_windows():
        # No systemd here: the native service task is what starts this daemon
        # at logon and restarts it, and its state file is the evidence.
        from jarvis.service import supervisors
        return supervisors.audit_native_service()
    out = []
    if not shutil.which("systemctl"):
        return [_finding("daemon", "medium", "systemd not available",
                         "cannot verify that the monitor runs continuously", "")]

    # `--priority` moves the unit to the system manager (still running as this
    # user) so it can hold a negative nice and OOM score. Accept either scope.
    user_active = _cmd(["systemctl", "--user", "is-active", "jarvis.service"])
    system_active = _cmd(["systemctl", "is-active", "jarvis.service"])
    user_enabled = _cmd(["systemctl", "--user", "is-enabled", "jarvis.service"])
    system_enabled = _cmd(["systemctl", "is-enabled", "jarvis.service"])
    enabled_states = ("enabled", "enabled-runtime", "static")
    duplicate = ((user_active == "active" and system_active == "active") or
                 (user_enabled in enabled_states and system_enabled in enabled_states))
    if duplicate:
        out.append(_finding(
            "daemon", "high", "two JARVIS service managers are enabled",
            "Both the user and system managers can launch the same daemon on the "
            "same port. One instance crash-loops while duplicate collection consumes "
            "CPU. Keep the priority system unit and disable the user unit.",
            "systemctl --user disable --now jarvis.service"))

    # Prefer the privileged system unit whenever it is active; otherwise use
    # whichever scope is actually running so health remains truthful.
    flag = "--system" if system_active == "active" else "--user"
    active = system_active if flag == "--system" else user_active
    scope = [] if flag == "--system" else ["--user"]
    enabled = system_enabled if flag == "--system" else user_enabled
    hint = "" if flag == "--system" else "--user "
    if active != "active":
        out.append(_finding("daemon", "critical", "the monitor is not running",
                            f"jarvis.service is '{active or 'unknown'}' — nothing "
                            f"is being collected right now",
                            f"systemctl {hint}status jarvis.service"))
    if enabled not in enabled_states:
        out.append(_finding("daemon", "high", "the monitor will not start on boot",
                            f"jarvis.service is '{enabled or 'unknown'}'",
                            f"systemctl {hint}enable jarvis.service"))

    # Priority: a monitor that loses CPU/IO contention or gets OOM-killed under
    # load is not continuous when it matters most.
    mainpid = _cmd(["systemctl", *scope, "show", "jarvis.service",
                    "-p", "MainPID", "--value"])
    if mainpid.isdigit() and mainpid != "0":
        try:
            with open(f"/proc/{mainpid}/stat", errors="replace") as fh:
                nice = int(fh.read().split(") ", 1)[1].split()[16])
        except (OSError, IndexError, ValueError):
            nice = 0
        try:
            with open(f"/proc/{mainpid}/oom_score_adj", errors="replace") as fh:
                oom = int(fh.read().strip())
        except (OSError, ValueError):
            oom = 0
        if nice > 0 or oom > 0:
            out.append(_finding(
                "daemon", "medium", "the monitor runs at default priority",
                f"nice {nice}, oom_score_adj {oom} — under CPU, IO or memory "
                f"pressure it can be starved or killed. `./install.sh "
                f"--priority` moves it to the system manager with nice -10 and "
                f"OOM immunity", "install.sh --priority"))

    # Linger only keeps a *user* manager alive; a system unit does not need it.
    linger = "yes" if flag == "--system" else _cmd(
        ["loginctl", "show-user", os.environ.get("USER", ""), "--property=Linger"])
    if "yes" not in linger.lower():
        out.append(_finding(
            "daemon", "high", "linger is off — the monitor dies with your shell",
            "without linger systemd tears down the user manager when your last "
            "session ends, so closing the terminal stops monitoring",
            f"sudo loginctl enable-linger {os.environ.get('USER', '$USER')}"))

    if not out:
        out.append(_finding("daemon", "ok", "the monitor runs continuously",
                            "service active and enabled, linger on — survives "
                            "logout and restarts on failure", "systemd --user"))
    return out


def bridge_status():
    """One finding: is the Windows interop bridge reachable right now?

    Split out of visibility() so the scheduler can run it on a short interval
    of its own. The Windows side going blind is the single blind spot that has
    to page in seconds, not on the ten-minute self-audit cycle — every Windows
    collector, including the injected-input/keylogger hook, reports nothing the
    moment powershell.exe stops answering, and nothing else notices.

    Category is "collectors" and the wording carries "is down" / "interop
    bridge" on purpose: alert.py classifies that as an outage, so it bypasses
    the min-severity filter and the persistence gate and mails immediately.
    """
    if not host.has_windows():
        return []           # a Linux server has no Windows side to go blind
    if collect_windows.available():
        via = ("started directly (native Windows)" if host.native_windows()
               else f"reachable via {os.environ.get('WSL_INTEROP', '?')}")
        out = [_finding(
            "collectors", "ok", "Windows bridge is up", f"powershell.exe {via}",
            collect_windows._PS or "", host="win")]
        mode = collect_windows.interop_mode()
        if mode != "direct":
            # Wording deliberately avoids alert.py's outage markers: the
            # bridge works through /init, so this must not page as "down".
            out.append(_finding(
                "collectors", "medium" if mode == "init" else "critical",
                "the WSL interop registration was removed from binfmt_misc",
                "The kernel's WSLInterop entry is missing, so the kernel no "
                "longer knows how to run a .exe by name. "
                + ("JARVIS starts PowerShell through /init meanwhile, so "
                   "collection continues; " if mode == "init" else
                   "/init is not executable here, so Windows collectors "
                   "cannot run until it is restored; ")
                + "a privileged container running its own systemd flushes "
                "the shared table (seen 2026-10-22). Restore with "
                "`sudo systemctl restart systemd-binfmt` on the WSL side.",
                collect_windows.BINFMT_DIR, host="win"))
        out.extend(_interop_gate_findings())
        return out
    if host.native_windows():
        # Same category and "is down" wording as below: alert.py pages on it.
        return [_finding(
            "collectors", "critical",
            "the Windows side is blind — PowerShell is down",
            "powershell.exe was not found in System32 or could not be started, "
            "so every Windows collector reports nothing rather than reporting "
            "a problem. Check that Windows PowerShell 5.1 is present and that "
            "application control is not blocking it for this account.",
            "powershell.exe", host="win")]
    return [_finding(
        "collectors", "critical",
        "the Windows side is blind — interop bridge is down",
        "powershell.exe is unreachable, so every Windows collector — firewall, "
        "autostart, spyware, intrusion, evasion, hidden-process cross-view and "
        "the injected-input/keylogger hook — reports nothing rather than "
        "reporting a problem. Usually a WSL interop stall rather than tampering; "
        "`wsl --shutdown` from Windows rebuilds it, and the daemon recovers on "
        "its own once it is back.",
        "WSL interop", host="win")]


def _interop_gate_findings():
    """The daemon's own interop admission state (platform/interop_gate.py).

    Wording avoids alert.py's outage markers on purpose: the bridge still
    answers, JARVIS is easing off a slow relay, and Windows collectors are
    reported as failed while it does, so nothing unobserved reads as clean."""
    from jarvis.platform import interop_gate
    st = interop_gate.GATE.state()
    if not st["degraded"]:
        return []
    if st["open"]:
        now = (f"new launches paused for {st['open_for_s']} s (backoff {round(st['backoff_s'])} s, "
               f"{st['consecutive_failures']} launches failed in a row)")
    else:
        now = f"one launch at a time ({st['recent_failures']} of the last {st['recent']} failed)"
    return [_finding(
        "collectors", "medium", "Windows interop is degraded — collectors throttled",
        f"PowerShell launches through WSL interop are failing or timing out, so JARVIS "
        f"limits them: {now}; {st['refused']} launches deferred since start. Windows "
        f"collectors that could not run are reported as failed, not clean. This "
        f"backpressure is what keeps a slow relay from wedging into a `wsl --shutdown`.",
        "WSL interop", host="win")]


def visibility():
    """Which individual views are unavailable, and what each blind spot costs."""
    out = []

    # -- the Windows bridge (also run standalone on a fast interval) ------
    out.extend(bridge_status())

    # -- the Windows drive mount -------------------------------------------
    # A stale DrvFS mount fails every path with EIO — including files JARVIS
    # never wrote, like another program's own policy reads. Name it once here
    # so the per-collector "unreadable" noise below is read as one outage with
    # one fix, not many mysteries.
    try:
        from jarvis.platform import mounts as _mounts
        if _mounts.windows_drive() == _mounts.STALE:
            out.append(_finding(
                "visibility", "medium", "Windows drive mount is stale",
                _mounts.stale_detail() + " Windows-drive reads (sensor spool, "
                "profiles, guard state files) wait until it answers again.",
                _mounts.WINDOWS_DRIVE))
    except Exception:
        pass

    # -- jobs with nothing to observe on this machine -----------------------
    if NOT_APPLICABLE:
        out.append(_finding(
            "limits", "low", "audits not applicable on this machine",
            f"{', '.join(sorted(NOT_APPLICABLE))}: "
            + "; ".join(sorted(set(NOT_APPLICABLE.values()))) + ". They are not "
            "scheduled, not scored and not counted as coverage.",
            f"host kind: {host.kind()}", host=host.local_label()))
    if not host.has_linux():
        # Everything below reads the Linux kernel's own views.
        return out

    # -- elevation ---------------------------------------------------------
    from jarvis.platform import privilege
    lacking = privilege.missing()
    if lacking:
        out.append(_finding(
            "visibility", "medium", "running unprivileged",
            "invisible from here: other accounts' open files, memory maps and "
            "environment, root-only kernel tracing state, and kernel module "
            f"addresses (missing {', '.join(lacking)}).",
            "needs a root-owned install run with python3 -I; see "
            "systemd/capabilities.conf before granting anything"))
    elif privilege.code_tree_problems(str(REPO_ROOT), limit=1):
        out.append(_finding(
            "visibility", "high", "privileged monitor runs editable code",
            "JARVIS holds visibility capabilities while running from code a "
            "non-root account can change ("
            + privilege.code_tree_problems(str(REPO_ROOT), limit=1)[0] + "), so "
            "that account can take the capabilities by editing it. Deploy a "
            "sealed release (scripts/deploy_root_runtime.py) or remove the grant.",
            "/etc/systemd/system/jarvis.service.d/"))
    elif os.geteuid() != 0:
        out.append(_finding(
            "limits", "low", "least-privilege visibility",
            "reading other accounts' processes, kernel tracing and module "
            "addresses through " + ", ".join(privilege.CAPS) + ". Deliberately "
            "not held: " + ", ".join(privilege.NOT_REQUESTED) + "; those views "
            "stay dark rather than run the monitor with near-root power.",
            "systemd/capabilities.conf"))

    # -- Linux cross-views -------------------------------------------------
    if hidden.view_getdents() is None:
        out.append(_finding(
            "visibility", "medium", "syscall view unavailable",
            f"getdents64 cannot be called directly on {os.uname().machine}, so "
            f"an LD_PRELOAD rootkit hiding pids from libc would not be caught",
            "hidden.view_getdents"))
    if hidden.pid_namespace_nested():
        # Not a failed read: the scheduler reports global pids and this
        # distro's /proc numbers its own, so the two can never be compared.
        out.append(_finding(
            "limits", "low", "scheduler view not comparable here",
            "this system runs in a child pid namespace (a WSL2 distro or a "
            "container), where the kernel scheduler's task list uses global "
            "pids that do not map to this /proc. That cross-view cannot run; "
            "readdir, getdents64, the stat sweep and the signal path still do.",
            "/proc/self/ns/pid"))
    elif hidden.view_sched_debug() is None:
        out.append(_finding(
            "visibility", "low", "scheduler view unavailable",
            "neither /proc/sched_debug nor " + hidden.SCHED_DEBUGFS + " is "
            "readable (debugfs unmounted, or root or CAP_DAC_READ_SEARCH "
            "missing), so a process hidden from /proc cannot be cross-checked "
            "against the scheduler. The signal-path view still covers this case.",
            hidden.SCHED_DEBUGFS))

    # -- io_uring ----------------------------------------------------------
    try:
        with open("/proc/sys/kernel/io_uring_disabled", errors="replace") as fh:
            val = fh.read().strip()
    except OSError:
        val = ""
    if val == "0":
        out.append(_finding(
            "visibility", "medium", "io_uring is unrestricted",
            "file, socket and process operations can be performed through a "
            "shared ring instead of syscalls, where no syscall-based monitoring "
            "sees them. `sysctl -w kernel.io_uring_disabled=2` closes it.",
            "/proc/sys/kernel/io_uring_disabled"))

    return out


def known_limits():
    """State the things this design cannot do, so silence is never over-read."""
    return [
        _finding("limits", "low", "sampling, not interception",
                 "the sampling collectors read state on an interval, so anything "
                 "that starts and exits between two passes is invisible to them. "
                 "The kernel-event collectors — `sysmon-linux` (eBPF) and "
                 "`sysmon` (Windows) — are not sampled and close this gap "
                 "wherever they are installed and recording.",
                 "by design"),
        _finding("limits", "low", "no kernel component",
                 "every check runs in userland, so a rootkit already in the "
                 "kernel can lie to all of them at once. The cross-view and "
                 "kernel-integrity checks are built to make that lying visible, "
                 "not to make it impossible.",
                 "by design"),
    ] + ([
        _finding("limits", "low", "WSL is not a security boundary",
                 "anything in WSL can read and write /mnt/c, and Windows can see "
                 "into WSL. Treat findings on either side as findings about one "
                 "machine.",
                 "by design"),
    ] if host.on_wsl() else []) + ([
        _finding("limits", "low", "file privacy is not verified on NTFS",
                 "Windows mode bits enforce nothing, and the access-control "
                 "lists that do are not inspected. JARVIS therefore never "
                 "treats a file here as private: credential findings are not "
                 "downgraded, and an API key is read from the environment "
                 "only, never from a key file.",
                 "by design", host=host.local_label()),
    ] if host.native_windows() else [])


def audit(db_path=DEFAULT_DB, hosts=("wsl", "win")):
    out = []
    out.extend(job_health(db_path))
    out.extend(daemon_health())
    out.extend(visibility())
    out.extend(known_limits())
    return out


CAT_ORDER = {"collectors": 0, "daemon": 1, "visibility": 2, "limits": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9),
                                    x["title"]))
