"""Who is watching the mouse and keyboard?

The elevated broker keeps a Win32k audit trace running (inputaudit.ps1) and
reports every process that registered a low-level hook or a background
raw-input sink since the trace started, with its image path and signature.
This module turns that inventory into findings.

What it can and cannot see was measured on this machine on 2026-09-23 with a
positive control: hook (1002) and raw-input (1001) registrations are logged
and attributed. Key-state polling (1003) is written by the kernel only at a
key event, and only for a process that called GetAsyncKeyState at one call
per millisecond or more since the previous key event; slower polling is never
logged, and the 2026-09-23 control polled too slowly to show whether faster
polling is (re-measured by scripts/tools/probe-win32k-polling.ps1). A
registration is logged only once, when it happens, so anything that
registered before the trace started this boot is missing too. Both gaps are
stated in every summary. WinEvent hooks (1000: focus and window events, the
accessibility API) are listed too; they see windows, not keystrokes.

Severity follows what the evidence can carry. A keyboard watcher that runs
unsigned code, or runs inside a script host, has the shape of a keylogger and
is high. One whose process could not be identified is a visibility gap, not a
verdict. Signed software that watches input (push-to-talk, remapping, remote
control, accessibility) is named at low so it is visible without lowering the
score. JARVIS's own hook is recognised by the pids its supervisor verifies,
never by name or command line, which anyone can imitate.
"""

import ntpath

from jarvis.core import collection
from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import iso, now
from jarvis.platform import broker

# SetWindowsHookEx filter types that see input. Low-level hooks are always
# global. The others may be thread-local (an app watching its own window),
# which the event does not distinguish, so they are only ever low.
HOOK_TYPES = {13: ("keyboard", "low-level keyboard hook", True),
              14: ("mouse", "low-level mouse hook", True),
              0: ("keyboard", "journal-record hook", True),
              2: ("keyboard", "keyboard hook", False),
              7: ("mouse", "mouse hook", False),
              3: ("keyboard", "message hook", False)}

RIDEV_REMOVE = 0x1
RIDEV_INPUTSINK = 0x100
RIDEV_EXINPUTSINK = 0x1000
RAW_DEVICES = {(1, 6): "keyboard", (1, 2): "mouse"}

# Signed programs that run whatever script they are given. Their signature
# says nothing about the code that installed the hook.
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "python.exe", "pythonw.exe", "node.exe",
                "java.exe", "javaw.exe", "rundll32.exe", "regsvr32.exe",
                "autohotkey.exe", "autohotkey64.exe", "autohotkeyu64.exe"}

SYSTEM_DIRS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
BOOT_GAP_S = 300        # trace started this long after boot: early watchers unseen
MAX_TRACE_TRIES = 3     # mirrors $MaxTries in inputaudit.ps1

POLLING_BLIND_SPOT = (
    "Key-state polling (GetAsyncKeyState) is logged by Windows only at one call "
    "per millisecond or more between key events, and anything that registered "
    "before the trace started is missing, so this list is not everything that "
    "can read input.")
# The trace must carry keyword 0x1400 for 1003 to exist at all (measured
# 2026-10-21); an older broker script traces 0x400 and sees no polling.
POLLING_UNTRACED = (
    "This broker's trace does not carry the keyword that logs key-state polling "
    "(GetAsyncKeyState), so polling keyloggers are invisible until the broker is "
    "reinstalled; anything that registered before the trace started is missing too.")

# Kernel gate for 1003: calls since the previous key event / ms elapsed >= 1.
# A row below the Velociraptor community thresholds is still reported: the
# kernel already applied its own gate, and the thresholds only bound what one
# burst looks like.
POLL_LABEL = "key-state polling (GetAsyncKeyState at one call/ms or more)"
WINEVENT_LABEL = "WinEvent hook (window and focus events)"


def _watch(row):
    """-> (device, label, always_global) for an input watcher, else None."""
    kind = row.get("kind")
    if kind == "hook":
        if row.get("failed"):
            return None
        try:
            return HOOK_TYPES.get(int(row.get("type")))
        except (TypeError, ValueError):
            return None
    if kind == "rawinput":
        try:
            page, usage, flags = (int(x) for x in str(row.get("type")).split("/"))
        except ValueError:
            return None
        device = RAW_DEVICES.get((page, usage))
        # Foreground raw input (games, drawing apps) sees input only while its
        # own window has focus; only a background sink watches everything.
        if not device or flags & RIDEV_REMOVE or not flags & (RIDEV_INPUTSINK | RIDEV_EXINPUTSINK):
            return None
        return device, "background raw-input sink", True
    if kind == "poll":
        return "keyboard", POLL_LABEL, True
    if kind == "winevent":
        # Sees window and focus changes (which app is active, titles via
        # follow-up calls), never key codes; always low or ok.
        return "window", WINEVENT_LABEL, False
    return None


def _trust(row):
    """-> 'unidentified' | 'script-host' | 'unsigned' | 'signed-user' | 'signed-system'."""
    path = (row.get("path") or "").lower()
    if not path:
        return "unidentified"
    if ntpath.basename(path) in SCRIPT_HOSTS:
        return "script-host"
    if row.get("sig") != "Valid":
        return "unsigned"
    return "signed-system" if path.startswith(SYSTEM_DIRS) else "signed-user"


def classify(row, own_pids=()):
    """One inventory row -> finding, or None when it does not watch input."""
    watch = _watch(row)
    if not watch:
        return None
    device, label, is_global = watch
    path = row.get("path") or ""
    name = ntpath.basename(path) or f"pid {row.get('pid')}"
    since = iso(int(row.get("first") or 0))
    if int(row.get("pid") or -1) in set(own_pids):
        return _finding("input", "ok", f"JARVIS's own {label}",
                        f"the injected-input monitor (pid {row.get('pid')}), "
                        f"verified by its supervisor, registered at {since}", path)
    trust = _trust(row)
    windows = row.get("visible_windows")
    hidden = (" It has no visible window." if windows == 0 else "")
    if row.get("exited"):
        hidden += " It has since exited, so it ran only briefly."
    lib = (f" Hook library: {row['lib']}."
           if row.get("lib") and row["lib"] != "NULL" else "")
    if row.get("kind") == "poll" and row.get("calls") is not None:
        lib += (f" Windows measured {row.get('calls')} key-state calls in "
                f"{row.get('ms')} ms between two key events.")
    if device == "window":
        if trust == "unidentified":
            return None
        return _finding(
            "input", "low" if trust in ("unsigned", "script-host") else "ok",
            f"{name} watches window and focus events",
            f"a {label} registered at {since} (pid {row.get('pid')}); it sees which "
            f"window is active, not keystrokes. Screen readers, window managers and "
            f"automation tools do this.{hidden}", path)
    if trust in ("unsigned", "script-host") and is_global:
        sev = "high" if device == "keyboard" else "medium"
        why = ("it runs inside a script host, so its signature says nothing "
               "about the code that installed the hook" if trust == "script-host"
               else f"its image is not validly signed ({row.get('sig') or 'unknown'})")
        return _finding(
            "input", sev, f"{name} is watching every {device} event",
            f"a {label} registered at {since} (pid {row.get('pid')}); {why}. "
            f"This is the shape of a {'keylogger' if device == 'keyboard' else 'mouse tracker'}, "
            f"not proof of one: confirm you installed and started it.{hidden}{lib}", path)
    if trust == "unidentified":
        return _finding(
            "input", "medium" if device == "keyboard" and is_global else "low",
            f"an unidentified process registered a {label}",
            f"pid {row.get('pid')} at {since} exited before it could be identified "
            f"and Sysmon has no record of its start. What it was is unknown, "
            f"which is a visibility gap, not a verdict.", "")
    if trust in ("unsigned", "script-host"):
        return _finding(
            "input", "low", f"{name} registered a {label}",
            f"at {since} (pid {row.get('pid')}); this hook type may watch only "
            f"its own window, which the audit event does not show.{lib}", path)
    signer = row.get("signer") or "a valid signature"
    return _finding(
        "input", "ok" if trust == "signed-system" else "low",
        f"{name} is watching {device} input",
        f"a {label} registered at {since} (pid {row.get('pid')}), signed by "
        f"{signer}. Push-to-talk, key remapping, remote control and "
        f"accessibility software do this; make sure it is software you use.{hidden}",
        path)


def audit(own_pids=(), result=None, clock=None):
    """Findings from the broker's watcher inventory. `result` is injectable."""
    data, why = result if result is not None else broker.result("inputaudit")
    if data is None:
        # Blind to keyboard hooks is a coverage failure, not a footnote: the
        # run must not read "complete" (2026-10-27: the broker timed out on a
        # 70 MB trace for hours while every input run was recorded complete).
        collection.failed("inputaudit", why)
        return [_finding(
            "input", "medium", "input watcher audit unavailable",
            f"{why}. Until it runs again, a program that starts watching the "
            f"keyboard or mouse is not seen. Install or refresh the broker with "
            f"`jarvis broker install`.",
            "broker")]
    collection.succeeded("inputaudit")
    t = clock if clock is not None else now()
    out = []
    watchers = [r for r in (data.get("watchers") or []) if isinstance(r, dict)]
    found = [f for f in (classify(r, own_pids) for r in watchers) if f]
    out += found

    started, boot = int(data.get("session_started") or 0), int(data.get("boot") or 0)
    if started and boot and started - boot > BOOT_GAP_S:
        out.append(_finding(
            "input", "low", "input watchers from early in this boot are unseen",
            f"the audit trace started {(started - boot) // 60} min after boot "
            f"({iso(started)}); anything that registered a hook or raw-input sink "
            f"before then is not in this inventory.", "inputaudit"))
    if int(data.get("parse_failures") or 0):
        out.append(_finding(
            "input", "low", "some input-audit events could not be read",
            f"{data['parse_failures']} event(s) failed to parse this run; the "
            f"watchers they described are missing from the inventory.", "inputaudit"))
    polled = int(data.get("polling_events") or 0)
    if polled and not any(r.get("kind") == "poll" for r in watchers):
        # Events were counted but no row survived (parse failure or row cap):
        # say so rather than lose them.
        out.append(_finding(
            "input", "medium", "key-state polling was logged but not attributed",
            f"Windows wrote {polled} GetAsyncKeyState audit event(s) this run and "
            f"none could be tied to a process; a fast poller may be present.",
            "inputaudit"))

    # Distinct processes, not watchers: one program often holds both a
    # keyboard and a mouse watcher. JARVIS's own hook is not counted.
    mine = {int(p) for p in own_pids}
    watching = {(r.get("pid"), r.get("start")) for r in watchers
                if _watch(r) and r.get("kind") != "winevent"
                and int(r.get("pid") or -1) not in mine}
    # WinEvent hooks see which window has focus and its title, never keys.
    # Screen readers, window managers and UI-automation scrapers all use
    # them; counted but never reported until 2026-10-23, so a scraper that
    # Windows logged was invisible.
    winevent = {}
    for r in watchers:
        if r.get("kind") == "winevent" and int(r.get("pid") or -1) not in mine:
            name = ntpath.basename(r.get("path") or "") or f"pid {r.get('pid')}"
            winevent.setdefault(name, _trust(r))
    if winevent:
        untrusted = sorted(n for n, t in winevent.items() if t in ("unsigned", "unidentified", "script-host"))
        out.append(_finding(
            "input", "low",
            f"{len(winevent)} process(es) hold window-event hooks",
            "these see focus changes and window titles (which app you are in), "
            "not keystrokes: " + ", ".join(sorted(winevent))
            + (f". Unsigned or unidentified: {', '.join(untrusted)}" if untrusted else "")
            + ". Screen readers and window tools do this; a scraper logging which "
              "sites you visit looks the same here.", "inputaudit"))
    traced = bool(data.get("polling_logged"))
    if data.get("etl_capped"):
        out.append(_finding(
            "input", "medium", "input audit trace hit its size cap",
            f"the trace file reached {int(data.get('etl_bytes') or 0) // (1 << 20)} MB "
            f"before this run, so registrations after that point are lost; the "
            f"next rotation starts clean.", "inputaudit"))
    # The queue (2026-10-31): a closed trace is dropped only past its bounds or
    # after it killed the run repeatedly, and never without saying so.
    dropped = int(data.get("dropped_files") or 0)
    if dropped:
        retries = int(data.get("dropped_retries") or 0)
        out.append(_finding(
            "input", "medium", "input audit trace dropped before it was read",
            f"{dropped} closed trace file(s), {int(data.get('dropped_bytes') or 0) // (1 << 20)} MB, "
            f"were deleted unparsed"
            + (f" ({retries} after reading them failed {MAX_TRACE_TRIES} times)" if retries else
               " because the queue was over its bound")
            + "; input watchers registered in those windows are not in this inventory.",
            "inputaudit"))
    backlog = int(data.get("backlog_files") or 0)
    if backlog:
        out.append(_finding(
            "input", "low", "input audit is catching up",
            f"{backlog} closed trace file(s) are queued for the next run; watchers "
            f"registered in them are reported then.", "inputaudit"))
    lost = int(data.get("overflow") or 0) + int(data.get("identity_failures") or 0)
    if lost:
        out.append(_finding(
            "input", "low", "part of the input audit was not kept",
            f"{int(data.get('overflow') or 0)} registration group(s) past the run's cap and "
            f"{int(data.get('identity_failures') or 0)} failed Sysmon lookup(s); the watchers "
            f"involved may be missing or unidentified.", "inputaudit"))
    out.append(_finding(
        "input", "ok",
        f"{len(watching)} process(es) watching keyboard or mouse input",
        (f"inventory since {iso(started)}, refreshed {iso(t)}. " if started else "")
        + (POLLING_BLIND_SPOT if traced else POLLING_UNTRACED), "inputaudit"))
    return out
