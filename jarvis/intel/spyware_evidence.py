"""Fuse live, read-only evidence into reasoning subjects, source by source.

Every source reports `current`, `partial` or `unavailable`, and every kind of
evidence JARVIS does not collect is listed in `not_connected`, so a quiet
result is never read as a clean one. Nothing here changes host state.
"""

import ntpath
import re

from jarvis.core.reasoning import vocab
from jarvis.core.reasoning.vocab import Observation, Subject
from jarvis.platform import spy_linux, spy_windows

KEYBOARD_HOOKS = {13, 0, 2, 3}          # low-level, journal-record, keyboard, message
RAW_KEYBOARD = (1, 6)
RIDEV_REMOVE, RIDEV_SINK, RIDEV_EXSINK = 0x1, 0x100, 0x1000
MAX_WATCHERS = 2000

NOT_CONNECTED = (
    "keyboard polling (GetAsyncKeyState) - Windows does not log it (measured 2026-09-23)",
    "screen capture by BitBlt or DXGI duplication - not consent-gated, no sensor",
    "clipboard listeners - no sensor",
    "who called SendInput - Windows records no sender",
    "local staging writes - no file-write sensor outside the Sysmon policy",
    "beacon timing - connection snapshots only, no flow history",
    "kernel-level process hiding - user-mode cross-views only, no supported kernel sensor",
)


def keyboard_watchers(rows, own_pids=()):
    """{(pid, start): row} for processes registering a keyboard-capable watcher."""
    own, out = {int(p) for p in own_pids if isinstance(p, int) or str(p).isdigit()}, {}
    for row in (rows or [])[:MAX_WATCHERS]:
        if not isinstance(row, dict) or row.get("failed"):
            continue
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            continue
        kind, ok = row.get("kind"), False
        if kind == "hook":
            try:
                ok = int(row.get("type")) in KEYBOARD_HOOKS
            except (TypeError, ValueError):
                ok = False
        elif kind == "rawinput":
            try:
                page, usage, flags = (int(x) for x in str(row.get("type")).split("/"))
            except ValueError:
                continue
            ok = ((page, usage) == RAW_KEYBOARD and not flags & RIDEV_REMOVE
                  and bool(flags & (RIDEV_SINK | RIDEV_EXSINK)))
        if ok:
            out[(pid, row.get("start"))] = {"row": row, "own": pid in own}
    return out


def _epoch(iso):
    try:
        from datetime import datetime
        return int(datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp())
    except (TypeError, ValueError):
        return None


def merge_hooks(subjects, watchers, boot_id=""):
    """Attach hook facts to live subjects by (pid, start); unmatched watchers
    (already exited or unidentified) become subjects of their own."""
    by_pid = {}
    for s in subjects:
        m = re.match(r"win:[^:]*:(\d+):(.*)$", s.key)
        if m:
            by_pid[int(m.group(1))] = s
    extra = []
    for (pid, start), info in watchers.items():
        row = info["row"]
        live = by_pid.get(pid)
        # A live process with this pid that started at another time is a reused
        # pid, not the process that registered the watcher.
        same = False
        if live is not None:
            began = _epoch(live.key.split(":", 3)[3]) if live.key.count(":") >= 3 else None
            same = (not start) or began is None or abs(began - int(start)) <= 2
        target = live if same else None
        if target is None:
            path = row.get("path") or ""
            target = Subject(
                key=f"win:{boot_id}:{pid}:exited-or-unmatched:{start}", host="win",
                label=ntpath.basename(path) or f"pid {pid}",
                signature={"Valid": "valid"}.get(row.get("sig"), "unknown" if not path else "invalid"),
                publisher=str(row.get("signer") or ""), path_class=spy_windows.path_class(path),
                runs_script=ntpath.basename(path).lower() in vocab.SCRIPT_HOSTS)
            extra.append(target)
        if info["own"]:
            target.declared = vocab.JARVIS_COMPONENT
        target.observations.append(Observation("cap.keyboard.hook", "win32k-audit"))
    return extra


def windows_contradictions(data, boot_id=""):
    """Subjects for processes visible to only some independent views.

    Mirrors the hidden-process collector's own confirmation rules: a raw
    `wmiOnly` or `apiOnly` entry counts only when the pid is also in that view
    and absent from the other, and a network owner only when it appears in no
    listing at all. The other ghost lists were re-verified in PowerShell.
    """
    def ints(key):
        return {p for p in (data.get(key) or []) if isinstance(p, int) and p > 4}

    def listed(key):
        return {p.get("pid") for p in (data.get(key) or [])
                if isinstance(p, dict) and isinstance(p.get("pid"), int) and p["pid"] > 4}

    def ghost_pids(key):
        return {g.get("pid") for g in (data.get(key) or [])
                if isinstance(g, dict) and isinstance(g.get("pid"), int) and g["pid"] > 4}
    wmi, api, tasklist = listed("wmi"), listed("api"), listed("tasklist")
    reasons = {}
    for pid in ghost_pids("openable"):
        reasons.setdefault(pid, []).append("handle-table")
    for key, name in (("ghostThreads", "threads"), ("ghostPerf", "perf-counters"),
                      ("ghostSvc", "service-controller")):
        for pid in ghost_pids(key):
            reasons.setdefault(pid, []).append(name)
    for pid in (ghost_pids("ghostNet") & ints("netpids")) - wmi - api - tasklist:
        reasons.setdefault(pid, []).append("network-owner")
    for pid in ints("wmiOnly") & (wmi - api):
        reasons.setdefault(pid, []).append("wmi-only")
    for pid in ints("apiOnly") & (api - wmi):
        reasons.setdefault(pid, []).append("process-api-only")
    return [Subject(key=f"win:{boot_id}:{pid}:contradiction", host="win", label=f"pid {pid}",
                    observations=[Observation("conceal.contradiction", "hidden:" + "+".join(sorted(v)))])
            for pid, v in sorted(reasons.items())]


_LINUX_TITLES = ("process hidden from /proc listing", "process hidden from libc but visible to the kernel",
                 "pid answers signals but has no /proc entry")


def linux_contradictions(findings, boot_id=""):
    out = []
    for f in findings or []:
        if f.get("severity") == "critical" and f.get("title") in _LINUX_TITLES:
            m = re.match(r"pid (\d+)\b", str(f.get("detail") or ""))
            if m:
                out.append(Subject(
                    key=f"linux:{boot_id}:contradiction:{m.group(1)}", host="wsl",
                    label=f"pid {m.group(1)}",
                    observations=[Observation("conceal.contradiction", "hidden-linux")]))
    return out


def gather(hosts=("win", "wsl"), *, deep=False, own_pids=None, sources=None):
    """Subjects and per-source coverage. `sources` injects readers for tests."""
    src = sources or {}
    subjects, coverage = [], {}
    boot = ""
    if "win" in hosts:
        payload = (src["windows"]() if "windows" in src else spy_windows.collect())
        boot = str((payload or {}).get("observed_at", ""))[:10] if isinstance(payload, dict) else ""
        subs, cov = spy_windows.build(payload, boot)
        coverage["windows-processes"] = cov["status"]
        subjects += subs
        audit = src["inputaudit"]() if "inputaudit" in src else _broker("inputaudit")
        if audit is None:
            coverage["keyboard-hooks"] = "unavailable"
        else:
            if own_pids is None:
                own_pids = _own_pids()
            extra = merge_hooks(subs, keyboard_watchers(audit.get("watchers"), own_pids or ()), boot)
            subjects += extra
            coverage["keyboard-hooks"] = "partial" if int(audit.get("parse_failures") or 0) else "current"
        if deep:
            data = src["hidden_windows"]() if "hidden_windows" in src else _hidden_windows()
            if data is None:
                coverage["hidden-windows"] = "unavailable"
            else:
                subjects += windows_contradictions(data, boot)
                coverage["hidden-windows"] = "current"
    if "wsl" in hosts:
        subs, cov = (src["linux"]() if "linux" in src else spy_linux.subjects())
        coverage["linux-processes"] = cov["status"]
        subjects += subs
        if deep:
            findings = src["hidden_linux"]() if "hidden_linux" in src else _hidden_linux()
            coverage["hidden-linux"] = "unavailable" if findings is None else "current"
            subjects += linux_contradictions(findings or [], "")
    return subjects, coverage


def _broker(name):
    from jarvis.platform import broker
    try:
        data, _why = broker.result(name)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _own_pids():
    try:
        from jarvis.collectors.host.inputwatch.helper import running
        return list(running() or [])
    except Exception:
        return []


def _hidden_windows():
    from jarvis.collectors.process.hidden.windows import audit_windows
    try:
        result = audit_windows()
    except Exception:
        return None
    return result[1] if isinstance(result, tuple) and len(result) == 2 else None


def _hidden_linux():
    from jarvis.collectors.process.hidden.run import audit_linux
    try:
        return audit_linux(deep=False)
    except Exception:
        return None
