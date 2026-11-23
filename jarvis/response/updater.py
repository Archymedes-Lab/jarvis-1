"""Install the updates `collectors/host/updates.py` listed: bounded, logged, verified.

Two callers, two authorities:

  * the owner, through `jarvis update apply` at a terminal: anything they
    confirm, including apt and snap when run with sudo, Chocolatey and
    machine-scope winget (Windows shows its own administrator prompt);
  * the daemon, only when the owner set auto_update to "important" or "all",
    and only for items `updates.auto_eligible` accepts (user-scope winget,
    Homebrew): no elevation, no prompt.

Maximum damage boundary of the automatic path: at most AUTO_PER_DAY items a
day, one at a time, each under ITEM_TIMEOUT_S; never a removal (apt uses
--only-upgrade, winget upgrades by exact id); never a reboot; never an item
the owner excluded or pinned. Evidence: every attempt is appended to an
owner-only log with the version before and after. Recovery: a winget item can
be put back to its recorded version (`jarvis update revert`); other managers
have no general downgrade and that is stated, not hidden. An update is
"verified" only when a fresh listing no longer shows the old version.
"""

from __future__ import annotations

import json
import os
import threading
import time

LOG = os.path.expanduser("~/.jarvis/updates/log.jsonl")
AUTO_META = "updates_auto_v1"
AUTO_PER_DAY = 10
ITEM_TIMEOUT_S = 600
LOG_MAX_BYTES = 2 * 1024 * 1024
_lock = threading.Lock()


# --- commands (pure) ---------------------------------------------------------------

def command(item):
    """(kind, argv-or-script) to update one item; kind is "linux" or "ps"."""
    pid = item["id"]
    if item["manager"] == "apt":
        return "linux", ["apt-get", "install", "--only-upgrade", "-y", "-q",
                         "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", pid]
    if item["manager"] == "snap":
        return "linux", ["snap", "refresh", pid]
    if item["manager"] == "brew":
        from jarvis.collectors.host import updates
        return "linux", [updates.BREW, "upgrade", pid]
    if item["manager"] == "winget":
        scope = " --scope user" if item.get("scope") == "user" else ""
        return "ps", _ps(f"winget upgrade --id {_q(pid)} --exact --silent --accept-package-agreements "
                         f"--accept-source-agreements --disable-interactivity{scope}")
    if item["manager"] == "choco":
        return "ps", _ps(f"choco upgrade {_q(pid)} -y --no-progress")
    raise ValueError(f"unknown manager {item['manager']!r}")


def revert_command(entry):
    """Put a winget item back to the version recorded before it was updated."""
    if entry.get("manager") != "winget" or not entry.get("from") or entry["from"] in ("Unknown",) \
            or entry["from"].startswith(("<", ">")):
        raise ValueError("only a winget update with a recorded exact version can be reverted")
    return "ps", _ps(f"winget install --id {_q(entry['id'])} --exact --version {_q(entry['from'])} --force "
                     "--silent --accept-package-agreements --accept-source-agreements --disable-interactivity")


def _q(value):
    value = str(value)
    if not value or any(c in value for c in "'\"`$;&|<>\r\n"):
        raise ValueError(f"refusing an unsafe package argument {value!r}")
    return "'" + value + "'"


def _ps(line):
    return ("$ErrorActionPreference='Continue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            f"$out = ({line} 2>&1 | Out-String -Width 300); $code = $LASTEXITCODE; "
            "$tail = ($out -split \"`n\" | Where-Object { $_.Trim() -and $_ -notmatch '^\\s*[-\\\\|/]\\s*$' } "
            "| Select-Object -Last 6) -join \"`n\"; "
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{code=$code; tail=$tail} | ConvertTo-Json -Compress)))")


# --- execution ---------------------------------------------------------------------

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
       "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l", "APT_LISTCHANGES_FRONTEND": "none"}


def _run_linux(argv, timeout):
    import subprocess
    env = dict(ENV)
    if argv and argv[0].endswith("/brew"):
        env.update(PATH=os.path.dirname(argv[0]) + ":" + ENV["PATH"], HOME=os.path.expanduser("~"),
                   HOMEBREW_NO_ANALYTICS="1", HOMEBREW_NO_ENV_HINTS="1")
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout,
                           env=env, cwd="/")
        tail = "\n".join([ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()][-6:])
        return r.returncode, tail
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout} s"
    except OSError as exc:
        return None, type(exc).__name__


def _run_ps(script, timeout):
    from jarvis.platform import windows as collect_windows
    out = collect_windows.ps_json(script, timeout=timeout)
    if not isinstance(out, dict):
        return None, "PowerShell gave no answer"
    try:
        code = int(out.get("code")) if out.get("code") is not None else None
    except (TypeError, ValueError):
        code = None
    return code, str(out.get("tail") or "").replace("\r", "")[-600:]


def run_item(item, runners=None, timeout=ITEM_TIMEOUT_S):
    """(exit code or None, output tail). Never raises."""
    runners = runners or {"linux": _run_linux, "ps": _run_ps}
    try:
        kind, what = command(item)
    except ValueError as exc:
        return None, str(exc)
    try:
        return runners[kind](what, timeout)
    except Exception as exc:  # noqa: BLE001 - one item's failure must not stop the log
        return None, type(exc).__name__


def verify(items, fresh_plan):
    """{key: (verified, now_version)} from a listing taken after the attempts.

    Verified: the item is no longer outdated, or its installed version moved
    away from the one recorded before. Unverified when its manager could not
    be listed: absence of evidence is not success."""
    pending = {(i["manager"], i["id"]): i for i in fresh_plan.get("items") or []}
    unreadable = set((fresh_plan.get("failed") or {}))
    out = {}
    for i in items:
        key = (i["manager"], i["id"])
        if i["manager"] in unreadable or i["manager"] not in (fresh_plan.get("managers") or []):
            out[key] = (False, None)
        elif key not in pending:
            out[key] = (True, i["available"])
        else:
            now_v = pending[key]["installed"]
            out[key] = (now_v != i["installed"] and bool(now_v), now_v)
    return out


def apply(items, actor, *, runners=None, plan_fn=None, now=None, log_path=None, on_item=None):
    """Update `items` one at a time, then verify with one fresh listing.
    Returns the result rows (also appended to the log)."""
    from jarvis.collectors.host import updates
    started = time.time() if now is None else now
    rows = []
    for item in items:
        t0 = time.time()
        code, tail = run_item(item, runners)
        row = {"at": t0, "actor": actor, "manager": item["manager"], "id": item["id"],
               "name": item["name"], "from": item["installed"], "to": item["available"],
               "important": item["important"], "exit": code, "tail": tail[-400:],
               "seconds": round(time.time() - t0, 1)}
        rows.append(row)
        if on_item:
            on_item(row)
    fresh = (plan_fn or updates.plan)()
    checked = verify(items, fresh)
    for row, item in zip(rows, items):
        ok, now_v = checked[(item["manager"], item["id"])]
        row["verified"] = bool(ok)
        row["now"] = now_v
        if not ok:
            row["error"] = ("still outdated after the attempt" if row["exit"] == 0
                            else (row["tail"].splitlines()[-1] if row["tail"] else f"exit {row['exit']}"))[:200]
    _append(rows, log_path)
    return {"started": started, "finished_at": time.time(), "results": rows, "plan": fresh}


def _append(rows, path=None):
    path = path or LOG
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    try:
        if os.path.getsize(path) > LOG_MAX_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def read_log(path=None, limit=200):
    path = path or LOG
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# --- the automatic path ------------------------------------------------------------

def _auto_state(store):
    try:
        st = json.loads(store.get_meta(AUTO_META, "{}") or "{}")
        return st if isinstance(st, dict) else {}
    except (TypeError, ValueError):
        return {}


def last_auto(store):
    return _auto_state(store)


def budget_left(store, now):
    """Items still allowed today (rolling 24 h)."""
    st = _auto_state(store)
    recent = [t for t in st.get("attempts") or [] if now - float(t) < 86400]
    return max(0, AUTO_PER_DAY - len(recent)), recent


def start_auto(store, eligible, now=None, *, apply_fn=None, background=True, db_path=None):
    """Hand eligible items to one background run. Single flight: returns False
    when a run is already going or today's budget is spent. Items that failed
    in the last 24 h are not retried automatically (the owner sees them)."""
    now = time.time() if now is None else now
    if not _lock.acquire(blocking=False):
        return False
    try:
        left, recent = budget_left(store, now)
        st = _auto_state(store)
        # Failures are remembered for a day across runs, so an item that failed
        # is shown to the owner instead of being retried every run.
        failures = {k: float(t) for k, t in (st.get("failures") or {}).items() if now - float(t) < 86400}
        todo = [i for i in eligible if f"{i['manager']}:{i['id']}" not in failures][:left]
        if not todo:
            _lock.release()
            return False
        st.update(running=True, started_at=now, queued=[f"{i['manager']}:{i['id']}" for i in todo],
                  attempts=recent + [now] * len(todo))
        store.set_meta(AUTO_META, json.dumps(st, sort_keys=True))
        path = db_path or getattr(store, "path", None)
    except Exception:
        _lock.release()
        raise

    def work():
        try:
            result = (apply_fn or apply)(todo, "auto")
            fails = dict(failures)
            for r in result["results"]:
                if not r.get("verified"):
                    fails[f"{r.get('manager')}:{r.get('id')}"] = float(r.get("at") or now)
            fin = {**st, "running": False, "finished_at": result["finished_at"],
                   "results": result["results"], "failures": fails}
            fin.pop("queued", None)
            _save(path, store if not background else None, fin)
        except Exception as exc:  # noqa: BLE001 - record the failure, never crash the daemon
            _save(path, store if not background else None,
                  {**st, "running": False, "finished_at": time.time(), "results": [],
                   "error": type(exc).__name__})
        finally:
            _lock.release()

    if background:
        threading.Thread(target=work, name="argus-updater", daemon=True).start()
    else:
        work()
    return True


def _save(db_path, store, state):
    if store is not None:
        store.set_meta(AUTO_META, json.dumps(state, sort_keys=True))
        return
    from jarvis.core.store import Store
    s = Store(db_path) if db_path else Store()
    try:
        s.set_meta(AUTO_META, json.dumps(state, sort_keys=True))
    finally:
        s.close()
