"""Off-box heartbeat: a ping to a dead-man service, so silence pages someone.

docs/architecture/ARGUS-SERVER.md W10. Every other channel runs on this
machine; when the host or the daemon dies they all go quiet together. With
`heartbeat_url` set (https) in the alert config, the fast-lane `heartbeat` job
sends one GET per run to a service the owner chose (healthchecks.io, an Uptime
Kuma push monitor, Better Stack, a self-hosted equivalent), and that service
alerts when the pings stop.

The URL carries the owner's token, so it is a secret: it is never logged, put in
a finding or passed on a command line, and errors are reported by type and HTTP
status only. Nothing about this machine is sent: no body, no added parameters.
A ping proves the scheduler's fast lane ran this minute; collector failures
reach the owner through the normal channels.
"""

import json
import time
import urllib.error
import urllib.request

from jarvis.core.finding import LOCAL_HOST
from jarvis.response import alert

META = "heartbeat_state"
TIMEOUT_S = 10
FAILING_AFTER = 5
UA = "jarvis-heartbeat/1"


def _f(severity, title, detail):
    return {"category": "daemon", "severity": severity, "title": title, "detail": detail,
            "where": "heartbeat_url", "host": LOCAL_HOST}


def _ping(url, opener=urllib.request.urlopen):
    """'' on success, else a short reason that never contains the URL."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    try:
        with opener(req, timeout=TIMEOUT_S) as resp:
            resp.read(4096)
            code = getattr(resp, "status", 200)
            return "" if 200 <= code < 300 else f"HTTP {code}"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None)
        return f"{type(exc).__name__}" + (f" ({type(reason).__name__})" if reason is not None else "")


def _load(store):
    try:
        state = json.loads(store.get_meta(META, "{}") or "{}")
        return state if isinstance(state, dict) else {}
    except (TypeError, ValueError):
        return {}


def run(store, conf=None, now=None, opener=urllib.request.urlopen):
    conf = alert.load_conf() if conf is None else conf
    now = int(time.time() if now is None else now)
    url = (conf.get("heartbeat_url") or "").strip()
    if not url:
        return [_f("low", "no off-box heartbeat: nothing outside this machine notices if it goes silent",
                   "Every alert channel runs here, so a dead host or daemon pages no one. Create a "
                   "dead-man check (healthchecks.io, an Uptime Kuma push monitor, Better Stack) and put "
                   "its ping URL in heartbeat_url in the alert config (https). It gets one request a "
                   "minute and alerts you when they stop.")]
    if not alert._https(url):
        return [_f("medium", "heartbeat_url is not an https URL",
                   "The heartbeat is not sent: a ping URL carries a token and must not travel in "
                   "clear. Use the https form your dead-man service gives you.")]
    state = _load(store)
    error = _ping(url, opener)
    if error:
        state["failures"] = int(state.get("failures", 0)) + 1
        state["last_error"] = error
    else:
        state.update(failures=0, last_error="", last_ok=now)
    state["last_try"] = now
    store.set_meta(META, json.dumps(state, sort_keys=True))
    if state["failures"] >= FAILING_AFTER:
        last_ok = state.get("last_ok")
        since = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(last_ok)) if last_ok else "never"
        return [_f("medium", "heartbeat cannot reach its dead-man service",
                   f"{state['failures']} pings in a row failed ({state['last_error']}); last success "
                   f"{since}. The dead-man service will alert you as if this machine were down.")]
    if error:
        return [_f("low", "heartbeat ping failed once",
                   f"{error}; the next run retries. {FAILING_AFTER} failures in a row become medium.")]
    return [_f("ok", "off-box heartbeat delivered", "the dead-man service heard from this machine")]
