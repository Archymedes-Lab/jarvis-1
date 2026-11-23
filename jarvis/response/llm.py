"""The one door to the local language model.

Everything that asks Ollama for text — the dashboard assistant, the email
narrator — goes through `chat`, so they share the transport, the loopback
bridge and a single lock. CPU inference serves one request at a time; letting
callers race only queues them inside Ollama while each holds a thread.

The model is advisory by construction: this returns text, never a tool call,
and callers decide what that text is allowed to become.
"""

import json
import re
import threading
import time
import urllib.error
import urllib.request

from jarvis.core.finding import LOCAL_HOST
from jarvis.platform.windows import ps_json, stdin_text
from jarvis.response.privacy import redact

DEFAULT_MODEL = "llama3.2:1b"
DEFAULT_URL = "http://127.0.0.1:11434"
BUSY = "busy"
PING_TIMEOUT = 3

LOCK = threading.Lock()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("model redirects are forbidden")


def _open(req, timeout):
    # Ignore environment proxies; evidence must stay on loopback.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()).open(req, timeout=timeout)


def model_name(conf):
    return (conf.get("ollama_model") or DEFAULT_MODEL).strip()


def _origins(conf):
    base = (conf.get("ollama_url") or DEFAULT_URL).rstrip("/")
    return base, base not in ("http://127.0.0.1:11434", "http://localhost:11434")


def ping(conf, timeout=PING_TIMEOUT):
    """-> (model_loaded | model_ready | offline | refused | misconfigured, seconds).

    A cheap GET of Ollama's model list — no generation, no lock, so it is safe
    from the scheduler thread and from HTTP handlers. The bridge fallback keeps
    the same guarantee as chat: on NAT-based WSL installs the only door to
    Windows loopback is the existing PowerShell bridge, never the LAN.
    """
    base, forbidden = _origins(conf)
    if forbidden:
        return "misconfigured", 0.0
    started = time.monotonic()
    req = urllib.request.Request(base + "/api/tags", method="GET")
    try:
        with _open(req, timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if not isinstance(exc, urllib.error.HTTPError):
            try:
                data = _bridge_get(timeout)
            except (urllib.error.URLError, OSError, ValueError):
                return "offline", time.monotonic() - started
            if data is None:
                return "offline", time.monotonic() - started
            if isinstance(data, dict) and data.get("_jarvis_error"):
                return "refused", time.monotonic() - started
    if not isinstance(data, dict):
        return "offline", time.monotonic() - started
    loaded = [m.get("name") or m.get("model") or ""
              for m in data.get("models") or () if isinstance(m, dict)]
    if any(name.split(":")[0] == model_name(conf).split(":")[0] for name in loaded):
        return "model_loaded", time.monotonic() - started
    return "model_ready", time.monotonic() - started


# Plain-language reading of why the model can't answer. `ok` is the only state
# in which a generation is worth attempting.
DIAGNOSES = {
    "ok": "Local AI is ready.",
    "stopped": "Local AI is not running. Basic assistance is still working.",
    "model_missing": "Local AI is running but the {model} model is not installed. "
                     "Basic assistance is still working.",
    "misconfigured": "Local AI is pointed at a non-local address, which ARGUS refuses. "
                     "Basic assistance is still working.",
    "refused": "Local AI refused the request. Basic assistance is still working.",
    "inference_failed": "Local AI is running but could not answer just now. "
                        "Basic assistance is still working.",
}


def _installed(data, wanted):
    """True when `wanted` (e.g. llama3.2:1b) is in an /api/tags listing.

    A bare name means ":latest", as Ollama resolves it. A different size tag
    of the same family is a different model and does not count."""
    def norm(name):
        name = str(name or "").strip().lower()
        return name if ":" in name else name + ":latest"
    names = {norm(m.get("name") or m.get("model")) for m in (data.get("models") or ())
             if isinstance(m, dict)}
    return norm(wanted) in names


_HTTP_STATUS = re.compile(r"\((\d{3})\)")


def classify_failure(error):
    """Cause of a failed request, from the error text alone (no second request).

    -> stopped | model_missing | refused | inference_failed. A transport error
    (nothing listening, DNS, timeout) is "stopped"; an HTTP status is read from
    the server's own answer: 404 or "not found" means the model, 5xx means the
    service is up but generation failed, other 4xx means it refused us."""
    text = str(error or "")
    match = _HTTP_STATUS.search(text)
    low = text.lower()
    if match:
        status = int(match.group(1))
        if status == 404 or "model" in low and "not found" in low:
            return "model_missing"
        return "inference_failed" if status >= 500 else "refused"
    if "model" in low and "not found" in low:
        return "model_missing"
    return "stopped"


def diagnose(conf, timeout=PING_TIMEOUT):
    """-> {state, label, model, seconds}. Read-only: lists models, never generates.

    Separates a stopped service from a missing model and a refused request, so
    the interface can say which one without showing a connection error."""
    model = model_name(conf)
    base, forbidden = _origins(conf)
    if forbidden:
        state, seconds = "misconfigured", 0.0
    else:
        started = time.monotonic()
        req = urllib.request.Request(base + "/api/tags", method="GET")
        data = None
        try:
            with _open(req, timeout) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError:
            data = {"_jarvis_error": "http"}
        except (urllib.error.URLError, OSError, ValueError):
            try:
                data = _bridge_get(timeout)
            except (urllib.error.URLError, OSError, ValueError):
                data = None
        seconds = time.monotonic() - started
        if not isinstance(data, dict):
            state = "stopped"
        elif data.get("_jarvis_error"):
            state = classify_failure(data["_jarvis_error"])
            state = "refused" if state in ("model_missing", "inference_failed") else state
        else:
            state = "ok" if _installed(data, model) else "model_missing"
    if state == "ok":
        note_success()
    else:
        note_failure(state)
    return {"state": state, "label": DIAGNOSES[state].format(model=model),
            "model": model, "seconds": round(seconds, 2)}


# Reconnect backoff for interactive callers. After a failed attempt the next
# few seconds of questions skip the model instead of each waiting out a
# connection timeout; the wait doubles per consecutive failure, up to a cap.
_BACKOFF = {"failures": 0, "until": 0.0, "state": "unknown"}
_BACKOFF_BASE, _BACKOFF_CAP = 5.0, 120.0
_BACKOFF_LOCK = threading.Lock()


def note_failure(state="stopped", now=None):
    now = time.monotonic() if now is None else now
    with _BACKOFF_LOCK:
        _BACKOFF["failures"] += 1
        wait = min(_BACKOFF_CAP, _BACKOFF_BASE * 2 ** (_BACKOFF["failures"] - 1))
        _BACKOFF.update(until=now + wait, state=state)


def note_success():
    with _BACKOFF_LOCK:
        _BACKOFF.update(failures=0, until=0.0, state="ok")


def reset_backoff():
    """The user asked to retry: forget the cooldown."""
    with _BACKOFF_LOCK:
        _BACKOFF.update(failures=0, until=0.0, state="unknown")


def cooling_down(now=None):
    now = time.monotonic() if now is None else now
    with _BACKOFF_LOCK:
        return now < _BACKOFF["until"]


def last_state():
    """State from the most recent attempt, with no network call."""
    with _BACKOFF_LOCK:
        return _BACKOFF["state"]


def _bridge_get(timeout):
    """GET through the Windows bridge; returns None when the bridge is down.

    ps_json already decodes the base64 JSON payload it asked PowerShell for,
    so what comes back here is a dict — not a blob to decode again.
    """
    script = (
        "try{$r=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' "
        f"-MaximumRedirection 0 -Method Get -TimeoutSec {int(timeout)};"
        "$j=$r|ConvertTo-Json -Depth 10 -Compress}"
        "catch{$j=@{_jarvis_error=[string]$_.Exception.Message}|ConvertTo-Json -Compress};"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))")
    try:
        data = ps_json(script, timeout=timeout + 10)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def status_findings(conf, timeout=PING_TIMEOUT):
    """One visibility finding: is the local model actually there?

    The model's only job is colour on mail and answers on ask, so its absence
    is never an outage and never pages — but a dead model must be a known
    state, not something noticed the one time someone asks it a question.
    "ok" when healthy; severity never rises above "low".
    """
    state, seconds = ping(conf, timeout)
    where = f"{model_name(conf)} at {(conf.get('ollama_url') or DEFAULT_URL).rstrip('/')}"
    if state in ("model_loaded", "model_ready"):
        detail = ("responding" if state == "model_loaded" else "service up; "
                  f"model {model_name(conf)} not resident — it loads on first use, "
                  "which makes the first question slow")
        return {"category": "model", "severity": "ok", "host": LOCAL_HOST,
                "title": "the local model is available", "detail":
                f"{detail} ({seconds:.2f}s).", "where": where}
    if state == "misconfigured":
        return {"category": "model", "severity": "low", "host": LOCAL_HOST,
                "title": "the model endpoint is misconfigured",
                "detail": "ollama_url must be the local loopback endpoint "
                          "http://127.0.0.1:11434 — other origins are refused by policy, "
                          "so every model feature is silently off.", "where": where}
    label = "refused" if state == "refused" else "not responding"
    return {"category": "model", "severity": "low", "host": LOCAL_HOST,
            "title": f"the local model is {label}",
            "detail": f"No answer from {where} after {seconds:.1f}s. The deterministic "
                      "assistant still answers operational questions; only the local-model "
                      "features (voice, open questions, plan notes) are affected. "
                      "Start Ollama on the Windows host to restore them, or, if it is not "
                      "installed, run `jarvis model install`: it shows what it would "
                      "download and asks before changing anything.",
            "where": where}


def _bridge(body, timeout):
    """POST through Windows PowerShell when Ollama is on Windows loopback.

    WSL's loopback is separate on NAT-based installs, and Ollama deliberately
    listens only on Windows loopback, so cross that boundary through the
    existing PowerShell bridge instead of exposing Ollama to the LAN.
    """
    script = (
        "$ErrorActionPreference='Stop';"
        + stdin_text("b") +
        "try{$r=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/chat' "
        f"-MaximumRedirection 0 -Method Post -ContentType 'application/json' -Body $b -TimeoutSec {int(timeout)};"
        "$j=$r|ConvertTo-Json -Depth 10 -Compress}"
        "catch{$j=@{_jarvis_error=[string]$_.Exception.Message}|ConvertTo-Json -Compress};"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))")
    return ps_json(script, timeout=timeout + 10, payload=body)


def _request(conf, body, timeout):
    base = (conf.get("ollama_url") or DEFAULT_URL).rstrip("/")
    if base not in ("http://127.0.0.1:11434", "http://localhost:11434"):
        return None, "Security policy requires the local loopback model endpoint."
    req = urllib.request.Request(base + "/api/chat", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with _open(req, timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace")), None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if base not in ("http://127.0.0.1:11434", "http://localhost:11434"):
            return None, exc
        data = _bridge(body, timeout)
        if isinstance(data, dict) and data.get("_jarvis_error"):
            return None, data["_jarvis_error"]
        return data, (None if data is not None else exc)


def chat(conf, system, user, *, examples=(), model="", num_predict=110, temperature=0.2,
         timeout=90, wait=0.0):
    """-> (text, error). `error` is "" on success, BUSY when the model is taken.

    `examples` are (user, assistant) turns shown before the real request; small
    models imitate a demonstrated exchange far more faithfully than a described
    one. `wait` is how long to queue for the model: 0 for interactive callers
    that should answer "busy" at once, longer for background work.
    """
    messages = [{"role": "system", "content": system}]
    for asked, answered in examples:
        messages += [{"role": "user", "content": asked},
                     {"role": "assistant", "content": answered}]
    messages.append({"role": "user", "content": user})
    messages = [{**m, "content": redact(m["content"])} for m in messages]
    acquired = LOCK.acquire(timeout=wait) if wait > 0 else LOCK.acquire(blocking=False)
    if not acquired:
        return "", BUSY
    try:
        body = json.dumps({
            "model": model or model_name(conf), "stream": False, "keep_alive": "5m",
            "options": {"temperature": temperature, "num_ctx": 2048,
                        "num_predict": num_predict},
            "messages": messages,
        }).encode()
        data, error = _request(conf, body, timeout)
    finally:
        LOCK.release()
    if isinstance(data, dict):
        text = str((data.get("message") or {}).get("content") or "").strip()
        return (text, "") if text else ("", "the local model returned no answer")
    return "", str(error or "the local model returned an invalid response")
